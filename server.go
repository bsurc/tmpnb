// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"sort"
	"time"
)

const (
	defaultNotebook   = "jupyter/minimal-notebook"
	containerLifetime = 5 * time.Minute
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

// TODO(kyle): embed or add to notebookServer?
type serverConfig struct {
	ContainerLifetime time.Duration `json:"container_lifetime"`
	ImageRegexp       string        `json:"image_regexp"`
	MaxContainers     int           `json:"max_containers"`
	HTTPRedirect      bool          `json:"http_redirect"`
	Port              string        `json:"port"`
	TLSCert           string        `json:"tls_cert"`
	TLSKey            string        `json:"tls_key"`
}

var defaultConfig = serverConfig{
	ContainerLifetime: defaultContainerLifetime,
	ImageRegexp:       allImageMatch,
	MaxContainers:     defaultMaxContainers,
}

type notebookServer struct {
	// pool manages the containers
	pool *notebookPool
	// token is the generated random auth token
	token string
	// mux routes http traffic
	mux *http.ServeMux
	// embed a server
	*http.Server

	httpRedirect bool
	tlsCert      string
	tlsKey       string
}

func readConfig(r io.Reader) (serverConfig, error) {
	sc := defaultConfig
	err := json.NewDecoder(r).Decode(&sc)
	return sc, err
}

func newNotebookServer(config string) (*notebookServer, error) {
	sc := defaultConfig
	if config != "" {
		fin, err := os.Open(config)
		if err != nil {
			return nil, err
		}
		sc, err = readConfig(fin)
		if err != nil {
			return nil, err
		}
	}
	p, err := newNotebookPool(sc.ImageRegexp, sc.MaxContainers, sc.ContainerLifetime)
	if err != nil {
		return nil, err
	}
	tkn := newHash(defaultHashSize)
	srv := &notebookServer{}
	srv.pool = p
	srv.token = tkn
	srv.pool.token = tkn
	srv.Server = &http.Server{
		Addr: sc.Port,
	}
	srv.mux = http.NewServeMux()
	srv.mux.HandleFunc("/", srv.listImages)
	srv.mux.HandleFunc("/new", srv.newNotebookHandler)
	srv.Handler = srv.mux

	srv.tlsCert = sc.TLSCert
	srv.tlsKey = sc.TLSKey
	srv.httpRedirect = sc.HTTPRedirect

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		log.Println("Shutting down server...")
		err := srv.pool.releaseContainers(true)
		if err != nil {
			log.Print(err)
		}
		os.Exit(0)
	}()
	return srv, nil
}

func (srv *notebookServer) newNotebookHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err)
		return
	}

	var imageName = r.FormValue("image")
	if imageName == "" {
		imageName = defaultNotebook
	}

	if _, ok := srv.pool.availableImages[imageName]; !ok {
		http.Error(w, fmt.Sprintf("invalid image name: %s", imageName), http.StatusBadRequest)
		log.Printf("invalid image name: %s", imageName)
		return
	}

	pull := false
	if s := r.FormValue("pull"); s != "" {
		switch s {
		case "true", "1", "yes":
			pull = true
		}
	}

	tmpnb, err := srv.pool.newNotebook(imageName, pull)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err)
		return
	}

	proxyURL := url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", tmpnb.port),
	}
	log.Printf("reverse proxy URL: %s", proxyURL.String())

	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = proxyURL.Scheme
			r.URL.Host = proxyURL.Host
		},
	}
	handlerPath := path.Join("/book", tmpnb.hash) + "/"
	log.Printf("handler: %s", handlerPath)
	srv.mux.HandleFunc(handlerPath, func(w http.ResponseWriter, r *http.Request) {
		tmpnb.lastAccessed = time.Now()
		log.Printf("%s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())
		if isWebsocket(r) {
			log.Print("proxying to websocket handler")
			f := websocketProxy(fmt.Sprintf(":%d", tmpnb.port))
			f.ServeHTTP(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})
	// FIXME(kyle): check for valid connection on the tmpnb port
	time.Sleep(time.Second)
	handlerURL := url.URL{}
	handlerURL.Path = handlerPath
	q := url.Values{}
	q.Set("token", srv.token)
	handlerURL.RawQuery = q.Encode()
	fmt.Fprintln(w, "<html>")
	fmt.Fprintf(w, `<a href="%s">wait a tick, then click</a>`, handlerURL.String())
	fmt.Fprintln(w, "</html>")
}

func (srv *notebookServer) listImages(w http.ResponseWriter, r *http.Request) {
	page := `
  <!DOCTYPE HTML>
  <html>
  <ul>
    {{range . -}}
      <li><a href="new?image={{.}}">{{.}}</a></li>
    {{end -}}
  </ul>
  </html>`

	tmpl, err := template.New("").Parse(page)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	images := []string{}
	for k := range srv.pool.availableImages {
		images = append(images, k)
	}
	sort.Slice(images, func(i, j int) bool {
		return images[i] < images[j]
	})
	err = tmpl.Execute(w, images)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (srv *notebookServer) Start() {
	if srv.tlsCert != "" && srv.tlsKey != "" {
		if srv.httpRedirect {
			httpServer := http.Server{}
			httpMux := http.NewServeMux()
			httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
				u := *r.URL
				u.Scheme = "https"
				u.Host = r.Host
				r.ParseForm()
				u.RawPath = r.Form.Encode()
				http.Redirect(w, r, u.String(), http.StatusPermanentRedirect)
			})
			httpServer.Handler = httpMux
			go func() {
				log.Fatal(httpServer.ListenAndServe())
			}()
		}
		log.Fatal(srv.ListenAndServeTLS(srv.tlsCert, srv.tlsKey))
	} else {
		log.Fatal(srv.ListenAndServe())
	}
}

func main() {
	cfg := ""
	if len(os.Args) > 1 {
		cfg = os.Args[1]
	}
	srv, err := newNotebookServer(cfg)
	if err != nil {
		log.Fatal(err)
	}
	srv.Start()
}
