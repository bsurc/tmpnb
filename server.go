// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"html/template"
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

type notebookServer struct {
	// pool manages the containers
	pool *notebookPool
	// token is the generated random auth token
	token string
	// mux routes http traffic
	mux *http.ServeMux
	// embed a server
	*http.Server
}

func newNotebookServer(config string) (*notebookServer, error) {
	_ = config
	p, err := newNotebookPool(`.*`, 0, time.Duration(0))
	if err != nil {
		return nil, err
	}
	tkn := newHash(defaultHashSize)
	srv := &notebookServer{}
	srv.pool = p
	srv.token = tkn
	srv.pool.token = tkn
	srv.Server = &http.Server{
		Addr: ":8888",
	}
	srv.mux = http.NewServeMux()
	srv.mux.HandleFunc("/", srv.listImages)
	srv.mux.HandleFunc("/new", srv.newNotebookHandler)
	srv.Handler = srv.mux

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

	tmpnb, err := srv.pool.newNotebook(imageName, false)
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

func main() {
	srv, err := newNotebookServer("")
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.ListenAndServe())
}
