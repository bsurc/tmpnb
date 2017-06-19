// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

const (
	// defaultNotebook is used if the request doesn't specify a docker image.
	defaultNotebook = "jupyter/minimal-notebook"
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

// TODO(kyle): embed or add to notebookServer?
type serverConfig struct {
	AssetPath         string        `json:"asset_path"`
	ContainerLifetime time.Duration `json:"container_lifetime"`
	EnablePProf       bool          `json:"enable_pprof"`
	ImageRegexp       string        `json:"image_regexp"`
	MaxContainers     int           `json:"max_containers"`
	HTTPRedirect      bool          `json:"http_redirect"`
	Logfile           string        `json:"logfile"`
	Port              string        `json:"port"`
	TLSCert           string        `json:"tls_cert"`
	TLSKey            string        `json:"tls_key"`
}

var defaultConfig = serverConfig{
	ContainerLifetime: defaultContainerLifetime,
	ImageRegexp:       allImageMatch,
	MaxContainers:     defaultMaxContainers,
}

// notebookServer handles the http tasks for the temporary notebooks.
type notebookServer struct {
	// pool manages the containers
	pool *notebookPool
	// token is the generated random auth token
	token string
	// mux routes http traffic
	mux *ServeMux
	// embed a server
	*http.Server
	// httpRedirect determines whether http redirects to https
	httpRedirect bool
	// TLS certificate path
	tlsCert string
	// TLS private key path
	tlsKey string
	// html templates
	templates *template.Template
	// logging io.Writer
	logWriter io.Writer
}

// readConfig reads json config from r
func readConfig(r io.Reader) (serverConfig, error) {
	sc := defaultConfig
	err := json.NewDecoder(r).Decode(&sc)
	return sc, err
}

// newNotebookServer initializes a server and owned resources, using a
// configuration if supplied.
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
	var err error
	srv := &notebookServer{}
	if sc.Logfile != "" {
		srv.logWriter, err = os.OpenFile(sc.Logfile, os.O_CREATE|os.O_RDWR|os.O_APPEND, os.ModePerm)
		if err != nil {
			return nil, err
		}
		log.SetOutput(srv.logWriter)
	}
	p, err := newNotebookPool(sc.ImageRegexp, sc.MaxContainers, sc.ContainerLifetime)
	if err != nil {
		return nil, err
	}
	tkn := newHash(defaultHashSize)
	srv.pool = p
	srv.token = tkn
	srv.pool.token = tkn
	srv.Server = &http.Server{
		Addr: sc.Port,
	}
	//srv.mux = http.NewServeMux()
	srv.mux = new(ServeMux)
	srv.mux.Handle("/about", accessLogHandler(http.HandlerFunc(srv.aboutHandler)))
	srv.mux.Handle("/list", accessLogHandler(http.HandlerFunc(srv.listImagesHandler)))
	srv.mux.Handle("/new", accessLogHandler(http.HandlerFunc(srv.newNotebookHandler)))
	srv.mux.Handle("/static/", accessLogHandler(http.FileServer(http.Dir(sc.AssetPath))))
	srv.mux.Handle("/stats", accessLogHandler(http.HandlerFunc(srv.statsHandler)))
	srv.mux.Handle("/status", accessLogHandler(http.HandlerFunc(srv.statusHandler)))
	if sc.EnablePProf {
		srv.mux.Handle("/debug/pprof/", accessLogHandler(http.HandlerFunc(pprof.Index)))
		srv.mux.Handle("/debug/pprof/cmdline", accessLogHandler(http.HandlerFunc(pprof.Cmdline)))
		srv.mux.Handle("/debug/pprof/profile", accessLogHandler(http.HandlerFunc(pprof.Profile)))
		srv.mux.Handle("/debug/pprof/symbol", accessLogHandler(http.HandlerFunc(pprof.Symbol)))
	}

	srv.Handler = srv.mux

	srv.tlsCert = sc.TLSCert
	srv.tlsKey = sc.TLSKey
	srv.httpRedirect = sc.HTTPRedirect

	templateFiles, err := filepath.Glob(filepath.Join(sc.AssetPath, "templates", "*.html"))
	if err != nil {
		return nil, err
	}
	var templatePaths []string
	for _, t := range templateFiles {
		log.Printf("loading template: %s", t)
		templatePaths = append(templatePaths, t)
	}

	srv.templates = template.Must(template.New("").ParseFiles(templatePaths...))

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		log.Println("Shutting down server...")
		err := srv.pool.releaseContainers(true)
		if err != nil {
			log.Print(err)
		}
		if c, ok := srv.logWriter.(io.Closer); ok {
			log.Println("closing log file")
			err = c.Close()
			// If we hit an error, dump it to stdout.
			log.SetOutput(os.Stdout)
		}
		os.Exit(0)
	}()
	go func() {
		for {
			select {
			case p := <-srv.pool.deregisterMux:
				log.Printf("deregistering %s from mux", p)
				srv.mux.Deregister(p)
			}
		}
	}()
	return srv, nil
}

func accessLogHandler(h http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(f)
}

// statusHandler checks the status of a single container, returning 200 if it
// is running, another value otherwise.
func (srv *notebookServer) statusHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := r.FormValue("container")
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}
	filter := filters.NewArgs()
	if id != "" {
		filter.Add("id", id)
	}
	opts := types.ContainerListOptions{
		Filters: filter,
	}
	containers, err := cli.ContainerList(context.Background(), opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if len(containers) < 1 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	state := containers[0].State
	log.Printf("container %s state: %s", id, state)
	_, ping := r.Form["ping"]
	if state != "running" {
		w.WriteHeader(http.StatusNotFound)
	} else if !ping {
		time.Sleep(time.Millisecond * 500)
		w.WriteHeader(http.StatusOK)
		return
	}
	// ping && running
	var tmpnb *tempNotebook
	for _, v := range srv.pool.containerMap {
		if v.id == id {
			tmpnb = v
			break
		}
	}
	if tmpnb == nil {
		log.Printf("couldn't find container in containerMap: %s", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	pingURL := url.URL{
		Scheme: "http",
		Host:   strings.Split(r.Host, ":")[0] + fmt.Sprintf(":%d", tmpnb.port),
		Path:   path.Join("/book", tmpnb.hash) + "/",
	}
	log.Printf("ping target: %s", pingURL.String())
	var resp *http.Response
	status := http.StatusNotFound
	for i := 0; i < 10; i++ {
		resp, err = http.Get(pingURL.String())
		if err != nil {
			log.Printf("ping failed: %s (attempt %d)", err, i)
			time.Sleep(2 * time.Second)
			continue
		}
		resp.Body.Close()
		status = resp.StatusCode
		switch status {
		case http.StatusOK, http.StatusFound:
			log.Println("container pinged successfully")
			status = http.StatusOK
			goto found
		}
	}
found:
	w.WriteHeader(status)
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

	_, pull := r.Form["pull"]

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
	handler := func(w http.ResponseWriter, r *http.Request) {
		tmpnb.lastAccessed = time.Now()
		log.Printf("%s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())
		if isWebsocket(r) {
			log.Print("proxying to websocket handler")
			f := websocketProxy(fmt.Sprintf(":%d", tmpnb.port))
			f.ServeHTTP(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	}
	srv.mux.HandleFunc(handlerPath, handler)

	handlerURL := url.URL{}
	handlerURL.Path = handlerPath
	forwardPath := r.FormValue("path")
	if forwardPath != "" {
		handlerURL.Path = path.Join(handlerPath, forwardPath)
		log.Printf("forwarding path: %s", handlerURL.Path)
	}
	q := url.Values{}
	q.Set("token", srv.token)
	handlerURL.RawQuery = q.Encode()
	srv.templates.ExecuteTemplate(w, "new", struct {
		ID    string
		Path  string
		Token string
	}{
		ID:    tmpnb.id,
		Path:  handlerURL.Path,
		Token: srv.token,
	})
}

// aboutHandler serves the about text directly.
func (srv *notebookServer) aboutHandler(w http.ResponseWriter, r *http.Request) {
	err := srv.templates.ExecuteTemplate(w, "about", nil)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// listImagesHandler lists html links to the different docker images.
func (srv *notebookServer) listImagesHandler(w http.ResponseWriter, r *http.Request) {
	images := []string{}
	for k := range srv.pool.availableImages {
		images = append(images, k)
	}
	sort.Slice(images, func(i, j int) bool {
		return images[i] < images[j]
	})
	err := srv.templates.ExecuteTemplate(w, "list", images)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (srv *notebookServer) statsHandler(w http.ResponseWriter, r *http.Request) {
	/*
		err := srv.templates.ExecuteTemplate(w, "header", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	*/
	nbs := srv.pool.activeNotebooks()
	fmt.Fprintf(w, "Notebooks in use: %d\n", len(nbs))
	fmt.Fprintf(w, "Containers by image:\n")
	m := map[string]int{}
	for _, nb := range nbs {
		m[nb.imageName]++
	}
	tw := tabwriter.NewWriter(w, 0, 8, 0, '\t', 0)
	for k, v := range m {
		fmt.Fprintf(tw, "%s\t%d\n", k, v)
	}
	tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintf(w, "All Containers:\n")
	for _, nb := range nbs {
		fmt.Fprintf(tw, "%s\t%s\n", nb.imageName, nb.lastAccessed)
	}
	tw.Flush()
}

// Start starts the http/s listener.
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
