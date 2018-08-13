// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/bsurc/misc"
	"github.com/bsurc/oauth2"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// defaultNotebook is used if the request doesn't specify a docker image.
	defaultNotebook = "jupyter/minimal-notebook"
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

// notebookServer handles the http tasks for the temporary notebooks.
//
// XXX: note that larger configurations in the docker images, many files can be
// opened.  You may need to set a higher ulimit for files on the server.  On a
// server with ~60 open notebooks, ~20K files were opened.  Setting the limit
// on the order of 1<<18 should be enough, I hope.
type notebookServer struct {
	// pool manages the containers
	pool *notebookPool

	// enableOAuth if the
	enableOAuth bool
	// oauthClient is the authenticator for boise state
	oauthClient *oauth2.Client

	// buildMu guards buildMap
	buildMu sync.Mutex
	// buildMap holds names of images currently being built
	buildMap map[string]struct{}

	// mux routes http traffic
	mux *ServeMux
	// embed a server
	*http.Server
	// html templates
	templates *template.Template

	//Configuration options for the server
	AssetPath          string
	ContainerLifetime  time.Duration
	DisableJupyterAuth bool
	EnablePProf        bool
	EnableStats        bool
	ImageRegexp        string
	MaxContainers      int
	Persistant         bool
	Port               string
	Host               string
	HTTPRedirect       bool
	EnableACME         bool
	TLSCert            string
	TLSKey             string
	OAuthConfig        struct {
		WhiteList []string
		RegExp    string
	}
}

// newNotebookServer initializes a server and owned resources, using a
// configuration if supplied.
func main() {
	srv := &notebookServer{}
	flag.StringVar(&srv.AssetPath, "assets", "./assets", "asset directory")
	flag.StringVar(&srv.Port, "port", ":8888", "address to listen on (:8888)")

	flag.BoolVar(&srv.EnableStats, "stats", false, "enable /stats endpoint")

	flag.DurationVar(&srv.ContainerLifetime, "lifetime", 10*time.Minute, "idle container lifetime")
	flag.StringVar(&srv.ImageRegexp, "imageregexp", allImageMatch, "allowed image regexp")
	flag.IntVar(&srv.MaxContainers, "maxcontainers", defaultMaxContainers, "maximum live containers")

	flag.Parse()

	var err error
	// Disallow http -> https redirect if not using standard ports
	if srv.HTTPRedirect && srv.Port != "" {
		log.Fatal(fmt.Errorf("cannot set http redirect with non-standard port: %s", srv.Port))
	}
	srv.pool, err = newNotebookPool(srv.ImageRegexp, srv.MaxContainers, srv.ContainerLifetime, srv.Persistant)
	if err != nil {
		log.Fatal(err)
	}
	srv.pool.token = newKey(defaultKeySize)
	srv.Server = &http.Server{
		Addr:         srv.Port,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	srv.pool.disableJupyterAuth = srv.DisableJupyterAuth
	srv.enableOAuth = srv.OAuthConfig.RegExp != "" || len(srv.OAuthConfig.WhiteList) > 0
	if !srv.enableOAuth && srv.Persistant {
		log.Fatal("OAuth must be enabled in persistent mode")
	}
	if srv.enableOAuth {
		token := misc.ReadOrPanic(filepath.Join(srv.AssetPath, "token"))
		secret := misc.ReadOrPanic(filepath.Join(srv.AssetPath, "secret"))
		if srv.Host == "" {
			srv.Host, err = os.Hostname()
			if err != nil {
				log.Print(err)
			}
		}
		rdu := url.URL{
			Scheme: "https",
			Host:   srv.Host,
			Path:   "/auth",
		}
		// switch to http if not cert/key provided
		if (srv.TLSCert == "" || srv.TLSKey == "") && !srv.EnableACME {
			rdu.Scheme = "http"
		}
		if srv.Port != "" {
			rdu.Host += srv.Port
		}

		log.Print("rdu", rdu.String())

		if srv.OAuthConfig.RegExp == "bsu" {
			srv.OAuthConfig.RegExp = oauth2.BSUEmail
		}

		srv.oauthClient, err = oauth2.NewClient(oauth2.Config{
			Token:       token,
			Secret:      secret,
			RedirectURL: rdu.String(),
			Regexp:      srv.OAuthConfig.RegExp,
			CookieName:  "bsuJupyter",
		})
		if err != nil {
			log.Fatal(err)
		}
		srv.oauthClient.CI = true
		for _, s := range srv.OAuthConfig.WhiteList {
			srv.oauthClient.Grant(s)
		}
	}

	srv.buildMap = map[string]struct{}{}

	// Use the internal mux, it has deregister
	srv.mux = new(ServeMux)
	// handle '/' explicitly.  If the path isn't exactly '/', the handler issues
	// 404.
	srv.mux.Handle("/", srv.accessLogHandler(http.HandlerFunc(srv.rootHandler)))
	srv.mux.Handle("/about", srv.accessLogHandler(http.HandlerFunc(srv.aboutHandler)))
	srv.mux.HandleFunc("/auth", srv.oauthClient.AuthHandler)
	srv.mux.Handle("/list", srv.accessLogHandler(http.HandlerFunc(srv.listImagesHandler)))
	srv.mux.Handle("/new", srv.accessLogHandler(http.HandlerFunc(srv.newNotebookHandler)))
	srv.mux.Handle("/privacy", srv.accessLogHandler(http.HandlerFunc(srv.privacyHandler)))
	srv.mux.Handle("/static/", srv.accessLogHandler(http.FileServer(http.Dir(srv.AssetPath))))
	srv.mux.Handle("/stats", srv.accessLogHandler(http.HandlerFunc(srv.statsHandler)))
	srv.mux.Handle("/status", srv.accessLogHandler(http.HandlerFunc(srv.statusHandler)))
	if srv.EnablePProf {
		srv.mux.Handle("/debug/pprof/", srv.accessLogHandler(http.HandlerFunc(pprof.Index)))
		srv.mux.Handle("/debug/pprof/cmdline", srv.accessLogHandler(http.HandlerFunc(pprof.Cmdline)))
		srv.mux.Handle("/debug/pprof/profile", srv.accessLogHandler(http.HandlerFunc(pprof.Profile)))
		srv.mux.Handle("/debug/pprof/symbol", srv.accessLogHandler(http.HandlerFunc(pprof.Symbol)))
	}

	srv.mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("User-agent: *\nDisallow: /"))
	})

	srv.Handler = srv.mux

	templateFiles, err := filepath.Glob(filepath.Join(srv.AssetPath, "templates", "*.html"))
	if err != nil {
		log.Fatal(err)
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
		log.Print("Shutting down server...")
		err := srv.pool.releaseContainers(true, false)
		if err != nil {
			log.Print(err)
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
	srv.Start()
}

func memInfo() (total, free, avail uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	s := bufio.NewScanner(f)
	i := 0
	for s.Scan() {
		tkn := strings.Split(s.Text(), ":")
		if len(tkn) < 2 {
			continue
		}
		sz := strings.Fields(tkn[1])
		x, _ := strconv.Atoi(sz[0])
		switch tkn[0] {
		case "MemTotal":
			total = uint64(x)
			i++
		case "MemFree":
			free = uint64(x)
			i++
		case "MemAvailable":
			avail = uint64(x)
			i++
		}
		if i == 3 {
			break
		}
	}
	return
}

func (srv *notebookServer) accessLogHandler(h http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		log.Printf("ACCESS: %s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())
		if srv.HTTPRedirect {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		h.ServeHTTP(w, r)
	}
	if srv.enableOAuth {
		return srv.oauthClient.ShimHandler(http.HandlerFunc(f))
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cli.Close()
	filter := filters.NewArgs()
	if id != "" {
		filter.Add("id", id)
	}
	opts := types.ContainerListOptions{
		Filters: filter,
	}
	var containers []types.Container
	for i := 0; i < 3; i++ {
		containers, err = cli.ContainerList(context.Background(), opts)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(containers) < 1 {
			// Nothing is spun up yet, wait a tick, then try one more time.
			time.Sleep(time.Second)
			continue
		} else {
			break
		}
	}
	if len(containers) < 1 {
		log.Printf("could not find container %s", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	state := containers[0].State
	log.Printf("container %s state: %s", id, state)
	_, ping := r.Form["ping"]
	if state != "running" {
		log.Printf("container %s not running", id)
		w.WriteHeader(http.StatusNotFound)
	} else if !ping {
		time.Sleep(time.Millisecond * 500)
		w.WriteHeader(http.StatusOK)
		return
	}
	// ping && running
	var nb *notebook
	for _, v := range srv.pool.containerMap {
		if v.id == id {
			nb = v
			break
		}
	}
	if nb == nil {
		log.Printf("couldn't find container in containerMap: %s", id)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	pingURL := url.URL{
		Scheme: "http",
		Host:   strings.Split(r.Host, ":")[0] + fmt.Sprintf(":%d", nb.port),
		Path:   nb.path(),
	}
	log.Printf("ping target: %s", pingURL.String())
	var resp *http.Response
	status := http.StatusNotFound
	// Wait for the container to boot up.  If docker is 'cold', this can take a
	// bit.  The maximum wait time here is 32 seconds.  If it doesn't start by
	// then, it's probably not going to start.
	sleep := time.Millisecond * 500
	for i := 0; i < 6; i++ {
		resp, err = http.Get(pingURL.String())
		if err != nil {
			log.Printf("ping failed: %s (attempt %d)", err, i)
			time.Sleep(sleep)
			sleep *= 2
			continue
		}
		resp.Body.Close()
		status = resp.StatusCode
		switch status {
		case http.StatusOK, http.StatusFound:
			log.Print("container pinged successfully")
			status = http.StatusOK
			goto found
		}
	}
found:
	// Under load, sometimes the full image isn't ready for use, we wait one more
	// time.
	time.Sleep(2 * time.Second)
	w.WriteHeader(status)
}

func (srv *notebookServer) newNotebookHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err)
		return
	}

	email := ""
	if srv.enableOAuth {
		email = srv.oauthClient.Email(r)
	}

	var imageName = r.FormValue("image")
	if imageName == "" {
		imageName = defaultNotebook
	}

	if _, ok := srv.pool.baseImages[imageName]; !ok {
		http.Error(w, fmt.Sprintf("invalid image name: %s", imageName), http.StatusBadRequest)
		log.Printf("invalid image name: %s", imageName)
		return
	}

	_, pull := r.Form["pull"]

	srv.buildMu.Lock()
	_, ok := srv.buildMap[imageName]
	srv.buildMu.Unlock()
	if ok {
		http.Error(w, "image is currently being re-built", http.StatusServiceUnavailable)
		return
	}
	nb, err := srv.pool.newNotebook(imageName, pull, email)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err)
		return
	}

	if srv.Persistant {
		// If we have a valid notebook, it may already be running in persistent
		// mode.  Check the mux and see if the path is already registered.  If it
		// is, just point it to the existing notebook.
		if srv.mux.Registered(nb.path()) {
			http.Redirect(w, r, nb.path(), http.StatusTemporaryRedirect)
			return
		}
	}

	proxyURL := url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("localhost:%d", nb.port),
	}
	log.Printf("reverse proxy URL: %s", proxyURL.String())

	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = proxyURL.Scheme
			r.URL.Host = proxyURL.Host
		},
	}
	// We may need to supply time outs:
	/*
		proxy.Transport = &http.Transport{
			MaxIdleConns:    10,
			IdleConnTimeout: 30 * time.Second,
		}
	*/
	handlerPath := nb.path()
	log.Printf("handler: %s", handlerPath)
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Read the cookie for session information and compare the
		// email to the email provided by the nb. If they match,
		// allow access, else redirect them to /list
		if srv.enableOAuth {
			email := srv.oauthClient.Email(r)
			if email != nb.email {
				http.Redirect(w, r, "/list", http.StatusUnauthorized)
				return
			}
		}

		nb.Lock()
		nb.lastAccessed = time.Now()
		nb.Unlock()
		log.Printf("%s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())
		if isWebsocket(r) {
			log.Print("proxying to websocket handler")
			f := websocketProxy(fmt.Sprintf(":%d", nb.port))
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
	q.Set("token", srv.pool.token)
	handlerURL.RawQuery = q.Encode()
	srv.templates.ExecuteTemplate(w, "new", struct {
		ID    string
		Path  string
		Token string
	}{
		ID:    nb.id,
		Path:  handlerURL.Path,
		Token: srv.pool.token,
	})
}

// Handle the root request.  All un-muxed requests come through here, if it
// isn't exactly '/', 404.
func (srv *notebookServer) rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	srv.listImagesHandler(w, r)
}

// aboutHandler serves the about text directly.
func (srv *notebookServer) aboutHandler(w http.ResponseWriter, r *http.Request) {
	err := srv.templates.ExecuteTemplate(w, "about", nil)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// privacyHandler serves the privacy text directly.
func (srv *notebookServer) privacyHandler(w http.ResponseWriter, r *http.Request) {
	err := srv.templates.ExecuteTemplate(w, "privacy", nil)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// listImagesHandler lists html links to the different docker images.
func (srv *notebookServer) listImagesHandler(w http.ResponseWriter, r *http.Request) {
	images := []string{}
	srv.pool.Lock()
	for k := range srv.pool.baseImages {
		images = append(images, k)
	}
	srv.pool.Unlock()
	sort.Slice(images, func(i, j int) bool {
		return images[i] < images[j]
	})
	err := srv.templates.ExecuteTemplate(w, "list", images)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// statsHandler reports statistics for the server.  It apparently leaks file
// descriptors.  return immediately for now, until we can fix.
func (srv *notebookServer) statsHandler(w http.ResponseWriter, r *http.Request) {
	if !srv.EnableStats {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	tw := tabwriter.NewWriter(w, 0, 8, 0, '\t', 0)
	fmt.Fprintf(w, "Go version: %s\n", runtime.Version())
	total, free, avail := memInfo()
	used := total - free
	fmt.Fprintf(w, "Memory Stats\n")
	fmt.Fprintf(tw, "Type\tBytes\tMB\n")
	fmt.Fprintf(tw, "Used:\t%d\t%d\n", used, used>>20)
	fmt.Fprintf(tw, "Free:\t%d\t%d\n", free, free>>20)
	fmt.Fprintf(tw, "Available:\t%d\t%d\n", avail, avail>>20)
	tw.Flush()
	fmt.Fprintln(w)
	t := srv.pool.NextCollection()
	fmt.Fprintf(w, "Next container reclamation: %s (%s)\n", t, t.Sub(time.Now()))
	fmt.Fprintf(w, "Persistent mode: %t\n", srv.Persistant)
	fmt.Fprintf(w, "Container lifetime: %s\n", srv.pool.containerLifetime)
	// XXX: these are copies, they are local and we don't need to hold locks when
	// accessing them.
	nbs := srv.pool.activeNotebooks()
	fmt.Fprintf(w, "Notebooks in use: %d\n", len(nbs))
	fmt.Fprintf(w, "Notebooks by image:\n")
	m := map[string]int{}
	var keys []string
	for i := 0; i < len(nbs); i++ {
		if _, ok := m[nbs[i].imageName]; !ok {
			keys = append(keys, nbs[i].imageName)
		}
		m[nbs[i].imageName]++
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	for _, k := range keys {
		fmt.Fprintf(tw, "%s\t%d\n", k, m[k])
	}
	tw.Flush()
	fmt.Fprintln(w)
	// sort the notebooks by expiration
	sort.Slice(nbs, func(i, j int) bool {
		a := nbs[i].lastAccessed
		b := nbs[j].lastAccessed
		return a.Before(b)
	})
	fmt.Fprintf(w, "all notebooks:\n")
	fmt.Fprintf(tw, "key prefix\tdocker id\timage name\tlast accessed\texpires in\n")
	for i := 0; i < len(nbs); i++ {
		e := time.Until(nbs[i].lastAccessed.Add(srv.pool.containerLifetime))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", nbs[i].key[:8], nbs[i].id[:8], nbs[i].imageName, nbs[i].lastAccessed, e)
	}
	tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintf(tw, "zombies:\n")
	fmt.Fprintf(tw, "docker id\tnames\timage\tcreated\n")
	zombies, _ := srv.pool.zombieContainers()
	for _, z := range zombies {
		t := time.Unix(z.Created, 0)
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", z.ID[:8], strings.Join(z.Names, ","), z.Image, t)
	}
	tw.Flush()
	// Dump the sock stats
	pid := os.Getpid()
	x, err := ioutil.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", pid), "net", "sockstat"))
	if err == nil {
		fmt.Fprintln(w)
		fmt.Fprintln(w, string(x))
	}
	tw.Flush()
}

// Start starts the http/s listener.
func (srv *notebookServer) Start() {
	if (srv.TLSCert != "" && srv.TLSKey != "") || srv.EnableACME {
		if srv.HTTPRedirect {
		}
		if srv.EnableACME {
			log.Print("using acme via letsencrypt")
			m := &autocert.Manager{
				Cache:      autocert.DirCache("/opt/acme/"),
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(srv.Host),
			}
			go func() {
				log.Fatal(http.ListenAndServe(":http", m.HTTPHandler(nil)))
			}()
			srv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}
			log.Fatal(srv.ListenAndServeTLS("", ""))
		} else {
			log.Print("using standard tls")
			log.Fatal(srv.ListenAndServeTLS(srv.TLSCert, srv.TLSKey))
		}
	} else {
		log.Fatal(srv.ListenAndServe())
	}
}
