// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
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
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/shirou/gopsutil/mem"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	// defaultNotebook is used if the request doesn't specify a docker image.
	defaultNotebook = "jupyter/minimal-notebook"
	// sessionKey is the cookie name for session managment
	sessionKey = "sessionKey"
	// redirectKey holds some context on login/oauth
	redirectKey = "redirectFrom"
	// bsuDefaultRegexp is a regular expression allowing all u.boisestate.edu and
	// boisestate.edu users login.  As far as we know, BSU doesn't allow symbols
	// in emails, but we may have to add:
	//
	// !#$%&'*+-/=?^_`{|}~
	//
	// in the future.  See RFC 5322 (https://tools.ietf.org/html/rfc5322).
	bsuRegexp = `^.+@(u\.)?boisestate.edu$`
	// use the hardened TLS config
	hardenTLS = false
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

type session struct {
	sync.Mutex
	m     map[string]string
	token *oauth2.Token
}

func newSession() *session {
	return &session{m: make(map[string]string), token: nil}
}

func (s *session) get(key string) string {
	s.Lock()
	v := s.m[key]
	s.Unlock()
	return v
}

func (s *session) set(key, val string) {
	s.Lock()
	s.m[key] = val
	s.Unlock()
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
	// token is the generated random auth token
	token string
	// sessionLock guards sessions
	sessionMu sync.Mutex
	// sessions holds cookie keys and user emails
	sessions map[string]*session
	// enableDockerPush listens for container updates
	enableDockerPush bool
	// enableOAuth if the
	enableOAuth bool
	// oauthConf is the OAuth2 client configuration
	oauthConf *oauth2.Config
	// oauthState is the string passed to the api to validate on return
	oauthState string
	// oauthToken is the API token
	oauthToken string
	// oauthSecret is the API secret
	oauthSecret string
	// oauthDomainRegexp is used to match whitelisted domains
	oauthMatch *regexp.Regexp
	// oauthWhiteList is automagically enabled user emails
	oauthWhiteList map[string]struct{}
	// buildMu guards buildMap
	buildMu sync.Mutex
	// buildMap holds names of images currently being built
	buildMap map[string]struct{}
	// githubToken holds the github secret for the push event
	githubToken string
	// redirectLock locks the redirectMap
	redirectMu sync.Mutex
	// redirectMap handles initial incoming requests before the user is
	// authenticated through OAuth.  The keys are a session type key, the value
	// is the path and query string of the request.
	redirectMap map[string]string
	// mux routes http traffic
	mux *ServeMux
	// embed a server
	*http.Server
	// html templates
	templates *template.Template
	// accessLogWriter is the access logging Writer
	accessLogWriter io.Writer
	// accessLog logs access
	accessLog *log.Logger
	// logWriter is the error logging Writer, the standard logger handles all
	// others.
	logWriter io.Writer

	//Configuration options for the server
	AccessLogfile      string
	AssetPath          string
	ContainerLifetime  string
	DisableJupyterAuth bool
	EnableCSP          bool
	EnableDockerPush   bool
	// Github repository name (bsurc/tmpnb)
	GithubRepo    string
	EnablePProf   bool
	EnableStats   bool
	ImageRegexp   string
	MaxContainers int
	Logfile       string
	Persistant    bool
	Port          string
	RotateLogs    bool
	Host          string
	HTTPRedirect  bool
	EnableACME    bool
	TLSCert       string
	TLSKey        string
	OAuthConfig   struct {
		WhiteList []string
		RegExp    string
	}
}

// init initializes a server and owned resources, using a
// configuration if supplied.
func (srv *notebookServer) init() error {
	var err error
	if srv.AccessLogfile != "" {
		srv.accessLogWriter, err = os.OpenFile(srv.AccessLogfile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			return err
		}
		srv.accessLog = log.New(srv.accessLogWriter, "ACCESS: ", log.LstdFlags|log.Lshortfile)
	} else {
		srv.accessLog = log.New(os.Stdout, "ACCESS: ", log.LstdFlags|log.Lshortfile)
	}
	if srv.Logfile != "" {
		srv.logWriter, err = os.OpenFile(srv.Logfile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			return err
		}
		log.SetOutput(srv.logWriter)
	}
	// Set up some basic log rotation
	if (srv.AccessLogfile != "" || srv.Logfile != "") && srv.RotateLogs {
		t := time.NewTicker(time.Hour * 24 * 14)
		go func() {
			for {
				select {
				case <-t.C:
					for _, fname := range []string{srv.AccessLogfile, srv.Logfile} {
						if fname == "" {
							continue
						}
						fout, err := os.Create(fname + "." + time.Now().Format("20060102150405") + ".gz")
						if err != nil {
							log.Print(err)
							continue
						}
						w := gzip.NewWriter(fout)
						fin, err := os.Open(fname)
						if err != nil {
							log.Print(err)
							fout.Close()
							continue
						}
						_, err = io.Copy(w, fin)
						w.Flush()
						w.Close()
						fout.Close()
						fin.Close()
						os.Truncate(fname, 0)
						logs, err := filepath.Glob(fname + "*" + ".gz")
						if err != nil {
							log.Print(err)
							continue
						}
						sort.Strings(logs)
						for len(logs) > 5 {
							err = os.Remove(logs[0])
							logs = logs[1:]
						}
					}
				default:
					time.Sleep(time.Hour * 24)
				}
			}
		}()
	}

	// Disallow http -> https redirect if not using standard ports
	if srv.HTTPRedirect && srv.Port != "" {
		return fmt.Errorf("cannot set http redirect with non-standard port: %s", srv.Port)
	}
	lifetime, err := time.ParseDuration(srv.ContainerLifetime)
	if err != nil {
		return err
	}
	p, err := newNotebookPool(srv.ImageRegexp, srv.MaxContainers, lifetime, srv.Persistant)
	if err != nil {
		return err
	}
	tkn := newKey(defaultKeySize)
	srv.pool = p
	srv.token = tkn
	srv.pool.token = tkn
	srv.Server = &http.Server{
		Addr:         srv.Port,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	srv.pool.disableJupyterAuth = srv.DisableJupyterAuth
	srv.enableOAuth = srv.OAuthConfig.RegExp != "" || len(srv.OAuthConfig.WhiteList) > 0
	if !srv.enableOAuth && srv.Persistant {
		return fmt.Errorf("OAuth must be enabled in persistent mode")
	}
	if srv.enableOAuth {
		// OAuth
		srv.sessions = map[string]*session{}
		// FIXME(kyle): errors after we add files
		apiToken, err := ioutil.ReadFile(filepath.Join(srv.AssetPath, "token"))
		if err != nil {
			return err
		}
		srv.oauthToken = strings.TrimSpace(string(apiToken))
		apiSecret, err := ioutil.ReadFile(filepath.Join(srv.AssetPath, "secret"))
		if err != nil {
			return err
		}
		srv.oauthSecret = strings.TrimSpace(string(apiSecret))
		// If we don't have a config hostname, try.  This doesn't use our cname, so
		// the actual server name must be whitelisted in google.
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
		log.Printf("redirect: %s", rdu.String())
		srv.oauthConf = &oauth2.Config{
			ClientID:     srv.oauthToken,
			ClientSecret: srv.oauthSecret,
			RedirectURL:  rdu.String(),
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
			},
			Endpoint: google.Endpoint,
		}
		srv.oauthState = newKey(defaultKeySize)
		switch srv.OAuthConfig.RegExp {
		case "bsu":
			srv.oauthMatch = regexp.MustCompile(bsuRegexp)
		case "":
			break
		default:
			if srv.oauthMatch, err = regexp.Compile(srv.OAuthConfig.RegExp); err != nil {
				return err
			}
		}
	}
	log.Print("OAuth2 whitelist:")
	srv.oauthWhiteList = map[string]struct{}{}
	for _, s := range srv.OAuthConfig.WhiteList {
		srv.oauthWhiteList[s] = struct{}{}
		log.Print(s)
	}

	srv.buildMap = map[string]struct{}{}

	srv.redirectMap = map[string]string{}

	log.Print("OAuth2 regexp:", srv.OAuthConfig.RegExp)

	// Docker push support
	srv.enableDockerPush = srv.EnableDockerPush

	// Use the internal mux, it has deregister
	srv.mux = new(ServeMux)
	// handle '/' explicitly.  If the path isn't exactly '/', the handler issues
	// 404.
	srv.mux.Handle("/", srv.accessLogHandler(http.HandlerFunc(srv.rootHandler)))
	srv.mux.Handle("/about", srv.accessLogHandler(http.HandlerFunc(srv.aboutHandler)))
	srv.mux.HandleFunc("/auth", srv.oauthHandler)
	srv.mux.HandleFunc("/docker/push/", srv.dockerPushHandler)
	srv.mux.Handle("/github/push/", http.HandlerFunc(srv.githubPushHandler))
	srv.mux.Handle("/list", srv.accessLogHandler(http.HandlerFunc(srv.listImagesHandler)))
	srv.mux.Handle("/new", srv.accessLogHandler(http.HandlerFunc(srv.newNotebookHandler)))
	srv.mux.Handle("/privacy", srv.accessLogHandler(http.HandlerFunc(srv.privacyHandler)))
	srv.mux.Handle("/csp_report", http.HandlerFunc(srv.cspReportHandler))
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
		return err
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
		if c, ok := srv.logWriter.(io.Closer); ok {
			log.Print("closing log file")
			err = c.Close()
			// If we hit an error, dump it to stdout.
			log.SetOutput(os.Stdout)
			if err != nil {
				log.Print(err)
			}
		}
		if c, ok := srv.accessLogWriter.(io.Closer); ok {
			log.Print("closing log file")
			err = c.Close()
			// If we hit an error, dump it to stdout.
			if err != nil {
				log.Print(err)
			}
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
	return nil
}

func (srv *notebookServer) accessLogHandler(h http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		var ses *session
		srv.accessLog.Printf("%s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())
		// Set the CSP headers if enabled
		if srv.EnableCSP {
			w.Header().Set(cspKey, csp())
		}
		if srv.HTTPRedirect {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if srv.enableOAuth {
			c, err := r.Cookie(sessionKey)
			if err == nil {
				srv.sessionMu.Lock()
				ses, ok = srv.sessions[c.Value]
				srv.sessionMu.Unlock()
			}
			if !ok || !ses.token.Valid() {
				u, err := url.Parse(r.RequestURI)
				if err != nil {
					// revert to default handling
					u.Path = "/list"
					log.Print(err)
				}
				// If the request is asking for some specific resource, and the user
				// isn't authenticated, store the request state and try to redirect
				// properly after the authentication.
				// TODO(kyle): we should check the path if it is a book as well, and
				// not let people without a valid session cookie get to another
				// person's notebook.
				switch u.Path {
				case "/", "/about", "/list", "/privacy", "/stats":
					break
				default:
					key := newKey(defaultKeySize)
					srv.redirectMu.Lock()
					srv.redirectMap[key] = r.RequestURI
					srv.redirectMu.Unlock()
					const redirectExpire = 60
					http.SetCookie(w, &http.Cookie{
						Name:     redirectKey,
						Value:    key,
						MaxAge:   redirectExpire,
						HttpOnly: true,
					})

					// Delete the key after 2 * redirectExpire.  This ensures that the
					// map is cleared, even if the key is never used.  We could do it
					// right after it's used, but if something goes wrong, or the user
					// doesn't authenticate successfully, it will never be deleted.  The
					// javascript function that creates the link for the new container
					// times out after 60 seconds, so the cookie expires after that, then
					// the map is cleaned up soon after.
					go func() {
						<-time.After(redirectExpire * time.Second * 2)
						srv.redirectMu.Lock()
						delete(srv.redirectMap, key)
						log.Printf("redirect map size: %d", len(srv.redirectMap))
						srv.redirectMu.Unlock()
					}()
					log.Printf("setting redirect map %s: %s", key, r.RequestURI)
				}
				http.Redirect(w, r, srv.oauthConf.AuthCodeURL(srv.oauthState), http.StatusTemporaryRedirect)
				return
			}
		}
		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(f)
}

func (srv *notebookServer) cspReportHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Print(err)
		return
	}
	log.Print(string(body))
}

func (srv *notebookServer) oauthHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tok, err := srv.oauthConf.Exchange(oauth2.NoContext, r.FormValue("code"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	client := srv.oauthConf.Client(oauth2.NoContext, tok)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	type oauthUser struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Domain        string `json:"hd"`
	}

	var u oauthUser
	err = json.NewDecoder(resp.Body).Decode(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, white := srv.oauthWhiteList[u.Email]
	if white {
		log.Printf("%s is whitelisted", u.Email)
	} else {
		log.Printf("%s is not whitelisted", u.Email)
	}

	matched := srv.oauthMatch != nil && srv.oauthMatch.MatchString(u.Email)
	if matched {
		log.Printf("%s is regexp match", u.Email)
	} else {
		log.Printf("%s is not regexp match", u.Email)
	}

	if !white && !matched {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	key := newKey(defaultKeySize)
	srv.sessionMu.Lock()
	srv.sessions[key] = newSession()
	srv.sessions[key].token = tok
	srv.sessions[key].set("sub", u.Sub)
	srv.sessions[key].set("email", u.Email)
	srv.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionKey,
		Value:    key,
		MaxAge:   2419200,
		HttpOnly: true,
	})
	c, err := r.Cookie(redirectKey)
	if err != nil {
		http.Redirect(w, r, "/list", http.StatusTemporaryRedirect)
		return
	}
	srv.redirectMu.Lock()
	uri, ok := srv.redirectMap[c.Value]
	srv.redirectMu.Unlock()
	if !ok {
		http.Redirect(w, r, "/list", http.StatusTemporaryRedirect)
		return
	}
	log.Printf("using custom redirect %s", r.RequestURI)
	http.Redirect(w, r, uri, http.StatusTemporaryRedirect)
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
		c, err := r.Cookie(sessionKey)
		if err != nil {
			http.Redirect(w, r, "/list", http.StatusTemporaryRedirect)
			return
		}
		srv.sessionMu.Lock()
		s := srv.sessions[c.Value]
		srv.sessionMu.Unlock()
		if s != nil {
			email = s.get("email")
		}
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
			email := ""
			c, err := r.Cookie(sessionKey)
			if err != nil {
				log.Printf("invalid cookie")
				http.Redirect(w, r, "/list", http.StatusUnauthorized)
				return
			}
			srv.sessionMu.Lock()
			s := srv.sessions[c.Value]
			srv.sessionMu.Unlock()
			if s != nil {
				email = s.get("email")
			}
			if email != nb.email {
				http.Redirect(w, r, "/list", http.StatusUnauthorized)
				return
			}
		}

		nb.Lock()
		nb.lastAccessed = time.Now()
		nb.Unlock()
		srv.accessLog.Printf("%s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())
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
	q.Set("token", srv.token)
	handlerURL.RawQuery = q.Encode()
	srv.templates.ExecuteTemplate(w, "new", struct {
		ID    string
		Path  string
		Token string
	}{
		ID:    nb.id,
		Path:  handlerURL.Path,
		Token: srv.token,
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

func (srv *notebookServer) githubPushHandler(w http.ResponseWriter, r *http.Request) {
	if srv.GithubRepo == "" {
		// If the updating from Github is disabled, just tell Github to go away
		// nicely.
		w.WriteHeader(http.StatusOK)
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// ping okay
	if r.Header.Get("X-GitHub-Event") == "ping" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" ||
		r.Header.Get("X-GitHub-Event") != "push" ||
		!strings.HasPrefix(r.UserAgent(), "GitHub-Hookshot/") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var push githubPush
	err := json.NewDecoder(r.Body).Decode(&push)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	if push.Repository.FullName != srv.GithubRepo {
		w.WriteHeader(http.StatusPreconditionFailed)
		return
	}
	// TODO(kyle): check signature/secret/HMAC

	// If any of the docker/$PI_NAME/Dockerfile has changes, download the file
	// from master, run docker build.
	var build []string
	var remove []string
	for _, commit := range push.Commits {
		allChanges := append(commit.Added, commit.Modified...)
		for _, file := range allChanges {
			if strings.HasSuffix(file, "Dockerfile") {
				build = append(build, file)
			}
		}
		for _, file := range commit.Removed {
			if strings.HasSuffix(file, "Dockerfile") {
				remove = append(remove, file)
			}
		}
	}
	if build == nil && remove == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// TODO(kyle): should we remove the dropped files?  This would 'mirror' the
	// repo more consistently.
	for _, r := range remove {
		_ = r
		/*
			ctx := context.Background()
			cli, err := client.NewEnvClient()
			resp, err := cli.ImageRemove(ctx, imageID string, options types.ImageRemoveOptions)
			srv.pool.Lock()
			delete(srv.pool.availableImages[tag])
			srv.pool.Unlock()
		*/
	}

	// Write OK early, let us do work in the background.  Github doesn't need to
	// know any errors we encounter when building the images.
	w.WriteHeader(http.StatusOK)

	for _, d := range build {
		// TODO(kyle): look at granularity here.  Probably move the goroutine up
		// and let it chug one at a time.  If there was a blanket update of all
		// containers or a lot added at once, it would be bad.
		dockerfile := d
		go func() {
			u := url.URL{
				Scheme: "https",
				Host:   "github.com",
				// FIXME(kyle): branch may not be master or xxx
				Path: filepath.Join("/bsurc/tmpnb/raw/", "git-push", dockerfile),
			}
			resp, err := http.Get(u.String())
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Print(err)
				return
			}
			body, err := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				log.Print(err)
				return
			}
			buf := &bytes.Buffer{}
			tw := tar.NewWriter(buf)
			h := &tar.Header{
				Name:     "Dockerfile",
				Size:     int64(len(body)),
				Typeflag: tar.TypeReg,
			}
			tw.WriteHeader(h)
			_, err = tw.Write(body)
			if err != nil {
				log.Print(err)
				return
			}
			err = tw.Close()
			if err != nil {
				log.Print(err)
				return
			}
			tag := "boisestate/" + strings.Split(dockerfile, "/")[1] + "-notebook:latest"
			srv.buildMu.Lock()
			srv.buildMap[tag] = struct{}{}
			srv.buildMu.Unlock()
			cli, err := client.NewEnvClient()
			if err != nil {
				log.Print(err)
				return
			}
			ctx := context.Background()
			buildResp, err := cli.ImageBuild(ctx, buf, types.ImageBuildOptions{
				Tags:           []string{tag},
				Context:        buf,
				SuppressOutput: true,
				PullParent:     true,
				//BuildArgs   map[string]*string
				//Target      string
			})

			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				srv.buildMu.Lock()
				delete(srv.buildMap, tag)
				srv.buildMu.Unlock()
				return
			}
			buildResp.Body.Close()
			srv.buildMu.Lock()
			delete(srv.buildMap, tag)
			srv.buildMu.Unlock()
		}()
	}
}

func (srv *notebookServer) dockerPushHandler(w http.ResponseWriter, r *http.Request) {
	if !srv.enableDockerPush {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		log.Print("invalid /docker/push/ method")
		return
	}
	log.Print("request for docker pull")
	var push dockerPush
	if err := json.NewDecoder(r.Body).Decode(&push); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err)
		return
	}
	repo := push.Repository.RepoName + ":" + push.PushData.Tag
	var update bool
	srv.pool.Lock()
	_, update = srv.pool.availableImages[repo]
	srv.pool.Unlock()
	if !update {
		log.Printf("image: %s not on server", repo)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
		defer cancel()
		cli, err := client.NewEnvClient()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer cli.Close()
		log.Printf("attempting to pull %s", repo)
		out, err := cli.ImagePull(ctx, repo, types.ImagePullOptions{})
		if err != nil {
			log.Printf("pull failed: %s", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer out.Close()
		s := bufio.NewScanner(out)
		var ps dockerPullStatus
		for s.Scan() {
			err := json.Unmarshal([]byte(s.Text()), &ps)
			if err != nil {
				log.Print(err)
			}
			log.Print(ps.Progress)
		}
	}()
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
	vm, _ := mem.VirtualMemory()
	fmt.Fprintf(w, "Memory Stats\n")
	fmt.Fprintf(tw, "Type\tBytes\tMB\n")
	fmt.Fprintf(tw, "Used:\t%d\t%d\n", vm.Used, vm.Used>>20)
	fmt.Fprintf(tw, "Free:\t%d\t%d\n", vm.Free, vm.Free>>20)
	fmt.Fprintf(tw, "Available:\t%d\t%d\n", vm.Available, vm.Available>>20)
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
		if hardenTLS {
			// Straight outta https://blog.cloudflare.com/exposing-go-on-the-internet/
			srv.Server.TLSConfig = &tls.Config{
				// Causes servers to use Go's default ciphersuite preferences,
				// which are tuned to avoid attacks. Does nothing on clients.
				PreferServerCipherSuites: true,
				// Only use curves which have assembly implementations
				CurvePreferences: []tls.CurveID{
					tls.CurveP256,
					tls.X25519,
				},
				// If you can take the compatibility loss of the Modern configuration, you
				// should then also set MinVersion and CipherSuites.
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,

					// Best disabled, as they don't provide Forward Secrecy,
					// but might be necessary for some clients
					// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					// tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				},
			}
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

func main() {
	srv := &notebookServer{}
	flag.StringVar(&srv.AccessLogfile, "accesslog", "", "file path for access log")
	flag.StringVar(&srv.AssetPath, "assets", "./assets", "path to html and oauth tokens")
	flag.StringVar(&srv.ContainerLifetime, "life", "1h", "container lifetime formatted in duration format")
	flag.BoolVar(&srv.DisableJupyterAuth, "nojupyterauth", true, "enable jupyter authentication")
	flag.BoolVar(&srv.EnableCSP, "csp", false, "enable csp (experimental)")
	flag.BoolVar(&srv.EnableDockerPush, "dockerpush", false, "enable pushing to docker hub (experimental)")
	flag.StringVar(&srv.GithubRepo, "github", "", "master github repo (experimental)")
	flag.BoolVar(&srv.EnablePProf, "pprof", false, "expose net/http/pprof endpoints")
	flag.BoolVar(&srv.EnableStats, "stats", false, "expose the /stats page")
	flag.StringVar(&srv.ImageRegexp, "imgregexp", ".*", "image name regular expression to expose")
	flag.IntVar(&srv.MaxContainers, "max", 100, "maximum living containers")
	flag.StringVar(&srv.Logfile, "log", "", "file path for log")
	flag.BoolVar(&srv.Persistant, "persistant", false, "enable persistant images (experimental)")
	flag.StringVar(&srv.Port, "addr", ":8888", "address to listen on (:8888, :http, :https, \"\" is automagic")
	flag.BoolVar(&srv.RotateLogs, "rotate", false, "manually rotate the logs")
	flag.StringVar(&srv.Host, "host", "127.0.0.1", "hostname to use in redirects for oauth2 and acme")
	flag.BoolVar(&srv.HTTPRedirect, "redirect", false, "redirect http to https")
	flag.BoolVar(&srv.EnableACME, "acme", false, "use ACME via letsencrypt, overrides tls flags")
	flag.StringVar(&srv.TLSCert, "tlscert", "", "path to tls certificate")
	flag.StringVar(&srv.TLSKey, "tlskey", "", "path to tls key")
	whitelist := flag.String("oawhite", "", "comma separated whitelist of valid OAuth2 emails")
	flag.StringVar(&srv.OAuthConfig.RegExp, "oaregexp", ".*", "regular expression for valid OAuth2 emails")
	flag.Parse()

	srv.OAuthConfig.WhiteList = strings.Split(*whitelist, ",")

	err := srv.init()
	if err != nil {
		log.Fatal(err)
	}
	srv.Start()
}
