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
	// in the future.
	bsuRegexp = `^.+@(u.)?boisestate.edu$`
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

// TODO(kyle): embed or add to notebookServer?
type serverConfig struct {
	AssetPath         string        `json:"asset_path"`
	UseBSUAuth        bool          `json:"bsu_auth"`
	ContainerLifetime time.Duration `json:"container_lifetime"`
	EnablePProf       bool          `json:"enable_pprof"`
	ImageRegexp       string        `json:"image_regexp"`
	MaxContainers     int           `json:"max_containers"`
	HTTPRedirect      bool          `json:"http_redirect"`
	AccessLogfile     string        `json:"access_logfile"`
	Logfile           string        `json:"logfile"`
	Port              string        `json:"port"`
	TLSCert           string        `json:"tls_cert"`
	TLSKey            string        `json:"tls_key"`
	OAuthConfig       struct {
		WhiteList []string `json:"whitelist"`
		RegExp    string   `json:"match"`
	} `json:"oauth_confg"`
}

var defaultConfig = serverConfig{
	ContainerLifetime: defaultContainerLifetime,
	ImageRegexp:       allImageMatch,
	MaxContainers:     defaultMaxContainers,
}

type session struct {
	m     map[string]string
	token *oauth2.Token
}

func newSession() *session {
	return &session{make(map[string]string), nil}
}

func (s *session) get(key string) string {
	return s.m[key]
}

func (s *session) set(key, val string) {
	s.m[key] = val
}

// notebookServer handles the http tasks for the temporary notebooks.
type notebookServer struct {
	// pool manages the containers
	pool *notebookPool
	// token is the generated random auth token
	token string
	// sessionLock guards sessions
	sessionLock sync.Mutex
	// sessions holds cookie keys and user emails
	sessions map[string]*session

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
	// redirectLock locks the redirectMap
	redirectLock sync.Mutex
	// redirectMap handles initial incoming requests before the user is
	// authenticated through OAuth.  The keys are a session type key, the value
	// is the path and query string of the request.
	redirectMap map[string]string
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
	// accessLogWriter is the access logging Writer
	accessLogWriter io.Writer
	// accessLog logs access
	accessLog *log.Logger
	// logWriter is the error logging Writer, the standard logger handles all
	// others.
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
	if sc.AccessLogfile != "" {
		srv.accessLogWriter, err = os.OpenFile(sc.AccessLogfile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			return nil, err
		}
		srv.accessLog = log.New(srv.accessLogWriter, "ACCESS: ", log.LstdFlags|log.Lshortfile)
	} else {
		srv.accessLog = log.New(os.Stdout, "ACCESS: ", log.LstdFlags|log.Lshortfile)
	}
	if sc.Logfile != "" {
		srv.logWriter, err = os.OpenFile(sc.Logfile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
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
	// OAuth
	srv.sessions = map[string]*session{}
	// FIXME(kyle): errors after we add files
	apiToken, err := ioutil.ReadFile(filepath.Join(sc.AssetPath, "token"))
	if err != nil {
		return nil, err
	}
	srv.oauthToken = strings.TrimSpace(string(apiToken))
	apiSecret, err := ioutil.ReadFile(filepath.Join(sc.AssetPath, "secret"))
	if err != nil {
		return nil, err
	}
	srv.oauthSecret = strings.TrimSpace(string(apiSecret))
	// TODO(kyle): fix RedirectURL so we don't have to set it manually
	srv.oauthConf = &oauth2.Config{
		ClientID:     srv.oauthToken,
		ClientSecret: srv.oauthSecret,
		RedirectURL:  "http://127.0.0.1:8888/auth",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	srv.oauthState = newHash(defaultHashSize)
	srv.enableOAuth = sc.OAuthConfig.RegExp != "" || len(sc.OAuthConfig.WhiteList) > 0
	if srv.enableOAuth {
		switch sc.OAuthConfig.RegExp {
		case "bsu":
			srv.oauthMatch = regexp.MustCompile(bsuRegexp)
		case "":
			break
		default:
			if srv.oauthMatch, err = regexp.Compile(sc.OAuthConfig.RegExp); err != nil {
				return nil, err
			}
		}
	}
	log.Println("OAuth2 whitelist:")
	srv.oauthWhiteList = map[string]struct{}{}
	for _, s := range sc.OAuthConfig.WhiteList {
		srv.oauthWhiteList[s] = struct{}{}
		log.Println(s)
	}

	srv.redirectMap = map[string]string{}

	log.Println("OAuth2 regexp:", sc.OAuthConfig.RegExp)

	// Use the internal mux, it has deregister
	srv.mux = new(ServeMux)
	srv.mux.Handle("/", srv.accessLogHandler(http.HandlerFunc(srv.listImagesHandler)))
	srv.mux.Handle("/about", srv.accessLogHandler(http.HandlerFunc(srv.aboutHandler)))
	srv.mux.HandleFunc("/auth", srv.oauthHandler)
	srv.mux.Handle("/docker/push/", srv.accessLogHandler(http.HandlerFunc(srv.dockerPushHandler)))
	srv.mux.Handle("/list", srv.accessLogHandler(http.HandlerFunc(srv.listImagesHandler)))
	srv.mux.Handle("/new", srv.accessLogHandler(http.HandlerFunc(srv.newNotebookHandler)))
	srv.mux.Handle("/privacy", srv.accessLogHandler(http.HandlerFunc(srv.privacyHandler)))
	srv.mux.Handle("/static/", srv.accessLogHandler(http.FileServer(http.Dir(sc.AssetPath))))
	srv.mux.Handle("/stats", srv.accessLogHandler(http.HandlerFunc(srv.statsHandler)))
	srv.mux.Handle("/status", srv.accessLogHandler(http.HandlerFunc(srv.statusHandler)))
	if sc.EnablePProf {
		srv.mux.Handle("/debug/pprof/", srv.accessLogHandler(http.HandlerFunc(pprof.Index)))
		srv.mux.Handle("/debug/pprof/cmdline", srv.accessLogHandler(http.HandlerFunc(pprof.Cmdline)))
		srv.mux.Handle("/debug/pprof/profile", srv.accessLogHandler(http.HandlerFunc(pprof.Profile)))
		srv.mux.Handle("/debug/pprof/symbol", srv.accessLogHandler(http.HandlerFunc(pprof.Symbol)))
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
			if err != nil {
				log.Print(err)
			}
		}
		if c, ok := srv.accessLogWriter.(io.Closer); ok {
			log.Println("closing log file")
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
	return srv, nil
}

func (srv *notebookServer) accessLogHandler(h http.Handler) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		var ok bool
		var ses *session
		srv.accessLog.Printf("%s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())
		if srv.enableOAuth {
			c, err := r.Cookie(sessionKey)
			if err == nil {
				srv.sessionLock.Lock()
				ses, ok = srv.sessions[c.Value]
				srv.sessionLock.Unlock()
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
				switch u.Path {
				case "/", "/about", "/list", "/privacy", "/stats":
					break
				default:
					key := newHash(defaultHashSize)
					srv.redirectLock.Lock()
					srv.redirectMap[key] = r.RequestURI
					srv.redirectLock.Unlock()
					const redirectExpire = 60
					http.SetCookie(w, &http.Cookie{Name: redirectKey, Value: key, MaxAge: redirectExpire})
					// Delete the key after 2 * redirectExpire.  This ensures that the
					// map is cleared, even if the key is never used.  We could do it
					// right after it's used, but if something goes wrong, or the user
					// doesn't authenticate successfully, it will never be deleted.  The
					// javascript function that creates the link for the new container
					// times out after 60 seconds, so the cookie expires after that, then
					// the map is cleaned up soon after.
					go func() {
						<-time.After(redirectExpire * time.Second * 2)
						srv.redirectLock.Lock()
						delete(srv.redirectMap, key)
						log.Printf("redirect map size: %d", len(srv.redirectMap))
						srv.redirectLock.Unlock()
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
	key := newHash(defaultHashSize)
	srv.sessionLock.Lock()
	srv.sessions[key] = newSession()
	srv.sessions[key].token = tok
	srv.sessions[key].set("sub", u.Sub)
	srv.sessions[key].set("email", u.Email)
	srv.sessionLock.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionKey, Value: key, MaxAge: 0})
	c, err := r.Cookie(redirectKey)
	if err != nil {
		http.Redirect(w, r, "/list", http.StatusTemporaryRedirect)
		return
	}
	srv.redirectLock.Lock()
	uri, ok := srv.redirectMap[c.Value]
	srv.redirectLock.Unlock()
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
		srv.accessLog.Printf("%s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())
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

// privacyHandler serves the privacy text directly.
func (srv *notebookServer) privacyHandler(w http.ResponseWriter, r *http.Request) {
	err := srv.templates.ExecuteTemplate(w, "privacy", nil)
	if err != nil {
		log.Print(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type dockerPush struct {
	CallbackURL string `json:"callback_url"`
	PushData    struct {
		Images   []string `json:"images"`
		PushedAt float64  `json:"pushed_at"`
		Pusher   string   `json:"pusher"`
		Tag      string   `json:"tag"`
	} `json:"push_data"`
	Repository struct {
		CommentCount    string  `json:"comment_count"`
		DateCreated     float64 `json:"date_created"`
		Description     string  `json:"description"`
		Dockerfile      string  `json:"dockerfile"`
		FullDescription string  `json:"full_description"`
		IsOfficial      bool    `json:"is_official"`
		IsPrivate       bool    `json:"is_private"`
		IsTrusted       bool    `json:"is_trusted"`
		Name            string  `json:"name"`
		Namespace       string  `json:"namespace"`
		Owner           string  `json:"owner"`
		RepoName        string  `json:"repo_name"`
		RepoURL         string  `json:"repo_url"`
		StarCount       int     `json:"star_count"`
		Status          string  `json:"status"`
	} `json:"repository"`
}

func (srv *notebookServer) dockerPushHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	log.Print("request for docker pull")
	var push dockerPush
	if err := json.NewDecoder(r.Body).Decode(&push); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	repo := push.Repository.RepoName
	var update bool
	srv.pool.Lock()
	_, update = srv.pool.availableImages[repo]
	srv.pool.Unlock()
	if !update {
		log.Printf("image: %s not on server", repo)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("attempting to pull %s", repo)
	_, err = cli.ImagePull(ctx, repo+defaultTag, types.ImagePullOptions{})
	if err != nil {
		log.Printf("pull failed: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("pull successful")
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
	fmt.Fprintf(w, "Go version: %s\n", runtime.Version())
	vm, _ := mem.VirtualMemory()
	fmt.Fprintf(w, "Used memory: %d(%d MB)\n", vm.Used, vm.Used>>20)
	fmt.Fprintf(w, "Free memory: %d(%d MB)\n", vm.Free, vm.Free>>20)
	t := srv.pool.NextCollection()
	fmt.Fprintf(w, "Next container reclamation: %s (%s)\n", t, t.Sub(time.Now()))
	nbs := srv.pool.activeNotebooks()
	fmt.Fprintf(w, "Notebooks in use: %d\n", len(nbs))
	fmt.Fprintf(w, "Notebooks by image:\n")
	m := map[string]int{}
	var keys []string
	for _, nb := range nbs {
		if _, ok := m[nb.imageName]; !ok {
			keys = append(keys, nb.imageName)
		}
		m[nb.imageName]++
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	tw := tabwriter.NewWriter(w, 0, 8, 0, '\t', 0)
	for _, k := range keys {
		fmt.Fprintf(tw, "%s\t%d\n", k, m[k])
	}
	tw.Flush()
	fmt.Fprintln(w)
	// sort the notebooks by expiration
	sort.Slice(nbs, func(i, j int) bool {
		return nbs[i].lastAccessed.Before(nbs[j].lastAccessed)
	})
	fmt.Fprintf(w, "All Notebooks:\n")
	fmt.Fprintf(tw, "Hash Prefix\tImage Name\tLast Accessed\tExpires in\n")
	for _, nb := range nbs {
		e := time.Until(nb.lastAccessed.Add(srv.pool.containerLifetime))
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", nb.hash[:8], nb.imageName, nb.lastAccessed, e)
	}
	tw.Flush()
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Zombie Containers:\n")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "ID\tNames\tImage\tCreated\n")
	zombies, _ := srv.pool.zombieContainers()
	for _, z := range zombies {
		t := time.Unix(z.Created, 0)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", z.ID, strings.Join(z.Names, ","), z.Image, t)
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
