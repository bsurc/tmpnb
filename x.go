// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

const (
	defaultNotebook   = "jupyter/minimal-notebook"
	containerLifetime = 5 * time.Minute
)

var (
	availableImages = map[string]struct{}{}
	containerLock   sync.Mutex
	containerMap    = map[string]*tempNotebook{}
	portLock        sync.Mutex
	mux             = http.NewServeMux()
	ports           = newPortRange(8000, 100)
	token           string
	imageMatch      = regexp.MustCompile(`[a-zA-Z0-9]+/[a-zA-Z0-9]+-notebook[:]{0,1}[a-zA-Z0-9]*`)
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

func newNotebookHandler(w http.ResponseWriter, r *http.Request) {
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

	if _, ok := availableImages[imageName]; !ok {
		http.Error(w, fmt.Sprintf("invalid image name: %s", imageName), http.StatusBadRequest)
		log.Printf("invalid image name: %s", imageName)
		return
	}

	tmpnb, err := newTempNotebook(imageName)
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
	mux.HandleFunc(handlerPath, func(w http.ResponseWriter, r *http.Request) {
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
	q.Set("token", token)
	handlerURL.RawQuery = q.Encode()
	fmt.Fprintln(w, "<html>")
	fmt.Fprintf(w, `<a href="%s">wait a tick, then click</a>`, handlerURL.String())
	fmt.Fprintln(w, "</html>")
}

func releaseContainers() error {
	containerLock.Lock()
	defer containerLock.Unlock()
	trash := []tempNotebook{}
	for _, c := range containerMap {
		age := time.Now().Sub(c.lastAccessed)
		if age.Seconds() > containerLifetime.Seconds() {
			log.Printf("age: %v\n", age)
			trash = append(trash, *c)
		}
	}
	cli, err := client.NewEnvClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	d := time.Minute
	for _, c := range trash {
		log.Printf("attempting to release container %s last accessed at %v", c.id, c.lastAccessed)
		if err := cli.ContainerStop(ctx, c.id, &d); err != nil {
			log.Print(err)
		}
		if err := cli.ContainerRemove(ctx, c.id, types.ContainerRemoveOptions{Force: true}); err != nil {
			log.Print(err)
		}
		ports.Drop(c.port)
		delete(containerMap, c.hash)
	}
	return nil
}

func listImages(w http.ResponseWriter, r *http.Request) {
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
	for k := range availableImages {
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
	var buf [32]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		panic(err)
	}
	token = fmt.Sprintf("%x", buf[:])
	log.Printf("using token: %s", token)
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}
	images, err := cli.ImageList(context.Background(), types.ImageListOptions{})
	if err != nil {
		panic(err)
	}
	for _, image := range images {
		if len(image.RepoTags) < 1 || !imageMatch.MatchString(image.RepoTags[0]) {
			continue
		}
		log.Printf("found image %s", image.RepoTags[0])
		availableImages[strings.Split(image.RepoTags[0], ":")[0]] = struct{}{}
	}
	go func() {
		for {
			time.Sleep(time.Minute)
			releaseContainers()
		}
	}()
	mux.HandleFunc("/", listImages)
	mux.HandleFunc("/new", newNotebookHandler)

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	go func() {
		<-quit
		log.Println("Shutting down server...")
		containerLock.Lock()
		for hash := range containerMap {
			// TODO(kyle): this is potentially racy.  Probably change
			// releaseContainers() to take a force option to kill/remove all
			// containers of ours regardless of age.
			containerMap[hash].lastAccessed = time.Unix(1, 0)
		}
		containerLock.Unlock()
		// XXX: * racy * see above
		releaseContainers()
		os.Exit(0)
	}()

	srv := http.Server{
		Addr:    ":8888",
		Handler: mux,
	}
	log.Fatal(srv.ListenAndServe())
}
