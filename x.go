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
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

const (
	defaultNotebook = "jupyter/minimal-notebook"
	//defaultNotebook = "ksshannon/scipy-notebook-ext"

	containerLifetime = time.Minute
)

var (
	availableImages = map[string]struct{}{}

	containerLock sync.Mutex
	containerMap  = map[string]*tempNotebook{}
	portLock      sync.Mutex
	mux           = http.NewServeMux()
	ports         = newPortBitmap(8000, 100)
)

type portRange struct {
	mu     sync.Mutex
	bits   uint32
	start  int
	length int
}

func newPortBitmap(start, length int) *portRange {
	return &portRange{start: start, length: length}
}

func (pr *portRange) Acquire() (int, error) {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	for p := uint(0); p < uint(pr.length); p++ {
		if pr.bits&(1<<p) == 0 {
			pr.bits |= (1 << p)
			return int(p) + pr.start, nil
		}
	}
	return -1, fmt.Errorf("port range full")
}

func (pr *portRange) Drop(p int) error {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	if p < pr.start || p >= pr.start+pr.length {
		return fmt.Errorf("port out of range")
	}
	pr.bits &= ^(1 << uint(p-pr.start))
	return nil
}

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

type tempNotebook struct {
	id, hash     string
	created      time.Time
	lastAccessed time.Time
	port         int
}

func newTempNotebook(image string) (*tempNotebook, error) {
	t := new(tempNotebook)
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		return t, err
	}

	_, err = cli.ImagePull(ctx, image, types.ImagePullOptions{})
	if err != nil {
		return t, err
	}

	var buf [32]byte
	_, err = rand.Read(buf[:])
	if err != nil {
		return t, err
	}
	hash := fmt.Sprintf("%x", buf)
	basePath := fmt.Sprintf("--NotebookApp.base_url=%s", path.Join("/book", hash))

	port, err := ports.Acquire()
	if err != nil {
		return t, err
	}
	portString := fmt.Sprintf("%d", port)

	var pSet = nat.PortSet{}
	p, err := nat.NewPort("tcp", portString)
	pSet[p] = struct{}{}
	containerConfig := container.Config{
		Hostname: "0.0.0.0",
		User:     "jovyan",
		Cmd: []string{`jupyter`,
			`notebook`,
			`--no-browser`,
			`--port`,
			portString,
			`--ip=0.0.0.0`,
			basePath,
			`--NotebookApp.port_retries=0`,
			`--NotebookApp.token="ABCD"`,
			`--NotebookApp.disable_check_xsrf=True`,
		},
		Env:          []string{"CONFIGPROXY_AUTH_TOKEN=ABCD"},
		Image:        image,
		ExposedPorts: pSet,
	}

	hostConfig := container.HostConfig{
		NetworkMode: "host",
		//Binds           []string      // List of volume bindings for this container
		//NetworkMode     NetworkMode   // Network mode to use for the container
		//PortBindings    nat.PortMap   // Port mapping between the exposed port (container) and the host
		//AutoRemove      bool          // Automatically remove container when it exits
		//DNS             []string          `json:"Dns"`        // List of DNS server to lookup
	}

	resp, err := cli.ContainerCreate(ctx, &containerConfig, &hostConfig, nil, "")
	if err != nil {
		return t, err
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return t, err
	}
	t = &tempNotebook{resp.ID, hash, time.Now(), time.Now(), port}
	containerLock.Lock()
	containerMap[hash] = t
	containerLock.Unlock()
	return t, nil
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

	//proxy := httputil.NewSingleHostReverseProxy(&proxyURL)
	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			log.Print(r.URL.String())
			r.URL.Scheme = proxyURL.Scheme
			r.URL.Host = proxyURL.Host
		},
	}
	handlerPath := path.Join("/book", tmpnb.hash) + "/"
	log.Printf("handler: %s", handlerPath)
	mux.HandleFunc(handlerPath, func(w http.ResponseWriter, r *http.Request) {
		tmpnb.lastAccessed = time.Now()
		log.Printf("%s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())
		proxy.ServeHTTP(w, r)
	})
	fmt.Fprintln(w, "<html>")
	fmt.Fprintf(w, `<a href="%s">click</a>`, handlerPath)
	fmt.Fprintln(w, "</html>")
	//http.Redirect(w, r, handlerPath, http.StatusContinue)
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
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}
	images, err := cli.ImageList(context.Background(), types.ImageListOptions{})
	if err != nil {
		panic(err)
	}
	for _, image := range images {
		if len(image.RepoTags) < 1 {
			continue
		}
		log.Printf("found image %s", image.RepoTags[0])
		availableImages[strings.Split(image.RepoTags[0], ":")[0]] = struct{}{}
	}
	go func() {
		for {
			time.Sleep(time.Second * 10)
			releaseContainers()
		}
	}()
	mux.HandleFunc("/", listImages)
	mux.HandleFunc("/new", newNotebookHandler)
	log.Fatal(http.ListenAndServe(":8888", mux))
}
