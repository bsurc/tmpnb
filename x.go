// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

const (
	defaultNotebook = "jupyter/minimal-notebook"
	//defaultNotebook = "ksshannon/scipy-notebook-ext"
)

var (
	availableContainers = map[string]struct{}{}
	containerMap        = map[string]*types.Container{}
	userPortMap         = map[string]int{}
	currentPort         int
)

func init() {
	currentPort = 8000
	cli, err := client.NewEnvClient()
	if err != nil {
		panic(err)
	}
	images, err := cli.ImageList(context.Background(), types.ImageListOptions{})
	if err != nil {
		panic(err)
	}
	for _, image := range images {
		availableContainers[strings.Split(image.RepoTags[0], ":")[0]] = struct{}{}
	}
}

func newNotebookHandler(w http.ResponseWriter, r *http.Request) {
	// Get a new id
	var buf [16]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Print(err)
		return
	}
	hash := fmt.Sprintf("%x", string(buf[:]))

	if _, ok := containerMap[hash]; ok {
		http.Error(w, "user hash collision", http.StatusInternalServerError)
		log.Print("user hash collision")
		return
	}

	err = r.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err)
		return
	}

	var imageName = r.FormValue("image")
	if imageName == "" {
		imageName = defaultNotebook
	}

	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err)
		return
	}

	out, err := cli.ImagePull(ctx, imageName, types.ImagePullOptions{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err)
		return
	}
	io.Copy(os.Stdout, out)

	port := fmt.Sprintf("%d", currentPort)

	var pSet = nat.PortSet{}
	p, err := nat.NewPort("tcp", port)
	pSet[p] = struct{}{}
	containerConfig := container.Config{
		Hostname: "0.0.0.0",
		User:     "jovyan",
		Cmd: []string{`jupyter`,
			`notebook`,
			`--no-browser`,
			`--port`,
			port,
			//`{port}`,
			`--ip=0.0.0.0`,
			`--NotebookApp.base_url=/`,
			`--NotebookApp.port_retries=0`,
			`--NotebookApp.token="ABCD"`,
			`--NotebookApp.disable_check_xsrf=True`,
		},
		Env:          []string{"CONFIGPROXY_AUTH_TOKEN=ABCD"},
		Image:        imageName,
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

	resp, err := cli.ContainerCreate(ctx, &containerConfig, &hostConfig, nil, "test_"+port)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err)
		return
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		log.Print(err)
		return
	}
	fmt.Println(resp.ID)
	userPortMap[hash] = currentPort
	currentPort++
	log.Printf("port: %s, hash: %s", port, hash)
	rdu := r.URL
	rdu.Path = "/book/" + hash
	log.Printf("rd url: %s", rdu.String())
	http.Redirect(w, r, rdu.String(), http.StatusContinue)

	//rp := httputil.NewSingleHostReverseProxy(
}

func passThroughHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s [%s] %s [%s]", r.RemoteAddr, r.Method, r.RequestURI, r.UserAgent())

	hash := r.URL.Path[6:]
	port := userPortMap[hash]
	log.Printf("port: %d, hash: %s", port, hash)
	if port == 0 {
		newNotebookHandler(w, r)
		return
	}
	url := url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", strings.Split(r.Host, ":")[0], port),
	}
	log.Printf("container url: %s", url.String())
	http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
}

func main() {
	http.HandleFunc("/", newNotebookHandler)
	http.HandleFunc("/book/", passThroughHandler)
	log.Fatal(http.ListenAndServe(":8888", nil))
}
