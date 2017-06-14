// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

const (
	// jupyterNotebookImageMatch matches images from jupyter/docker-stacks, for
	// example: jupyter/minimal-notebook
	jupyterNotebookImageMatch = `[a-zA-Z0-9]+/[a-zA-Z0-9]+-notebook[:]{0,1}[a-zA-Z0-9]*`

	// allImageMatch applies no filter
	allImageMatch = `.*`

	// defaultContainerLifetime is used if a lifetime is not provided
	defaultContainerLifetime = time.Minute * 10

	// defaultMaxContainers governs the port set size and triggers reclamation
	defaultMaxContainers = 100
)

// tempNotebook holds context for a single container
type tempNotebook struct {
	// id is the docker container id.
	id string
	// hash is  a random generated hash that is used in the path of the server.
	hash string
	// lastAccessed is when the container was used last.
	lastAccessed time.Time
	// port is the passthrough port for the reverse proxy.
	port int
}

type notebookPool struct {
	// guards the entire struct
	sync.Mutex

	// availableImages is a list of docker images that installed on the machine,
	// and match the imageMatch expression
	availableImages map[string]struct{}

	// imageMatch filters available images by name
	imageMatch *regexp.Regexp

	// containerMap is stores the contexts for the containers.
	containerMap map[string]*tempNotebook

	// portSet holds free ports
	portSet *portRange

	// maxContainers governs the port set size and resource reclamation.
	maxContainers int

	// containerLifetime governs when the container resources are reclaimed.
	containerLifetime time.Duration

	// token is the security token for auto-auth
	token string
}

func newNotebookPool(imageRegexp string, maxContainers int, lifetime time.Duration) (*notebookPool, error) {
	if imageRegexp == "" {
		imageRegexp = jupyterNotebookImageMatch
	}
	if int64(lifetime) <= 0 {
		lifetime = defaultContainerLifetime
	}
	if maxContainers < 1 {
		maxContainers = defaultMaxContainers
	}
	imageMatch, err := regexp.Compile(imageRegexp)
	if err != nil {
		return nil, err
	}
	imageMap := map[string]struct{}{}
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	images, err := cli.ImageList(context.Background(), types.ImageListOptions{})
	if err != nil {
		return nil, err
	}
	for _, image := range images {
		if len(image.RepoTags) < 1 || !imageMatch.MatchString(image.RepoTags[0]) {
			continue
		}
		log.Printf("found image %s", image.RepoTags[0])
		imageMap[strings.Split(image.RepoTags[0], ":")[0]] = struct{}{}
	}
	return &notebookPool{
		availableImages:   imageMap,
		imageMatch:        imageMatch,
		containerMap:      make(map[string]*tempNotebook),
		portSet:           newPortRange(8000, maxContainers),
		maxContainers:     maxContainers,
		containerLifetime: lifetime,
	}, nil
}

// defaultHashSize is used for the unique hash generation
const defaultHashSize = 32

// newHash makes a n byte hash and returns the hex encoding.
func newHash(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}

func (p *notebookPool) newNotebook(image string, pull bool) (*tempNotebook, error) {
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}

	if pull {
		_, err = cli.ImagePull(ctx, image, types.ImagePullOptions{})
		if err != nil {
			return nil, err
		}
	}

	hash := newHash(defaultHashSize)

	port, err := p.portSet.Acquire()
	if err != nil {
		return nil, err
	}
	portString := fmt.Sprintf("%d", port)

	var pSet = nat.PortSet{}
	pt, err := nat.NewPort("tcp", portString)
	pSet[pt] = struct{}{}
	containerConfig := container.Config{
		Hostname: "0.0.0.0",
		User:     "jovyan",
		Cmd: []string{`jupyter`,
			`notebook`,
			`--no-browser`,
			`--port`,
			portString,
			`--ip=0.0.0.0`,
			fmt.Sprintf("--NotebookApp.base_url=%s", path.Join("/book", hash)),
			`--NotebookApp.port_retries=0`,
			fmt.Sprintf(`--NotebookApp.token="%s"`, p.token),
			`--NotebookApp.disable_check_xsrf=True`,
		},
		Env:          []string{fmt.Sprintf("CONFIGPROXY_AUTH_TOKEN=%s", p.token)},
		Image:        image,
		ExposedPorts: pSet,
	}

	hostConfig := container.HostConfig{
		NetworkMode: "host",
	}

	resp, err := cli.ContainerCreate(ctx, &containerConfig, &hostConfig, nil, "")
	if err != nil {
		return nil, err
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return nil, err
	}
	t := &tempNotebook{resp.ID, hash, time.Now(), port}
	p.Lock()
	p.containerMap[hash] = t
	p.Unlock()
	return t, nil
}

func (p *notebookPool) releaseContainers(force bool) error {
	p.Lock()
	defer p.Unlock()
	trash := []tempNotebook{}
	for _, c := range p.containerMap {
		age := time.Now().Sub(c.lastAccessed)
		if age.Seconds() > p.containerLifetime.Seconds() || force {
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
		p.portSet.Drop(c.port)
		delete(p.containerMap, c.hash)
	}
	return nil
}
