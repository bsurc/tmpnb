// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"path"
	"regexp"
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
	jupyterNotebookImageMatch = `[a-zA-Z0-9]+/[a-zA-Z0-9]+-notebook(:[a-zA-Z0-9]*)?`

	// allImageMatch applies no filter
	allImageMatch = `.*`

	// defaultContainerLifetime is used if a lifetime is not provided
	defaultContainerLifetime = time.Minute * 10

	// defaultMaxContainers governs the port set size and triggers reclamation
	defaultMaxContainers = 100

	// collectionFraction is the fraction of lifetime to collect containers.  For
	// example 4 collects every 1/4 of the container lifetime.
	collectionFraction = 4
)

// tempNotebook holds context for a single container
type tempNotebook struct {
	// guard struct (only used for lastAccessed right now)
	sync.Mutex
	// id is the docker container id.
	id string
	// key is  a random generated key that is used in the path of the server.
	key string
	// imageName is the name of the image used to start the container
	imageName string
	// lastAccessed is when the container was used last.
	lastAccessed time.Time
	// port is the passthrough port for the reverse proxy.
	port int
	// userEmail is the email of the user who created this container.
	userEmail string
}

// notebookPool holds data regarding running notebooks.
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

	// disableJupyterAuth controls using an auth token
	disableJupyterAuth bool

	// token is the security token for auto-auth
	token string

	// killCollection stops the automated resource reclamation
	killCollection chan struct{}

	// lastCollMu guards the time for reclamation.  It is used infrequently, and
	// we don't need to lock the whole object.
	lastCollMu sync.Mutex

	// lastCollection is the timestamp the last time the containers were
	// reclaimed.
	lastCollection time.Time

	// deregisterMux is a channel for sending a path that needs to be
	// de-registered from the server mux.
	deregisterMux chan string
}

// errNotebookPoolFull indicates the pool is at maxContainers
var errNotebookPoolFull = errors.New("container pool hit max size limit")

// newNotebookPool creates a notebookPool and sets defaults, overriding some
// with passed arguments.
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
	defer cli.Close()
	images, err := cli.ImageList(context.Background(), types.ImageListOptions{})
	if err != nil {
		return nil, err
	}
	for _, image := range images {
		if len(image.RepoTags) < 1 || !imageMatch.MatchString(image.RepoTags[0]) {
			continue
		}
		log.Printf("found image %s", image.RepoTags[0])
		imageMap[image.RepoTags[0]] = struct{}{}
	}
	pool := &notebookPool{
		availableImages:   imageMap,
		imageMatch:        imageMatch,
		containerMap:      make(map[string]*tempNotebook),
		portSet:           newPortRange(8000, maxContainers),
		maxContainers:     maxContainers,
		containerLifetime: lifetime,
		killCollection:    make(chan struct{}),
		deregisterMux:     make(chan string),
	}
	pool.startCollector(time.Duration(int64(lifetime) / collectionFraction))
	pool.lastCollMu.Lock()
	pool.lastCollection = time.Now()
	pool.lastCollMu.Unlock()
	return pool, nil
}

// defaultKeySize is used for the unique key generation
const defaultKeySize = 32

// newKey makes a n byte key and returns the hex encoding.
func newKey(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", b)
}

// newNotebook initializes and sets values for a new notebook.
func (p *notebookPool) newNotebook(image string, pull bool, email string) (*tempNotebook, error) {
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		log.Print(err)
		return nil, err
	}
	defer cli.Close()
	// TODO(kyle): possibly provide tag support
	if pull {
		log.Printf("pulling container %s", image)
		ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
		out, err := cli.ImagePull(ctx, image, types.ImagePullOptions{})
		if err != nil {
			log.Print(err)
			return nil, err
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
	}

	key := newKey(defaultKeySize)

	port, err := p.portSet.Acquire()
	if err != nil {
		return nil, err
	}
	portString := fmt.Sprintf("%d", port)

	tokenArg := fmt.Sprintf(`--NotebookApp.token="%s"`, p.token)
	var env []string
	if p.disableJupyterAuth {
		tokenArg = fmt.Sprintf(`--NotebookApp.token=""`)
	} else {
		env = []string{fmt.Sprintf("CONFIGPROXY_AUTH_TOKEN=%s", p.token)}
	}
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
			fmt.Sprintf("--NotebookApp.base_url=%s", path.Join("/book", key)),
			`--NotebookApp.port_retries=0`,
			tokenArg,
			`--NotebookApp.disable_check_xsrf=True`,
		},
		Env:          env,
		Image:        image,
		ExposedPorts: pSet,
	}

	hostConfig := container.HostConfig{
		NetworkMode: "host",
	}

	resp, err := cli.ContainerCreate(ctx, &containerConfig, &hostConfig, nil, "")
	if err != nil {
		p.portSet.Drop(port)
		return nil, err
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		p.portSet.Drop(port)
		return nil, err
	}
	log.Printf("created container: %s", resp.ID)
	t := &tempNotebook{
		id:           resp.ID,
		key:          key,
		imageName:    image,
		lastAccessed: time.Now(),
		port:         port,
		userEmail:    email,
	}
	err = p.addNotebook(t)
	if err != nil {
		log.Print(err)
		p.portSet.Drop(port)
		return nil, err
	}
	// TODO(kyle): call cli.ContainerWait() to let it start up...
	return t, nil
}

// addNotebook adds a tempNotebook to the containerMap, if there is room.
func (p *notebookPool) addNotebook(t *tempNotebook) error {

	p.Lock()
	n := len(p.containerMap)
	log.Printf("pool size: %d of %d", n+1, p.maxContainers)
	if n+1 > p.maxContainers {
		p.releaseContainers(false, true)
	}
	n = len(p.containerMap)
	if n+1 > p.maxContainers {
		return errNotebookPoolFull
	}
	p.containerMap[t.key] = t
	p.Unlock()
	return nil
}

// stopAndKillContainer requests the stopping (docker stop) and the removal of
// the container (docker rm).  Errors are logged, but not returned and rm is
// always called.
func (p *notebookPool) stopAndKillContainer(id string) {
	d := time.Minute
	cli, err := client.NewEnvClient()
	if err != nil {
		log.Print(err)
	}
	defer cli.Close()
	ctx := context.Background()
	if err := cli.ContainerStop(ctx, id, &d); err != nil {
		log.Print(err)
	}
	if err := cli.ContainerRemove(ctx, id, types.ContainerRemoveOptions{Force: true}); err != nil {
		log.Print(err)
	}
}

// activeNotebooks fetchs copies of the tempNotebooks and returns them as a
// slice.  The lock is obviously invalid.
func (p *notebookPool) activeNotebooks() []tempNotebook {
	p.Lock()
	n := len(p.containerMap)
	nbs := make([]tempNotebook, n)
	i := 0
	for k := range p.containerMap {
		c := p.containerMap[k]
		nbs[i] = tempNotebook{
			id:           c.id,
			key:          c.key,
			imageName:    c.imageName,
			lastAccessed: c.lastAccessed,
			port:         c.port,
		}
		i++
	}
	p.Unlock()
	return nbs
}

// zombieNotebooks queries docker for containers that aren't under our
// supervision.  These can block ports assigned to our containers.
func (p *notebookPool) zombieContainers() ([]types.Container, error) {
	var cs []types.Container
	ids := map[string]struct{}{}
	p.Lock()
	for _, c := range p.containerMap {
		ids[c.id] = struct{}{}
	}
	p.Unlock()
	cli, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	defer cli.Close()
	opts := types.ContainerListOptions{}
	containers, err := cli.ContainerList(context.Background(), opts)
	if err != nil {
		return nil, err
	}
	for _, c := range containers {
		// If we manage it, leave it be
		if _, ok := ids[c.ID]; ok {
			continue
		}
		cs = append(cs, c)
	}
	return cs, nil
}

// nextCollection returns when the collector is run again
func (p *notebookPool) NextCollection() time.Time {
	p.lastCollMu.Lock()
	t := p.lastCollection.Add(p.containerLifetime / collectionFraction)
	p.lastCollMu.Unlock()
	return t
}

// startCollector launches a goroutine that checks for expired containers at
// interval d.  d is typically set to containerLifetime / collectionFraction.  Call
// stopCollector to stop the reclamation.
func (p *notebookPool) startCollector(d time.Duration) {
	go func() {
		ticker := time.NewTicker(d)
		for {
			select {
			case <-ticker.C:
				p.releaseContainers(false, true)
				p.lastCollMu.Lock()
				p.lastCollection = time.Now()
				p.lastCollMu.Unlock()
			case <-p.killCollection:
				ticker.Stop()
				return
			}
		}
	}()
}

// stopCollector sends a message on a channel to kill the auto reclamation.
func (p *notebookPool) stopCollector() {
	p.killCollection <- struct{}{}
}

// releaseContainers checks for expired containers and frees them from the
// containerMap.  It also frees the port in the portSet.  If force is true, age
// is ignored.
func (p *notebookPool) releaseContainers(force, async bool) error {
	p.Lock()
	trash := []tempNotebook{}
	for _, c := range p.containerMap {
		c.Lock()
		age := time.Now().Sub(c.lastAccessed)
		if age.Seconds() > p.containerLifetime.Seconds() || force {
			log.Printf("age: %v\n", age)
			//trash = append(trash, *c)
			trash = append(trash, tempNotebook{
				id:           c.id,
				key:          c.key,
				imageName:    c.imageName,
				lastAccessed: c.lastAccessed,
				port:         c.port,
			})
		}
		c.Unlock()
	}
	p.Unlock()
	for i := 0; i < len(trash); i++ {
		type nbCopy struct {
			id           string
			key          string
			imageName    string
			lastAccessed time.Time
			port         int
		}
		c := nbCopy{
			id:           trash[i].id,
			key:          trash[i].key,
			imageName:    trash[i].imageName,
			lastAccessed: trash[i].lastAccessed,
			port:         trash[i].port,
		}
		f := func(c nbCopy) {
			log.Printf("attempting to release container %s last accessed at %v", c.id, c.lastAccessed)
			p.stopAndKillContainer(c.id)
			p.portSet.Drop(c.port)
			p.Lock()
			delete(p.containerMap, c.key)
			p.Unlock()
			// This isn't very elegant, but we couldn't delete the pattern from the mux
			// before, but now we can with the vendored/updated copy in mux.go.  We add
			// a trailing slash when we register the path, so we must add it here too.
			p.deregisterMux <- path.Join("/book", c.key) + "/"
		}
		if async {
			go f(c)
		} else {
			f(c)
		}
	}
	return nil
}

// killZombieContainers stops and kills any docker containers that aren't under
// out supervision.
//
// FIXME(kyle): not currently called at any time, when, why, etc...
func (p *notebookPool) killZombieContainers() error {
	zombies, err := p.zombieContainers()
	if err != nil {
		return err
	}
	for _, c := range zombies {
		p.stopAndKillContainer(c.ID)
	}
	return nil
}
