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
	jupyterNotebookImageMatch = `[a-zA-Z0-9]+/[a-zA-Z0-9]+-notebook(:[a-zA-Z0-9]+)?$`

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
type notebook struct {
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
	// email is the email of the user who created this container.
	email string
}

// Return the path that should be registered in a mux.  This avoids duplicate
// code everywhere that is fragile.
func (n *notebook) path() string {
	return path.Join("/book", n.key) + "/"
}

// notebookPool holds data regarding running notebooks.
type notebookPool struct {
	// guards the entire struct
	sync.Mutex

	// availableImages holds a list of all images on the system that match
	// imageMatch.
	availableImages map[string]struct{}

	// baseImages holds the base label for the image (tagless)
	baseImages map[string]struct{}

	// imageMatch filters available images by name
	imageMatch *regexp.Regexp

	// containerMap is stores the contexts for the containers.
	containerMap map[string]*notebook

	// allMu guards the allContainer map
	allMu sync.Mutex

	// allContainers holds all containers spawned by the pool during the lifetime
	// of the pool.  This can help decide what containers are actually 'zombies'.
	allContainers map[string]struct{}

	// persisent allows changes to be stored in new docker images for continued
	// use.
	persistent bool

	// writeMu guards imageWrite
	writeMu sync.Mutex

	// imageWrite contains keys of the images currently being written to disk.
	// New containers from this image cannot be spawned while writing is in
	// progress.
	imageWrite map[string]struct{}

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
func newNotebookPool(imageRegexp string, maxContainers int, lifetime time.Duration, persistent bool) (*notebookPool, error) {
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
	baseMap := map[string]struct{}{}
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
		baseMap[strings.Split(image.RepoTags[0], ":")[0]] = struct{}{}
	}
	pool := &notebookPool{
		availableImages:   imageMap,
		baseImages:        baseMap,
		imageMatch:        imageMatch,
		containerMap:      make(map[string]*notebook),
		persistent:        persistent,
		imageWrite:        map[string]struct{}{},
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
func (p *notebookPool) newNotebook(image string, pull bool, email string) (*notebook, error) {
	ctx := context.Background()
	cli, err := client.NewEnvClient()
	if err != nil {
		log.Print(err)
		return nil, err
	}
	defer cli.Close()

	tag := "latest"
	utag := strings.Split(email, "@")[0]
	if p.persistent {
		uim := image + ":" + utag
		// Check and see if the image is currently being written.  If it is, give
		// it a chance before erroring.
		writing := false
		d := time.Millisecond * 250
		for i := 0; i < 4; i++ {
			p.writeMu.Lock()
			_, writing = p.imageWrite[uim]
			p.writeMu.Unlock()
			if !writing {
				break
			}
			time.Sleep(d)
			d *= 2
		}
		// If we are still writing, nothing we can do...
		if writing {
			return nil, fmt.Errorf("%s is being written to disk, please try again later", image)
		}
		p.Lock()
		if _, ok := p.availableImages[image+":"+utag]; ok {
			tag = utag
		}
		p.Unlock()
	}
	image += ":" + tag

	// Check for an already running container with the user and the image name.
	if p.persistent {
		var pnb *notebook
		p.Lock()
		for _, nb := range p.containerMap {
			nb.Lock()
			e := nb.email
			img := nb.imageName
			nb.Unlock()
			if e == nb.email && image == img {
				pnb = nb
				break
			}
		}
		p.Unlock()
		if pnb != nil {
			log.Printf("container is running at: %s", pnb.key)
			return pnb, nil
		}
	}

	log.Printf("creating container from image %s", image)

	if pull && !p.persistent {
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
	t := &notebook{
		id:           resp.ID,
		key:          key,
		imageName:    image,
		lastAccessed: time.Now(),
		port:         port,
		email:        email,
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
func (p *notebookPool) addNotebook(t *notebook) error {
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
	p.allMu.Lock()
	p.allContainers[t.key] = struct{}{}
	p.allMu.Unlock()
	p.Unlock()
	return nil
}

// nbCopy holds metadata about a notebook, it can't be locked.
type nbCopy struct {
	id           string
	key          string
	imageName    string
	lastAccessed time.Time
	port         int
	email        string
}

func (n nbCopy) path() string {
	return (&notebook{key: n.key}).path()
}

// saveImage writes the container changes to disk.  Note that this is
// potentially a long(ish) running process.
//
// TODO(kyle): lock images while writing to disk?
func (p *notebookPool) saveImage(c nbCopy, image string) error {
	// Notify that we are writing to disk
	p.writeMu.Lock()
	p.imageWrite[image] = struct{}{}
	p.writeMu.Unlock()
	defer func() {
		p.writeMu.Lock()
		delete(p.imageWrite, image)
		p.writeMu.Unlock()
	}()
	cli, err := client.NewEnvClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	// Get the container info
	cj, err := cli.ContainerInspect(ctx, c.id)
	_ = cj
	opts := types.ContainerCommitOptions{
		Reference: image,
		Comment:   fmt.Sprintf("%s|%s", c.email, time.Now()),
		Author:    c.email,
		Changes:   []string{},
		Pause:     true,
		Config:    &container.Config{},
	}
	_, err = cli.ContainerCommit(ctx, c.id, opts)
	if err != nil {
		return err
	}
	p.Lock()
	p.availableImages[image] = struct{}{}
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
func (p *notebookPool) activeNotebooks() []notebook {
	p.Lock()
	n := len(p.containerMap)
	nbs := make([]notebook, n)
	i := 0
	for k := range p.containerMap {
		c := p.containerMap[k]
		nbs[i] = notebook{
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
	p.allMu.Lock()
	defer p.allMu.Unlock()
	for _, c := range containers {
		// If we manage it, leave it be
		if _, ok := ids[c.ID]; ok {
			continue
		}
		if _, ok := p.allContainers[c.ID]; ok {
			cs = append(cs, c)
			delete(p.allContainers, c.ID)
		}
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
	trash := []notebook{}
	for _, c := range p.containerMap {
		c.Lock()
		age := time.Now().Sub(c.lastAccessed)
		if age.Seconds() > p.containerLifetime.Seconds() || force {
			log.Printf("age: %v\n", age)
			//trash = append(trash, *c)
			trash = append(trash, notebook{
				id:           c.id,
				key:          c.key,
				imageName:    c.imageName,
				lastAccessed: c.lastAccessed,
				port:         c.port,
				email:        c.email,
			})
		}
		c.Unlock()
	}
	p.Unlock()
	for i := 0; i < len(trash); i++ {
		c := nbCopy{
			id:           trash[i].id,
			key:          trash[i].key,
			imageName:    trash[i].imageName,
			lastAccessed: trash[i].lastAccessed,
			port:         trash[i].port,
			email:        trash[i].email,
		}
		f := func(c nbCopy) {
			// Get the key out of the map as soon as possible, then it's unreachable
			// by the server and we don't have to worry about messy access
			p.Lock()
			delete(p.containerMap, c.key)
			p.Unlock()
			// This isn't very elegant, but we couldn't delete the pattern from the mux
			// before, but now we can with the vendored/updated copy in mux.go.  We add
			// a trailing slash when we register the path, so we must add it here too.
			p.deregisterMux <- c.path()
			// If we are saving the image, check and see if it exists.  If it does,
			// overwrite it.  If it doesn't create a new image name.  make it the
			// original image name, with a tag of the users email.
			if p.persistent && c.email != "" {
				image := strings.Split(c.imageName, ":")[0] + ":" + strings.Split(c.email, "@")[0]
				log.Printf("attempting to save container %s last accessed at %v as %s", c.id, c.lastAccessed, image)
				err := p.saveImage(c, image)
				if err != nil {
					log.Print(err)
				}
			} else {
				log.Println(p.persistent, c.email)
			}
			log.Printf("attempting to release container %s last accessed at %v", c.id, c.lastAccessed)
			p.stopAndKillContainer(c.id)
			p.portSet.Drop(c.port)
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
// out supervision.  Since they aren't under our supervision, we don't need to
// guard them while deleting.
//
// TODO(kyle): what are actual zombies?  Do we respect image name?
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
