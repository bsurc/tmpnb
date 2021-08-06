package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

const (
	buster          = "buster"
	defaultLifetime = 30 * time.Minute
	defaultLimit    = 32
)

type Pool struct {
	// TODO(kyle): sync.Map?
	mu        sync.RWMutex
	notebooks map[string]*notebook

	lifetime time.Duration
	limit    int

	port uint32

	dc *client.Client

	cache    map[string]chan *notebook
	shutdown uint32
}

func NewPool(limit int, lifetime time.Duration) (*Pool, error) {
	if limit < 1 {
		limit = defaultLimit
	}
	if lifetime < 1 {
		lifetime = defaultLifetime
	}
	dc, err := client.NewEnvClient()
	if err != nil {
		return nil, err
	}
	p := &Pool{
		notebooks: map[string]*notebook{},
		lifetime:  lifetime,
		limit:     limit,
		port:      8000,
		dc:        dc,
	}
	go func() {
		t := time.NewTicker(lifetime / 4)
		for {
			select {
			case <-t.C:
				p.gc(nil)
			}
		}
	}()
	images, err := p.dc.ImageList(context.TODO(), types.ImageListOptions{})
	if err != nil {
		return nil, err
	}
	const cacheSize = 12
	p.cache = map[string]chan *notebook{}
	for _, image := range images {
		img := image.RepoTags[0]
		p.cache[img] = make(chan *notebook, cacheSize)
		log.Printf("found image %s", img)
		go func(image string) {
			for {
				if atomic.LoadUint32(&p.shutdown) == 1 {
					return
				}
				n, err := p.createNotebook(context.TODO(), img)
				if err != nil {
					log.Print(err)
					return
				}
				p.cache[image] <- n
			}
		}(img)
	}

	return p, nil
}

func (p *Pool) newHandler(w http.ResponseWriter, r *http.Request) {
	image := r.FormValue("image")
	key, err := p.NewNotebook(r.Context(), image)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/"+key, http.StatusFound)
}

func (p *Pool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	//log.Println(r.URL.String())
	if r.URL.Path == "/new" || r.URL.Path == "/new/" {
		p.newHandler(w, r)
		return
	}
	tkns := strings.Split(r.URL.Path, "/")
	if len(tkns) < 2 {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	key := tkns[1]
	p.mu.RLock()
	n, ok := p.notebooks[key]
	p.mu.RUnlock()
	if !ok {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}
	n.handler.ServeHTTP(w, r)
	n.Lock()
	n.touched = time.Now()
	n.Unlock()
}

const (
	created = iota
	started
	stopped
	deleted
)

type notebook struct {
	sync.Mutex
	id      string
	key     string
	touched time.Time
	port    string
	handler http.Handler
	state   uint32
}

func rhex(n int) string {
	x := make([]byte, n)
	_, err := rand.Read(x)
	if err != nil {
		panic(err.Error())
	}
	return hex.EncodeToString(x)
}

func (p *Pool) nextPort() (string, nat.Port) {
	port := atomic.AddUint32(&p.port, 1)
	s := strconv.Itoa(int(port))
	return s, nat.Port(s + "/tcp")
}

func (p *Pool) NewNotebook(ctx context.Context, image string) (string, error) {
	st := time.Now()
	var (
		n   *notebook
		err error
	)
	if c, ok := p.cache[image]; ok {
		select {
		case n = <-c:
			log.Printf("using fast path for %s", image)
		default:
		}
	}
	if n == nil {
		log.Printf("using slow path for %s", image)
		n, err = p.createNotebook(ctx, image)
		if err != nil {
			return "", err
		}
	}

	n.touched = time.Now()
	p.mu.Lock()
	p.notebooks[n.key] = n
	p.mu.Unlock()
	println(n.key)
	log.Printf("new notebook time: %s", time.Since(st))
	return n.key, nil
}

func (p *Pool) createNotebook(ctx context.Context, image string) (*notebook, error) {
	n := &notebook{}
	n.key = rhex(16)
	var natp nat.Port
	n.port, natp = p.nextPort()

	var env []string
	containerConfig := container.Config{
		Hostname: "0.0.0.0",
		User:     buster,
		Cmd: []string{`jupyter-lab`,
			`--no-browser`,
			`--port`, n.port,
			`--ip=0.0.0.0`,
			`--ServerApp.token=''`,
			`--ServerApp.base_url=/` + n.key,
			`--debug`,
		},
		Env:   env,
		Image: image,
		ExposedPorts: nat.PortSet{
			natp: struct{}{},
		},
	}

	hostConfig := container.HostConfig{
		PortBindings: nat.PortMap{
			natp: []nat.PortBinding{
				{
					HostIP:   "0.0.0.0",
					HostPort: n.port,
				},
			},
		},
	}
	st := time.Now()
	resp, err := p.dc.ContainerCreate(ctx, &containerConfig, &hostConfig, nil, nil, "")
	if err != nil {
		return nil, err
	}
	n.id = resp.ID
	log.Printf("container create time: %s", time.Since(st))
	st = time.Now()
	if err := p.dc.ContainerStart(ctx, n.id, types.ContainerStartOptions{}); err != nil {
		return nil, err
	}
	log.Printf("container start time: %s", time.Since(st))
	n.handler = httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   "localhost:" + n.port,
	})
	return n, nil
}

func (p *Pool) Flush() {
	atomic.StoreUint32(&p.shutdown, 1)
	p.mu.Lock()
	for _, n := range p.notebooks {
		n.touched = time.Time{}
	}
	p.mu.Unlock()

	var ids []string
	for k, v := range p.cache {
		fmt.Printf("draining %s cache\n", k)
		for {
			select {
			case n := <-v:
				ids = append(ids, n.id)
			default:
				goto done
			}
		}
	done:
		fmt.Printf("cache %s drained\n", k)
	}
	fmt.Println(ids)
	p.gc(ids)
}

func (p *Pool) gc(fids []string) {
	// gather the docker ids so we can release the lock
	var ids []string
	var keys []string
	p.mu.Lock()
	for _, v := range p.notebooks {
		if time.Since(v.touched) > p.lifetime {
			keys = append(keys, v.key)
			ids = append(ids, v.id)
			log.Printf("marking %s/%s for deletion", v.key, v.id)
		}
	}
	for _, k := range keys {
		log.Printf("deleting %s...", k)
		delete(p.notebooks, k)
	}
	p.mu.Unlock()

	// add force ids
	ids = append(ids, fids...)
	log.Printf("forcing stop/rm of %s", fids)

	for _, k := range ids {
		log.Printf("stopping and removing %s...", k)
		d := time.Minute
		ctx := context.TODO()
		if err := p.dc.ContainerStop(ctx, k, &d); err != nil {
			log.Print(err)
		}
		if err := p.dc.ContainerRemove(ctx, k, types.ContainerRemoveOptions{Force: true}); err != nil {
			log.Print(err)
		}
	}
}
