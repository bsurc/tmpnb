// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"path"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

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
			fmt.Sprintf(`--NotebookApp.token="%s"`, token),
			`--NotebookApp.disable_check_xsrf=True`,
		},
		Env:          []string{fmt.Sprintf("CONFIGPROXY_AUTH_TOKEN=%s", token)},
		Image:        image,
		ExposedPorts: pSet,
	}

	hostConfig := container.HostConfig{
		NetworkMode: "host",
		//DNS:            []string
		//Binds           []string      // List of volume bindings for this container
		//NetworkMode     NetworkMode   // Network mode to use for the container
		//PortBindings    nat.PortMap   // Port mapping between the exposed port (container) and the host
		//AutoRemove      bool          // Automatically remove container when it exits
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
