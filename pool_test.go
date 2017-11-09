// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"testing"
	"time"
)

func init() {
	f, _ := os.Create(os.DevNull)
	log.SetOutput(f)
}

func TestImageMatch(t *testing.T) {
	match := regexp.MustCompile(jupyterNotebookImageMatch)
	tests := []struct {
		s string
		m bool
	}{
		{"ksshannon/geo-notebook", true},
		{"ksshannon/geo-notebook:latest", true},
		{"ksshannon/geo-notebook:sometag", true},
		{"ksshannon/notanotebook", false},
		{"notanotebook", false},
		{"notanotebook:invalid", false},
		{"jupyter/tmpnb:latest", false},
		{"jupyter/configurable-http-proxy:latest", false},
	}
	for _, test := range tests {
		if match.MatchString(test.s) != test.m {
			t.Errorf("missed match: %v", test)
		}
	}
}

const skipDocker = "skipping docker dependent test"

func TestNewNotebook(t *testing.T) {
	if testing.Short() {
		t.Skip(skipDocker)
	}
	p, err := newNotebookPool(".*", 2, time.Minute*2, false)
	if err != nil {
		t.Fatal(err)
	}
	p.disableJupyterAuth = true
	p.stopCollector()
	nb, err := p.newNotebook("jupyter/minimal-notebook", false, "")
	if err != nil {
		t.Error(err)
	}
	time.Sleep(time.Second * 10)
	if len(p.activeNotebooks()) != 1 {
		t.Fatal("failed to create a notebook")
	}
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/?token=", nb.port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	p.stopAndKillContainer(nb.id)
}

func TestCollection(t *testing.T) {
	if testing.Short() {
		t.Skip(skipDocker)
	}
	p, err := newNotebookPool(".*", 2, time.Second*5, false)
	if err != nil {
		t.Fatal(err)
	}
	p.disableJupyterAuth = true
	// Stop the collector, then restart it with an aggressive rate
	p.stopCollector()
	p.startCollector(time.Second)
	nb, err := p.newNotebook("jupyter/minimal-notebook", false, "")
	if err != nil {
		t.Error(err)
	}
	time.Sleep(time.Second * 10)
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/?token=", nb.port))
	defer resp.Body.Close()
	if err == nil {
		t.Errorf("container should be dead")
	}
	n := len(p.activeNotebooks())
	if n != 0 {
		t.Errorf("pool not drained (%d)", n)
	}
	p.stopAndKillContainer(nb.id)
}

func TestZombies(t *testing.T) {
	if testing.Short() {
		t.Skip(skipDocker)
	}
	p, err := newNotebookPool(".*", 2, time.Minute*2, false)
	if err != nil {
		t.Fatal(err)
	}
	p.disableJupyterAuth = true
	p.stopCollector()
	nb, err := p.newNotebook("jupyter/minimal-notebook", false, "")
	if err != nil {
		t.Error(err)
	}
	if len(p.containerMap) != 1 {
		t.Error("failed to create container")
	}
	// manually remove the container from the container map, and drop the port
	p.portSet.Drop(nb.port)
	p.Lock()
	delete(p.containerMap, nb.key)
	p.Unlock()
	c, err := p.zombieContainers()
	if len(c) != 1 {
		t.Error("failed to locate zombie")
	}
	err = p.killZombieContainers()
	if err != nil {
		t.Error(err)
	}
	c, err = p.zombieContainers()
	if len(c) != 0 {
		t.Error("failed to kill zombie")
	}
}
