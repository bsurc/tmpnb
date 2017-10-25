// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"regexp"
	"testing"
	"time"
)

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

func TestNewNotebook(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker dependent test")
	}
	p, err := newNotebookPool(".*", 2, time.Minute*2)
	if err != nil {
		t.Fatal(err)
	}
	p.disableJupyterAuth = false
	nb, err := p.newNotebook("jupyter/minimal-notebook", false, "")
	if err != nil {
		t.Error(err)
	}
	time.Sleep(time.Second * 10)
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/?token=", nb.port))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	p.stopAndKillContainer(nb.id)
}
