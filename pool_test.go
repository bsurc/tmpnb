// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
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

func TestNotebookQueue(t *testing.T) {
	var nbs []tempNotebook
	for i := 0; i < 3; i++ {
		nb := tempNotebook{
			id:           fmt.Sprintf("%d", i),
			hash:         fmt.Sprintf("hash_%d", i),
			imageName:    fmt.Sprintf("image_%d", i),
			lastAccessed: time.Now(),
			port:         8000 + i,
		}
		nbs = append(nbs, nb)
	}
	q := notebookQueue{}
	q.Push(&nbs[0])
	if len(q.q) != 1 {
		t.Error("failed to Push()")
	}
	n := q.Pop()
	if n == nil {
		t.Error("failed to Pop()")
	}
	if n.id != "0" {
		t.Errorf("invalid notebook, %+v", n)
	}
	n = q.Pop()
	if n != nil {
		t.Fatal("failed to Pop()")
	}
	q.Push(&nbs[1])
	q.Push(&nbs[2])
	if len(q.q) != 2 {
		t.Error("failed to Push()")
	}

	n = q.Pop()
	if n.id != "1" {
		t.Errorf("invalid notebook, %+v", n)
	}
	n = q.Pop()
	if n.id != "2" {
		t.Errorf("invalid notebook, %+v", n)
	}
}
