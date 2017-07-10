// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"testing"
)

func TestPortRange(t *testing.T) {
	pr := newPortRange(8000, 8)
	p, err := pr.Acquire()
	if err != nil {
		t.Error(err)
	}
	if !pr.ports[0] {
		t.Errorf("didn't acquire port %d", p)
	}
	pr.Drop(p)
	if pr.ports[0] {
		t.Errorf("failed to drop %d", p)
	}
}

func TestFullPortRange(t *testing.T) {
	const n = 8
	const sp = 8000
	pr := newPortRange(sp, n)
	for i := 0; i < n; i++ {
		_, err := pr.Acquire()
		if err != nil {
			t.Error(err)
		}
	}
}

func TestPortOverflow(t *testing.T) {
	pr := newPortRange(8000, 100)
	for i := 0; i < 100; i++ {
		_, err := pr.Acquire()
		if err != nil {
			t.Error(err)
		}
	}
	_, err := pr.Acquire()
	if err != errNotebookPoolFull {
		t.Errorf("should have errored with %s, didn't", errNotebookPoolFull)
	}
}

func TestZombiePort(t *testing.T) {
	pr := newPortRange(8000, 10)
	_, err := pr.Acquire()
	if err != nil {
		t.Error(err)
	}
	// steal port 8001
	s, err := net.Listen("tcp", ":8001")
	// if it fails then the port is likely taken
	if err != nil {
		t.Error(err)
	}
	p, err := pr.Acquire()
	if err != nil {
		t.Error(err)
	}
	s.Close()
	if p != 8002 {
		t.Errorf("bad port exp: %d, got: %d", 8002, p)
	}
}

func BenchmarkPortRange(b *testing.B) {
	pr := newPortRange(8000, 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			pr.Acquire()
		}
		for p := 8000; p < 100; p++ {
			pr.Drop(i)
		}
	}
}
