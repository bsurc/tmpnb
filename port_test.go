// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
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
