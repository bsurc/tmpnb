// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"sync"
)

// portRange manages available ports given a range
type portRange struct {
	// Mutex guards access to the bit map
	sync.Mutex
	// bits is the bit map representing the port range where bit 0 represents
	// start
	bits uint32
	// start is the first port in the range
	start int
	// length is the range of ports so that start + length-1 == last port in
	// range
	length int
}

// newPortRange creates a bit map that handles port assignments for the docker
// containers.
func newPortRange(start, length int) *portRange {
	return &portRange{start: start, length: length}
}

// Acquire finds an open port and returns it.  If no port is available
// errPortRangeFull is returned.
func (pr *portRange) Acquire() (int, error) {
	pr.Lock()
	defer pr.Unlock()
	for p := uint(0); p < uint(pr.length); p++ {
		if pr.bits&(1<<p) == 0 {
			pr.bits |= (1 << p)
			return int(p) + pr.start, nil
		}
	}
	return -1, errNotebookPoolFull
}

// errPortOutOfRange indicates the port is invalid for the portRange.
var errPortOutOfRange = errors.New("port out of range")

// Drop releases a port back to the available pool.  If the requested port is
// not valid for the port range, errPortOutOfRange is returned.
func (pr *portRange) Drop(p int) error {
	pr.Lock()
	defer pr.Unlock()
	if p < pr.start || p >= pr.start+pr.length {
		return errPortOutOfRange
	}
	pr.bits &= ^(1 << uint(p-pr.start))
	return nil
}
