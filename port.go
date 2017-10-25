// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

const portMapDebug = true

// portRange manages available ports given a range
type portRange struct {
	// Mutex guards access to the bit map
	sync.Mutex
	// ports is the slice representing the port range where port[0] represents
	// start
	ports []bool
	// start is the first port in the range
	start int
	// length is the range of ports so that start + length-1 == last port in
	// range
	length int
}

// newPortRange creates a bit map that handles port assignments for the docker
// containers.
func newPortRange(start, length int) *portRange {
	ports := make([]bool, length)
	return &portRange{ports: ports, start: start, length: length}
}

// Acquire finds an open port and returns it.  If no port is available
// errPortRangeFull is returned.
func (pr *portRange) Acquire() (int, error) {
	pr.Lock()
	defer pr.Unlock()
	for i, p := range pr.ports {
		if !p {
			host := fmt.Sprintf(":%d", pr.start+i)
			s, err := net.Listen("tcp", host)
			if err != nil {
				// port in use, probably a zombie
				// TODO(kyle): increase port range so we still get length ports?
				continue
			}
			s.Close()
			pr.ports[i] = true
			return pr.start + i, nil
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
	pr.ports[p-pr.start] = false
	return nil
}
