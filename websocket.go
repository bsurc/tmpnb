// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

// isWebsocket inspects an incoming request and determines if it is for a
// websocket.
func isWebsocket(r *http.Request) bool {
	upgrade := false
	for _, h := range r.Header["Connection"] {
		if strings.Index(strings.ToLower(h), "upgrade") >= 0 {
			upgrade = true
			break
		}
	}
	if !upgrade {
		return false
	}

	for _, h := range r.Header["Upgrade"] {
		if strings.Index(strings.ToLower(h), "websocket") >= 0 {
			return true
		}
	}
	return false
}

// websocketProxy handles websocket requests for reverse proxy calls.
// Written by @bradfitz.  See:
//
// https://groups.google.com/forum/#!msg/golang-nuts/KBx9pDlvFOc/QC5v-uC5UOgJ
func websocketProxy(target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, err := net.Dial("tcp", target)
		if err != nil {
			http.Error(w, "Error contacting backend server.", 500)
			log.Printf("Error dialing websocket backend %s: %v", target, err)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Not a hijacker?", 500)
			return
		}
		nc, _, err := hj.Hijack()
		if err != nil {
			log.Printf("Hijack error: %v", err)
			return
		}
		defer nc.Close()
		defer d.Close()

		err = r.Write(d)
		if err != nil {
			log.Printf("Error copying request to target: %v", err)
			return
		}

		errc := make(chan error, 2)
		cp := func(dst io.Writer, src io.Reader) {
			_, err := io.Copy(dst, src)
			errc <- err
		}
		go cp(d, nc)
		go cp(nc, d)
		<-errc
	})
}
