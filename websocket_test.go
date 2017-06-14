// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"net/http"
	"testing"
)

// TestIsWebSocket checks for proper websocket detection in a request header.
func TestIsWebSocket(t *testing.T) {
	// Taken from an actual request, deleted the cookie header
	header := map[string][]string{
		"Sec-Websocket-Version":    []string{"13"},
		"Pragma":                   []string{"no-cache"},
		"User-Agent":               []string{"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:53.0) Gecko/20100101 Firefox/53.0"},
		"Accept-Encoding":          []string{"gzip", "deflate"},
		"Connection":               []string{"keep-alive", "Upgrade"},
		"Sec-Websocket-Key":        []string{"VMH5PmmUlBK09WRom394Hw=="},
		"Cache-Control":            []string{"no-cache"},
		"Accept":                   []string{"text/html", "application/xhtml+xml", "application/xml;q=0.9,*/*;q=0.8"},
		"Sec-Websocket-Extensions": []string{"permessage-deflate"},
		"Upgrade":                  []string{"websocket"},
		"Accept-Language":          []string{"en-US,en;q=0.5"},
		"Origin":                   []string{"http://localhost:8888"},
		"Dnt":                      []string{"1"},
	}
	r, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Error(err)
	}
	r.Header = header
	if !isWebsocket(r) {
		t.Error("failed to detect websocket upgrade")
	}
}
