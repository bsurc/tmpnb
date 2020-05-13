// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"time"
)

var (
	tmpnbid   string
	tmpnbhost string
)

func checkin() {
	ticker := time.NewTicker(time.Minute)
	for {
		select {
		case <-ticker.C:
			u := url.URL{
				Scheme: "https",
				Host:   tmpnbhost,
				Path:   path.Join("/", "book", tmpnbid),
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			http.DefaultClient.Do(req)
			cancel()
		}
	}
}

func main() {
	tmpnbid = os.Getenv("TMPNB_ID")
	tmpnbhost = os.Getenv("TMPNB_HOST")
	shell := os.Getenv("SHELL")
	if tmpnbid == "" || tmpnbhost == "" {
		log.Fatalf("TMPNB_ID or TMPNB_HOST not set, just use %s, not tmpnbsh", shell)
	}

	if shell == "" {
		shell = "bash"
	}

	go checkin()

	sh := exec.Command(shell, "-i")
	sh.Env = []string{
		"TMPNB_ID=" + tmpnbid,
		"TMPNB_HOST=" + tmpnbhost,
	}
	sh.Stdin = os.Stdin
	sh.Stdout = os.Stdout
	sh.Stderr = os.Stderr
	err := sh.Run()
	if err != nil {
		log.Fatal(err)
	}
}
