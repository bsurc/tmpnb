// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"time"
)

var (
	insecure  bool
	tmpnbid   string
	tmpnbhost string
	tick      time.Duration
)

func checkin() {
	ticker := time.NewTicker(tick)
	for {
		select {
		case <-ticker.C:
			u := url.URL{
				Host: tmpnbhost,
				Path: path.Join("/", "book", tmpnbid),
			}
			if insecure {
				u.Scheme = "http"
			} else {
				u.Scheme = "https"
			}
			log.Printf("checking in to %s at %s", u.String(), time.Now())
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
			if err != nil {
				log.Print(err)
				continue
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Print(err)
				continue
			}
			cancel()
			resp.Body.Close()
			if resp.StatusCode != 200 {
				log.Print(resp.Status)
			}
		}
	}
}

func main() {
	flag.BoolVar(&insecure, "insecure", false, "use http instead of https")
	flagLog := flag.String("log", "", "log file for verbose output")
	flag.DurationVar(&tick, "tick", time.Minute, "time between check in")
	flag.Parse()
	var (
		fout io.WriteCloser
		err  error
	)
	if *flagLog != "" {
		fout, err = os.Create(*flagLog)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		fout, err = os.Create(os.DevNull)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer fout.Close()
	log.SetOutput(fout)

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
		"TERM=" + os.Getenv("TERM"),
	}
	sh.Stdin = os.Stdin
	sh.Stdout = os.Stdout
	sh.Stderr = os.Stderr
	err = sh.Run()
	if err != nil {
		log.Fatal(err)
	}
}
