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
	"sync/atomic"
	"time"
)

var (
	insecure     bool
	tmpnbid      string
	tmpnbhost    string
	tmpnbsession string
	tick         time.Duration
	phonehome    uint32
)

func checkin() {
	ticker := time.NewTicker(tick)
	for {
		select {
		case <-ticker.C:
			if !atomic.CompareAndSwapUint32(&phonehome, 1, 0) {
				continue
			}
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
			ck := &http.Cookie{Name: "bsuJupyter", Value: os.Getenv("TMPNB_SESSION")}
			req.AddCookie(ck)
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

type writer struct{}

func (w writer) Write(p []byte) (int, error) {
	n, err := os.Stdout.Write(p)
	if n > 0 {
		atomic.CompareAndSwapUint32(&phonehome, 0, 1)
	}
	return n, err
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
	switch *flagLog {
	case "":
		fout, _ = os.Create(os.DevNull)
	default:
		fout, err = os.Create(*flagLog)
		if err != nil {
			log.Fatal(err)
		}
	}
	defer fout.Close()

	tmpnbid = os.Getenv("TMPNB_ID")
	tmpnbhost = os.Getenv("TMPNB_HOST")
	tmpnbsession = os.Getenv("TMPNB_SESSION")
	shell := os.Getenv("SHELL")
	if tmpnbid == "" || tmpnbhost == "" {
		log.Fatalf("TMPNB_ID or TMPNB_HOST not set, just use %s, not tmpnbsh", shell)
	}

	if shell == "" {
		shell = "bash"
	}

	log.SetOutput(fout)
	go checkin()

	sh := exec.Command(shell, "-i")
	sh.Env = []string{
		"TMPNB_ID=" + tmpnbid,
		"TMPNB_HOST=" + tmpnbhost,
		"TMPNB_SESSION=" + tmpnbsession,
		"TERM=" + os.Getenv("TERM"),
	}
	var w writer
	sh.Stdin = os.Stdin
	sh.Stdout = w
	//sh.Stdout = os.Stdout
	sh.Stderr = os.Stderr
	err = sh.Run()
	if err != nil {
		log.Fatal(err)
	}
}
