// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

func TestBSURegexp(t *testing.T) {
	re := regexp.MustCompile(bsuRegexp)
	tests := []struct {
		s     string
		match bool
	}{
		{"kyleshannon@boisestate.edu", true},
		{"k@boisestate.edu", true},
		{"kyleshannon@u.boisestate.edu", true},
		{"kyleshannon@uxboisestate.edu", false},
		{"k@u.boisestate.edu", true},
		{"@boisestate.edu", false},
		{"kyleshannon@boisestate.com", false},
		{"kyleshannon@boise.edu", false},
		{"kyle@example.edu", false},
		{"kyle@example.com", false},
		{"kyle@gmail.com", false},
		{"kyle@.edu", false},
	}
	for _, test := range tests {
		if re.MatchString(test.s) != test.match {
			t.Errorf("mismatch %s match should be %t", test.s, test.match)
		}
	}
}

func TestGithubPush(t *testing.T) {
	if testing.Short() {
		t.Skip(skipDocker)
	}
	var push githubPush
	push.Commits = make([]githubPushCommit, 1)
	push.Commits[0].Added = []string{"docker/snakemake/Dockerfile"}
	srv := &notebookServer{}
	ts := httptest.NewServer(http.HandlerFunc(srv.githubPushHandler))
	defer ts.Close()
	tc := ts.Client()
	var b bytes.Buffer
	err := json.NewEncoder(&b).Encode(push)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL, &b)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GitHub-Hookshot/")
	req.Header.Set("X-GitHub-Event", "push")

	resp, err := tc.Do(req)
	if err != nil {
		t.Error(err)
	} else {
		t.Log(resp.Status)
	}
}
