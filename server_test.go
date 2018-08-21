// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"regexp"
	"testing"

	"github.com/bsurc/oauth2"
)

func TestBSURegexp(t *testing.T) {
	re := regexp.MustCompile(oauth2.BSUEmail)
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
