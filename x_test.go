// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"testing"
)

func TestImageMatch(t *testing.T) {
	tests := []struct {
		s string
		m bool
	}{
		{"ksshannon/geo-notebook", true},
		{"ksshannon/geo-notebook:latest", true},
		{"ksshannon/geo-notebook:sometag", true},
		{"ksshannon/notanotebook", false},
		{"notanotebook", false},
		{"notanotebook:invalid", false},
		{"jupyter/tmpnb:latest", false},
		{"jupyter/configurable-http-proxy:latest", false},
	}
	for _, test := range tests {
		if imageMatch.MatchString(test.s) != test.m {
			t.Errorf("missed match: %v", test)
		}
	}
}
