// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import "testing"

func TestCSP(t *testing.T) {
	if csp() != expCSP {
		t.Errorf("invalid csp, got: %s, want: %s", csp(), expCSP)
	}
}
