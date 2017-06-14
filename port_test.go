// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"
)

func printBits(b uint32) string {
	return fmt.Sprintf("%08b\n", b)
}

func TestPortRange(t *testing.T) {
	pr := newPortRange(8000, 8)
	p, err := pr.Acquire()
	if err != nil {
		t.Error(err)
	}
	pr.Drop(p)
	if pr.bits != 0 {
		t.Errorf("failed to drop %d", p)
	}

	for i := 0; i < 3; i++ {
		pr.Acquire()
	}
	mask := uint32(1<<3 - 1)
	if pr.bits != mask {
		t.Errorf("cleared wrong bit, exp: %s, got: %s", printBits(mask), printBits(pr.bits))
	}

	pr.Drop(8000)
	mask--
	if pr.bits != mask {
		t.Errorf("cleared wrong bit, exp: %s, got: %s", printBits(mask), printBits(pr.bits))
	}
}
