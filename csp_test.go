package main

import "testing"

func TestCSP(t *testing.T) {
	s := csp()
	if s == "" {
		t.Fail()
	}
}
