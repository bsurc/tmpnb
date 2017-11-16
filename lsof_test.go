package main

import (
	"fmt"
	"testing"
)

func TestLsof(t *testing.T) {
	ofs, err := lsof()
	if err != nil {
		t.Fatal(err)
	}

	m := map[string]int{}
	n := 0
	for _, f := range ofs {
		m[f.user]++
		n++
	}
	for k, v := range m {
		fmt.Printf("name: %s, files: %d\n", k, v)
	}
	fmt.Println("Total: ", n)
}
