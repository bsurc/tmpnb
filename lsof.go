package main

import (
	"bufio"
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

type of struct {
	pid  int
	name string
	user string
	t    string
}

func lsof() ([]of, error) {
	cmd := exec.Command("lsof")
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	err := cmd.Run()
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(buf)
	var f of
	var fs []of
	for s.Scan() {
		tkns := strings.Fields(s.Text())
		f.pid, _ = strconv.Atoi(tkns[1])
		f.name = tkns[0]
		f.user = tkns[2]
		f.t = tkns[4]
		fs = append(fs, f)
	}
	return fs, nil
}
