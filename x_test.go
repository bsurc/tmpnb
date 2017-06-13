package main

import (
	"fmt"
	"net/http"
	"testing"
)

func printBits(b uint32) string {
	return fmt.Sprintf("%08b\n", b)
}

func TestPortRange(t *testing.T) {
	pr := newPortBitmap(8000, 8)
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
	mask -= 1
	if pr.bits != mask {
		t.Errorf("cleared wrong bit, exp: %s, got: %s", printBits(mask), printBits(pr.bits))
	}
}

func TestIsWebSocket(t *testing.T) {
	m := map[string][]string{
		"Sec-Websocket-Version": []string{"13"},
		"Pragma":                []string{"no-cache"},
		"User-Agent":            []string{"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:53.0) Gecko/20100101 Firefox/53.0"},
		"Accept-Encoding":       []string{"gzip", "deflate"},
		"Connection":            []string{"keep-alive", "Upgrade"},
		"Sec-Websocket-Key":     []string{"VMH5PmmUlBK09WRom394Hw=="},
		//"Cookie":[]string{"lang=en-US; sessionKey=e3bc3ae5deaf464a62947ae22485cf809066b1e8cbcfdfaf9c3470308f5e2c09; _xsrf=2|5e7fab8b|e54fc6bd739b6837c98e4d84b2aa4092|1497028274; username-localhost-8001="2|1:0|10:1497306348|23:username-localhost-8001|44:MWI2ZjcxZTZhMTBlNDAyOWE5MTJiNDdkYzU4NTk4ZjU=|30fa1baf3a6844ebcc5917f9e3110c89549a325b01563413d18fd3cce1787ad2"; username-localhost-8000="2|1:0|10:1497306458|23:username-localhost-8000|44:NTJkNTNlNTM2MjlmNDczM2IzNTJjMDdkOGJmN2U2ZTg=|2df6b76f74460dac1549c78b352722aec2edacfacd77b9606eb1517eda19eba8"; username-localhost-8888="2|1:0|10:1497368002|23:username-localhost-8888|44:NzU3ZjVjOTFkOGRkNDlkNjk1NjFjZDcyYTEyYzEzNTU=|da062d821308f7554d70446571e0446e2c30454083daff39a26c19108d71b846"]
		"Cache-Control":            []string{"no-cache"},
		"Accept":                   []string{"text/html", "application/xhtml+xml", "application/xml;q=0.9,*/*;q=0.8"},
		"Sec-Websocket-Extensions": []string{"permessage-deflate"},
		"Upgrade":                  []string{"websocket"},
		"Accept-Language":          []string{"en-US,en;q=0.5"},
		"Origin":                   []string{"http://localhost:8888"},
		"Dnt":                      []string{"1"},
	}
	r, err := http.NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Error(err)
	}
	r.Header = m
	if !isWebsocket(r) {
		t.Error("failed to detect websocket upgrade")
	}
}
