package main

import (
	"strings"
)

const cspKey = "Content-Security-Policy"

func csp() string {
	pairs := map[string][]string{
		"default-src":     nil,
		"script-src":      nil,
		"style-src":       []string{"'self'"},
		"img-src":         []string{"'self'"},
		"connect-src":     nil,
		"font-src":        nil,
		"object-src":      nil,
		"media-src":       nil,
		"sandbox":         nil,
		"report-uri":      []string{"/csp_report"},
		"child-src":       nil,
		"form-action":     []string{"'self'"},
		"frame-ancestors": nil,
		"plugin-types":    nil,
	}

	s := ""
	for k, v := range pairs {
		if v != nil {
			s += k + " " + strings.Join(v, " ")
			s += "; "
		}
	}
	return s
}
