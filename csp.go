package main

import (
	"strings"
)

const cspKey = "Content-Security-Policy"

func csp() string {
	pairs := map[string][]string{
		"default-src":     []string{"'self'"},
		"script-src":      nil,
		"style-src":       nil,
		"img-src":         nil,
		"connect-src":     nil,
		"font-src":        nil,
		"object-src":      nil,
		"media-src":       nil,
		"sandbox":         nil,
		"report-uri":      []string{"/csp_report"},
		"child-src":       nil,
		"form-action":     nil,
		"frame-ancestors": nil,
		"plugin-types":    nil,
	}

	s := ""
	for k, v := range pairs {
		if v != nil && len(v) > 0 {
			s += k + " " + strings.Join(v, " ")
			s += "; "
		}
	}
	return s
}
