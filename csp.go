// Copyright (c) 2017, Boise State University All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"sort"
	"strings"
)

var (
	// Enable Content Security Policy.  We'll use the full blanket of 'self' for
	// everything as long as we can.  We only had one inline javascript section,
	// and we moved that into assets/static.  The /csp_report URI receives the
	// reports of any violations.  Note that an empty string slice actually means
	// no value is set, but the key is present.  This has the affect of setting
	// that key to 'none', which disallows that resource.  For example:
	//
	// "script-src": []string{}
	//
	// generates: "script-src;"
	//
	// which is evaluated in firefox as "script-src 'none';"
	pairs = map[string][]string{
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
		"frame-ancestors": []string{"'none'"},
		"plugin-types":    nil,
	}
	sortedCSPKeys []string
)

const (
	// cspKey is the header key for the assigned values
	cspKey = "Content-Security-Policy"

	// expCSP is what we should get based on the key value pairs above
	expCSP = "default-src 'self'; report-uri /csp_report; "
)

func init() {
	sortedCSPKeys = make([]string, len(pairs))
	i := 0
	for k := range pairs {
		sortedCSPKeys[i] = k
		i++
	}
	sort.Strings(sortedCSPKeys)
}

func csp() string {
	s := ""
	for _, k := range sortedCSPKeys {
		v, ok := pairs[k]
		if ok && v != nil {
			s += k + " " + strings.Join(v, " ")
			s += "; "
		}
	}
	return s
}
