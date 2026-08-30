package main

import (
	"net/http"
	"net/url"
)

func vuln(r *http.Request) {
	u := r.URL.Query().Get("url")
	// ruleid: go.security.ssrf
	resp, _ := http.Get("http://internal/" + u)
	_ = resp
	// ok: go.security.ssrf
	resp2, _ := http.Get("https://api.example.com/v1")
	_ = resp2
}
