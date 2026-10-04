// ruleid: go.security.path-traversal
f, err := os.Open(r.URL.Query().Get("file"))
// ok: go.security.path-traversal
f2, err := os.Open("/var/log/app.log")
