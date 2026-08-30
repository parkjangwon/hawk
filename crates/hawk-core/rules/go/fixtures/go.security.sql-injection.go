package main

import (
	"database/sql"
	"net/http"
)

func vuln(r *http.Request, db *sql.DB) {
	name := r.FormValue("name")
	// ruleid: go.security.sql-injection
	db.Query("SELECT * FROM users WHERE name='" + name + "'")
	user := "admin"
	// ok: go.security.sql-injection
	db.Query("SELECT * FROM users WHERE name=?", user)
}
