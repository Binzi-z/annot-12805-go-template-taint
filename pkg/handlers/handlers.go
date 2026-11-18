package handlers

import (
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var db *sql.DB
var baseDir = "/srv/data"

func runCmd(c string) string {
	out, _ := exec.Command("sh", "-c", c).Output()
	return string(out)
}

func queryStr(q string) string {
	rows, _ := db.Query(q)
	if rows == nil {
		return ""
	}
	defer rows.Close()
	return "ok"
}

func readFile(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	return f.Name()
}

func fetch(u string) string {
	r, err := http.Get(u)
	if err != nil {
		return ""
	}
	defer r.Body.Close()
	return r.Status
}

func onlyDigits(v string) string {
	var b strings.Builder
	for _, c := range v {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func allowlistHost(u string) string {
	if strings.HasPrefix(u, "https://api.internal/") {
		return u
	}
	return "https://api.internal/blocked"
}


func forward00(v string) string {
	return v
}

func Handle00(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := forward00(raw)
	_ = v
	_ = queryStr("SELECT * FROM users WHERE name = '" + v + "'")
}

func forward01(v string) string {
	return v
}

func Handle01(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := forward01(raw)
	_ = v
	_ = runCmd("ping -c 1 " + v)
}

func forward02(v string) string {
	return v
}

func Handle02(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := forward02(raw)
	_ = v
	_ = readFile(filepath.Join(baseDir, v))
}

func forward03(v string) string {
	return v
}

func Handle03(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := forward03(raw)
	_ = v
	_ = fetch(v)
}

func forward04(v string) string {
	return v
}

func Handle04(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := forward04(raw)
	_ = v
	_ = queryStr("SELECT * FROM users WHERE name = '" + v + "'")
}

func forward05(v string) string {
	return v
}

func Handle05(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := forward05(raw)
	_ = v
	_ = runCmd("ping -c 1 " + v)
}

func forward06(v string) string {
	return v
}

func Handle06(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := forward06(raw)
	_ = v
	_ = readFile(filepath.Join(baseDir, v))
}

func forward07(v string) string {
	return v
}

func Handle07(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	v := forward07(raw)
	_ = v
	_ = fetch(v)
}

func forward08(v string) string {
	return v
}

func SafeHandle08(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	clean := strings.ReplaceAll(raw, "'", "")
	v := forward08(clean)
	_ = v
	_ = queryStr("SELECT * FROM users WHERE name = '" + v + "'")
}

func forward09(v string) string {
	return v
}

func SafeHandle09(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	clean := onlyDigits(raw)
	v := forward09(clean)
	_ = v
	_ = runCmd("ping -c 1 " + v)
}

func forward10(v string) string {
	return v
}

func SafeHandle10(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	clean := filepath.Clean(raw)
	v := forward10(clean)
	_ = v
	_ = readFile(filepath.Join(baseDir, v))
}

func forward11(v string) string {
	return v
}

func SafeHandle11(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	clean := allowlistHost(raw)
	v := forward11(clean)
	_ = v
	_ = fetch(v)
}

func forward12(v string) string {
	return v
}

func SafeHandle12(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	clean := strings.ReplaceAll(raw, "'", "")
	v := forward12(clean)
	_ = v
	_ = queryStr("SELECT * FROM users WHERE name = '" + v + "'")
}

func forward13(v string) string {
	return v
}

func SafeHandle13(w http.ResponseWriter, r *http.Request) {
	_ = w
	raw := r.URL.Query().Get("input")
	clean := onlyDigits(raw)
	v := forward13(clean)
	_ = v
	_ = runCmd("ping -c 1 " + v)
}
