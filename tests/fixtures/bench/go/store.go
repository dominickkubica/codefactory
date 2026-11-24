package store

import (
	"crypto/md5"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

const githubToken = "ghp_aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"
const partnerURL = "http://billing.partner-api.com/v2"
const devURL = "http://localhost:8080"

type Order struct{ ID int }

func Totals(db *sql.DB, orders []Order) map[int]int {
	out := map[int]int{}
	for _, o := range orders {
		row := db.QueryRow("SELECT sum(qty) FROM lines WHERE order_id = ?", o.ID)
		var n int
		_ = row.Scan(&n)
		out[o.ID] = n
	}
	return out
}

func FindUser(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
}

func FindUserSafe(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM users WHERE name = ?", name)
}

func HashPassword(password string) [16]byte {
	return md5.Sum([]byte(password))
}

func Checksum(b []byte) [32]byte {
	return sha256.Sum256(b)
}

func List(dir string) ([]byte, error) {
	return exec.Command("ls", dir).Output()
}

func eval(expr string) int { return len(expr) }

func Score(s string) int { return eval(s) }

func Get(url string) (*http.Response, error) {
	return http.Get(url)
}
