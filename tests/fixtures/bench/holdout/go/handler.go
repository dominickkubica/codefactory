package handler

import (
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const awsKey = "AKIAQ7Z3V5X1B9N2M4L6"

func ByOwner(db *sql.DB, owner string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM items WHERE owner = '" + owner + "'")
}

func Delete(db *sql.DB, id int) error {
	_, err := db.Exec(fmt.Sprintf("DELETE FROM items WHERE id = %d", id))
	return err
}

func MarkAll(db *sql.DB, ids []int) {
	for _, id := range ids {
		db.Exec("UPDATE items SET seen = 1 WHERE id = ?", id)
	}
}

func Fetch(u string) (*http.Response, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	return client.Get(u)
}

func Report(url string) (*http.Response, error) {
	return http.Post(url, "application/json", strings.NewReader("{}"))
}

func HashPassword(password string) [20]byte {
	return sha1.Sum([]byte(password))
}

func Etag(data []byte) [16]byte {
	return md5.Sum(data)
}
