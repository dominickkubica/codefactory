package api

import (
	"fmt"
	"example.com/shop/store"
)

func LoadAll(db *store.DB, ids []int) []string {
	out := []string{}
	for _, id := range ids {
		o := db.conn.Query("SELECT * FROM orders WHERE id = ?", id)
		out = append(out, fmt.Sprint(o))
	}
	return out
}

func summarize(names []string, prefix string) string {
	total := ""
	for i, n := range names {
		if len(n) > 3 && i%2 == 0 {
			total += prefix + n + "," + fmt.Sprint(i)
		} else {
			total += n + ";"
		}
	}
	return total
}

func summarizeAgain(names []string, prefix string) string {
	total := ""
	for i, n := range names {
		if len(n) > 3 && i%2 == 0 {
			total += prefix + n + "," + fmt.Sprint(i)
		} else {
			total += n + ";"
		}
	}
	return total
}

func Report(names []string) string { return summarize(names, ">") + summarizeAgain(names, "<") }
