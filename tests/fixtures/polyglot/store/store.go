package store

type DB struct{ conn *Conn }

// Get loads one order.
func (d *DB) Get(id int) Order { return d.conn.Query("SELECT * FROM orders WHERE id = ?", id) }

func helperUnused(x int) int {
	total := 0
	for i := 0; i < x; i++ {
		total += i * 2
	}
	return total
}

func usedByGenerated(x int) int { return x + 1 }

func pick(rows []Order, id int) Order {
	for _, r := range rows {
		if r.ID == id {
			return r
		}
	}
	return Order{}
}
