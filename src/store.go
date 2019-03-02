package main

import (
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"

	"log"
)

type device struct {
	address       string
	numPackets    int
	score         int
	used          bool
	routerAddress string
}

type store struct {
	db *sql.DB
	tx *sql.Tx
}

func (s *store) initDB() (*sql.DB, error) {
	dbPath := "./store.db"
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}
	s.db = db

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		// Create user table
		if _, err := s.db.Exec(`
			CREATE TABLE interfaces (
				id integer not null primary key,
				interface char (25),
				address char (17)
			);
		`); err != nil {
			log.Println(err)
		}

		// Create devices table
		if _, err := s.db.Exec(`
			CREATE TABLE devices (
				id integer not null primary key,
				address char (17) not null unique,
				num_packets int,
				score int,
				used bool,
				router_address char (17)
			);
		`); err != nil {
			log.Println(err)
		}
	}

	return db, nil
}

func (s *store) insert(table string, keys []string, values []string) {
	tx, err := s.db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	s.tx = tx

	columns := strings.Join(keys, ", ")
	p := make([]string, len(values))
	for i := 0; i < len(values); i++ {
		p[i] = "?"
	}
	valuePlaceholders := strings.Join(p, ", ")

	stmt, err := s.tx.Prepare(fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s) ON DUPLICATE KEY UPDATE address", table, columns, valuePlaceholders))
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	newValues := make([]interface{}, len(values))
	for i, v := range values {
		newValues[i] = v
	}

	if _, err := stmt.Exec(newValues...); err != nil {
		log.Fatal(err)
		return
	}
	tx.Commit()
}

func (s *store) getDevices() []device {
	rows, err := s.db.Query(fmt.Sprintf("SELECT address, num_packets FROM devices"))
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var devices []device
	for rows.Next() {
		var address string
		var numPackets int
		err = rows.Scan(&address, &numPackets)
		if err != nil {
			log.Fatal(err)
		}
		d := device{
			address:    address,
			numPackets: numPackets,
		}
		devices = append(devices, d)
	}
	return devices
}
