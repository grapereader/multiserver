package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net"

	_ "github.com/mattn/go-sqlite3"
)

var ErrInvalidAddress = errors.New("invalid ip address format")

func banList(db *DB) (map[string]string, error) {
	rows, err := db.Query(`SELECT addr, name FROM ban;`)
	if err != nil {
		return nil, err
	}

	r := make(map[string]string)

	for rows.Next() {
		var addr, name string

		if err = rows.Scan(&addr, &name); err != nil {
			return nil, err
		}

		r[addr] = name
	}

	return r, nil
}

func (p *sqliteProvider) BanList() (map[string]string, error) {
	return banList(p.db)
}

func (p *postgresProvider) BanList() (map[string]string, error) {
	return banList(p.db)
}

// BanList returns the list of banned players and IP addresses
func BanList() (map[string]string, error) {
	db, err := authDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	return db.BanList()
}

func isBanned(db *DB, addr string) (bool, string, error) {
	var name string
	err := db.QueryRow(`SELECT name FROM ban WHERE addr = $1;`, addr).Scan(&name)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return true, "", err
	}

	return name != "", name, nil
}

func (p *sqliteProvider) IsBanned(addr string) (bool, string, error) {
	return isBanned(p.db, addr)
}

func (p *postgresProvider) IsBanned(addr string) (bool, string, error) {
	return isBanned(p.db, addr)
}

// IsBanned reports whether an IP address is banned
func IsBanned(addr string) (bool, string, error) {
	db, err := authDB()
	if err != nil {
		return true, "", err
	}
	defer db.Close()
	return db.IsBanned(addr)
}

// IsBanned reports whether a Conn is banned
func (c *Conn) IsBanned() (bool, string, error) {
	addr := c.Addr().(*net.UDPAddr).IP.String()

	banned, name, err := IsBanned(addr)
	if err != nil {
		return true, "", err
	}

	return banned, name, nil
}

func ban(db *DB, addr, name string) error {
	if net.ParseIP(addr) == nil {
		return ErrInvalidAddress
	}

	_, err := db.Exec(`INSERT INTO ban (
		addr,
		name
	) VALUES (
		$1,
		$2
	);`, addr, name)
	return err
}

func (p *sqliteProvider) Ban(addr, name string) error {
	return ban(p.db, addr, name)
}

func (p *postgresProvider) Ban(addr, name string) error {
	return ban(p.db, addr, name)
}

// Ban adds an IP address to the ban list
func Ban(addr, name string) error {
	db, err := authDB()
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Ban(addr, name)
}

// Ban adds a Conn to the ban list
func (c *Conn) Ban() error {
	banned, _, err := c.IsBanned()
	if err != nil {
		return err
	}

	if banned {
		return fmt.Errorf("ip address %s is already banned", c.Addr().String())
	}

	name := c.Username()
	addr := c.Addr().(*net.UDPAddr).IP.String()

	Ban(addr, name)

	c.CloseWith(AccessDeniedCustomString, "Banned.", false)
	return nil
}

func unban(db *DB, id string) error {
	_, err := db.Exec(`DELETE FROM ban WHERE name = $1 OR addr = $2;`, id, id)
	return err
}

func (p *sqliteProvider) Unban(id string) error {
	return unban(p.db, id)
}

func (p *postgresProvider) Unban(id string) error {
	return unban(p.db, id)
}

// Unban removes a player from the ban list
func Unban(id string) error {
	db, err := authDB()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Unban(id)
}
