package main

import (
	"database/sql"
	"errors"
	"log"
	"strings"

	"github.com/lib/pq"

	_ "github.com/mattn/go-sqlite3"
)

func encodePrivs(privs map[string]bool) string {
	lenP := 0
	for priv := range privs {
		if privs[priv] {
			lenP++
		}
	}

	ps := make([]string, lenP)

	i := 0
	for priv := range privs {
		if privs[priv] {
			ps[i] = priv

			i++
		}
	}

	r := strings.Join(ps, "|")

	return r
}

func decodePrivs(s string) map[string]bool {
	ps := strings.Split(s, "|")

	r := make(map[string]bool)

	for i := range ps {
		if ps[i] != "" {
			r[ps[i]] = true
		}
	}

	return r
}

func (p *sqliteProvider) Privs(name string) (map[string]bool, error) {
	var eprivs string
	err := p.db.QueryRow(`SELECT privileges FROM privileges WHERE name = $1;`, name).Scan(&eprivs)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return make(map[string]bool), err
	}

	return decodePrivs(eprivs), nil
}

func (p *postgresProvider) Privs(name string) (map[string]bool, error) {
	rows, err := p.db.Query(`SELECT privilege FROM user_privileges INNER JOIN auth ON user_privileges.id = auth.id WHERE auth.name = $1;`, name)

	if err != nil {
		return make(map[string]bool), err
	}

	privs := make(map[string]bool)
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			log.Print(err)
			return make(map[string]bool), err
		}
		privs[r] = true
	}

	return privs, nil
}

// Privs returns the privileges of a player
func Privs(name string) (map[string]bool, error) {
	db, err := authDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	return db.Privs(name)
}

// Privs returns the privileges of a Conn
func (c *Conn) Privs() (map[string]bool, error) {
	return Privs(c.Username())
}

func (p *sqliteProvider) SetPrivs(name string, privs map[string]bool) error {
	_, err := p.db.Exec(`INSERT INTO privileges (
		name,
		privileges
	) VALUES ($1, $2) 
	ON CONFLICT (name) DO UPDATE SET
		privileges = excluded.privileges;
	`, name, encodePrivs(privs))
	return err
}

func (p *postgresProvider) SetPrivs(name string, privs map[string]bool) error {
	_, err := p.db.Exec(`DELETE FROM user_privileges INNER JOIN auth ON user_privileges.id = auth.id WHERE auth.name = $1`, name)
	if err != nil {
		log.Print(err)
	}

	var id int
	err = p.db.QueryRow(`SELECT id FROM auth WHERE name = $1`, name).Scan(&id)
	if err != nil {
		log.Print(err)
		return err
	}

	txn, err := p.db.Begin()
	if err != nil {
		return err
	}

	stmt, err := txn.Prepare(pq.CopyIn("user_privileges", "id", "privilege"))
	if err != nil {
		return err
	}

	for priv := range privs {
		if privs[priv] {
			_, err = stmt.Exec(id, priv)
			if err != nil {
				log.Print(err)
			}
		}
	}

	_, err = stmt.Exec()
	if err != nil {
		return err
	}

	err = stmt.Close()
	if err != nil {
		return err
	}

	err = txn.Commit()
	if err != nil {
		return err
	}

	return err
}

// SetPrivs sets the privileges of a player
func SetPrivs(name string, privs map[string]bool) error {
	db, err := authDB()
	if err != nil {
		return err
	}
	defer db.Close()

	return db.SetPrivs(name, privs)
}

// SetPrivs sets the privileges of a Conn
func (c *Conn) SetPrivs(privs map[string]bool) error {
	return SetPrivs(c.Username(), privs)
}

// CheckPrivs reports if a player has all of the specified privileges
func CheckPrivs(name string, req map[string]bool) (bool, error) {
	privs, err := Privs(name)
	if err != nil {
		return false, err
	}

	for priv := range req {
		if req[priv] && !privs[priv] {
			return false, nil
		}
	}

	return true, nil
}

// CheckPrivs reports if a Conn has all of the specified privileges
func (c *Conn) CheckPrivs(req map[string]bool) (bool, error) {
	return CheckPrivs(c.Username(), req)
}

func init() {
	if admin, ok := ConfKey("admin").(string); ok {
		privs, err := Privs(admin)
		if err != nil {
			log.Print(err)
			return
		}

		privs["privs"] = true

		if err = SetPrivs(admin, privs); err != nil {
			log.Print(err)
			return
		}
	}
}
