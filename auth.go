package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

const (
	_ = 1 << iota
	AuthMechSRP
	AuthMechFirstSRP
)

type authProvider interface {
	CreateUser(name string, password string) error
	Password(name string) (string, error)
	SetPassword(name string, password string) error
	Ban(addr, name string) error
	Unban(id string) error
	BanList() (map[string]string, error)
	IsBanned(addr string) (bool, string, error)
	Privs(name string) (map[string]bool, error)
	SetPrivs(name string, privs map[string]bool) error
	Close() error
}

type sqliteProvider struct {
	db *DB
}
type postgresProvider struct {
	db *DB
}

var passPhrase []byte

func encodeVerifierAndSalt(s, v []byte) string {
	return base64.StdEncoding.EncodeToString(s) + "#" + base64.StdEncoding.EncodeToString(v)
}

func decodeVerifierAndSalt(src string) ([]byte, []byte, error) {
	sString := strings.Split(src, "#")[0]
	vString := strings.Split(src, "#")[1]

	s, err := base64.StdEncoding.DecodeString(sString)
	if err != nil {
		return nil, nil, err
	}

	v, err := base64.StdEncoding.DecodeString(vString)
	if err != nil {
		return nil, nil, err
	}

	return s, v, nil
}

func authDB() (authProvider, error) {
	sqlite3 := func() (*sqliteProvider, error) {
		db, err := OpenSQLite3("auth.sqlite", `
			CREATE TABLE IF NOT EXISTS auth (
				name VARCHAR(32) PRIMARY KEY NOT NULL,
				password VARCHAR(512) NOT NULL
			);
			CREATE TABLE IF NOT EXISTS privileges (
				name VARCHAR(32) PRIMARY KEY NOT NULL,
				privileges VARCHAR(1024)
			);
			CREATE TABLE IF NOT EXISTS ban (
				addr VARCHAR(39) PRIMARY KEY NOT NULL,
				name VARCHAR(32) NOT NULL
			);
		`)
		return &sqliteProvider{db: db}, err
	}

	psql := func(name, user, password, host string, port int) (*postgresProvider, error) {
		db, err := OpenPSQL(name, user, password, `
			CREATE TABLE IF NOT EXISTS auth (
				id SERIAL,
				name VARCHAR(32) NOT NULL,
				password VARCHAR(512) NOT NULL,
				PRIMARY KEY (id)
			);
			CREATE TABLE IF NOT EXISTS user_privileges (
				id INT,
				name VARCHAR(32) NOT NULL,
				privilege VARCHAR(1024),
				PRIMARY KEY (id, privilege),
				CONSTRAINT fk_id FOREIGN KEY (id) REFERENCES auth (id) ON DELETE CASCADE
			);
			CREATE TABLE IF NOT EXISTS ban (
				addr VARCHAR(39) NOT NULL,
				name VARCHAR(32) NOT NULL
			);
		`, host, port)
		return &postgresProvider{db: db}, err
	}

	db, ok := ConfKey("psql_db").(string)
	if !ok {
		return sqlite3()
	}

	host, ok := ConfKey("psql_host").(string)
	if !ok {
		host = "localhost"
	}

	port, ok := ConfKey("psql_port").(int)
	if !ok {
		port = 5432
		return sqlite3()
	}

	user, ok := ConfKey("psql_user").(string)
	if !ok {
		log.Print("PostgreSQL user not set or not a string")
		return sqlite3()
	}

	password, ok := ConfKey("psql_password").(string)
	if !ok {
		log.Print("PostgreSQL password not set or not a string")
		return sqlite3()
	}

	return psql(db, user, password, host, port)
}

func (p *sqliteProvider) Close() error {
	return p.db.Close()
}

func (p *postgresProvider) Close() error {
	return p.db.Close()
}

func (p *sqliteProvider) CreateUser(name string, password string) error {
	_, err := p.db.Exec(`INSERT INTO auth (
		name,
		password
	) VALUES (
		?,
		?
	);`, name, password)
	return err
}

func (p *postgresProvider) CreateUser(name string, password string) error {
	_, err := p.db.Exec(`INSERT INTO auth (
		name,
		password
	) VALUES (
		$1,
		$2
	);`, name, "#1#"+password)
	return err
}

func (p *sqliteProvider) Password(name string) (string, error) {
	var pwd string
	err := p.db.QueryRow(`SELECT password FROM auth WHERE name = ?;`, name).Scan(&pwd)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	return pwd, nil
}

func (p *postgresProvider) Password(name string) (string, error) {
	var pwd string
	err := p.db.QueryRow(`SELECT password FROM auth WHERE name = $1;`, name).Scan(&pwd)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}

	// lop off the #1# bit to be consistent with minetest
	runes := []rune(pwd)[3:]

	return string(runes), nil
}

func (p *sqliteProvider) SetPassword(name string, password string) error {
	_, err := p.db.Exec(`UPDATE auth SET password = ? WHERE name = ?;`, password, name)
	return err
}

func (p *postgresProvider) SetPassword(name string, password string) error {
	_, err := p.db.Exec(`UPDATE auth SET password = $1 WHERE name = $2;`, password, name)
	return err
}

// CreateUser creates a new entry in the authentication database
func CreateUser(name string, verifier, salt []byte) error {
	db, err := authDB()
	if err != nil {
		return err
	}
	defer db.Close()

	pwd := encodeVerifierAndSalt(salt, verifier)

	return db.CreateUser(name, pwd)
}

// Password returns the SRP tokens of a user
func Password(name string) ([]byte, []byte, error) {
	db, err := authDB()
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()

	pwd, err := db.Password(name)
	if err != nil {
		return nil, nil, err
	}

	if pwd == "" {
		return nil, nil, nil
	}

	salt, verifier, err := decodeVerifierAndSalt(pwd)
	return verifier, salt, err
}

// SetPassword changes the SRP tokens of a user
func SetPassword(name string, verifier, salt []byte) error {
	db, err := authDB()
	if err != nil {
		return err
	}
	defer db.Close()

	pwd := encodeVerifierAndSalt(salt, verifier)

	err = db.SetPassword(pwd, name)
	return err
}

func init() {
	pwd, err := StorageKey("auth:passphrase")
	if err != nil {
		log.Fatal(err)
	}

	if pwd == "" {
		passPhrase = make([]byte, 16)
		_, err := rand.Read(passPhrase)
		if err != nil {
			log.Fatal(err)
		}

		// Save the passphrase for future use
		// This passphrase should not be changed wihtout deleting
		// the auth databases on the minetest servers
		err = SetStorageKey("auth:passphrase", string(passPhrase))
		if err != nil {
			log.Fatal(err)
		}
	} else {
		passPhrase = []byte(pwd)
	}
}
