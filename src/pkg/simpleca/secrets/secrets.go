// MIT License
//
// Copyright (c) 2026 Slawomir Koszewski
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// Package secrets holds the one-time secrets of a CA: values encrypted with a key derived from
// the one-time code that reveals them once.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/database"
	"github.com/skoszewski/simple-ca/src/pkg/simpleca/tokens"
)

// SecretsFile is the file of a CA directory holding its secrets.
const SecretsFile = "secrets-db.json"

// MaxValue is the largest value of a secret, in bytes.
const MaxValue = 16 << 10

// MaxValid is the longest validity of a secret.
const MaxValid = 30 * 24 * time.Hour

// The refusals of Take: an unknown or used code, an expired code, and a client the code is not
// usable from.
var (
	ErrUnknown = errors.New("unknown or used code")
	ErrExpired = errors.New("the code has expired")
	ErrClient  = errors.New("the code is not usable")
)

// Secret is a secret of a CA: the SHA-256 of its one-time code, as tokens.SetupCodeHash gives it,
// the salt of the key derived from the code, the nonce and the AES-256-GCM ciphertext of its
// value, the prefixes of the client addresses it is taken from, any without them, when it was
// created and expires, and the actor that created it.
type Secret struct {
	Code    string    `json:"code"`
	Salt    []byte    `json:"salt"`
	Nonce   []byte    `json:"nonce"`
	Value   []byte    `json:"value"`
	Clients []string  `json:"clients,omitempty"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	Creator string    `json:"creator,omitempty"`
}

// SecretsDB is secrets-db.json of a CA directory, its secrets by name.
type SecretsDB struct {
	Secrets map[string]*Secret `json:"secrets"`
}

// secretsTable returns the quoted table of the secrets of caDir and the ID of its CA, or an empty
// table when database.secrets_db of its root CA names none; an error when caDir holds no CA, or
// the table is named and secrets-db.json is still there.
func secretsTable(caDir string) (table, ca string, err error) {
	rootDir, ca, err := simpleca.LocateCA(caDir)
	if err != nil {
		return "", "", err
	}
	cfg, err := simpleca.LoadConfig(rootDir)
	if err != nil {
		return "", "", err
	}
	if cfg.Database.SecretsDB == "" {
		return "", ca, nil
	}
	if simpleca.FileExists(filepath.Join(caDir, SecretsFile)) {
		return "", "", fmt.Errorf("%q is not migrated to the database; run simple-ca database migrate secrets_db",
			filepath.Join(caDir, SecretsFile))
	}
	return database.Table(cfg.Database, cfg.Database.SecretsDB), ca, nil
}

// Store names where the secrets of caDir are kept: secrets-db.json, or the table of
// database.secrets_db.
func Store(caDir string) string {
	if table, _, err := secretsTable(caDir); err == nil && table != "" {
		return "the table " + table
	}
	return fmt.Sprintf("%q", filepath.Join(caDir, SecretsFile))
}

// Load reads the secrets of caDir from secrets-db.json, or from the table of database.secrets_db,
// an empty database when there are none.
func Load(caDir string) (*SecretsDB, error) {
	table, ca, err := secretsTable(caDir)
	if err != nil {
		return nil, err
	}
	if table == "" {
		return loadFile(caDir)
	}
	db := &SecretsDB{Secrets: map[string]*Secret{}}
	ctx := context.Background()
	p, err := database.Pool(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := p.Query(ctx, "SELECT name, secret FROM "+table+" WHERE ca = $1", ca)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var b []byte
		if err := rows.Scan(&name, &b); err != nil {
			return nil, err
		}
		var s Secret
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("could not read the secret %q of %s: %w", name, table, err)
		}
		db.Secrets[name] = &s
	}
	return db, rows.Err()
}

// loadFile reads secrets-db.json of caDir, an empty database when it does not exist.
func loadFile(caDir string) (*SecretsDB, error) {
	db := &SecretsDB{Secrets: map[string]*Secret{}}
	b, err := os.ReadFile(filepath.Join(caDir, SecretsFile))
	if errors.Is(err, os.ErrNotExist) {
		return db, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, db); err != nil {
		return nil, fmt.Errorf("could not read %q: %w", filepath.Join(caDir, SecretsFile), err)
	}
	if db.Secrets == nil {
		db.Secrets = map[string]*Secret{}
	}
	return db, nil
}

// Save drops the expired secrets and writes the others of caDir to secrets-db.json, a new file of
// the private mode, or replaces those of its CA in the table of database.secrets_db in one
// transaction.
func (db *SecretsDB) Save(caDir string) error {
	now := time.Now()
	for name, s := range db.Secrets {
		if !now.Before(s.Expires) {
			delete(db.Secrets, name)
		}
	}
	table, ca, err := secretsTable(caDir)
	if err != nil {
		return err
	}
	if table != "" {
		ctx := context.Background()
		p, err := database.Pool(ctx)
		if err != nil {
			return err
		}
		tx, err := p.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE ca = $1", ca); err != nil {
			return err
		}
		for name, s := range db.Secrets {
			b, err := json.Marshal(s)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (ca, name, secret) VALUES ($1, $2, $3)", ca, name, b); err != nil {
				return err
			}
		}
		return tx.Commit(ctx)
	}
	b, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(caDir, SecretsFile+".tmp")
	os.Remove(tmp)
	if err := simpleca.WritePrivateFile(tmp, append(b, '\n')); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(caDir, SecretsFile))
}

// Lock locks the secrets of caDir: secrets-db.json, as simpleca.LockFile does, or its CA in the
// table of database.secrets_db, with an advisory lock held on a connection of its own, waiting as
// long.
func Lock(caDir string) (func(), error) {
	table, ca, err := secretsTable(caDir)
	if err != nil {
		return nil, err
	}
	if table == "" {
		return simpleca.LockFile(filepath.Join(caDir, SecretsFile))
	}
	ctx := context.Background()
	p, err := database.Pool(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := p.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	key := database.LockKey(table, ca)
	deadline := time.Now().Add(simpleca.TokensLockWait)
	for {
		var locked bool
		if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&locked); err != nil {
			conn.Release()
			return nil, err
		}
		if locked {
			return func() {
				conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", key)
				conn.Release()
			}, nil
		}
		if time.Now().After(deadline) {
			conn.Release()
			return nil, fmt.Errorf("the secrets of CA %q in %s are locked by another process", ca, table)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Migrated is the count of the secrets a migration moved of the CA of an ID, empty for the root CA.
type Migrated struct {
	CA    string
	Count int
}

// Migrate moves the secrets-db.json files of the root CA in rootDir and its issuing CAs to the
// table of database.secrets_db of cfg, in one transaction refused when the table already holds
// secrets of one of those CAs, renames each file to secrets-db.json.migrated, and returns the
// counts.
func Migrate(rootDir string, cfg *simpleca.Config) ([]Migrated, error) {
	if cfg.Database.SecretsDB == "" {
		return nil, fmt.Errorf("database.secrets_db of %q names no table", cfg.Path)
	}
	table := database.Table(cfg.Database, cfg.Database.SecretsDB)
	var dirs []string
	var counts []Migrated
	files := map[string]*SecretsDB{}
	for _, id := range simpleca.CAIDs(rootDir) {
		dir := filepath.Join(rootDir, id)
		if !simpleca.FileExists(filepath.Join(dir, SecretsFile)) {
			continue
		}
		unlock, err := simpleca.LockFile(filepath.Join(dir, SecretsFile))
		if err != nil {
			return nil, err
		}
		defer unlock()
		db, err := loadFile(dir)
		if err != nil {
			return nil, err
		}
		dirs, files[id] = append(dirs, dir), db
		counts = append(counts, Migrated{CA: id, Count: len(db.Secrets)})
	}
	if len(dirs) == 0 {
		return nil, fmt.Errorf("no %s in %q or its issuing CAs", SecretsFile, rootDir)
	}
	ctx := context.Background()
	p, err := database.Pool(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	for _, m := range counts {
		var found bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+table+" WHERE ca = $1)", m.CA).Scan(&found); err != nil {
			return nil, err
		}
		if found {
			return nil, fmt.Errorf("%s already holds secrets of the CA %q; nothing is migrated", table, m.CA)
		}
		for name, s := range files[m.CA].Secrets {
			b, err := json.Marshal(s)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Exec(ctx, "INSERT INTO "+table+" (ca, name, secret) VALUES ($1, $2, $3)", m.CA, name, b); err != nil {
				return nil, err
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	for _, dir := range dirs {
		if err := os.Rename(filepath.Join(dir, SecretsFile), filepath.Join(dir, SecretsFile+".migrated")); err != nil {
			return nil, err
		}
	}
	return counts, nil
}

// aead returns the AES-256-GCM of the key derived from the one-time code and salt.
func aead(code string, salt []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, []byte(tokens.NormalSetupCode(code)), salt, "simple-ca secret", 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// additionalData binds the ciphertext of a secret to its CA, empty for the root CA, and its name.
func additionalData(ca, name string) []byte {
	return []byte(ca + "\x00" + name)
}

// Add adds the secret name of value to the CA in caDir, valid for valid and taken from the client
// addresses clients, any without them, created by creator, and returns its one-time code.
func Add(caDir, name string, value []byte, valid time.Duration, clients []string, creator string) (string, error) {
	switch {
	case !simpleca.KebabCaseRE.MatchString(name):
		return "", fmt.Errorf("secret name %q is not a kebab-case name, such as db-password", name)
	case len(value) == 0:
		return "", errors.New("the value of a secret is empty")
	case len(value) > MaxValue:
		return "", fmt.Errorf("the value of a secret is larger than %d bytes", MaxValue)
	case valid < time.Second || valid > MaxValid:
		return "", fmt.Errorf("the validity of a secret must be from 1s to %s", simpleca.DurationText(MaxValid))
	}
	prefixes, err := tokens.ToPrefixes("client", clients, false)
	if err != nil {
		return "", err
	}
	_, ca, err := simpleca.LocateCA(caDir)
	if err != nil {
		return "", err
	}
	code := tokens.NewSetupCode()
	salt := make([]byte, 16)
	rand.Read(salt)
	gcm, err := aead(code, salt)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	now := time.Now().UTC().Truncate(time.Second)
	s := &Secret{Code: tokens.SetupCodeHash(code), Salt: salt, Nonce: nonce,
		Value: gcm.Seal(nil, nonce, value, additionalData(ca, name)), Clients: prefixes, Created: now,
		Expires: now.Add(valid), Creator: creator}
	unlock, err := Lock(caDir)
	if err != nil {
		return "", err
	}
	defer unlock()
	db, err := Load(caDir)
	if err != nil {
		return "", err
	}
	if old, ok := db.Secrets[name]; ok && time.Now().Before(old.Expires) {
		return "", fmt.Errorf("secret %q exists", name)
	}
	db.Secrets[name] = s
	if err := db.Save(caDir); err != nil {
		return "", err
	}
	return code, nil
}

// Take finds the secret of the one-time code among those of the root CA in rootDir and its issuing
// CAs, taken from the address client, removes it, and returns the ID of its CA, its name and its
// value. It refuses an unknown or used code with ErrUnknown, an expired one with ErrExpired, and a
// client outside the prefixes of the secret with ErrClient.
func Take(rootDir, code string, client netip.Addr) (caID, name string, value []byte, err error) {
	hash := tokens.SetupCodeHash(code)
	for _, id := range simpleca.CAIDs(rootDir) {
		dir := filepath.Join(rootDir, id)
		if name, value, err := func() (string, []byte, error) {
			unlock, err := Lock(dir)
			if err != nil {
				return "", nil, err
			}
			defer unlock()
			db, err := Load(dir)
			if err != nil {
				return "", nil, err
			}
			for name, s := range db.Secrets {
				if s.Code != hash {
					continue
				}
				if !time.Now().Before(s.Expires) {
					return "", nil, errors.Join(ErrExpired, db.Save(dir))
				}
				if !(&tokens.APIToken{Clients: s.Clients}).ClientAllowed(client) {
					return "", nil, fmt.Errorf("%w from %s", ErrClient, client)
				}
				gcm, err := aead(code, s.Salt)
				if err != nil {
					return "", nil, err
				}
				value, err := gcm.Open(nil, s.Nonce, s.Value, additionalData(id, name))
				if err != nil {
					return "", nil, fmt.Errorf("secret %q: %w", name, err)
				}
				delete(db.Secrets, name)
				return name, value, db.Save(dir)
			}
			return "", nil, nil
		}(); err != nil || name != "" {
			return id, name, value, err
		}
	}
	return "", "", nil, ErrUnknown
}

// Remove removes the secret name of the CA in caDir.
func Remove(caDir, name string) error {
	unlock, err := Lock(caDir)
	if err != nil {
		return err
	}
	defer unlock()
	db, err := Load(caDir)
	if err != nil {
		return err
	}
	if s, ok := db.Secrets[name]; !ok || !time.Now().Before(s.Expires) {
		return fmt.Errorf("secret %q not found in %s", name, Store(caDir))
	}
	delete(db.Secrets, name)
	return db.Save(caDir)
}
