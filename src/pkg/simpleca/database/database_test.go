package database

import (
	"context"
	"os"
	"os/user"
	"testing"

	"github.com/skoszewski/simple-ca/src/pkg/simpleca"
)

func TestConnString(t *testing.T) {
	env := map[string]string{
		"SIMPLE_CA_DB_HOST":     "db.example.com",
		"SIMPLE_CA_DB_DATABASE": "simple_ca",
		"SIMPLE_CA_DB_PASSWORD": `it's a \ secret`,
		"SIMPLE_CA_DB_APPNAME":  "simple ca",
		"PGHOST":                "ignored.example.com",
	}
	got := ConnString(func(name string) string { return env[name] })
	want := `host='db.example.com' dbname='simple_ca' password='it\'s a \\ secret' passfile='' application_name='simple ca'`
	if got != want {
		t.Errorf("ConnString:\n got %s\nwant %s", got, want)
	}
	env["SIMPLE_CA_DB_PASSFILE"] = "/etc/simple-ca/pgpass"
	if got := ConnString(func(name string) string { return env[name] }); got !=
		`host='db.example.com' dbname='simple_ca' password='it\'s a \\ secret' passfile='/etc/simple-ca/pgpass' application_name='simple ca'` {
		t.Errorf("ConnString with a passfile: %s", got)
	}
}

func TestPoolIgnoresPG(t *testing.T) {
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		pool = nil
	})
	for _, s := range settings {
		t.Setenv(EnvPrefix+s[0], "")
	}
	t.Setenv("PGHOST", "intruder.example.com")
	t.Setenv("PGUSER", "intruder")
	t.Setenv("PGSERVICE", "intruder")
	t.Setenv("SIMPLE_CA_DB_HOST", "db.example.com")
	t.Setenv("SIMPLE_CA_DB_PORT", "6543")
	p, err := Pool(context.Background())
	if err != nil {
		t.Fatalf("Pool: %v", err)
	}
	c := p.Config().ConnConfig
	if c.Host != "db.example.com" || c.Port != 6543 || c.User == "intruder" || c.Password != "" {
		t.Errorf("the pool connects to %s:%d as %q, want db.example.com:6543 without PGUSER", c.Host, c.Port, c.User)
	}
	if u, err := user.Current(); err == nil && c.User != u.Username {
		t.Errorf("the user is %q, want the OS user %q", c.User, u.Username)
	}
	for _, name := range []string{"PGHOST", "PGUSER", "PGSERVICE"} {
		if _, set := os.LookupEnv(name); set {
			t.Errorf("%s is still set", name)
		}
	}
}

func TestTable(t *testing.T) {
	if got := Table(simpleca.DatabaseConfig{}, "tokens"); got != `"public"."tokens"` {
		t.Errorf("Table without a schema: %s", got)
	}
	if got := Table(simpleca.DatabaseConfig{Schema: "pki_lab"}, "tokens"); got != `"pki_lab"."tokens"` {
		t.Errorf("Table of pki_lab: %s", got)
	}
	if LockKey("a", "b") == LockKey("ab", "") || LockKey("a", "b") != LockKey("a", "b") {
		t.Error("LockKey does not keep the parts apart")
	}
}
