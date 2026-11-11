package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestThemeConfig(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	css, err := themeConfig{Light: map[string]string{"head": "#7c2d12", "action": "oklch(0.55 0.2 40)"},
		Dark: map[string]string{"head": " darkred "}}.css("simple-ca.json")
	if err != nil || string(css) != ":root { --action: oklch(0.55 0.2 40); --head: #7c2d12; }\n"+
		`:root[data-theme="dark"] { --head: darkred; }`+"\n" {
		t.Errorf("css: %q, %v, want the variables of both themes", css, err)
	}
	if css, err := (themeConfig{}).css("simple-ca.json"); err != nil || css != "" {
		t.Errorf("css without colours: %q, %v, want none", css, err)
	}
	for _, theme := range []themeConfig{
		{Light: map[string]string{"header": "#123456"}},
		{Dark: map[string]string{"head": "red; } body { display: none"}},
		{Dark: map[string]string{"head": "url(x)"}},
	} {
		if _, err := theme.css("simple-ca.json"); err == nil {
			t.Errorf("css of %+v succeeded, want an error", theme)
		}
	}

	// theme.json of a CA directory holds the colours of that CA alone, none without it.
	dir := t.TempDir()
	if theme, err := loadTheme(dir); err != nil || theme.Light != nil || theme.Dark != nil {
		t.Errorf("loadTheme without theme.json: %+v, %v, want none", theme, err)
	}
	if css := pageTheme(dir); css != "" {
		t.Errorf("pageTheme without theme.json: %q, want none", css)
	}
	for _, c := range []struct{ file, want string }{
		{`{"light": {"head": "#7f1d1d"}}`, ":root { --head: #7f1d1d; }\n"},
		{`{"theme": {"light": {"head": "#7f1d1d"}}}`, ""},
		{`{"light": {"head": "not a colour"}}`, ""},
	} {
		if err := os.WriteFile(filepath.Join(dir, themeFile), []byte(c.file), 0o644); err != nil {
			t.Fatal(err)
		}
		if theme, err := loadTheme(dir); (err == nil) != (c.want != "") || (err == nil && theme.Light["head"] != "#7f1d1d") {
			t.Errorf("loadTheme of %s: %+v, %v, want the colours or an error", c.file, theme, err)
		}
		if css := pageTheme(dir); string(css) != c.want {
			t.Errorf("pageTheme of %s: %q, want %q", c.file, css, c.want)
		}
	}
}
