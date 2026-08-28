package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseYAMLNestedMaps(t *testing.T) {
	root, err := ParseYAML(strings.NewReader(`
defaults:
  output: json
  cache_ttl: 10m
contexts:
  prod:
    backends:
      prometheus:
        url: https://prom.example.com
        enabled: true
`))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	if got := root.String("defaults.output", ""); got != "json" {
		t.Errorf("defaults.output = %q", got)
	}
	if got := root.String("contexts.prod.backends.prometheus.url", ""); got != "https://prom.example.com" {
		t.Errorf("nested url = %q", got)
	}
	if !root.Bool("contexts.prod.backends.prometheus.enabled", false) {
		t.Error("enabled should parse as true")
	}
}

// A URL contains a colon; splitting on the wrong one silently truncates the
// endpoint and produces a baffling connection error much later.
func TestParseYAMLDoesNotSplitURLPorts(t *testing.T) {
	root, err := ParseYAML(strings.NewReader("url: https://prom.internal:9090/api\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := root.String("url", ""); got != "https://prom.internal:9090/api" {
		t.Errorf("URL was mangled: %q", got)
	}
}

func TestParseYAMLCommentHandling(t *testing.T) {
	root, err := ParseYAML(strings.NewReader(`
# a full-line comment
url: http://x.example.com   # trailing comment
token: "secret#notacomment"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := root.String("url", ""); got != "http://x.example.com" {
		t.Errorf("trailing comment not stripped: %q", got)
	}
	if got := root.String("token", ""); got != "secret#notacomment" {
		t.Errorf("hash inside quotes was treated as a comment: %q", got)
	}
}

func TestParseYAMLLists(t *testing.T) {
	root, err := ParseYAML(strings.NewReader("skip:\n  - loki\n  - jaeger\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := root.StringList("skip")
	if len(got) != 2 || got[0] != "loki" || got[1] != "jaeger" {
		t.Errorf("StringList = %v", got)
	}
}

func TestParseYAMLRejectsTabs(t *testing.T) {
	_, err := ParseYAML(strings.NewReader("key:\n\tnested: value\n"))
	if err == nil {
		t.Fatal("tabs should be rejected, not silently mis-parsed")
	}
	if !strings.Contains(err.Error(), "tab") {
		t.Errorf("error should mention tabs, got: %v", err)
	}
}

func TestParseYAMLRejectsDuplicateKeys(t *testing.T) {
	_, err := ParseYAML(strings.NewReader("url: a\nurl: b\n"))
	if err == nil {
		t.Fatal("duplicate keys should be an error — a silent overwrite hides typos")
	}
}

func TestLoadResolvesTokenFromEnv(t *testing.T) {
	t.Setenv("TEST_PROM_TOKEN", "s3cr3t-value")

	path := writeTemp(t, `
defaults:
  context: prod
contexts:
  prod:
    backends:
      prometheus:
        url: https://prom.example.com
        token_env: TEST_PROM_TOKEN
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ctx, err := cfg.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	if got := ctx.Backends["prometheus"].Token; got != "s3cr3t-value" {
		t.Errorf("token from env = %q", got)
	}
}

// Naming an empty variable is almost always a deployment mistake; failing loudly
// beats a 401 twenty seconds into an incident.
func TestLoadFailsOnEmptyTokenEnv(t *testing.T) {
	path := writeTemp(t, `
contexts:
  prod:
    backends:
      prometheus:
        url: https://prom.example.com
        token_env: DEFINITELY_NOT_SET_ANYWHERE
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error when token_env names an unset variable")
	}
}

func TestLoadMissingFileFallsBackToZeroConfig(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("a missing config should not be an error: %v", err)
	}
	if len(cfg.Contexts) == 0 {
		t.Error("zero-config should still provide a usable default context")
	}
}

func TestValidateRejectsUnknownDefaultContext(t *testing.T) {
	path := writeTemp(t, `
defaults:
  context: nonexistent
contexts:
  prod:
    backends:
      prometheus:
        url: https://prom.example.com
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation to reject an unknown default context")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error should name the bad context: %v", err)
	}
}

func TestValidateRejectsBadOutputFormat(t *testing.T) {
	path := writeTemp(t, "defaults:\n  output: yaml\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected an unsupported output format to be rejected")
	}
}

func TestDefaultsApplied(t *testing.T) {
	path := writeTemp(t, "defaults:\n  cache_ttl: 42m\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Defaults.CacheTTL != 42*time.Minute {
		t.Errorf("cache_ttl = %s", cfg.Defaults.CacheTTL)
	}
	// Unspecified values must keep their built-in defaults.
	if cfg.Defaults.AdapterTimeout != DefaultDefaults().AdapterTimeout {
		t.Errorf("unspecified adapter_timeout was not defaulted: %s", cfg.Defaults.AdapterTimeout)
	}
}

func TestExtraKeysPreservedForPlugins(t *testing.T) {
	path := writeTemp(t, `
contexts:
  prod:
    backends:
      my-custom-thing:
        url: https://custom.example.com
        region: eu-west-1
        tenant: acme
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	extra := cfg.Contexts["prod"].Backends["my-custom-thing"].Extra
	if extra["region"] != "eu-west-1" || extra["tenant"] != "acme" {
		t.Errorf("plugin settings were dropped: %v", extra)
	}
}
