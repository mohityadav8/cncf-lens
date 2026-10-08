package config

import (
	"strings"
	"testing"
)

const kindKubeconfig = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: FAKECA
    server: https://127.0.0.1:33149
  name: kind-one
- cluster:
    certificate-authority-data: FAKECA
    server: https://127.0.0.1:38437
  name: kind-two
contexts:
- context:
    cluster: kind-two
    user: kind-two
  name: kind-two
current-context: kind-two
kind: Config
preferences: {}
users:
- name: kind-two
  user:
    client-certificate-data: FAKECERT
    client-key-data: FAKEKEY
`

func TestParseYAMLKubeconfigIndentlessSequences(t *testing.T) {
	root, err := ParseYAML(strings.NewReader(kindKubeconfig))
	if err != nil {
		t.Fatalf("a standard kubeconfig must parse: %v", err)
	}

	clusters, ok := root.Child("clusters")
	if !ok || len(clusters.List) != 2 {
		t.Fatalf("want 2 clusters, got %+v", clusters)
	}
	second := clusters.List[1]
	if got := second.String("name", ""); got != "kind-two" {
		t.Errorf("cluster name = %q, want kind-two", got)
	}
	if got := second.String("cluster.server", ""); got != "https://127.0.0.1:38437" {
		t.Errorf("cluster server = %q", got)
	}

	if got := root.String("current-context", ""); got != "kind-two" {
		t.Errorf("current-context = %q", got)
	}

	users, ok := root.Child("users")
	if !ok || len(users.List) != 1 {
		t.Fatalf("want 1 user, got %+v", users)
	}
	if got := users.List[0].String("user.client-key-data", ""); got != "FAKEKEY" {
		t.Errorf("user key data = %q", got)
	}
}
