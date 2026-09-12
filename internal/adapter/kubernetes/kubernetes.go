// Package kubernetes implements the Adapter interface against the Kubernetes
// API server, reading events and pod state.
//
// It deliberately speaks the REST API directly rather than importing client-go.
// client-go pulls in roughly 200 transitive modules; for the two endpoints lens
// actually needs (events and pods) that is a poor trade against keeping the
// binary dependency-free and auditable.
package kubernetes

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mohityadav8/cncf-lens/internal/adapter"
	"github.com/mohityadav8/cncf-lens/internal/config"
	"github.com/mohityadav8/cncf-lens/internal/signal"
)

// Adapter reads cluster state and events.
type Adapter struct {
	http *adapter.HTTPClient
	name string
	// cluster labels every emitted signal so multi-cluster correlation works.
	cluster string
}

// New builds an adapter from resolved connection details.
func New(name, apiServer, token string, insecure bool, timeout time.Duration, cluster string) *Adapter {
	if name == "" {
		name = "kubernetes"
	}
	return &Adapter{
		name:    name,
		cluster: cluster,
		http:    adapter.NewHTTPClient(apiServer, token, insecure, timeout),
	}
}

// FromContext builds an adapter by resolving connection details from config,
// falling back to in-cluster service account credentials and then to the
// standard kubeconfig, in that order. This mirrors what kubectl does, so lens
// works wherever kubectl works.
func FromContext(ctx *config.Context, bc config.BackendConfig, timeout time.Duration) (*Adapter, error) {
	// 1. Explicit URL in config wins.
	if bc.URL != "" {
		return New("kubernetes", bc.URL, bc.Token, bc.Insecure, timeout, ctx.Name), nil
	}

	// 2. In-cluster: the API server is reachable via well-known env vars and
	// the projected service account token.
	if host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"); host != "" && port != "" {
		const tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
		if data, err := os.ReadFile(tokenPath); err == nil {
			return New("kubernetes",
				fmt.Sprintf("https://%s:%s", host, port),
				strings.TrimSpace(string(data)),
				bc.Insecure, timeout, ctx.Name), nil
		}
	}

	// 3. kubeconfig on disk.
	path := ctx.Kubeconfig
	if path == "" {
		path = os.Getenv("KUBECONFIG")
	}
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("cannot locate kubeconfig: %w", err)
		}
		path = filepath.Join(home, ".kube", "config")
	}

	server, token, insecure, err := parseKubeconfig(path, ctx.Kubecontext)
	if err != nil {
		return nil, err
	}
	return New("kubernetes", server, token, insecure || bc.Insecure, timeout, ctx.Name), nil
}

func (a *Adapter) Name() string { return a.name }

func (a *Adapter) Capabilities() []signal.Type {
	return []signal.Type{signal.TypeEvent, signal.TypeDeploy}
}

func (a *Adapter) HealthCheck(ctx context.Context) error {
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := a.http.GetJSON(ctx, "/version", nil, &v); err != nil {
		return fmt.Errorf("kubernetes API unreachable: %w", err)
	}
	if v.GitVersion == "" {
		return fmt.Errorf("kubernetes API returned no version — is the URL an API server?")
	}
	return nil
}

// Fetch retrieves events in the window, plus deployment/rollout signals derived
// from those events.
func (a *Adapter) Fetch(ctx context.Context, q adapter.Query) (signal.Set, error) {
	if !q.WantsType(signal.TypeEvent) && !q.WantsType(signal.TypeDeploy) {
		return nil, nil
	}

	path := "/api/v1/events"
	if q.Namespace != "" {
		path = "/api/v1/namespaces/" + url.PathEscape(q.Namespace) + "/events"
	}

	params := url.Values{}
	if q.Limit > 0 {
		params.Set("limit", fmt.Sprint(q.Limit))
	} else {
		params.Set("limit", "1000")
	}

	var resp eventList
	if err := a.http.GetJSON(ctx, path, params, &resp); err != nil {
		return nil, err
	}

	var out signal.Set
	for _, ev := range resp.Items {
		ts := eventTime(ev)
		if ts.IsZero() {
			continue
		}
		// The events endpoint has no server-side time filter, so we window
		// client-side. Events live ~1h by default, which keeps this cheap.
		if ts.Before(q.From) || ts.After(q.To) {
			continue
		}
		if q.Pod != "" && ev.InvolvedObject.Name != q.Pod {
			continue
		}

		s := a.eventToSignal(ev, ts)
		if !q.WantsType(s.Type) {
			continue
		}
		out = append(out, s)
	}

	out.SortByTime()
	return out, nil
}

// eventToSignal classifies a Kubernetes event.
//
// The classification matters more than it looks: marking rollouts and image
// changes as TypeDeploy is what lets the causal engine apply its heaviest
// weight to them, because deployments really are the most common root cause.
func (a *Adapter) eventToSignal(ev event, ts time.Time) signal.Signal {
	sev := signal.ParseSeverity(ev.Type)

	// Certain reasons are always more serious than their event type suggests.
	switch ev.Reason {
	case "Failed", "FailedMount", "FailedScheduling", "FailedCreatePodSandBox", "BackOff":
		sev = signal.SevError
	case "OOMKilling", "OOMKilled", "NodeNotReady", "Evicted":
		sev = signal.SevCritical
	case "Unhealthy", "ProbeWarning":
		sev = signal.SevWarning
	}

	typ := signal.TypeEvent
	switch ev.Reason {
	case "ScalingReplicaSet", "SuccessfulCreate", "SuccessfulDelete":
		typ = signal.TypeDeploy
	}

	s := signal.Signal{
		Timestamp: ts.UTC(),
		Type:      typ,
		Source:    a.name,
		Severity:  sev,
		Title:     fmt.Sprintf("%s: %s", ev.Reason, ev.InvolvedObject.Name),
		Detail:    strings.TrimSpace(ev.Message),
	}

	s.SetLabel(signal.LabelCluster, a.cluster)
	s.SetLabel(signal.LabelNamespace, firstNonEmpty(ev.InvolvedObject.Namespace, ev.Namespace))
	s.SetLabel(signal.LabelNode, ev.Source.Host)

	switch ev.InvolvedObject.Kind {
	case "Pod":
		s.SetLabel(signal.LabelPod, ev.InvolvedObject.Name)
		s.SetLabel(signal.LabelWorkload, workloadFromPod(ev.InvolvedObject.Name))
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job":
		s.SetLabel(signal.LabelWorkload, ev.InvolvedObject.Name)
	case "Service":
		s.SetLabel(signal.LabelService, ev.InvolvedObject.Name)
	}

	return s
}

// eventTime picks the most accurate timestamp available. Kubernetes populates
// these inconsistently across versions and event sources, so we try all four.
func eventTime(ev event) time.Time {
	for _, t := range []string{ev.EventTime, ev.LastTimestamp, ev.FirstTimestamp, ev.Metadata.CreationTimestamp} {
		if t == "" {
			continue
		}
		if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
			return parsed
		}
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

// workloadFromPod strips the ReplicaSet and pod hash suffixes to recover the
// Deployment name. `payments-7d4b9c5f8-x2k9p` becomes `payments`.
//
// This is a heuristic — the authoritative path is to follow ownerReferences —
// but it is right for the standard Deployment→ReplicaSet→Pod chain, and it
// costs zero extra API calls during an incident.
func workloadFromPod(pod string) string {
	parts := strings.Split(pod, "-")
	if len(parts) < 3 {
		return pod
	}

	// Deployment-managed Pods follow:
	//
	//   <deployment>-<replicaset-hash>-<pod-suffix>
	//
	// The five-character Pod suffix may be entirely alphabetic, so do not
	// require a digit. The preceding ReplicaSet hash must still have the
	// expected 8-10 character lowercase alphanumeric shape.
	end := len(parts)

	if len(parts[end-1]) != 5 || !isAlphanumericLower(parts[end-1]) {
		return pod
	}
	end--

	if end < 1 || len(parts[end-1]) < 8 || len(parts[end-1]) > 10 || !isAlphanumericLower(parts[end-1]) {
		return pod
	}
	end--

	return strings.Join(parts[:end], "-")
}

func isAlphanumericLower(s string) bool {
	if s == "" {
		return false
	}

	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		default:
			return false
		}
	}

	return true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- kubeconfig parsing -----------------------------------------------------

// parseKubeconfig extracts the server URL and credentials for a named context.
// It reuses the project's YAML subset parser rather than importing clientcmd.
func parseKubeconfig(path, wantContext string) (server, token string, insecure bool, err error) {
	f, openErr := os.Open(path)
	if openErr != nil {
		return "", "", false, fmt.Errorf("opening kubeconfig %s: %w", path, openErr)
	}
	defer f.Close()

	root, parseErr := config.ParseYAML(f)
	if parseErr != nil {
		return "", "", false, fmt.Errorf("parsing kubeconfig %s: %w", path, parseErr)
	}

	if wantContext == "" {
		wantContext = root.String("current-context", "")
	}
	if wantContext == "" {
		return "", "", false, fmt.Errorf("kubeconfig %s has no current-context and none was specified", path)
	}

	clusterName, userName := "", ""
	if contexts, ok := root.Child("contexts"); ok {
		for _, item := range contexts.List {
			if item.String("name", "") != wantContext {
				continue
			}
			clusterName = item.String("context.cluster", "")
			userName = item.String("context.user", "")
			break
		}
	}
	if clusterName == "" {
		return "", "", false, fmt.Errorf("context %q not found in %s", wantContext, path)
	}

	if clusters, ok := root.Child("clusters"); ok {
		for _, item := range clusters.List {
			if item.String("name", "") != clusterName {
				continue
			}
			server = item.String("cluster.server", "")
			insecure = item.Bool("cluster.insecure-skip-tls-verify", false)
			break
		}
	}
	if server == "" {
		return "", "", false, fmt.Errorf("cluster %q in %s has no server URL", clusterName, path)
	}

	if users, ok := root.Child("users"); ok {
		for _, item := range users.List {
			if item.String("name", "") != userName {
				continue
			}
			token = item.String("user.token", "")
			if token == "" {
				if tf := item.String("user.tokenFile", ""); tf != "" {
					if data, readErr := os.ReadFile(tf); readErr == nil {
						token = strings.TrimSpace(string(data))
					}
				}
			}
			// Some kubeconfigs base64-encode the token inline.
			if token != "" && !strings.Contains(token, ".") {
				if decoded, decErr := base64.StdEncoding.DecodeString(token); decErr == nil {
					token = strings.TrimSpace(string(decoded))
				}
			}
			break
		}
	}

	if token == "" {
		// Client-certificate and exec-plugin auth are common and we cannot
		// support them without a TLS-config-aware client. Say so plainly
		// instead of failing with an opaque 401 later.
		return server, "", insecure, fmt.Errorf(
			"kubeconfig user %q uses client certificates or an exec credential plugin, "+
				"which lens cannot read directly.\n"+
				"Run `kubectl proxy` and point the kubernetes backend at http://127.0.0.1:8001, "+
				"or set a service account token via token_env", userName)
	}

	return server, token, insecure, nil
}

// --- Kubernetes API wire types ---------------------------------------------

type eventList struct {
	Items []event `json:"items"`
}

type event struct {
	Metadata struct {
		Name              string `json:"name"`
		Namespace         string `json:"namespace"`
		CreationTimestamp string `json:"creationTimestamp"`
	} `json:"metadata"`
	Namespace      string `json:"namespace"`
	Reason         string `json:"reason"`
	Message        string `json:"message"`
	Type           string `json:"type"`
	Count          int    `json:"count"`
	EventTime      string `json:"eventTime"`
	FirstTimestamp string `json:"firstTimestamp"`
	LastTimestamp  string `json:"lastTimestamp"`
	InvolvedObject struct {
		Kind      string `json:"kind"`
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		UID       string `json:"uid"`
	} `json:"involvedObject"`
	Source struct {
		Component string `json:"component"`
		Host      string `json:"host"`
	} `json:"source"`
}
