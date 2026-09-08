package xray

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fixtureUUID   = "11111111-1111-4111-8111-111111111111"
	fixturePubKey = "_Cfwmkcph1k8jGWjfjwGSO33zw40qW0fkNxXOrITeik"
)

func fixtureProfile(transport, security string) Profile {
	return Profile{
		ID:        "prof-1",
		Name:      "test",
		Protocol:  "vless",
		Server:    "example.com",
		Port:      443,
		Transport: transport,
		Security:  security,
		Country:   "DE",
	}
}

func fixtureSecrets() ConfigSecrets {
	return ConfigSecrets{UUID: fixtureUUID}
}

func fixtureParams(transport string) OutboundParams {
	p := OutboundParams{
		SNI:         "www.example.com",
		PublicKey:   fixturePubKey,
		ShortID:     "aabbccdd",
		Fingerprint: "chrome",
	}
	switch transport {
	case "ws":
		p.Path = "/vless"
		p.Host = "www.example.com"
	case "grpc":
		p.ServiceName = "gun"
	case "xhttp":
		p.Path = "/xhttp"
		p.Host = "www.example.com"
		p.Mode = "auto"
	}
	return p
}

func TestGoldenConfigs(t *testing.T) {
	cases := []struct {
		file      string
		transport string
		security  string
	}{
		{"golden-vless-reality-tcp.json", "tcp", "reality"},
		{"golden-vless-tls-tcp.json", "tcp", "tls"},
		{"golden-vless-tls-ws.json", "ws", "tls"},
		{"golden-vless-tls-grpc.json", "grpc", "tls"},
		{"golden-vless-tls-xhttp.json", "xhttp", "tls"},
	}
	update := os.Getenv("UPDATE_XRAY_GOLDEN") == "1"
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			got, err := Generate(fixtureProfile(tc.transport, tc.security), fixtureSecrets(), fixtureParams(tc.transport), Options{})
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("testdata", tc.file)
			if update {
				if err := os.WriteFile(path, append(append([]byte{}, got...), '\n'), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, bytes.TrimSuffix(want, []byte("\n"))) && !bytes.Equal(got, want) {
				t.Fatalf("golden mismatch\ngot:  %s\nwant: %s", got, bytes.TrimSpace(want))
			}
			var parsed any
			if err := json.Unmarshal(got, &parsed); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGenerateDeterministicAndCompact(t *testing.T) {
	a, err := Generate(fixtureProfile("tcp", "reality"), fixtureSecrets(), fixtureParams("tcp"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(fixtureProfile("tcp", "reality"), fixtureSecrets(), fixtureParams("tcp"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("Generate is not deterministic")
	}
	if bytes.Contains(a, []byte("\n")) || bytes.Contains(a, []byte("  ")) {
		t.Fatalf("compact JSON must not be pretty: %s", a)
	}
	pretty, err := Generate(fixtureProfile("tcp", "reality"), fixtureSecrets(), fixtureParams("tcp"), Options{Pretty: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(pretty, []byte("\n")) {
		t.Fatal("pretty debug JSON should contain newlines")
	}
}

func TestMalformedProfile(t *testing.T) {
	okSecrets := fixtureSecrets()
	okParams := fixtureParams("tcp")
	cases := []struct {
		name    string
		profile Profile
		secrets ConfigSecrets
		params  OutboundParams
		opts    Options
		sub     string
	}{
		{
			name:    "missing id",
			profile: Profile{Protocol: "vless", Server: "example.com", Port: 443, Security: "tls"},
			secrets: okSecrets, params: okParams,
			sub: "id is required",
		},
		{
			name:    "missing protocol",
			profile: Profile{ID: "p", Server: "example.com", Port: 443, Security: "tls"},
			secrets: okSecrets, params: okParams,
			sub: "protocol is required",
		},
		{
			name:    "vmess not p0",
			profile: Profile{ID: "p", Protocol: "vmess", Server: "example.com", Port: 443, Security: "tls"},
			secrets: okSecrets, params: okParams,
			sub: "not generated",
		},
		{
			name:    "missing server",
			profile: Profile{ID: "p", Protocol: "vless", Port: 443, Security: "tls"},
			secrets: okSecrets, params: okParams,
			sub: "server is required",
		},
		{
			name:    "bad port",
			profile: Profile{ID: "p", Protocol: "vless", Server: "example.com", Port: 0, Security: "tls"},
			secrets: okSecrets, params: okParams,
			sub: "port must be",
		},
		{
			name:    "security none",
			profile: Profile{ID: "p", Protocol: "vless", Server: "example.com", Port: 443, Security: "none"},
			secrets: okSecrets, params: okParams,
			sub: "security",
		},
		{
			name:    "transport mkcp",
			profile: Profile{ID: "p", Protocol: "vless", Server: "example.com", Port: 443, Security: "tls", Transport: "mkcp"},
			secrets: okSecrets, params: okParams,
			sub: "transport",
		},
		{
			name:    "missing uuid",
			profile: fixtureProfile("tcp", "tls"),
			secrets: ConfigSecrets{}, params: okParams,
			sub: "uuid is required",
		},
		{
			name:    "malformed uuid",
			profile: fixtureProfile("tcp", "tls"),
			secrets: ConfigSecrets{UUID: "not-a-uuid"}, params: okParams,
			sub: "uuid is malformed",
		},
		{
			name:    "reality without publicKey",
			profile: fixtureProfile("tcp", "reality"),
			secrets: okSecrets, params: OutboundParams{SNI: "www.example.com"},
			sub: "publicKey",
		},
		{
			name:    "lan listen rejected",
			profile: fixtureProfile("tcp", "tls"),
			secrets: okSecrets, params: okParams,
			opts: Options{ListenHost: "0.0.0.0", ListenPort: 11080},
			sub:  "127.0.0.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Generate(tc.profile, tc.secrets, tc.params, tc.opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.sub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.sub)
			}
			if strings.Contains(err.Error(), fixtureUUID) {
				t.Fatalf("error leaked uuid: %v", err)
			}
		})
	}
}

func TestEphemeralListenPort(t *testing.T) {
	raw, err := Generate(fixtureProfile("tcp", "tls"), fixtureSecrets(), fixtureParams("tcp"), Options{EphemeralPort: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"port":0`)) {
		t.Fatalf("expected port 0: %s", raw)
	}
	if !bytes.Contains(raw, []byte(`"listen":"127.0.0.1"`)) {
		t.Fatalf("expected loopback listen: %s", raw)
	}
}
