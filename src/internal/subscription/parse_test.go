package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"testing"
)

const (
	fixtureUUID   = "uuid-test"
	fixturePass   = "password-test"
	fixtureSSPass = "ss-pass-test"
)

func fixtureVLESS() string {
	return "vless://" + fixtureUUID + "@127.0.0.1:443?type=tcp&security=tls#lab"
}

func fixtureVLESSNL() string {
	return "vless://" + fixtureUUID + "@127.0.0.1:443?type=ws&security=tls#NL-1"
}

func fixtureTrojan() string {
	return "trojan://" + fixturePass + "@127.0.0.1:443?security=tls&sni=example.test#lab"
}

func fixtureSS() string {
	user := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:" + fixtureSSPass))
	return "ss://" + user + "@127.0.0.1:8388#lab"
}

func fixtureVMess() string {
	js := `{"v":"2","ps":"lab","add":"127.0.0.1","port":"443","id":"` + fixtureUUID + `","aid":"0","net":"ws","tls":"tls"}`
	return "vmess://" + base64.StdEncoding.EncodeToString([]byte(js))
}

func secrets() []string {
	return []string{fixtureUUID, fixturePass, fixtureSSPass}
}

func assertNoSecret(t *testing.T, text string) {
	t.Helper()
	if containsSecret(text, secrets()...) {
		t.Fatal("output contained a fixture secret")
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := Parse(nil)
	if err != ErrEmpty {
		t.Fatalf("nil: %v", err)
	}
	_, err = Parse([]byte("   \n# comment\n"))
	if err != ErrEmpty {
		t.Fatalf("comments: %v", err)
	}
}

func TestParseMalformed(t *testing.T) {
	cases := []string{
		"not-a-subscription",
		"vless://",
		"vless://" + fixtureUUID,
		`{"foo":1}`,
		`{"magic":"nope"}`,
		"[1,2,3]",
	}
	for _, c := range cases {
		_, err := Parse([]byte(c))
		if err == nil {
			t.Fatal("expected error for malformed input")
		}
		assertNoSecret(t, err.Error())
	}
}

func TestParseDuplicateEntries(t *testing.T) {
	body := fixtureVLESS() + "\n" + fixtureVLESS() + "\n" + "vless://" + fixtureUUID + "@127.0.0.1:443?type=tcp&security=tls#lab"
	out, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 {
		t.Fatalf("entries=%d", len(out.Entries))
	}
	if out.DuplicateCount != 2 {
		t.Fatalf("dupes=%d", out.DuplicateCount)
	}
}

func TestParseStableIDsNormalized(t *testing.T) {
	a, err := Parse([]byte(fixtureVLESS()))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte("vless://" + fixtureUUID + "@127.0.0.1:443?type=TCP&security=TLS#lab"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse([]byte("vless://other-fake-id@127.0.0.1:443?type=tcp&security=tls#lab"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Entries[0].StableID == "" || a.Entries[0].StableID != b.Entries[0].StableID {
		t.Fatal("normalized IDs must match")
	}
	if a.Entries[0].StableID != c.Entries[0].StableID {
		t.Fatal("secret must not affect stable ID")
	}
	d, err := Parse([]byte("vless://" + fixtureUUID + "@10.0.0.1:443?type=tcp&security=tls#lab"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Entries[0].StableID == d.Entries[0].StableID {
		t.Fatal("host must affect stable ID")
	}
}

func TestParseAllSchemes(t *testing.T) {
	body := strings.Join([]string{fixtureVLESS(), fixtureVMess(), fixtureTrojan(), fixtureSS()}, "\n")
	out, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 4 {
		t.Fatalf("entries=%d", len(out.Entries))
	}
	got := map[string]bool{}
	for _, e := range out.Entries {
		got[e.Protocol] = true
		if e.Host != "127.0.0.1" {
			t.Fatal("host")
		}
	}
	for _, p := range []string{"vless", "vmess", "trojan", "shadowsocks"} {
		if !got[p] {
			t.Fatalf("missing %s", p)
		}
	}
}

func TestParseBase64WrappedList(t *testing.T) {
	plain := fixtureVLESS() + "\n" + fixtureTrojan()
	enc := base64.StdEncoding.EncodeToString([]byte(plain))
	out, err := Parse([]byte(enc))
	if err != nil {
		t.Fatal(err)
	}
	if out.Encoding != encBase64 {
		t.Fatalf("encoding=%s", out.Encoding)
	}
	if len(out.Entries) != 2 {
		t.Fatalf("entries=%d", len(out.Entries))
	}
}

func TestParseJSONURIArray(t *testing.T) {
	raw, err := json.Marshal([]string{fixtureVLESS(), fixtureTrojan()})
	if err != nil {
		t.Fatal(err)
	}
	out, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Format != "json-uri-array" {
		t.Fatalf("format=%s", out.Format)
	}
	if len(out.Entries) != 2 {
		t.Fatalf("entries=%d", len(out.Entries))
	}
}

func TestParseJSONOutbound(t *testing.T) {
	raw := []byte(`{
		"outbounds": [
			{
				"protocol": "vless",
				"tag": "NL-edge",
				"settings": {"vnext": [{"address": "127.0.0.1", "port": 443, "users": [{"id": "uuid-test", "encryption": "none"}]}]},
				"streamSettings": {"network": "tcp", "security": "tls"}
			}
		]
	}`)
	out, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Entries[0].Protocol != "vless" || out.Entries[0].CountryHint != "NL" {
		t.Fatalf("entry=%v", out.Entries[0])
	}
	assertNoSecret(t, fmt.Sprintf("%v %#v", out, out.Entries[0]))
}

func TestParseUnknownJSON(t *testing.T) {
	_, err := Parse([]byte(`{"blackKey":"uuid-test","cabinet":true}`))
	if err != ErrUnknownJSON {
		t.Fatalf("got %v", err)
	}
	assertNoSecret(t, err.Error())
}

func TestSecretRedaction(t *testing.T) {
	out, err := Parse([]byte(strings.Join([]string{fixtureVLESS(), fixtureTrojan(), fixtureSS(), fixtureVMess()}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	l := log.New(&buf, "", 0)
	for _, e := range out.Entries {
		l.Printf("parsed %s %#v", e, e)
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		assertNoSecret(t, string(b))
		assertNoSecret(t, e.String())
		assertNoSecret(t, e.GoString())
		assertNoSecret(t, fmt.Sprintf("%v %+v %q", e, e, e))
	}
	assertNoSecret(t, buf.String())
	assertNoSecret(t, out.String())
}

func TestParserSupportTable(t *testing.T) {
	table := ParserSupport()
	if len(table) == 0 {
		t.Fatal("empty")
	}
	found := map[string]Level{}
	for _, row := range table {
		found[row.Scheme] = row.Parser
		if row.Runtime != NotObserved {
			t.Fatalf("runtime must be NOT OBSERVED for %s", row.Scheme)
		}
	}
	if found["vless://"] != Supported || found["vmess://"] != Supported || found["trojan://"] != Supported || found["ss://"] != Supported {
		t.Fatal("standard URI parsers")
	}
	if found["hysteria2://"] != NotImplemented {
		t.Fatal("hysteria2")
	}
	if found["provider-json"] != NotObserved {
		t.Fatal("provider json")
	}
}

func TestParseVLESSKeepsConnectionParams(t *testing.T) {
	raw := "vless://" + fixtureUUID + "@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.example.com&host=edge.example&path=/xhttp&serviceName=gun&mode=auto&alpn=h2,http/1.1&fp=chrome&pbk=test-pbk&sid=aabbccdd&spx=/&headerType=none#NL-1"
	out, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 {
		t.Fatalf("entries=%d", len(out.Entries))
	}
	e := out.Entries[0]
	p := e.Params
	if p.Flow != "xtls-rprx-vision" || p.SNI != "www.example.com" || p.Host != "edge.example" || p.Path != "/xhttp" {
		t.Fatalf("params=%#v", p)
	}
	if p.ServiceName != "gun" || p.Mode != "auto" || p.Fingerprint != "chrome" || p.RealityPublicKey != "test-pbk" || p.ShortID != "aabbccdd" || p.SpiderX != "/" || p.HeaderType != "none" {
		t.Fatalf("params=%#v", p)
	}
	if len(p.ALPN) != 2 || p.ALPN[0] != "h2" || p.ALPN[1] != "http/1.1" {
		t.Fatalf("alpn=%v", p.ALPN)
	}
	assertNoSecret(t, e.String())
	assertNoSecret(t, fmt.Sprintf("%+v", e))
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, string(b))
}

func TestHysteriaSkippedNotImplemented(t *testing.T) {
	body := fixtureVLESS() + "\nhysteria2://password-test@127.0.0.1:443\n"
	out, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || out.Skipped != 1 {
		t.Fatalf("entries=%d skipped=%d", len(out.Entries), out.Skipped)
	}
}
