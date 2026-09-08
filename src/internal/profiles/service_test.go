package profiles

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/keys"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/servers"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
)

const fixtureUUID = "uuid-test"

func fixtureVLESS() string {
	return "vless://" + fixtureUUID + "@127.0.0.1:443?type=tcp&security=tls#lab"
}

func fixtureVLESSAlt() string {
	return "vless://" + fixtureUUID + "@10.0.0.1:443?type=ws&security=tls#DE-1"
}

func assertNoSecret(t *testing.T, text string) {
	t.Helper()
	if strings.Contains(text, fixtureUUID) {
		t.Fatal("output contained a fixture secret")
	}
}

type fakeChanger struct {
	uri string
}

func (f fakeChanger) ChangeKey(context.Context, keys.ChangeKeyRequest) (keys.ChangeKeyResponse, error) {
	return keys.NewChangeKeyResponse(f.uri), nil
}

func TestImportShareAndLifecycle(t *testing.T) {
	svc := NewService(nil, fakeChanger{uri: fixtureVLESSAlt()})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: fixtureVLESS() + "\n" + fixtureVLESSAlt(), Name: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "lab" || p.ID == "" {
		t.Fatalf("profile=%v", p)
	}
	assertNoSecret(t, p.String())
	assertNoSecret(t, fmt.Sprintf("%#v", ImportRequest{BlackKey: fixtureVLESS(), Name: "lab"}))

	ks, err := svc.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) != 2 {
		t.Fatalf("keys=%d", len(ks))
	}
	srvs, err := svc.Servers(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(srvs) != 2 {
		t.Fatalf("servers=%d", len(srvs))
	}

	c, err := svc.SelectCandidate(p.ID, ks[0].ID, ks[0].ServerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CommitLastKnownGood(p.ID); err != nil {
		t.Fatal(err)
	}
	rot, err := svc.Rotate(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rot.ServerID == c.ServerID {
		t.Fatal("rotate should change server")
	}
	ch, err := svc.ChangeServer(p.ID, srvs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if ch.ServerID != srvs[0].ID {
		t.Fatalf("change server=%v", ch)
	}
	mode, err := svc.SelectServerMode(p.ID, servers.ModeManual, srvs[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if mode.ServerID != srvs[1].ID {
		t.Fatalf("mode=%v", mode)
	}
	next, err := svc.ChangeKey(context.Background(), p.ID, ks[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if next.KeyID == "" {
		t.Fatal("change key")
	}
	back, err := svc.Rollback(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if back.KeyID != c.KeyID {
		t.Fatalf("rollback=%v want %v", back, c)
	}

	co, ok := svc.Catalog().Lookup("DE")
	if !ok || co.ID != "DE" {
		t.Fatalf("country=%v %v", co, ok)
	}
}

func TestImportSubscriptionURL(t *testing.T) {
	body := fixtureVLESS() + "\n" + fixtureVLESS()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	svc := NewService(srv.Client(), nil)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL + "/sub?token=" + fixtureUUID, Name: "url"})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := svc.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) != 1 {
		t.Fatalf("dedup keys=%d", len(ks))
	}
	if err := svc.Refresh(context.Background(), p.ID); err != nil {
		t.Fatal(err)
	}
}

func TestImportEmptyAndMalformed(t *testing.T) {
	svc := NewService(nil, nil)
	if _, err := svc.Import(context.Background(), ImportRequest{}); err != ErrEmptyImport {
		t.Fatalf("empty: %v", err)
	}
	_, err := svc.Import(context.Background(), ImportRequest{BlackKey: "nope"})
	if err == nil {
		t.Fatal("malformed")
	}
	assertNoSecret(t, err.Error())
}

func TestChangeKeyWithoutProvider(t *testing.T) {
	svc := NewService(nil, nil)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: fixtureVLESS()})
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := svc.Keys(p.ID)
	_, err = svc.ChangeKey(context.Background(), p.ID, ks[0].ID)
	if err != keys.ErrProviderNotConfigured {
		t.Fatalf("got %v", err)
	}
}

func TestRefreshShareHasNoURL(t *testing.T) {
	svc := NewService(nil, nil)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: fixtureVLESS()})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Refresh(context.Background(), p.ID); err != ErrNoRefreshURL {
		t.Fatalf("got %v", err)
	}
}

func TestImportJSONAndBase64(t *testing.T) {
	list, err := json.Marshal([]string{fixtureVLESS()})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(nil, nil)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: string(list)})
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString([]byte(fixtureVLESS()))
	p2, err := svc.Import(context.Background(), ImportRequest{BlackKey: enc})
	if err != nil {
		t.Fatal(err)
	}
	if p.ID == p2.ID {
		t.Fatal("profiles must be distinct")
	}
}

func TestRedactionLogs(t *testing.T) {
	svc := NewService(nil, nil)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: fixtureVLESS(), Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := svc.Keys(p.ID)
	var buf bytes.Buffer
	l := log.New(&buf, "", 0)
	l.Printf("%s %s %s", p, ks[0], ImportRequest{BlackKey: fixtureVLESS()})
	assertNoSecret(t, buf.String())
	b, err := json.Marshal(ks[0])
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, string(b))
}

func TestStableIDsAcrossImport(t *testing.T) {
	svc := NewService(nil, nil)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: fixtureVLESS()})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := subscription.Parse([]byte(fixtureVLESS()))
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := svc.Keys(p.ID)
	if ks[0].ID != parsed.Entries[0].StableID {
		t.Fatal("key ID must equal parser stable ID")
	}
}
