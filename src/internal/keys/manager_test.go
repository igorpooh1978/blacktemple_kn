package keys

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"testing"
	"time"
)

const fixtureSecret = "uuid-test"

func TestStateSelectRotateRollback(t *testing.T) {
	k1 := New("id-a", "p1", "s1", "srv-a", "vless", "a", fixtureSecret)
	k2 := New("id-b", "p1", "s1", "srv-b", "vless", "b", fixtureSecret)
	st := NewState("p1", []Key{k1, k2})
	c, err := st.SelectCandidate("id-a", "srv-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CommitGood(time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	rot, err := st.RotateKey()
	if err != nil {
		t.Fatal(err)
	}
	if rot.KeyID == c.KeyID {
		t.Fatal("rotate should move")
	}
	back, err := st.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	if back.KeyID != "id-a" || back.ServerID != "srv-a" {
		t.Fatalf("rollback=%v", back)
	}
}

func TestReplaceKey(t *testing.T) {
	k1 := New("id-a", "p1", "s1", "srv-a", "vless", "a", fixtureSecret)
	st := NewState("p1", []Key{k1})
	next := New("id-c", "p1", "s1", "srv-c", "vless", "c", "other-fake-id")
	c, err := st.ReplaceKey("id-a", next)
	if err != nil {
		t.Fatal(err)
	}
	if c.KeyID != "id-c" {
		t.Fatalf("candidate=%v", c)
	}
	if _, ok := st.Key("id-a"); ok {
		t.Fatal("old key still present")
	}
}

func TestRollbackWithoutLKG(t *testing.T) {
	st := NewState("p1", nil)
	_, err := st.Rollback()
	if err != ErrNoLastKnownGood {
		t.Fatalf("got %v", err)
	}
}

func TestKeyRedaction(t *testing.T) {
	k := New("id-a", "p1", "s1", "srv-a", "vless", "lab", fixtureSecret)
	var buf bytes.Buffer
	log.New(&buf, "", 0).Printf("%s %#v %+v", k, k, k)
	assertNoSecret(t, buf.String())
	assertNoSecret(t, k.String())
	b, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, string(b))
	resp := NewChangeKeyResponse("vless://" + fixtureSecret + "@127.0.0.1:443")
	assertNoSecret(t, resp.String())
	assertNoSecret(t, fmt.Sprintf("%v", resp))
}

func TestUnconfiguredChanger(t *testing.T) {
	_, err := UnconfiguredChanger{}.ChangeKey(context.Background(), ChangeKeyRequest{ProfileID: "p", KeyID: "k"})
	if err != ErrProviderNotConfigured {
		t.Fatalf("got %v", err)
	}
}

func assertNoSecret(t *testing.T, text string) {
	t.Helper()
	if bytes.Contains([]byte(text), []byte(fixtureSecret)) {
		t.Fatal("output contained a fixture secret")
	}
}
