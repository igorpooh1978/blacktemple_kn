package connection

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
)

const resolvedTLSUUID = "11111111-1111-4111-8111-111111111111"

func wsTLSShare(host, remark string) string {
	return "vless://" + resolvedTLSUUID + "@" + host + ":443?type=ws&security=tls&sni=www.example.com&host=www.example.com&path=/vless#" + remark
}

func TestUnresolvedBlackKeyRequiresResolution(t *testing.T) {
	share := "vless://test@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.example.com&fp=chrome&pbk=abcde#boot"
	s := newTestService(t, &fakeEngine{})
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: share, Name: "bk"}); err != nil {
		t.Fatal(err)
	}
	err := s.Control(context.Background(), "connect")
	if !errors.Is(err, ErrBlackKeyResolutionRequired) {
		t.Fatalf("got %v want BLACKKEY_RESOLUTION_REQUIRED", err)
	}
	st := s.Status()
	if st.Connection != "failed" {
		t.Fatalf("connection=%s", st.Connection)
	}
	if st.ErrorClass != ClassBlackKeyResolutionRequired {
		t.Fatalf("errorClass=%q", st.ErrorClass)
	}
	if st.ErrorClass == "INVALID_REALITY_PUBLIC_KEY" {
		t.Fatal("bootstrap must not classify as INVALID_REALITY_PUBLIC_KEY")
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "abcde") {
		t.Fatal("status leaked credential")
	}
}

func TestCandidateLoopPromotesHealthyToLKG(t *testing.T) {
	eng := &fakeEngine{failValidateLeft: 1}
	s := newTestService(t, eng)
	body := wsTLSShare("10.0.0.1", "A") + "\n" + wsTLSShare("10.0.0.2", "B")
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: body, Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if st.Connection != "connected" {
		t.Fatalf("connection=%s class=%s", st.Connection, st.ErrorClass)
	}
	lkg, err := s.Profiles().LastKnownGood(s.Profiles().ActiveID())
	if err != nil {
		t.Fatal(err)
	}
	ks, err := s.Profiles().Keys(s.Profiles().ActiveID())
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) < 2 {
		t.Fatalf("keys=%d", len(ks))
	}
	if lkg.KeyID == ks[0].ID {
		t.Fatal("LKG should be the healthy second candidate, not the failed first")
	}
}

func TestRestartRestoresResolvedWithoutProvider(t *testing.T) {
	body := bootstrapURLBody()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	dir := t.TempDir()
	eng := &fakeEngine{}
	s := New(Config{
		Profiles:    profiles.New(profiles.Config{Client: srv.Client(), DataDir: dir}),
		Engine:      eng,
		DataDir:     dir,
		ListenPort:  11080,
		FastBackoff: true,
		Probe:       nopProbe{},
	})
	p, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: srv.URL + "/sub", Name: "bk"})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := s.Profiles().ImportResolvedJSON(p.ID, []byte(startLoopJSON))
	if err != nil {
		t.Fatal(err)
	}
	if sum.CandidateCount == 0 {
		t.Fatal("no resolved candidates")
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Profiles().LastKnownGood(p.ID); err != nil {
		t.Fatal(err)
	}
	beforeHits := hits
	srv.Close()

	s2 := New(Config{
		Profiles:    profiles.New(profiles.Config{DataDir: dir}),
		Engine:      &fakeEngine{},
		DataDir:     dir,
		ListenPort:  11080,
		FastBackoff: true,
		Probe:       nopProbe{},
	})
	ks, err := s2.Profiles().Keys(p.ID)
	if err != nil || len(ks) == 0 {
		t.Fatalf("restored keys=%v %v", len(ks), err)
	}
	if _, err := s2.Profiles().LastKnownGood(p.ID); err != nil {
		t.Fatal(err)
	}
	if err := s2.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	if hits != beforeHits {
		t.Fatalf("provider refetch hits=%d before=%d", hits, beforeHits)
	}
}

type r8FakeResolver struct {
	entries []subscription.ParsedShare
	hits    int
}

func (f *r8FakeResolver) Resolve(_ context.Context, source profiles.Source) ([]subscription.ParsedShare, error) {
	f.hits++
	_ = source
	return f.entries, nil
}

func TestAutomaticResolvedConnectsThroughSOCKS(t *testing.T) {
	body := bootstrapURLBody()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	parsed, err := subscription.Parse([]byte(wsTLSShare("example.com", "DE-1")))
	if err != nil {
		t.Fatal(err)
	}
	res := &r8FakeResolver{entries: parsed.Entries}
	eng := &fakeEngine{}
	s := New(Config{
		Profiles:    profiles.New(profiles.Config{Client: srv.Client(), Resolver: res}),
		Engine:      eng,
		DataDir:     t.TempDir(),
		ListenPort:  11080,
		FastBackoff: true,
		Probe:       nopProbe{},
	})
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: srv.URL + "/sub", Name: "bk"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Control(context.Background(), "connect"); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if st.Connection != "connected" {
		t.Fatalf("connection=%s class=%s", st.Connection, st.ErrorClass)
	}
	raw, err := os.ReadFile(s.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, `"port":11080`) {
		t.Fatal("SOCKS 11080 missing")
	}
	for _, bad := range []string{"11820", "redirect-in", "tproxy-in"} {
		if strings.Contains(text, bad) {
			t.Fatalf("contains %s", bad)
		}
	}
}

func bootstrapURLBody() string {
	return "vless://test@example.com:443?type=tcp&security=reality&pbk=abcde#boot"
}

const startLoopJSON = `{
  "outbounds": [
    {
      "protocol":"vless",
      "tag":"proxy",
      "settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111"}]}]},
      "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"www.example.com"},"wsSettings":{"path":"/vless","headers":{"Host":"www.example.com"}}}
    }
  ]
}`
