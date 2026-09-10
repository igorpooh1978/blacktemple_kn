package profiles

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
)

const resolvedUUID = "11111111-1111-4111-8111-111111111111"

func bootstrapRealityShare() string {
	return "vless://test@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.example.com&fp=chrome&pbk=abcde#boot"
}

func resolvedWSTLSShare() string {
	return "vless://" + resolvedUUID + "@example.com:443?type=ws&security=tls&sni=www.example.com&host=www.example.com&path=/vless#DE-1"
}

func TestBlackKeyBootstrapNotPublishedAsServer(t *testing.T) {
	body := bootstrapRealityShare()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	svc := NewService(srv.Client(), nil)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL + "/sub?token=fixture", Name: "bk"})
	if err != nil {
		t.Fatal(err)
	}
	if p.SourceKind != SourceKindBlackKey {
		t.Fatalf("SourceKind=%q want %q", p.SourceKind, SourceKindBlackKey)
	}
	if p.ResolutionState != ResolutionUnresolved {
		t.Fatalf("ResolutionState=%q want %q", p.ResolutionState, ResolutionUnresolved)
	}
	ks, err := svc.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) != 0 {
		t.Fatalf("bootstrap published keys=%d", len(ks))
	}
	srvs, err := svc.Servers(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(srvs) != 0 {
		t.Fatalf("bootstrap published servers=%d", len(srvs))
	}
}

func TestImportResolvedVLESSWSTLSPersists(t *testing.T) {
	body := bootstrapRealityShare()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	dir := t.TempDir()
	svc := New(Config{Client: srv.Client(), DataDir: dir})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL + "/sub", Name: "bk"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := testdataStartLoopJSON()
	if err != nil {
		t.Fatal(err)
	}
	sum, err := svc.ImportResolvedJSON(p.ID, raw)
	if err != nil {
		t.Fatal(err)
	}
	if sum.WSTLSCount < 1 {
		t.Fatalf("ws+tls=%d", sum.WSTLSCount)
	}
	if sum.RealityCount != 0 {
		t.Fatalf("reality imported=%d", sum.RealityCount)
	}
	ks, err := svc.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) == 0 {
		t.Fatal("resolved keys missing")
	}
	got, err := svc.Get(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ResolutionState != ResolutionResolved {
		t.Fatalf("ResolutionState=%q", got.ResolutionState)
	}
	srv.Close()
	svc2 := New(Config{DataDir: dir})
	ks2, err := svc2.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks2) != len(ks) {
		t.Fatalf("restored keys=%d want %d", len(ks2), len(ks))
	}
	if hits != 1 {
		t.Fatalf("provider refetch hits=%d", hits)
	}
}

func testdataStartLoopJSON() ([]byte, error) {
	return []byte(startLoopFixture), nil
}

const startLoopFixture = `{
  "inbounds": [{"protocol":"dokodemo-door","port":10808}],
  "outbounds": [
    {
      "protocol":"vless",
      "tag":"proxy",
      "settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","encryption":"none"}]}]},
      "streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"www.example.com"},"wsSettings":{"path":"/vless","headers":{"Host":"www.example.com"}}}
    },
    {"protocol":"freedom","tag":"direct"},
    {"protocol":"dns","tag":"dns-out"},
    {"protocol":"blackhole","tag":"block"},
    {
      "protocol":"vless",
      "tag":"reality-skip",
      "settings":{"vnext":[{"address":"example.net","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111"}]}]},
      "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"abcde"}}
    },
    {
      "protocol":"vless",
      "tag":"xhttp-1",
      "settings":{"vnext":[{"address":"example.org","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111"}]}]},
      "streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"www.example.org"},"xhttpSettings":{"path":"/x","host":"www.example.org","mode":"auto"}}
    }
  ]
}`

func TestStartLoopFixtureParses(t *testing.T) {
	res, err := subscription.ParseXrayConfig([]byte(startLoopFixture))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Entries) < 2 {
		t.Fatalf("entries=%d", len(res.Entries))
	}
	for _, e := range res.Entries {
		if strings.EqualFold(e.Security, "reality") {
			t.Fatal("parser should skip Reality outbounds")
		}
	}
}
