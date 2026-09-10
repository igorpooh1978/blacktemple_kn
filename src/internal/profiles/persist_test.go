package profiles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/atomicfile"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/keys"
	"github.com/igorpooh1978/blacktemple_kn/src/internal/subscription"
)

func persistVLESS() string {
	return fixtureVLESS()
}

func persistVLESSAlt() string {
	return fixtureVLESSAlt()
}

func TestFailedFetchDoesNotCreateProfile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	svc := NewService(srv.Client(), nil)
	_, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL + "/sub?token=not-a-real-key"})
	if err == nil {
		t.Fatal("import must fail")
	}
	assertNoSecret(t, err.Error())
	if strings.Contains(err.Error(), srv.URL) || strings.Contains(err.Error(), "not-a-real-key") {
		t.Fatalf("error leaked URL or token: %v", err)
	}
	if len(svc.List()) != 0 {
		t.Fatal("partial profile stored")
	}
}

func TestHTTPSImportParse(t *testing.T) {
	body := persistVLESS() + "\n" + persistVLESSAlt()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	token := "fixture-query-token"
	svc := NewService(srv.Client(), nil)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL + "/sub?token=" + token, Name: "https"})
	if err != nil {
		t.Fatal(err)
	}
	ks, err := svc.Keys(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ks) != 2 {
		t.Fatalf("entries=%d", len(ks))
	}
	assertNoSecret(t, errString(err))
	if strings.Contains(p.String(), token) {
		t.Fatal("profile string leaked token")
	}
}

func TestImportPersistsAndRestoresWithoutProvider(t *testing.T) {
	body := persistVLESS()
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	}))
	dir := t.TempDir()
	svc := New(Config{Client: srv.Client(), DataDir: dir})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL, Name: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetActive(p.ID); err != nil {
		t.Fatal(err)
	}
	ks, err := svc.Keys(p.ID)
	if err != nil || len(ks) == 0 {
		t.Fatal(err)
	}
	cand, err := svc.Candidate(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profiles.json")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	srv.Close()

	svc2 := New(Config{DataDir: dir})
	if svc2.PersistBlocked() {
		t.Fatal("good store must load")
	}
	if svc2.ActiveID() != p.ID {
		t.Fatalf("active %s want %s", svc2.ActiveID(), p.ID)
	}
	got, err := svc2.Get(p.ID)
	if err != nil || got.Name != "lab" {
		t.Fatalf("profile %+v %v", got, err)
	}
	ks2, err := svc2.Keys(p.ID)
	if err != nil || len(ks2) != len(ks) || ks2[0].Material() != ks[0].Material() {
		t.Fatalf("keys restored=%d", len(ks2))
	}
	srvs, err := svc2.Servers(p.ID)
	if err != nil || len(srvs) == 0 {
		t.Fatal("servers not restored")
	}
	cand2, err := svc2.Candidate(p.ID)
	if err != nil || cand2.KeyID != cand.KeyID || cand2.ServerID != cand.ServerID {
		t.Fatalf("candidate %+v want %+v %v", cand2, cand, err)
	}
	if hits != 1 {
		t.Fatalf("provider fetched on restart hits=%d", hits)
	}
}

func TestPersistFailureLeavesGoodState(t *testing.T) {
	dir := t.TempDir()
	svc := New(Config{DataDir: dir})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: persistVLESS(), Name: "good"})
	if err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected replace failure")
	fail := New(Config{
		DataDir: dir,
		Writer:  &atomicfile.Writer{Replace: func(tmp, dest string) error { return injected }},
	})
	if len(fail.List()) != 1 {
		t.Fatal("loaded previous")
	}
	_, err = fail.Import(context.Background(), ImportRequest{BlackKey: persistVLESSAlt(), Name: "bad"})
	if err == nil {
		t.Fatal("persist must fail")
	}
	if len(fail.List()) != 1 || fail.List()[0].ID != p.ID {
		t.Fatalf("memory mutated: %+v", fail.List())
	}
	now, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(now) != string(good) {
		t.Fatal("disk replaced on persist failure")
	}
}

func TestUnknownStoreVersionNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	raw := []byte(`{"version":99,"activeProfileId":"","profiles":[]}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	svc := New(Config{DataDir: dir})
	if !svc.PersistBlocked() {
		t.Fatal("unknown version must block persist")
	}
	if len(svc.List()) != 0 {
		t.Fatal("unknown version must not load as empty writable store")
	}
	_, err := svc.Import(context.Background(), ImportRequest{BlackKey: persistVLESS()})
	if err == nil {
		t.Fatal("import must fail when store version is unknown")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatal("unknown version file overwritten")
	}
}

func TestSecretAbsentFromAPIShape(t *testing.T) {
	svc := NewService(nil, nil)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: persistVLESS(), Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, p.String())
	assertNoSecret(t, svc.List()[0].String())
	ks, _ := svc.Keys(p.ID)
	b, err := json.Marshal(ks[0])
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, string(b))
}

func TestChangeKeyUsesAdapterNotRefresh(t *testing.T) {
	var fetches int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		_, _ = w.Write([]byte(persistVLESS()))
	}))
	defer srv.Close()
	changer := fakeChanger{uri: persistVLESSAlt()}
	svc := NewService(srv.Client(), changer)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 1 {
		t.Fatalf("import fetches=%d", fetches)
	}
	ks, _ := svc.Keys(p.ID)
	next, err := svc.ChangeKey(context.Background(), p.ID, ks[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if fetches != 1 {
		t.Fatalf("ChangeKey must not Refresh subscription fetches=%d", fetches)
	}
	ks2, _ := svc.Keys(p.ID)
	if len(ks2) != 1 {
		t.Fatalf("keys=%d", len(ks2))
	}
	if next.KeyID == "" {
		t.Fatal("missing new candidate")
	}
}

func TestChangeKeyProviderFailureLeavesOld(t *testing.T) {
	svc := NewService(nil, nil)
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: persistVLESS()})
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := svc.Keys(p.ID)
	old := ks[0].Material()
	_, err = svc.ChangeKey(context.Background(), p.ID, ks[0].ID)
	if !errors.Is(err, keys.ErrProviderNotConfigured) {
		t.Fatalf("got %v", err)
	}
	ks2, _ := svc.Keys(p.ID)
	if ks2[0].Material() != old {
		t.Fatal("old key mutated")
	}
}

func TestChangeKeyInvalidShareLeavesOld(t *testing.T) {
	svc := NewService(nil, fakeChanger{uri: "not-a-share"})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: persistVLESS()})
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := svc.Keys(p.ID)
	old := ks[0].ID
	_, err = svc.ChangeKey(context.Background(), p.ID, ks[0].ID)
	if err == nil {
		t.Fatal("invalid share")
	}
	ks2, _ := svc.Keys(p.ID)
	if ks2[0].ID != old {
		t.Fatal("old key replaced")
	}
}

func TestChangeKeyUnsupportedProtocolLeavesOld(t *testing.T) {
	ss := "ss://YWVzLTEyOC1nY206c3MtcGFzcy10ZXN0@127.0.0.1:8388#lab"
	svc := NewService(nil, fakeChanger{uri: ss})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: persistVLESS()})
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := svc.Keys(p.ID)
	old := ks[0].Material()
	_, err = svc.ChangeKey(context.Background(), p.ID, ks[0].ID)
	if !errors.Is(err, ErrUnsupportedProtocol) {
		t.Fatalf("got %v", err)
	}
	ks2, _ := svc.Keys(p.ID)
	if ks2[0].Material() != old {
		t.Fatal("old key replaced")
	}
}

func TestChangeKeyPersistsBeforeReload(t *testing.T) {
	dir := t.TempDir()
	svc := New(Config{DataDir: dir, Changer: fakeChanger{uri: persistVLESSAlt()}})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: persistVLESS()})
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := svc.Keys(p.ID)
	oldID := ks[0].ID
	next, err := svc.ChangeKey(context.Background(), p.ID, ks[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if next.KeyID == "" || next.KeyID == oldID {
		t.Fatalf("empty or unchanged candidate %+v", next)
	}
	svc2 := New(Config{DataDir: dir})
	ks2, err := svc2.Keys(p.ID)
	if err != nil || len(ks2) != 1 {
		t.Fatal(err)
	}
	if ks2[0].ID == oldID {
		t.Fatal("new key not persisted")
	}
	cand, err := svc2.Candidate(p.ID)
	if err != nil || cand.KeyID != ks2[0].ID {
		t.Fatalf("selection %+v %v", cand, err)
	}
}

func TestChangeKeyPersistFailureLeavesOld(t *testing.T) {
	dir := t.TempDir()
	svc := New(Config{DataDir: dir, Changer: fakeChanger{uri: persistVLESSAlt()}})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: persistVLESS()})
	if err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	fail := New(Config{
		DataDir: dir,
		Changer: fakeChanger{uri: persistVLESSAlt()},
		Writer:  &atomicfile.Writer{Replace: func(tmp, dest string) error { return errors.New("injected") }},
	})
	ks, _ := fail.Keys(p.ID)
	old := ks[0].Material()
	_, err = fail.ChangeKey(context.Background(), p.ID, ks[0].ID)
	if err == nil {
		t.Fatal("persist must fail")
	}
	ks2, _ := fail.Keys(p.ID)
	if ks2[0].Material() != old {
		t.Fatal("memory replaced on persist failure")
	}
	now, _ := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if string(now) != string(good) {
		t.Fatal("disk replaced")
	}
}

func TestChangeKeySecretNotInErrors(t *testing.T) {
	svc := NewService(nil, fakeChanger{uri: persistVLESSAlt()})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: persistVLESS()})
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := svc.Keys(p.ID)
	next, err := svc.ChangeKey(context.Background(), p.ID, ks[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, next.String())
	assertNoSecret(t, errString(err))
}

func TestChangeKeySourcesNeverTouchNetfilter(t *testing.T) {
	files := []string{
		"service.go",
		"persist.go",
		filepath.Join("..", "keys", "provider.go"),
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, bad := range []string{"ExecuteNetfilterReconcile", "S05xkeen", "iptables", "ipset"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains %s", f, bad)
			}
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestParseClassifiesReplacement(t *testing.T) {
	parsed, err := subscription.Parse([]byte(persistVLESSAlt()))
	if err != nil || len(parsed.Entries) == 0 {
		t.Fatal(err)
	}
	if !strings.EqualFold(parsed.Entries[0].Protocol, "vless") {
		t.Fatalf("protocol %s", parsed.Entries[0].Protocol)
	}
}

const (
	persistPathMarker     = "PATH_SECRET_MARKER"
	persistQueryMarker    = "QUERY_SECRET_MARKER"
	persistFragmentMarker = "FRAGMENT_SECRET_MARKER"
)

func TestRefreshAfterRestartKeepsPathSource(t *testing.T) {
	var hits int
	var lastPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		lastPath = r.URL.Path
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(persistVLESS()))
	}))
	defer srv.Close()
	raw := srv.URL + "/sub/" + persistPathMarker + "?token=" + persistQueryMarker + "#" + persistFragmentMarker
	dir := t.TempDir()
	svc := New(Config{Client: srv.Client(), DataDir: dir})
	p, err := svc.Import(context.Background(), ImportRequest{BlackKey: raw, Name: "path"})
	if err != nil {
		t.Fatal(err)
	}
	if lastPath != "/sub/"+persistPathMarker {
		t.Fatalf("import path %s", lastPath)
	}
	onDisk, err := os.ReadFile(filepath.Join(dir, "profiles.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(onDisk), persistPathMarker) {
		t.Fatal("profiles.json must retain raw source for Refresh")
	}
	assertNoSecret(t, p.String())
	for _, s := range []string{
		fmt.Sprint(p),
		fmt.Sprintf("%#v", p),
		fmt.Sprintf("%#v", ImportRequest{BlackKey: raw, Name: "path"}),
		svc.List()[0].String(),
	} {
		if strings.Contains(s, persistPathMarker) || strings.Contains(s, persistQueryMarker) || strings.Contains(s, persistFragmentMarker) {
			t.Fatalf("leaked subscription source: %s", s)
		}
	}

	svc2 := New(Config{Client: srv.Client(), DataDir: dir})
	if err := svc2.Refresh(context.Background(), p.ID); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Fatalf("refresh fetches=%d", hits)
	}
	if lastPath != "/sub/"+persistPathMarker {
		t.Fatalf("refresh path %s", lastPath)
	}

	k := keys.New("id", "p", "s", "srv", "vless", "lab", persistPathMarker)
	resp := keys.NewChangeKeyResponse("vless://" + persistPathMarker + "@127.0.0.1:443")
	for _, v := range []any{k, resp} {
		for _, s := range []string{fmt.Sprint(v), fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v)} {
			if strings.Contains(s, persistPathMarker) {
				t.Fatalf("leaked: %s", s)
			}
		}
	}
	kb, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(kb), persistPathMarker) {
		t.Fatal("key JSON leaked material")
	}
}
