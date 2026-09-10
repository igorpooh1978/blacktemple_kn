package connection

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
)

func TestConnectClassifiesCredentialFailures(t *testing.T) {
	eng := &fakeEngine{}
	s := newTestService(t, eng)
	share := "vless://test@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=www.example.com&fp=chrome&pbk=abcde#NL-1"
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: share, Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	err := s.Control(context.Background(), "connect")
	if err == nil {
		t.Fatal("connect must fail on dummy Reality public key")
	}
	if strings.Contains(err.Error(), "abcde") || strings.Contains(err.Error(), "test") {
		t.Fatalf("public error leaked credential: %v", err)
	}
	st := s.Status()
	if st.Connection != "failed" {
		t.Fatalf("connection=%s want failed", st.Connection)
	}
	if st.ErrorClass != "INVALID_REALITY_PUBLIC_KEY" && st.ErrorClass != "INVALID_VLESS_USER_ID" && st.ErrorClass != "XRAY_CONFIG_REJECTED" {
		t.Fatalf("errorClass=%q want a credential class", st.ErrorClass)
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Contains(text, "abcde") || strings.Contains(text, `"id":"test"`) {
		t.Fatal("status leaked credential")
	}
}
