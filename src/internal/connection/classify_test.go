package connection

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/igorpooh1978/blacktemple_kn/src/internal/profiles"
)

func TestConnectClassifiesCredentialFailures(t *testing.T) {
	eng := &fakeEngine{failValidate: true}
	s := newTestService(t, eng)
	share := vlessShare()
	if _, err := s.Profiles().Import(context.Background(), profiles.ImportRequest{BlackKey: share, Name: "lab"}); err != nil {
		t.Fatal(err)
	}
	err := s.Control(context.Background(), "connect")
	if err == nil {
		t.Fatal("connect must fail on rejected xray config")
	}
	if strings.Contains(err.Error(), testUUID) || strings.Contains(err.Error(), "_Cfw") {
		t.Fatalf("public error leaked credential: %v", err)
	}
	st := s.Status()
	if st.Connection != "failed" {
		t.Fatalf("connection=%s want failed", st.Connection)
	}
	if st.ErrorClass != "INVALID_VLESS_USER_ID" && st.ErrorClass != "INVALID_REALITY_PUBLIC_KEY" && st.ErrorClass != "INVALID_REALITY_SHORT_ID" && st.ErrorClass != "XRAY_CONFIG_REJECTED" {
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
