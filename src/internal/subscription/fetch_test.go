package subscription

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchHTTPErrorClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream body must not leak"))
	}))
	defer srv.Close()
	token := "query-token-secret"
	_, err := Fetch(context.Background(), srv.Client(), srv.URL+"/sub?token="+token)
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *ClassifiedError
	if !errors.As(err, &ce) || ce.Class != ClassHTTPError || ce.Status != 502 {
		t.Fatalf("got %#v", err)
	}
	if ce.Public != publicFetchFailed {
		t.Fatalf("public %q", ce.Public)
	}
	if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "upstream body") || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("leaked: %v", err)
	}
}

func TestFetchTooLargeClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, maxBodyBytes+2))
	}))
	defer srv.Close()
	_, err := Fetch(context.Background(), srv.Client(), srv.URL)
	var ce *ClassifiedError
	if !errors.As(err, &ce) || ce.Class != ClassTooLarge || ce.Status != 413 {
		t.Fatalf("got %#v", err)
	}
}

func TestFetchTimeoutClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	client := &http.Client{Timeout: 40 * time.Millisecond}
	_, err := Fetch(context.Background(), client, srv.URL)
	var ce *ClassifiedError
	if !errors.As(err, &ce) || ce.Class != ClassFetchTimeout || ce.Status != 504 {
		t.Fatalf("got %#v", err)
	}
}

func TestFetchTLSClassified(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	_, err := Fetch(context.Background(), client, srv.URL)
	var ce *ClassifiedError
	if !errors.As(err, &ce) || ce.Class != ClassTLSError || ce.Status != 502 {
		t.Fatalf("got %#v", err)
	}
	if strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("leaked URL: %v", err)
	}
}

func TestClassifyParseInvalid(t *testing.T) {
	err := ClassifyParse(ErrMalformed)
	var ce *ClassifiedError
	if !errors.As(err, &ce) || ce.Status != 400 || ce.Class != ClassInvalidSubscription {
		t.Fatalf("got %#v", err)
	}
	if ce.Public != publicInvalidFormat {
		t.Fatalf("public %q", ce.Public)
	}
}
