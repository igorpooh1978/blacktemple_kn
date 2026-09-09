package platform

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitNetworkReadyTimesOutWhenNotReady(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err := WaitNetworkReady(ctx, func() NetworkStatus {
		return NetworkStatus{}
	}, Backoff{Initial: time.Millisecond, Max: 5 * time.Millisecond, Factor: 2})
	if err == nil {
		t.Fatal("expected not-ready")
	}
	if err != ErrNetworkNotReady {
		t.Fatalf("err %v", err)
	}
}

func TestWaitNetworkReadySucceedsWhenConditionsFlip(t *testing.T) {
	var n atomic.Int32
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := WaitNetworkReady(ctx, func() NetworkStatus {
		ready := n.Add(1) >= 3
		return NetworkStatus{
			OptMounted:     ready,
			DefaultRoute:   ready,
			LANAvailable:   ready,
			XrayExecutable: ready,
		}
	}, Backoff{Initial: time.Millisecond, Max: 10 * time.Millisecond, Factor: 2})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNetworkStatusReadyRequiresAllFour(t *testing.T) {
	base := NetworkStatus{
		OptMounted:     true,
		DefaultRoute:   true,
		LANAvailable:   true,
		XrayExecutable: true,
	}
	if !base.Ready() {
		t.Fatal("all true must be ready")
	}
	cases := []NetworkStatus{
		{DefaultRoute: true, LANAvailable: true, XrayExecutable: true},
		{OptMounted: true, LANAvailable: true, XrayExecutable: true},
		{OptMounted: true, DefaultRoute: true, XrayExecutable: true},
		{OptMounted: true, DefaultRoute: true, LANAvailable: true},
	}
	for i, s := range cases {
		if s.Ready() {
			t.Fatalf("case %d should not be ready", i)
		}
	}
}

func TestWaitNetworkReadyNilContext(t *testing.T) {
	err := WaitNetworkReady(nil, func() NetworkStatus { return NetworkStatus{} }, Backoff{})
	if err == nil {
		t.Fatal("expected error")
	}
}
