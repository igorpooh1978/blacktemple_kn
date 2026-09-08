package servers

import "testing"

func TestSelectModes(t *testing.T) {
	list := []Server{
		{ID: "a", Host: "127.0.0.1", Port: 443},
		{ID: "b", Host: "10.0.0.1", Port: 443},
		{ID: "c", Host: "10.0.0.2", Port: 443},
	}
	auto, err := Select(ModeAuto, list, "", "")
	if err != nil || auto.ID != "a" {
		t.Fatalf("auto=%v %v", auto, err)
	}
	man, err := Select(ModeManual, list, "b", "")
	if err != nil || man.ID != "b" {
		t.Fatalf("manual=%v %v", man, err)
	}
	rot, err := Select(ModeRotate, list, "", "a")
	if err != nil || rot.ID != "b" {
		t.Fatalf("rotate=%v %v", rot, err)
	}
	fail, err := Select(ModeFailover, list, "", "c")
	if err != nil || fail.ID != "a" {
		t.Fatalf("failover wrap=%v %v", fail, err)
	}
}

func TestSelectEmpty(t *testing.T) {
	_, err := Select(ModeAuto, nil, "", "")
	if err != ErrEmpty {
		t.Fatalf("got %v", err)
	}
}

func TestSelectManualMissing(t *testing.T) {
	_, err := Select(ModeManual, []Server{{ID: "a"}}, "missing", "")
	if err != ErrNotFound {
		t.Fatalf("got %v", err)
	}
}

func TestParseMode(t *testing.T) {
	if ParseMode("ROTATE") != ModeRotate {
		t.Fatal("rotate")
	}
	if ParseMode("") != ModeAuto {
		t.Fatal("default")
	}
}
