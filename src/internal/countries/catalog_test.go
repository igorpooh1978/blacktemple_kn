package countries

import "testing"

func TestCatalogRegisterLookup(t *testing.T) {
	c := NewCatalog()
	nl := c.Register("nl", "Netherlands")
	if nl.ID != "NL" {
		t.Fatalf("id=%s", nl.ID)
	}
	got, ok := c.Lookup("nl")
	if !ok || got.Name != "Netherlands" {
		t.Fatalf("lookup=%v %v", got, ok)
	}
	c.CommitLastKnownGood()
	list := c.LastKnownGood()
	if len(list) != 1 || list[0].ID != "NL" {
		t.Fatalf("lkg=%v", list)
	}
}

func TestCatalogEmptyRegister(t *testing.T) {
	c := NewCatalog()
	if c.Register("  ", "") != (Country{}) {
		t.Fatal("empty id")
	}
}
