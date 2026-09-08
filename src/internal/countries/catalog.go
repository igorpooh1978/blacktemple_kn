package countries

import (
	"strings"
	"sync"
)

// Country is a catalog entry. It is not a key or server.
type Country struct {
	ID   string
	Name string
}

func (c Country) String() string {
	return "Country{ID:" + c.ID + " Name:" + c.Name + "}"
}

func (c Country) GoString() string { return c.String() }

// Catalog is an in-memory country index. Remote BlackCountry payloads are
// not decoded here; callers Register observed IDs.
type Catalog struct {
	mu   sync.Mutex
	byID map[string]Country
	lkg  []Country
}

func NewCatalog() *Catalog {
	return &Catalog{byID: map[string]Country{}}
}

func (c *Catalog) Register(id, name string) Country {
	id = strings.ToUpper(strings.TrimSpace(id))
	if id == "" {
		return Country{}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = id
	}
	country := Country{ID: id, Name: name}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byID == nil {
		c.byID = map[string]Country{}
	}
	c.byID[id] = country
	c.snapshotLocked()
	return country
}

func (c *Catalog) Lookup(id string) (Country, bool) {
	id = strings.ToUpper(strings.TrimSpace(id))
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.byID[id]
	return v, ok
}

func (c *Catalog) List() []Country {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Country, len(c.lkg))
	copy(out, c.lkg)
	return out
}

// CommitLastKnownGood freezes the current list for rollback of catalog refresh.
func (c *Catalog) CommitLastKnownGood() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snapshotLocked()
}

func (c *Catalog) LastKnownGood() []Country {
	return c.List()
}

func (c *Catalog) snapshotLocked() {
	c.lkg = c.lkg[:0]
	for _, v := range c.byID {
		c.lkg = append(c.lkg, v)
	}
	for i := 0; i < len(c.lkg); i++ {
		for j := i + 1; j < len(c.lkg); j++ {
			if c.lkg[j].ID < c.lkg[i].ID {
				c.lkg[i], c.lkg[j] = c.lkg[j], c.lkg[i]
			}
		}
	}
}
