package remotepolicy

import "sync"

// Manager stores layered policy. ApplyRemote never mutates local or session.
type Manager struct {
	mu      sync.Mutex
	builtin Settings
	remote  Settings
	local   Settings
	session Settings
	doc     Document
}

func NewManager(builtin Settings) *Manager {
	return &Manager{builtin: builtin}
}

func (m *Manager) SetLocal(s Settings) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.local = s
}

func (m *Manager) SetSession(s Settings) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = s
}

func (m *Manager) ClearSession() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.session = Settings{}
}

// ApplyRemote stores parsed remote defaults if origin is trusted and the
// body authenticates. Local and session layers are not overwritten.
func (m *Manager) ApplyRemote(origin Origin, body []byte, integ IntegrityInput) (Document, error) {
	if !origin.Allowed() {
		return Document{}, ErrUntrustedOrigin
	}
	status, err := ClassifyIntegrity(body, integ)
	if err != nil {
		return Document{}, err
	}
	doc, err := Parse(body)
	if err != nil {
		return Document{}, err
	}
	doc.Origin = origin
	doc.Integrity = status
	m.mu.Lock()
	defer m.mu.Unlock()
	m.remote = doc.Settings
	m.doc = doc
	return doc, nil
}

func (m *Manager) RemoteDocument() Document {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.doc
}

func (m *Manager) Effective() Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Merge(m.builtin, m.remote, m.local, m.session)
}
