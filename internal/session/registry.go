package session

import (
	"sync"
)

type Registry struct {
	sessions map[uint32]*SessionContext
	mu       sync.RWMutex
}

// NewRegistry initializes a new Registry
func NewRegistry() *Registry {
	return &Registry{
		sessions: make(map[uint32]*SessionContext),
	}
}

// Add inserts a new session
func (r *Registry) Add(sessionID uint32, sess *SessionContext) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[sessionID] = sess
}

// Get retrieves a session by sessionID. Returns nil if not found
func (r *Registry) Get(sessionID uint32) (*SessionContext, bool) {
    r.mu.RLock()
    defer r.mu.RUnlock()
    sess, ok := r.sessions[sessionID]
    return sess, ok
}

// Delete removes a session from the registry
func (r *Registry) Delete(sessionID uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, sessionID)
}

// ListAll returns all active sessions (copy of map)
func (r *Registry) ListAll() map[uint32]*SessionContext {
	r.mu.RLock()
	defer r.mu.RUnlock()
	copyMap := make(map[uint32]*SessionContext, len(r.sessions))
	for k, v := range r.sessions {
		copyMap[k] = v
	}
	return copyMap
}
