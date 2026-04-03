// policyengine/connidentity.go
//
// Shared in-memory store mapping downstream source address → SPIFFE ID.
// Populated by ext_authz on CONNECT requests (before the tunnel is
// established) and read by the MITM proxy to associate inner HTTP
// requests with the original client identity.
package main

import "sync"

// ConnIdentityStore is a concurrent-safe map from remote address to SPIFFE ID.
type ConnIdentityStore struct {
	mu sync.RWMutex
	m  map[string]string
}

func NewConnIdentityStore() *ConnIdentityStore {
	return &ConnIdentityStore{m: make(map[string]string)}
}

func (s *ConnIdentityStore) Set(remoteAddr, spiffeID string) {
	s.mu.Lock()
	s.m[remoteAddr] = spiffeID
	s.mu.Unlock()
}

func (s *ConnIdentityStore) Get(remoteAddr string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.m[remoteAddr]
}

func (s *ConnIdentityStore) Delete(remoteAddr string) {
	s.mu.Lock()
	delete(s.m, remoteAddr)
	s.mu.Unlock()
}
