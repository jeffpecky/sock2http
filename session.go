package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// sessionStore issues short-lived HttpOnly cookies after a rotate-token check.
// The cookie carries a random session id; the server keeps only the id's hash
// and an expiry, so a stolen config file or memory dump yields nothing usable.
//
// No JWT: one user, one server, already-authenticated issuance. A signed token
// would add key management for nothing. ponytail: in-memory sessions (lost on
// restart = one re-login); persist only if multi-user/long-lived sessions are
// ever needed.
const (
	sessionCookie  = "s2h_session"
	sessionUseTime = 12 * time.Hour
)

type sessionStore struct {
	mu     sync.Mutex
	hashes map[string]time.Time // sha256(id) → expiry
}

func newSessionStore() *sessionStore {
	return &sessionStore{hashes: make(map[string]time.Time)}
}

func hashSessionID(id string) string {
	h := sha256.Sum256([]byte(id))
	return base64.RawStdEncoding.EncodeToString(h[:])
}

// issue rands an id, records its hash, and sets the cookie.
func (s *sessionStore) issue(w http.ResponseWriter) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return
	}
	id := base64.RawURLEncoding.EncodeToString(raw)
	h := hashSessionID(id)

	s.mu.Lock()
	// Bound memory: drop expired sessions while we hold the lock.
	if len(s.hashes) > 512 {
		now := time.Now()
		for k, exp := range s.hashes {
			if exp.Before(now) {
				delete(s.hashes, k)
			}
		}
	}
	s.hashes[h] = time.Now().Add(sessionUseTime)
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // may be served over http on a LAN hop
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionUseTime.Seconds()),
	})
}

// valid reports whether the request's cookie maps to a live session, sliding
// the expiry forward so an actively-used session doesn't expire mid-work.
func (s *sessionStore) valid(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	h := hashSessionID(c.Value)
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.hashes[h]
	if !ok || exp.Before(now) {
		return false
	}
	s.hashes[h] = now.Add(sessionUseTime)
	return true
}

// expire kills the session server-side and clears the cookie.
func (s *sessionStore) expire(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		s.mu.Lock()
		delete(s.hashes, hashSessionID(c.Value))
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// checkDashboardAuth gates control endpoints: an existing session cookie OR a
// fresh rotate-token header/login. Session cookie bypasses the per-request
// token, so a reload or action doesn't re-prompt.
func (s *sessionStore) checkDashboardAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.valid(r) {
		return true
	}
	token := r.Header.Get("X-Rotate-Token")
	// Also accept ?token= for the printed first-run link's POST fallbacks.
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	want := currentToken()
	if want != "" && constTimeEq(token, want) {
		s.issue(w)
		return true
	}
	http.Error(w, "authentication required", http.StatusForbidden)
	return false
}
