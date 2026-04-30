// Copyright (c) 2026 Vincent Palmer. All rights reserved.
package bdd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"

	"github.com/google/uuid"
)

// enisaMockServer is a fake ENISA EVD API server for BDD testing.
// It accepts CSAF submissions at POST /submissions and returns
// standard ENISA-style responses.
type enisaMockServer struct {
	server     *httptest.Server
	mu         sync.RWMutex
	submissions []enisaMockSubmission
}

type enisaMockSubmission struct {
	ID     string                 `json:"id"`
	Status string                 `json:"status"`
	Body   map[string]interface{} `json:"body"`
}

func newEnisaMockServer() *enisaMockServer {
	m := &enisaMockServer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/submissions", m.handleSubmission)
	mux.HandleFunc("/submissions/", m.handleGetSubmission)
	mux.HandleFunc("/health", m.handleHealth)
	m.server = httptest.NewServer(mux)
	return m
}

func (m *enisaMockServer) URL() string {
	return m.server.URL
}

func (m *enisaMockServer) Close() {
	m.server.Close()
}

func (m *enisaMockServer) Reset() {
	m.mu.Lock()
	m.submissions = nil
	m.mu.Unlock()
}

func (m *enisaMockServer) Submissions() []enisaMockSubmission {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]enisaMockSubmission, len(m.submissions))
	copy(result, m.submissions)
	return result
}

func (m *enisaMockServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (m *enisaMockServer) handleSubmission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Validate auth
	auth := r.Header.Get("Authorization")
	if auth == "" {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "about:blank",
			"title":  "Unauthorized",
			"status": 401,
			"detail": "missing Authorization header",
		})
		return
	}

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"type":   "about:blank",
			"title":  "Bad Request",
			"status": 400,
			"detail": "invalid JSON body",
		})
		return
	}

	id := fmt.Sprintf("EUVD-2026-%s", uuid.New().String()[:8])

	submission := enisaMockSubmission{
		ID:     id,
		Status: "accepted",
		Body:   body,
	}

	m.mu.Lock()
	m.submissions = append(m.submissions, submission)
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":                  id,
		"status":              "accepted",
		"submission_id":       id,
		"estimated_duration":  "PT5M",
		"tracking_url":        fmt.Sprintf("%s/submissions/%s", m.server.URL, id),
	})
}

func (m *enisaMockServer) handleGetSubmission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Path[len("/submissions/"):]

	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, sub := range m.submissions {
		if sub.ID == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":     sub.ID,
				"status": "processed",
				"result": "published",
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   "about:blank",
		"title":  "Not Found",
		"status": 404,
		"detail": fmt.Sprintf("submission %s not found", id),
	})
}
