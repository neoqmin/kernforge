package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestKernforgeDaemonRPCRefreshesStaleProxyState(t *testing.T) {
	oldServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "old daemon should not be reached", http.StatusInternalServerError)
	}))
	oldAddr := strings.TrimPrefix(oldServer.URL, "http://")
	oldServer.Close()

	newServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			writeDaemonJSON(w, map[string]any{"ok": true})
		case "/rpc":
			var req kernforgeDaemonRPCRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if req.Token != "new-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			writeDaemonJSON(w, kernforgeDaemonRPCResponse{
				Respond: true,
				Response: map[string]any{
					"jsonrpc": "2.0",
					"id":      req.Message["id"],
					"result":  map[string]any{"ok": true},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer newServer.Close()
	newAddr := strings.TrimPrefix(newServer.URL, "http://")

	state := kernforgeDaemonState{Addr: oldAddr, Token: "old-token", PID: 1}
	readCount := 0
	readState := func() (kernforgeDaemonState, bool) {
		readCount++
		return kernforgeDaemonState{Addr: newAddr, Token: "new-token", PID: 2}, true
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, respond, err := callKernforgeDaemonRPCWithStateRefresh(
		client,
		&state,
		`C:\workspace`,
		"fallback",
		map[string]any{"jsonrpc": "2.0", "id": float64(1), "method": "ping"},
		readState,
		kernforgeDaemonHealth,
	)
	if err != nil {
		t.Fatalf("expected stale proxy state to refresh and retry: %v", err)
	}
	if !respond {
		t.Fatalf("expected refreshed rpc to respond")
	}
	if readCount != 1 {
		t.Fatalf("expected one daemon state reload, got %d", readCount)
	}
	if state.Addr != newAddr || state.Token != "new-token" || state.PID != 2 {
		t.Fatalf("expected proxy state to refresh to new daemon, got %+v", state)
	}
	result, ok := response["result"].(map[string]any)
	if !ok || result["ok"] != true {
		t.Fatalf("unexpected rpc response: %#v", response)
	}
}

func TestKernforgeDaemonRPCDoesNotRefreshForToolErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rpc":
			writeDaemonJSON(w, kernforgeDaemonRPCResponse{Respond: true, Error: "tool failed"})
		default:
			writeDaemonJSON(w, map[string]any{"ok": true})
		}
	}))
	defer server.Close()

	state := kernforgeDaemonState{Addr: strings.TrimPrefix(server.URL, "http://"), Token: "token", PID: 1}
	readCount := 0
	readState := func() (kernforgeDaemonState, bool) {
		readCount++
		return state, true
	}
	client := &http.Client{Timeout: 2 * time.Second}
	_, _, err := callKernforgeDaemonRPCWithStateRefresh(
		client,
		&state,
		`C:\workspace`,
		"fallback",
		map[string]any{"jsonrpc": "2.0", "id": float64(1), "method": "tools/call"},
		readState,
		kernforgeDaemonHealth,
	)
	if err == nil || !strings.Contains(err.Error(), "tool failed") {
		t.Fatalf("expected original tool error, got %v", err)
	}
	if readCount != 0 {
		t.Fatalf("expected non-transport tool error not to reload daemon state, got %d reloads", readCount)
	}
}
