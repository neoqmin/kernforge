package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionStoreSaveWritesBackup(t *testing.T) {
	root := t.TempDir()
	store := NewSessionStore(root)
	session := &Session{
		ID:             "session-a",
		Name:           "saved",
		WorkingDir:     root,
		Provider:       "test",
		Model:          "test-model",
		PermissionMode: "default",
		CreatedAt:      time.Now(),
	}

	if err := store.Save(session); err != nil {
		t.Fatalf("save session: %v", err)
	}

	backupPath := filepath.Join(root, "session-a.json.bak")
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("expected session backup: %v", err)
	}
	if !json.Valid(data) {
		t.Fatalf("expected valid session backup JSON")
	}
}

func TestSessionStoreLoadRecoversCorruptPrimaryFromBackup(t *testing.T) {
	root := t.TempDir()
	store := NewSessionStore(root)
	session := &Session{
		ID:             "session-a",
		Name:           "good",
		WorkingDir:     root,
		Provider:       "test",
		Model:          "test-model",
		PermissionMode: "default",
		CreatedAt:      time.Now(),
	}

	if err := store.Save(session); err != nil {
		t.Fatalf("save session: %v", err)
	}
	primaryPath := filepath.Join(root, "session-a.json")
	if err := os.WriteFile(primaryPath, []byte("{"), 0o644); err != nil {
		t.Fatalf("corrupt primary: %v", err)
	}

	loaded, err := store.Load(session.ID)
	if err != nil {
		t.Fatalf("load recovered session: %v", err)
	}
	if loaded.Name != "good" {
		t.Fatalf("expected backup session name, got %q", loaded.Name)
	}

	reloaded, err := store.Load(session.ID)
	if err != nil {
		t.Fatalf("load restored primary: %v", err)
	}
	if reloaded.Name != "good" {
		t.Fatalf("expected restored primary session name, got %q", reloaded.Name)
	}
}

func TestSessionStoreListUsesBackupWhenPrimaryIsCorrupt(t *testing.T) {
	root := t.TempDir()
	store := NewSessionStore(root)
	session := &Session{
		ID:             "session-a",
		Name:           "listed",
		WorkingDir:     root,
		Provider:       "test",
		Model:          "test-model",
		PermissionMode: "default",
		CreatedAt:      time.Now(),
	}

	if err := store.Save(session); err != nil {
		t.Fatalf("save session: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "session-a.json"), []byte("{"), 0o644); err != nil {
		t.Fatalf("corrupt primary: %v", err)
	}

	items, err := store.List()
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one listed session, got %d", len(items))
	}
	if items[0].ID != "session-a" || items[0].Name != "listed" {
		t.Fatalf("unexpected listed session: %#v", items[0])
	}
}
