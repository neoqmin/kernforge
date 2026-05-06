package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppendCappedJSONLTrimsOldEntries(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "errors.jsonl")
	for i := 0; i < 20; i++ {
		line := []byte(fmt.Sprintf(`{"i":%d,"payload":"%s"}`+"\n", i, strings.Repeat("x", 24)))
		if err := appendCappedJSONL(path, line, 260); err != nil {
			t.Fatalf("appendCappedJSONL: %v", err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat log: %v", err)
	}
	if info.Size() > 260 {
		t.Fatalf("expected capped log size <= 260, got %d", info.Size())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	text := string(data)
	if strings.Contains(text, `"i":0`) {
		t.Fatalf("expected oldest entry to be trimmed, got %q", text)
	}
	if !strings.Contains(text, `"i":19`) {
		t.Fatalf("expected newest entry to remain, got %q", text)
	}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("expected valid json line, got %q", line)
		}
	}
}
