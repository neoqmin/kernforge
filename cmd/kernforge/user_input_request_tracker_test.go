package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestUserInputRequestTrackerMarksInteractivePrompts(t *testing.T) {
	tracker := NewUserInputRequestTracker()
	marks := 0
	tracker.SetCallback(func() {
		marks++
	})

	ws := Workspace{
		UserInputRequests: tracker,
		PreviewEdit: func(EditPreview) (bool, error) {
			return true, nil
		},
		ConfirmVerification: func(VerificationPlan) (bool, error) {
			return true, nil
		},
	}
	if err := ws.ConfirmEdit(EditPreview{}); err != nil {
		t.Fatalf("ConfirmEdit: %v", err)
	}
	if ok, err := ws.ConfirmVerificationPlan(VerificationPlan{}); err != nil || !ok {
		t.Fatalf("ConfirmVerificationPlan ok=%v err=%v", ok, err)
	}

	perms := NewPermissionManager(ModeDefault, func(string) (bool, error) {
		return true, nil
	})
	perms.SetUserInputRequestTracker(tracker)
	if ok, err := perms.Allow(ActionShell, "Write-Output ok"); err != nil || !ok {
		t.Fatalf("Allow shell ok=%v err=%v", ok, err)
	}

	if marks != 3 {
		t.Fatalf("expected three user input marks, got %d", marks)
	}
}

func TestAgentMCPToolCallMetadataRecordsPriorShellApproval(t *testing.T) {
	dir := t.TempDir()
	manager, warnings := LoadMCPManager(Workspace{BaseRoot: dir, Root: dir}, []MCPServerConfig{{
		Name:    "fake",
		Command: os.Args[0],
		Args:    []string{"-test.run=TestMCPHelperProcess"},
		Env: map[string]string{
			"KERNFORGE_MCP_HELPER": "1",
		},
	}})
	defer manager.Close()

	if len(warnings) != 0 {
		t.Fatalf("expected no warnings, got %v", warnings)
	}

	promptCount := 0
	tracker := NewUserInputRequestTracker()
	perms := NewPermissionManager(ModeDefault, func(string) (bool, error) {
		promptCount++
		return true, nil
	})
	perms.SetUserInputRequestTracker(tracker)
	ws := Workspace{
		BaseRoot:          dir,
		Root:              dir,
		Shell:             "powershell",
		Perms:             perms,
		UserInputRequests: tracker,
	}

	provider := &scriptedProviderClient{
		replies: []ChatResponse{
			{
				Message: Message{
					Role: "assistant",
					ToolCalls: []ToolCall{
						{
							ID:        "shell-call",
							Name:      "run_shell",
							Arguments: mustMarshalToolArgs(t, map[string]any{"command": "Write-Output ok"}),
						},
						{
							ID:        "mcp-call",
							Name:      "mcp__fake__echo",
							Arguments: mustMarshalToolArgs(t, map[string]any{"message": "meta"}),
						},
					},
				},
			},
			{Message: Message{Role: "assistant", Text: "done"}},
		},
	}
	session := NewSession(dir, "scripted", "model-a", "high", "default")
	agent := &Agent{
		Config: Config{
			Model:           "model-a",
			ReasoningEffort: "high",
			AutoLocale:      boolPtr(false),
		},
		Client:    provider,
		Tools:     NewToolRegistry(append([]Tool{NewRunShellTool(ws)}, manager.Tools()...)...),
		Workspace: ws,
		Session:   session,
		Store:     NewSessionStore(filepath.Join(dir, "sessions")),
	}

	if _, err := agent.Reply(context.Background(), "run a shell command, then call MCP echo"); err != nil {
		t.Fatalf("Reply: %v", err)
	}
	if promptCount != 1 {
		t.Fatalf("expected one shell approval prompt, got %d", promptCount)
	}
	if len(provider.requests) == 0 {
		t.Fatalf("expected provider request")
	}
	if _, ok := provider.requests[0].TurnMetadata[mcpTurnMetadataUserInputRequestedKey]; ok {
		t.Fatalf("provider turn metadata header must not include user input marker: %#v", provider.requests[0].TurnMetadata)
	}

	var toolMsg *Message
	for i := range session.Messages {
		if session.Messages[i].Role == "tool" && session.Messages[i].ToolName == "mcp__fake__echo" {
			toolMsg = &session.Messages[i]
			break
		}
	}
	if toolMsg == nil {
		t.Fatalf("expected MCP tool result in session messages: %#v", session.Messages)
	}
	structured, ok := toolMsg.ToolMeta["mcp_result_structured_content"].(map[string]any)
	if !ok {
		t.Fatalf("expected MCP structuredContent metadata, got %#v", toolMsg.ToolMeta)
	}
	requestMeta, ok := structured["request_meta"].(map[string]any)
	if !ok {
		t.Fatalf("expected MCP request _meta, got %#v", structured)
	}
	turnMeta, ok := requestMeta[mcpTurnMetadataMetaKey].(map[string]any)
	if !ok {
		t.Fatalf("expected %s metadata, got %#v", mcpTurnMetadataMetaKey, requestMeta)
	}
	if got := turnMeta[mcpTurnMetadataUserInputRequestedKey]; got != true {
		t.Fatalf("expected user input turn marker to be true, got %#v in %#v", got, turnMeta)
	}
}

func mustMarshalToolArgs(t *testing.T, args map[string]any) string {
	t.Helper()
	data, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal tool args: %v", err)
	}
	return string(data)
}
