package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	runtimeErrorLogMaxBytes = int64(100 * 1024 * 1024)
	runtimeErrorLogName     = "errors.jsonl"
)

var runtimeErrorLogMu sync.Mutex

type RuntimeErrorLogEntry struct {
	Time          time.Time         `json:"time"`
	EventID       string            `json:"event_id,omitempty"`
	Kind          string            `json:"kind"`
	Severity      string            `json:"severity,omitempty"`
	Summary       string            `json:"summary"`
	Raw           string            `json:"raw,omitempty"`
	WorkspaceRoot string            `json:"workspace_root,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	TurnID        string            `json:"turn_id,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	Entities      map[string]string `json:"entities,omitempty"`
}

func runtimeErrorLogPath(workspaceRoot string) string {
	root := strings.TrimSpace(workspaceRoot)
	if root == "" {
		return ""
	}
	return filepath.Join(root, userConfigDirName, "logs", runtimeErrorLogName)
}

func (a *Agent) appendRuntimeErrorConversationEvent(event ConversationEvent, extraEntities map[string]string) {
	if a == nil {
		return
	}
	root := firstNonBlankString(a.Workspace.BaseRoot, a.Workspace.Root, sessionBaseWorkingDir(a.Session))
	_ = appendRuntimeErrorConversationEvent(root, a.Session, event, extraEntities)
}

func (rt *runtimeState) appendRuntimeErrorConversationEvent(event ConversationEvent, extraEntities map[string]string) {
	if rt == nil {
		return
	}
	root := firstNonBlankString(rt.workspace.BaseRoot, rt.workspace.Root, sessionBaseWorkingDir(rt.session))
	_ = appendRuntimeErrorConversationEvent(root, rt.session, event, extraEntities)
}

func (rt *runtimeState) noteCommandError(command string, err error) {
	if rt == nil || rt.session == nil || err == nil {
		return
	}
	command = strings.TrimSpace(command)
	normalized := normalizeRuntimeError(err)
	normalized.Kind = conversationEventKindCommandError
	normalized.Tool = "command"
	normalized.Raw = strings.TrimSpace(err.Error())
	event := runtimeErrorConversationEvent(normalized, rt.session)
	if command != "" {
		event.Summary = "command failed: " + summarizeShellCommand(command)
		if strings.TrimSpace(normalized.Message) != "" {
			event.Summary += " | " + compactPromptSection(normalized.Message, 180)
		}
		if event.Entities == nil {
			event.Entities = map[string]string{}
		}
		event.Entities["command"] = command
	}
	rt.session.AppendConversationEvent(event)
	rt.appendRuntimeErrorConversationEvent(event, nil)
	if rt.store != nil {
		_ = rt.store.Save(rt.session)
	}
}

func appendRuntimeErrorConversationEvent(workspaceRoot string, sess *Session, event ConversationEvent, extraEntities map[string]string) error {
	root := firstNonBlankString(workspaceRoot, sessionBaseWorkingDir(sess))
	if strings.TrimSpace(root) == "" {
		return nil
	}
	entry := RuntimeErrorLogEntry{
		Time:          event.Time,
		EventID:       strings.TrimSpace(event.ID),
		Kind:          strings.TrimSpace(event.Kind),
		Severity:      strings.TrimSpace(event.Severity),
		Summary:       compactPromptSection(event.Summary, 1000),
		Raw:           compactPromptSection(event.Raw, 8192),
		WorkspaceRoot: root,
		TurnID:        strings.TrimSpace(event.TurnID),
		CorrelationID: strings.TrimSpace(event.CorrelationID),
		Entities:      cloneStringMap(event.Entities),
	}
	if entry.Time.IsZero() {
		entry.Time = time.Now()
	}
	entry.Time = entry.Time.UTC()
	if sess != nil {
		entry.SessionID = strings.TrimSpace(sess.ID)
	}
	if len(extraEntities) > 0 {
		if entry.Entities == nil {
			entry.Entities = map[string]string{}
		}
		for key, value := range extraEntities {
			k := strings.TrimSpace(key)
			v := strings.TrimSpace(value)
			if k != "" && v != "" {
				entry.Entities[k] = v
			}
		}
	}
	if len(entry.Entities) == 0 {
		entry.Entities = nil
	}
	return appendRuntimeErrorLogEntry(root, entry)
}

func appendRuntimeErrorLogEntry(workspaceRoot string, entry RuntimeErrorLogEntry) error {
	path := runtimeErrorLogPath(workspaceRoot)
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if strings.TrimSpace(entry.Kind) == "" {
		entry.Kind = conversationEventKindProviderError
	}
	if strings.TrimSpace(entry.Severity) == "" {
		entry.Severity = conversationSeverityError
	}
	if entry.Time.IsZero() {
		entry.Time = time.Now().UTC()
	}
	entry.Time = entry.Time.UTC()
	entry.Summary = compactPromptSection(entry.Summary, 1000)
	entry.Raw = compactPromptSection(entry.Raw, 8192)
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return appendCappedJSONL(path, data, runtimeErrorLogMaxBytes)
}

func appendCappedJSONL(path string, line []byte, maxBytes int64) error {
	if strings.TrimSpace(path) == "" || len(line) == 0 {
		return nil
	}
	if maxBytes <= 0 {
		maxBytes = runtimeErrorLogMaxBytes
	}
	runtimeErrorLogMu.Lock()
	defer runtimeErrorLogMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := trimCappedJSONLForAppend(path, int64(len(line)), maxBytes); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(line)
	return err
}

func trimCappedJSONLForAppend(path string, incomingBytes int64, maxBytes int64) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if info.Size()+incomingBytes <= maxBytes {
		return nil
	}
	keepBytes := maxBytes - incomingBytes
	if keepBytes <= 0 {
		return os.WriteFile(path, nil, 0o644)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if int64(len(data)) > keepBytes {
		data = data[len(data)-int(keepBytes):]
		if index := bytes.IndexByte(data, '\n'); index >= 0 {
			data = data[index+1:]
		} else {
			data = nil
		}
	}
	return os.WriteFile(path, data, 0o644)
}
