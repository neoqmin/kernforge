package main

import (
	"fmt"
	"strings"
)

type LoopSignature struct {
	Kind          string   `json:"kind,omitempty"`
	Signature     string   `json:"signature,omitempty"`
	ToolNames     []string `json:"tool_names,omitempty"`
	Path          string   `json:"path,omitempty"`
	FailureClass  string   `json:"failure_class,omitempty"`
	RepeatCount   int      `json:"repeat_count,omitempty"`
	RequiredShift string   `json:"required_shift,omitempty"`
}

func loopSignatureForToolCalls(calls []ToolCall, repeatCount int) LoopSignature {
	signature := toolCallSignature(calls)
	if signature == "" {
		return LoopSignature{}
	}
	var names []string
	for _, call := range calls {
		name := strings.TrimSpace(call.Name)
		if name != "" {
			names = append(names, name)
		}
	}
	return LoopSignature{
		Kind:          "repeated_tool_calls",
		Signature:     computeReviewFingerprint("tool_calls", signature),
		ToolNames:     normalizeTaskStateList(names, 8),
		RepeatCount:   repeatCount,
		RequiredShift: "change tool, arguments, target path, or stop and summarize the blocker",
	}
}

func loopSignatureForRepeatedRead(path string, repeatCount int) LoopSignature {
	path = strings.TrimSpace(path)
	if path == "" {
		return LoopSignature{}
	}
	return LoopSignature{
		Kind:          "repeated_read_file",
		Signature:     computeReviewFingerprint("read_file", path),
		ToolNames:     []string{"read_file"},
		Path:          path,
		RepeatCount:   repeatCount,
		RequiredShift: "use existing excerpt, read a different path, or state the exact missing range before another read",
	}
}

func loopSignatureForToolFailure(toolErr string, repeatCount int) LoopSignature {
	toolErr = strings.TrimSpace(toolErr)
	if toolErr == "" {
		return LoopSignature{}
	}
	return LoopSignature{
		Kind:          "repeated_tool_error",
		Signature:     computeReviewFingerprint("tool_error", toolErr),
		FailureClass:  firstNonEmptyLine(toolErr),
		RepeatCount:   repeatCount,
		RequiredShift: "do not repeat the same failing call; change inputs, switch tools, or summarize the blocker",
	}
}

func renderLoopSignature(sig LoopSignature) string {
	if strings.TrimSpace(sig.Kind) == "" {
		return ""
	}
	var parts []string
	parts = append(parts, "kind="+sig.Kind)
	if strings.TrimSpace(sig.Signature) != "" {
		parts = append(parts, "signature="+sig.Signature)
	}
	if len(sig.ToolNames) > 0 {
		parts = append(parts, "tools="+strings.Join(sig.ToolNames, ","))
	}
	if strings.TrimSpace(sig.Path) != "" {
		parts = append(parts, "path="+sig.Path)
	}
	if strings.TrimSpace(sig.FailureClass) != "" {
		parts = append(parts, "failure="+sig.FailureClass)
	}
	if sig.RepeatCount > 0 {
		parts = append(parts, fmt.Sprintf("repeat_count=%d", sig.RepeatCount))
	}
	if strings.TrimSpace(sig.RequiredShift) != "" {
		parts = append(parts, "required_shift="+sig.RequiredShift)
	}
	return strings.Join(parts, " ")
}
