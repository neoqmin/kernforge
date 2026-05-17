package main

import "strings"

func toolMetaExplicitVerificationStatus(meta map[string]any) VerificationStatus {
	raw := strings.TrimSpace(strings.ToLower(toolMetaString(meta, "verification_status")))
	switch raw {
	case "passed", "pass", "success", "succeeded", "completed", "complete":
		return VerificationPassed
	case "failed", "fail", "failure", "error":
		return VerificationFailed
	case "skipped", "skip", "declined", "cancelled", "canceled":
		return VerificationSkipped
	case "pending", "running", "in_progress", "in-progress":
		return VerificationPending
	default:
		return ""
	}
}

func toolMetaCommandExecutionVerificationStatus(meta map[string]any) VerificationStatus {
	raw := strings.TrimSpace(strings.ToLower(toolMetaString(meta, "command_execution_status")))
	raw = strings.NewReplacer("-", "_", " ", "_").Replace(raw)
	switch raw {
	case "passed", "pass", "success", "succeeded", "completed", "complete":
		return VerificationPassed
	case "failed", "fail", "failure", "error", "errored", "timeout", "timed_out":
		return VerificationFailed
	case "declined", "skipped", "skip", "not_executed", "blocked", "cancelled", "canceled":
		return VerificationSkipped
	case "pending", "running", "in_progress", "queued":
		return VerificationPending
	default:
		return ""
	}
}

func toolMetaVerificationWasSkipped(meta map[string]any, text string) bool {
	if toolMetaExplicitVerificationStatus(meta) == VerificationSkipped {
		return true
	}
	if toolMetaCommandExecutionVerificationStatus(meta) == VerificationSkipped {
		return true
	}
	return runShellOutputLooksLikeSkippedVerification(text)
}

func toolResultLooksLikeVerificationAttempt(toolName string, meta map[string]any, text string) bool {
	if toolMetaBool(meta, "verification_like") {
		return true
	}
	if toolMetaExplicitVerificationStatus(meta) != "" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(toolName), "run_shell") {
		return runShellOutputLooksLikeVerification(text) || runShellOutputLooksLikeSkippedVerification(text)
	}
	return false
}

func toolResultHasSuccessfulVerificationEvidence(toolName string, meta map[string]any, text string) bool {
	if toolMetaVerificationWasSkipped(meta, text) {
		return false
	}
	status := toolMetaExplicitVerificationStatus(meta)
	if status != "" {
		return status == VerificationPassed && toolMetaBoolDefault(meta, "success", true) && toolMetaBoolDefault(meta, "verification_evidence", true)
	}
	if toolMetaBool(meta, "verification_like") && toolMetaBoolDefault(meta, "success", true) {
		return runShellOutputLooksLikeVerification(text)
	}
	if strings.EqualFold(strings.TrimSpace(toolName), "run_shell") && runShellOutputLooksLikeVerification(text) && toolMetaBoolDefault(meta, "success", true) {
		return true
	}
	return false
}
