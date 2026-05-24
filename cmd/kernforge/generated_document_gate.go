package main

import "strings"

func generatedDocumentArtifactGateAcceptedForRequest(session *Session, request string, changedPaths []string) bool {
	if session == nil {
		return false
	}
	contextRequest := generatedDocumentArtifactRequestContextForTurn(session, request)
	if contextRequest == "" {
		contextRequest = generatedDocumentArtifactRequestContextForTurn(session, codingHarnessSourcePrompt(session))
	}
	if contextRequest == "" && !sessionHasApprovedDocumentArtifactOnlyHarness(session) {
		return false
	}
	normalizedChangedPaths, ok := generatedDocumentArtifactGateChangedPaths(session, changedPaths)
	if !ok {
		return false
	}
	if len(normalizedChangedPaths) == 0 {
		return sessionHasApprovedDocumentArtifactOnlyHarness(session) ||
			sessionHasDocumentArtifactContentAcceptedHarness(session)
	}
	for _, path := range normalizedChangedPaths {
		if !preWritePathLooksLikeGeneratedDocumentArtifact(path) {
			return false
		}
	}
	if contextRequest != "" && changedPathsAreGeneratedDocumentArtifacts(session, contextRequest, normalizedChangedPaths) {
		return true
	}
	if sessionHasApprovedDocumentArtifactOnlyHarness(session) &&
		changedPathsMatchDocumentArtifactQuality(session, normalizedChangedPaths) {
		return true
	}
	if sessionHasDocumentArtifactContentAcceptedHarness(session) &&
		changedPathsMatchDocumentArtifactQuality(session, normalizedChangedPaths) {
		return true
	}
	if sessionHasDocumentArtifactQualityAcceptedHarness(session) &&
		changedPathsMatchDocumentArtifactQuality(session, normalizedChangedPaths) &&
		strings.TrimSpace(contextRequest) != "" {
		return true
	}
	return false
}

func generatedDocumentArtifactGateChangedPaths(session *Session, changedPaths []string) ([]string, bool) {
	normalizedChangedPaths := normalizeTaskStateList(changedPaths, 64)
	if len(normalizedChangedPaths) == 0 {
		normalizedChangedPaths = documentArtifactHarnessChangedPaths(session)
	}
	if len(normalizedChangedPaths) == 0 {
		return nil, true
	}
	artifactPaths := []string{}
	if session != nil {
		artifactPaths = generatedDocumentArtifactPathsFromHarnessReport(session.LastCodingHarnessReport)
	}
	selected := []string{}
	for _, path := range normalizedChangedPaths {
		normalized := normalizeSessionRelativePath(path)
		if normalized == "" {
			continue
		}
		if preWritePathLooksLikeGeneratedDocumentArtifact(normalized) {
			selected = append(selected, normalized)
			continue
		}
		if matches := generatedDocumentArtifactGateArtifactPathsUnder(normalized, artifactPaths); len(matches) > 0 {
			selected = append(selected, matches...)
			continue
		}
		if generatedDocumentArtifactGateInternalPath(normalized) {
			continue
		}
		return normalizeTaskStateList([]string{normalized}, 64), false
	}
	return normalizeTaskStateList(selected, 64), true
}

func generatedDocumentArtifactGateArtifactPathsUnder(path string, artifactPaths []string) []string {
	if len(artifactPaths) == 0 {
		return nil
	}
	normalized := strings.Trim(strings.ReplaceAll(strings.ToLower(normalizeSessionRelativePath(path)), "\\", "/"), "/")
	if normalized == "" {
		return nil
	}
	prefix := strings.TrimRight(normalized, "/") + "/"
	matches := []string{}
	for _, artifactPath := range artifactPaths {
		artifact := normalizeSessionRelativePath(artifactPath)
		lowerArtifact := strings.Trim(strings.ReplaceAll(strings.ToLower(artifact), "\\", "/"), "/")
		if lowerArtifact == normalized || strings.HasPrefix(lowerArtifact, prefix) {
			matches = append(matches, artifact)
		}
	}
	return normalizeTaskStateList(matches, 64)
}

func generatedDocumentArtifactGateInternalPath(path string) bool {
	normalized := strings.Trim(strings.ReplaceAll(strings.ToLower(normalizeSessionRelativePath(path)), "\\", "/"), "/")
	if normalized == "" {
		return true
	}
	return normalized == userConfigDirName ||
		strings.HasPrefix(normalized, userConfigDirName+"/completion_audit") ||
		strings.HasPrefix(normalized, userConfigDirName+"/goals") ||
		normalized == "sessions" ||
		strings.HasPrefix(normalized, "sessions/")
}
