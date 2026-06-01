package main

import (
	"fmt"
	"strings"
)

func buildAnalysisEvidenceGraphDoc(run ProjectAnalysisRun) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Evidence Graph\n\n")
	analysisDocsWriteHeader(&b, run)
	analysisDocsWriteDocMetadata(&b, run, "EVIDENCE_GRAPH.md")
	fmt.Fprintf(&b, "\n## Graph Summary\n\n")
	fmt.Fprintf(&b, "- Nodes: %d\n", run.EvidenceGraph.Metrics.NodeCount)
	fmt.Fprintf(&b, "- Edges: %d\n", run.EvidenceGraph.Metrics.EdgeCount)
	fmt.Fprintf(&b, "- File nodes: %d\n", run.EvidenceGraph.Metrics.FileNodes)
	fmt.Fprintf(&b, "- Symbol nodes: %d\n", run.EvidenceGraph.Metrics.SymbolNodes)
	fmt.Fprintf(&b, "- Build nodes: %d\n", run.EvidenceGraph.Metrics.BuildNodes)
	fmt.Fprintf(&b, "- Overlay nodes: %d\n", run.EvidenceGraph.Metrics.OverlayNodes)
	if len(run.EvidenceGraph.Metrics.EdgeTypes) > 0 {
		fmt.Fprintf(&b, "- Edge types: %s\n", strings.Join(limitStrings(run.EvidenceGraph.Metrics.EdgeTypes, 18), ", "))
	}
	fmt.Fprintf(&b, "\n## Graph Shards\n\n")
	if len(run.GraphShards.Shards) == 0 {
		fmt.Fprintf(&b, "No graph shard artifact was captured for this run.\n")
	} else {
		for _, shard := range limitAnalysisShards(run.GraphShards.Shards, 24) {
			fmt.Fprintf(&b, "### %s\n\n", firstNonBlankAnalysisString(shard.Name, shard.ID))
			fmt.Fprintf(&b, "- ID: `%s`\n", shard.ID)
			fmt.Fprintf(&b, "- Type: `%s`\n", firstNonBlankAnalysisString(shard.Type, "graph_community"))
			fmt.Fprintf(&b, "- Primary files: %d\n", len(shard.PrimaryFiles))
			fmt.Fprintf(&b, "- Required packets: %s\n", strings.Join(limitStrings(shard.RequiredPacketIDs, 8), ", "))
			fmt.Fprintf(&b, "- Graph fingerprint: `%s`\n", shortAnalysisHash(shard.GraphFingerprint))
			if shard.GraphNeighborhood != nil {
				fmt.Fprintf(&b, "- Nodes: %d\n", len(shard.GraphNeighborhood.NodeIDs))
				fmt.Fprintf(&b, "- Edges: %d\n", len(shard.GraphNeighborhood.EdgeIDs))
				if len(shard.GraphNeighborhood.EdgeTypes) > 0 {
					fmt.Fprintf(&b, "- Edge types: %s\n", strings.Join(limitStrings(shard.GraphNeighborhood.EdgeTypes, 8), ", "))
				}
			}
			if len(shard.MissingEvidenceClasses) > 0 {
				fmt.Fprintf(&b, "- Missing evidence classes: %s\n", strings.Join(shard.MissingEvidenceClasses, ", "))
			}
			b.WriteString("\n")
		}
	}
	fmt.Fprintf(&b, "\n## Incremental Reuse\n\n")
	fmt.Fprintf(&b, "- Previous run: `%s`\n", firstNonBlankAnalysisString(run.GraphReuse.PreviousRunID, "none"))
	fmt.Fprintf(&b, "- Reused shards: %d\n", run.GraphReuse.ReusedShards)
	fmt.Fprintf(&b, "- Recomputed shards: %d\n", run.GraphReuse.RecomputedShards)
	fmt.Fprintf(&b, "- Symbol-scoped invalidations: %d\n", run.GraphReuse.SymbolScopedInvalidation)
	for _, decision := range limitAnalysisGraphReuseDecisions(run.GraphReuse.Decisions, 24) {
		fmt.Fprintf(&b, "- `%s`: %s", firstNonBlankAnalysisString(decision.ShardName, decision.ShardID), firstNonBlankAnalysisString(decision.CacheStatus, "unknown"))
		if strings.TrimSpace(decision.InvalidationReason) != "" {
			fmt.Fprintf(&b, " (%s)", decision.InvalidationReason)
		}
		fmt.Fprintf(&b, " graph=%s\n", shortAnalysisHash(decision.GraphFingerprint))
	}
	return b.String()
}

func buildAnalysisSecurityOverlayDoc(run ProjectAnalysisRun) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Security / Anti-Cheat Overlay\n\n")
	analysisDocsWriteHeader(&b, run)
	analysisDocsWriteDocMetadata(&b, run, "SECURITY_OVERLAY.md")
	fmt.Fprintf(&b, "\n## Summary\n\n")
	fmt.Fprintf(&b, "- Nodes: %d\n", run.SecurityOverlay.Metrics.NodeCount)
	fmt.Fprintf(&b, "- Edges: %d\n", run.SecurityOverlay.Metrics.EdgeCount)
	fmt.Fprintf(&b, "- Blocking issue count: %d\n", run.SecurityOverlay.Metrics.BlockingIssueCount)
	fmt.Fprintf(&b, "- Missing validation candidates: %d\n", run.SecurityOverlay.Metrics.MissingValidationCandidates)
	if len(run.SecurityOverlay.Metrics.Surfaces) > 0 {
		fmt.Fprintf(&b, "- Surfaces: %s\n", strings.Join(run.SecurityOverlay.Metrics.Surfaces, ", "))
	}
	fmt.Fprintf(&b, "\n## Overlay Nodes\n\n")
	if len(run.SecurityOverlay.Nodes) == 0 {
		fmt.Fprintf(&b, "No security overlay nodes were detected.\n")
	} else {
		for _, node := range limitSecurityOverlayNodes(run.SecurityOverlay.Nodes, 32) {
			fmt.Fprintf(&b, "- `%s` [%s] %s", node.ID, node.Type, firstNonBlankAnalysisString(node.Label, node.Path))
			if strings.TrimSpace(node.Path) != "" {
				fmt.Fprintf(&b, " in `%s`", node.Path)
			}
			if len(node.Evidence) > 0 {
				fmt.Fprintf(&b, " evidence=%s", strings.Join(limitStrings(node.Evidence, 2), ", "))
			}
			b.WriteString("\n")
		}
	}
	fmt.Fprintf(&b, "\n## Overlay Edges\n\n")
	if len(run.SecurityOverlay.Edges) == 0 {
		fmt.Fprintf(&b, "No security overlay edges were detected.\n")
	} else {
		for _, edge := range limitSecurityOverlayEdges(run.SecurityOverlay.Edges, 40) {
			fmt.Fprintf(&b, "- `%s` -> `%s` [%s", edge.SourceID, edge.TargetID, edge.Type)
			if strings.TrimSpace(edge.Surface) != "" {
				fmt.Fprintf(&b, "/%s", edge.Surface)
			}
			fmt.Fprintf(&b, "]")
			if strings.TrimSpace(edge.ValidationState) != "" {
				fmt.Fprintf(&b, " validation=%s", edge.ValidationState)
			}
			if len(edge.Evidence) > 0 {
				fmt.Fprintf(&b, " evidence=%s", strings.Join(limitStrings(edge.Evidence, 3), ", "))
			}
			b.WriteString("\n")
		}
	}
	if len(run.SecurityOverlay.FollowUp) > 0 {
		fmt.Fprintf(&b, "\n## Follow-Up\n\n")
		for _, item := range run.SecurityOverlay.FollowUp {
			fmt.Fprintf(&b, "- %s\n", item)
		}
	}
	return b.String()
}

func buildAnalysisUnsupportedClaimsDoc(run ProjectAnalysisRun) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Unsupported Claims\n\n")
	analysisDocsWriteHeader(&b, run)
	analysisDocsWriteDocMetadata(&b, run, "UNSUPPORTED_CLAIMS.md")
	fmt.Fprintf(&b, "\n## Verification Summary\n\n")
	fmt.Fprintf(&b, "- Status: %s\n", firstNonBlankAnalysisString(run.ClaimVerification.Status, "unknown"))
	fmt.Fprintf(&b, "- Total claims: %d\n", run.ClaimVerification.TotalClaims)
	fmt.Fprintf(&b, "- Verified: %d\n", run.ClaimVerification.VerifiedCount)
	fmt.Fprintf(&b, "- Inferences: %d\n", run.ClaimVerification.InferenceCount)
	fmt.Fprintf(&b, "- Downgraded: %d\n", run.ClaimVerification.DowngradedCount)
	fmt.Fprintf(&b, "- Unsupported: %d\n", run.ClaimVerification.UnsupportedCount)
	fmt.Fprintf(&b, "- Blocking: %d\n", run.ClaimVerification.BlockingCount)
	fmt.Fprintf(&b, "- Unsupported high-confidence: %d\n", run.ClaimVerification.UnsupportedHighConfidenceCount)
	fmt.Fprintf(&b, "\n## Unsupported Or Downgraded Claims\n\n")
	if len(run.UnsupportedClaims) == 0 {
		fmt.Fprintf(&b, "No unsupported or downgraded claims were recorded.\n")
	} else {
		for _, claim := range limitUnsupportedClaims(run.UnsupportedClaims, 80) {
			fmt.Fprintf(&b, "### %s\n\n", firstNonBlankAnalysisString(claim.ClaimID, claim.Status))
			fmt.Fprintf(&b, "- Shard: `%s`\n", claim.ShardID)
			fmt.Fprintf(&b, "- Status: `%s`\n", claim.Status)
			fmt.Fprintf(&b, "- Confidence: `%s` -> `%s`\n", claim.OriginalConfidence, claim.FinalConfidence)
			fmt.Fprintf(&b, "- Claim: %s\n", claim.Claim)
			if strings.TrimSpace(claim.Reason) != "" {
				fmt.Fprintf(&b, "- Reason: %s\n", claim.Reason)
			}
			if len(claim.EvidencePacketIDs) > 0 {
				fmt.Fprintf(&b, "- Packet IDs: %s\n", strings.Join(claim.EvidencePacketIDs, ", "))
			}
			if len(claim.SourceAnchors) > 0 {
				fmt.Fprintf(&b, "- Source anchors: %s\n", strings.Join(claim.SourceAnchors, ", "))
			}
			if len(claim.Issues) > 0 {
				fmt.Fprintf(&b, "- Issues:\n")
				for _, issue := range claim.Issues {
					fmt.Fprintf(&b, "  - [%s] %s: %s\n", issue.Severity, issue.Code, issue.Message)
				}
			}
			b.WriteString("\n")
		}
	}
	fmt.Fprintf(&b, "\n## Verified Facts\n\n")
	if len(run.ClaimVerification.VerifiedClaims) == 0 {
		fmt.Fprintf(&b, "No verified claim objects were recorded.\n")
	} else {
		for _, claim := range limitVerifiedClaims(run.ClaimVerification.VerifiedClaims, 32) {
			fmt.Fprintf(&b, "- %s", claim.Claim)
			if len(claim.EvidencePacketIDs) > 0 {
				fmt.Fprintf(&b, " packets=%s", strings.Join(limitStrings(claim.EvidencePacketIDs, 4), ", "))
			}
			b.WriteString("\n")
		}
	}
	if len(run.ClaimVerification.FollowThrough) > 0 {
		fmt.Fprintf(&b, "\n## Verification Follow-Through\n\n")
		for _, item := range run.ClaimVerification.FollowThrough {
			fmt.Fprintf(&b, "- %s\n", item)
		}
	}
	return b.String()
}

func limitAnalysisShards(items []AnalysisShard, limit int) []AnalysisShard {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitAnalysisGraphReuseDecisions(items []AnalysisGraphReuseDecision, limit int) []AnalysisGraphReuseDecision {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func limitSecurityOverlayNodes(items []SecurityOverlayNode, limit int) []SecurityOverlayNode {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return items[:limit]
}

func analysisEvidenceGraphSourceAnchors(run ProjectAnalysisRun) []string {
	items := []string{}
	for _, edge := range run.EvidenceGraph.Edges {
		items = append(items, edge.Evidence...)
	}
	for _, shard := range run.Shards {
		if shard.GraphNeighborhood != nil {
			items = append(items, shard.GraphNeighborhood.EvidenceFiles...)
		}
		items = append(items, shard.PrimaryFiles...)
	}
	return analysisUniqueStrings(items)
}

func analysisSecurityOverlaySourceAnchors(run ProjectAnalysisRun) []string {
	items := []string{}
	for _, node := range run.SecurityOverlay.Nodes {
		items = append(items, node.Evidence...)
		if strings.TrimSpace(node.Path) != "" {
			items = append(items, node.Path)
		}
	}
	for _, edge := range run.SecurityOverlay.Edges {
		items = append(items, edge.Evidence...)
	}
	return analysisUniqueStrings(items)
}

func analysisUnsupportedClaimSourceAnchors(run ProjectAnalysisRun) []string {
	items := []string{}
	for _, claim := range run.UnsupportedClaims {
		items = append(items, claim.SourceAnchors...)
	}
	for _, result := range run.ClaimVerification.Results {
		if result.Status != "verified" {
			items = append(items, result.SourceAnchors...)
		}
	}
	return analysisUniqueStrings(items)
}
