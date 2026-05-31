package main

import "time"

type GraphShardSeed struct {
	ID            string   `json:"id"`
	Class         string   `json:"class"`
	Mode          string   `json:"mode,omitempty"`
	Files         []string `json:"files,omitempty"`
	Symbols       []string `json:"symbols,omitempty"`
	EdgeIDs       []string `json:"edge_ids,omitempty"`
	EvidenceClass string   `json:"evidence_class,omitempty"`
	Priority      int      `json:"priority,omitempty"`
}

type GraphExpansionPolicy struct {
	Mode          string   `json:"mode,omitempty"`
	MaxNodes      int      `json:"max_nodes,omitempty"`
	MaxEdges      int      `json:"max_edges,omitempty"`
	PriorityEdges []string `json:"priority_edges,omitempty"`
	PriorityTags  []string `json:"priority_tags,omitempty"`
}

type AnalysisGraphNeighborhood struct {
	Policy                 string   `json:"policy,omitempty"`
	SeedSymbols            []string `json:"seed_symbols,omitempty"`
	SeedFiles              []string `json:"seed_files,omitempty"`
	NodeIDs                []string `json:"node_ids,omitempty"`
	EdgeIDs                []string `json:"edge_ids,omitempty"`
	Paths                  []string `json:"paths,omitempty"`
	EdgeTypes              []string `json:"edge_types,omitempty"`
	EvidenceFiles          []string `json:"evidence_files,omitempty"`
	MissingEvidenceClasses []string `json:"missing_evidence_classes,omitempty"`
}

type AnalysisGraphNode struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Label      string   `json:"label,omitempty"`
	Path       string   `json:"path,omitempty"`
	SymbolID   string   `json:"symbol_id,omitempty"`
	StartLine  int      `json:"start_line,omitempty"`
	EndLine    int      `json:"end_line,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

type AnalysisGraphEdge struct {
	ID         string   `json:"id"`
	SourceID   string   `json:"source_id"`
	TargetID   string   `json:"target_id"`
	Type       string   `json:"type"`
	Domain     string   `json:"domain,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	PacketIDs  []string `json:"packet_ids,omitempty"`
}

type AnalysisEvidenceGraphMetrics struct {
	NodeCount      int      `json:"node_count,omitempty"`
	EdgeCount      int      `json:"edge_count,omitempty"`
	FileNodes      int      `json:"file_nodes,omitempty"`
	SymbolNodes    int      `json:"symbol_nodes,omitempty"`
	BuildNodes     int      `json:"build_nodes,omitempty"`
	OverlayNodes   int      `json:"overlay_nodes,omitempty"`
	EdgeTypes      []string `json:"edge_types,omitempty"`
	RequiredPacket int      `json:"required_packet_count,omitempty"`
}

type AnalysisEvidenceGraph struct {
	RunID       string                       `json:"run_id,omitempty"`
	GeneratedAt time.Time                    `json:"generated_at,omitempty"`
	Nodes       []AnalysisGraphNode          `json:"nodes,omitempty"`
	Edges       []AnalysisGraphEdge          `json:"edges,omitempty"`
	Metrics     AnalysisEvidenceGraphMetrics `json:"metrics,omitempty"`
}

type AnalysisGraphShardArtifact struct {
	GeneratedAt time.Time        `json:"generated_at,omitempty"`
	Mode        string           `json:"mode,omitempty"`
	Seeds       []GraphShardSeed `json:"seeds,omitempty"`
	Shards      []AnalysisShard  `json:"shards,omitempty"`
	Summary     []string         `json:"summary,omitempty"`
}

type AnalysisGraphReuseDecision struct {
	ShardID                 string               `json:"shard_id"`
	ShardName               string               `json:"shard_name,omitempty"`
	CacheStatus             string               `json:"cache_status,omitempty"`
	InvalidationReason      string               `json:"invalidation_reason,omitempty"`
	InvalidationClass       string               `json:"invalidation_class,omitempty"`
	InvalidationSignals     []string             `json:"invalidation_signals,omitempty"`
	InvalidationChanges     []InvalidationChange `json:"invalidation_changes,omitempty"`
	FileFingerprint         string               `json:"file_fingerprint,omitempty"`
	SymbolFingerprint       string               `json:"symbol_fingerprint,omitempty"`
	EdgeFingerprint         string               `json:"edge_fingerprint,omitempty"`
	BuildContextFingerprint string               `json:"build_context_fingerprint,omitempty"`
	OverlayFingerprint      string               `json:"overlay_fingerprint,omitempty"`
	GraphFingerprint        string               `json:"graph_fingerprint,omitempty"`
}

type AnalysisGraphReuseReport struct {
	GeneratedAt              time.Time                    `json:"generated_at,omitempty"`
	PreviousRunID            string                       `json:"previous_run_id,omitempty"`
	TotalShards              int                          `json:"total_shards,omitempty"`
	ReusedShards             int                          `json:"reused_shards,omitempty"`
	RecomputedShards         int                          `json:"recomputed_shards,omitempty"`
	SymbolScopedInvalidation int                          `json:"symbol_scoped_invalidation,omitempty"`
	Decisions                []AnalysisGraphReuseDecision `json:"decisions,omitempty"`
}

type ClaimVerificationIssue struct {
	Code     string   `json:"code"`
	Severity string   `json:"severity"`
	Message  string   `json:"message"`
	Evidence []string `json:"evidence,omitempty"`
}

type ClaimVerificationResult struct {
	ShardID             string                   `json:"shard_id,omitempty"`
	ClaimID             string                   `json:"claim_id,omitempty"`
	Kind                string                   `json:"kind,omitempty"`
	Claim               string                   `json:"claim"`
	OriginalConfidence  string                   `json:"original_confidence,omitempty"`
	FinalConfidence     string                   `json:"final_confidence,omitempty"`
	Status              string                   `json:"status"`
	EvidencePacketIDs   []string                 `json:"evidence_packet_ids,omitempty"`
	SourceAnchors       []string                 `json:"source_anchors,omitempty"`
	SupportingPacketIDs []string                 `json:"supporting_packet_ids,omitempty"`
	GraphEdgeIDs        []string                 `json:"graph_edge_ids,omitempty"`
	Issues              []ClaimVerificationIssue `json:"issues,omitempty"`
}

type VerifiedClaim struct {
	ShardID           string   `json:"shard_id,omitempty"`
	ClaimID           string   `json:"claim_id,omitempty"`
	Kind              string   `json:"kind,omitempty"`
	Claim             string   `json:"claim"`
	EvidencePacketIDs []string `json:"evidence_packet_ids,omitempty"`
	SourceAnchors     []string `json:"source_anchors,omitempty"`
	GraphEdgeIDs      []string `json:"graph_edge_ids,omitempty"`
}

type UnsupportedClaim struct {
	ShardID            string                   `json:"shard_id,omitempty"`
	ClaimID            string                   `json:"claim_id,omitempty"`
	Kind               string                   `json:"kind,omitempty"`
	Claim              string                   `json:"claim"`
	OriginalConfidence string                   `json:"original_confidence,omitempty"`
	FinalConfidence    string                   `json:"final_confidence,omitempty"`
	Status             string                   `json:"status"`
	Reason             string                   `json:"reason,omitempty"`
	EvidencePacketIDs  []string                 `json:"evidence_packet_ids,omitempty"`
	SourceAnchors      []string                 `json:"source_anchors,omitempty"`
	Issues             []ClaimVerificationIssue `json:"issues,omitempty"`
}

type ClaimVerificationReport struct {
	GeneratedAt                    time.Time                 `json:"generated_at,omitempty"`
	Status                         string                    `json:"status,omitempty"`
	TotalClaims                    int                       `json:"total_claims,omitempty"`
	VerifiedCount                  int                       `json:"verified_count,omitempty"`
	InferenceCount                 int                       `json:"inference_count,omitempty"`
	DowngradedCount                int                       `json:"downgraded_count,omitempty"`
	UnsupportedCount               int                       `json:"unsupported_count,omitempty"`
	BlockingCount                  int                       `json:"blocking_count,omitempty"`
	UnsupportedHighConfidenceCount int                       `json:"unsupported_high_confidence_count,omitempty"`
	Results                        []ClaimVerificationResult `json:"results,omitempty"`
	VerifiedClaims                 []VerifiedClaim           `json:"verified_claims,omitempty"`
	UnsupportedClaims              []UnsupportedClaim        `json:"unsupported_claims,omitempty"`
	FollowThrough                  []string                  `json:"follow_through,omitempty"`
}

type SecurityOverlayNode struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	Label      string   `json:"label,omitempty"`
	Path       string   `json:"path,omitempty"`
	SymbolID   string   `json:"symbol_id,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Tags       []string `json:"tags,omitempty"`
}

type SecurityOverlayEdge struct {
	ID                string   `json:"id"`
	SourceID          string   `json:"source_id"`
	TargetID          string   `json:"target_id"`
	Type              string   `json:"type"`
	Surface           string   `json:"surface,omitempty"`
	Confidence        string   `json:"confidence,omitempty"`
	Evidence          []string `json:"evidence,omitempty"`
	RequiredInvariant string   `json:"required_invariant,omitempty"`
	ValidationState   string   `json:"validation_state,omitempty"`
}

type SecurityOverlayMetrics struct {
	NodeCount                   int      `json:"node_count,omitempty"`
	EdgeCount                   int      `json:"edge_count,omitempty"`
	BlockingIssueCount          int      `json:"blocking_issue_count,omitempty"`
	MissingValidationCandidates int      `json:"missing_validation_candidates,omitempty"`
	Surfaces                    []string `json:"surfaces,omitempty"`
}

type SecurityOverlaySummary struct {
	GeneratedAt time.Time              `json:"generated_at,omitempty"`
	Nodes       []SecurityOverlayNode  `json:"nodes,omitempty"`
	Edges       []SecurityOverlayEdge  `json:"edges,omitempty"`
	Metrics     SecurityOverlayMetrics `json:"metrics,omitempty"`
	FollowUp    []string               `json:"follow_up,omitempty"`
}
