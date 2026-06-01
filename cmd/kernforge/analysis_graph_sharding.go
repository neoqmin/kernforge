package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

func buildGraphShardPlan(snapshot ProjectSnapshot, index SemanticIndexV2, mode string, desired int) []AnalysisShard {
	seeds := selectGraphSeeds(snapshot, index, mode)
	if len(seeds) == 0 {
		return nil
	}
	byClass := map[string]GraphShardSeed{}
	for _, seed := range seeds {
		if strings.TrimSpace(seed.Class) == "" {
			continue
		}
		cleanFiles := graphExistingFiles(snapshot, seed.Files)
		if len(cleanFiles) == 0 && len(seed.Symbols) > 0 {
			cleanFiles = graphExistingFiles(snapshot, graphFilesForSymbolIDs(index, seed.Symbols))
		}
		if len(cleanFiles) == 0 {
			continue
		}
		current := byClass[seed.Class]
		if current.Class == "" {
			current = GraphShardSeed{
				ID:            "seed-" + seed.Class,
				Class:         seed.Class,
				Mode:          normalizeProjectAnalysisMode(mode),
				EvidenceClass: firstNonBlankAnalysisString(seed.EvidenceClass, seed.Class),
				Priority:      seed.Priority,
			}
		}
		current.Files = analysisUniqueStrings(append(current.Files, cleanFiles...))
		current.Symbols = analysisUniqueStrings(append(current.Symbols, seed.Symbols...))
		current.EdgeIDs = analysisUniqueStrings(append(current.EdgeIDs, seed.EdgeIDs...))
		if seed.Priority > 0 && (current.Priority == 0 || seed.Priority < current.Priority) {
			current.Priority = seed.Priority
		}
		byClass[seed.Class] = current
	}
	if len(byClass) == 0 {
		return nil
	}
	classes := graphShardClassOrder(mode)
	shards := []AnalysisShard{}
	assigned := map[string]struct{}{}
	for _, class := range classes {
		seed, ok := byClass[class]
		if !ok {
			continue
		}
		files := graphRankedFiles(snapshot, seed.Files, seed.Symbols)
		if len(files) == 0 {
			continue
		}
		for _, path := range files {
			assigned[path] = struct{}{}
		}
		shards = append(shards, AnalysisShard{
			Name:                   graphShardNameForClass(class),
			Type:                   "graph_community",
			Objective:              graphShardObjectiveForClass(class),
			RequiredEvidence:       graphShardRequiredEvidenceForClass(class),
			SuccessCriteria:        graphShardSuccessCriteriaForClass(class),
			PrimaryFiles:           files,
			SeedSymbols:            analysisUniqueStrings(seed.Symbols),
			MissingEvidenceClasses: graphMissingEvidenceClassesForSeed(seed),
			EstimatedFiles:         len(files),
			EstimatedLines:         graphSumLines(snapshot, files),
		})
	}
	remaining := []ScannedFile{}
	for _, file := range snapshot.Files {
		if _, ok := assigned[file.Path]; ok {
			continue
		}
		remaining = append(remaining, file)
	}
	sort.SliceStable(remaining, func(i int, j int) bool {
		if remaining[i].ImportanceScore == remaining[j].ImportanceScore {
			return remaining[i].Path < remaining[j].Path
		}
		return remaining[i].ImportanceScore > remaining[j].ImportanceScore
	})
	if len(remaining) > 0 && len(shards) > 0 {
		target := desired - len(shards)
		if target < 1 && desired <= 0 {
			target = 1
		}
		if target > 0 {
			chunks := graphChunkRemainingFiles(remaining, target)
			for chunkIndex, chunk := range chunks {
				shards = append(shards, AnalysisShard{
					Name:           shardName("graph_fallback", chunkIndex, len(chunks)),
					Type:           "graph_fallback",
					PrimaryFiles:   filesToPaths(chunk),
					EstimatedFiles: len(chunk),
					EstimatedLines: sumLines(chunk),
				})
			}
		}
	}
	return shards
}

func selectGraphSeeds(snapshot ProjectSnapshot, index SemanticIndexV2, mode string) []GraphShardSeed {
	seeds := []GraphShardSeed{}
	add := func(class string, files []string, symbols []string, edgeIDs []string, evidenceClass string, priority int) {
		files = graphExistingFiles(snapshot, files)
		symbols = analysisUniqueStrings(symbols)
		edgeIDs = analysisUniqueStrings(edgeIDs)
		if len(files) == 0 && len(symbols) == 0 {
			return
		}
		seeds = append(seeds, GraphShardSeed{
			ID:            analysisGraphStableID("seed", class, strings.Join(files, "|"), strings.Join(symbols, "|")),
			Class:         class,
			Mode:          normalizeProjectAnalysisMode(mode),
			Files:         files,
			Symbols:       symbols,
			EdgeIDs:       edgeIDs,
			EvidenceClass: firstNonBlankAnalysisString(evidenceClass, class),
			Priority:      priority,
		})
	}
	startupFiles := analysisUniqueStrings(append(append([]string(nil), snapshot.EntrypointFiles...), startupProjectEntryFiles(snapshot)...))
	if strings.TrimSpace(snapshot.PrimaryStartup) != "" {
		for _, project := range snapshot.SolutionProjects {
			if strings.EqualFold(project.Name, snapshot.PrimaryStartup) {
				startupFiles = append(startupFiles, project.EntryFiles...)
				startupFiles = append(startupFiles, project.Path)
			}
		}
	}
	add("startup", startupFiles, graphSymbolsForFiles(index, startupFiles), nil, "startup_path", 10)

	signals := collectSemanticShardSignals(snapshot)
	add("build_context", graphMapKeys(signals.BuildPaths), graphSymbolsForFiles(index, graphMapKeys(signals.BuildPaths)), nil, "build_context", 20)
	add("asset_config", graphMapKeys(signals.AssetPaths), graphSymbolsForFiles(index, graphMapKeys(signals.AssetPaths)), nil, "asset_config", 30)
	add("unreal_gameplay", graphMapKeys(signals.GameplayPaths), graphSymbolsForFiles(index, graphMapKeys(signals.GameplayPaths)), nil, "unreal_gameplay", 32)
	add("unreal_ui", graphMapKeys(signals.UIPaths), graphSymbolsForFiles(index, graphMapKeys(signals.UIPaths)), nil, "unreal_ui", 33)
	add("unreal_ability", graphMapKeys(signals.AbilityPaths), graphSymbolsForFiles(index, graphMapKeys(signals.AbilityPaths)), nil, "unreal_ability", 34)
	add("security_driver", graphMapKeys(signals.DriverPaths), graphSymbolsForFiles(index, graphMapKeys(signals.DriverPaths)), nil, "driver_surface", 35)
	add("security_ioctl", graphMapKeys(signals.IoctlPaths), graphSymbolsForFiles(index, graphMapKeys(signals.IoctlPaths)), nil, "ioctl_surface", 40)
	add("security_handles", graphMapKeys(signals.HandlePaths), graphSymbolsForFiles(index, graphMapKeys(signals.HandlePaths)), nil, "handle_surface", 50)
	add("security_memory", graphMapKeys(signals.MemoryPaths), graphSymbolsForFiles(index, graphMapKeys(signals.MemoryPaths)), nil, "memory_surface", 52)
	add("security_rpc", graphMapKeys(signals.RPCPaths), graphSymbolsForFiles(index, graphMapKeys(signals.RPCPaths)), nil, "rpc_surface", 60)
	add("integrity_security", graphMapKeys(signals.SecurityPaths), graphSymbolsForFiles(index, graphMapKeys(signals.SecurityPaths)), nil, "integrity_surface", 70)

	callbackFiles := []string{}
	callbackSymbols := []string{}
	for _, symbol := range index.Symbols {
		corpus := strings.ToLower(strings.Join([]string{symbol.ID, symbol.Name, symbol.CanonicalName, symbol.Kind, symbol.File, strings.Join(symbol.Tags, " ")}, " "))
		if containsAny(corpus, "obregister", "psset", "cmregister", "fltregister", "callback", "notifyroutine", "minifilter", "wfp") {
			callbackFiles = append(callbackFiles, symbol.File)
			callbackSymbols = append(callbackSymbols, symbol.ID)
		}
	}
	add("callback_registration", callbackFiles, callbackSymbols, nil, "callback_registration", 45)

	generatedFiles := []string{}
	generatedSymbols := []string{}
	generatedEdges := []string{}
	for _, edge := range index.GeneratedCodeEdges {
		generatedFiles = append(generatedFiles, edge.SourceFile)
		generatedSymbols = append(generatedSymbols, edge.TargetID)
		generatedEdges = append(generatedEdges, analysisGraphStableID("generated", edge.SourceFile, edge.TargetID, edge.Type))
	}
	add("generated_artifact", generatedFiles, generatedSymbols, generatedEdges, "generated_artifact", 80)

	ueRPCFiles := []string{}
	ueRPCSymbols := []string{}
	for _, item := range snapshot.UnrealNetwork {
		ueRPCFiles = append(ueRPCFiles, item.File)
		if strings.TrimSpace(item.TypeName) != "" {
			ueRPCSymbols = append(ueRPCSymbols, "type:"+item.TypeName)
		}
	}
	add("unreal_network", ueRPCFiles, ueRPCSymbols, nil, "ue_rpc_authority", 35)

	for _, edge := range snapshot.ProjectEdges {
		files := graphFilesFromEvidence(snapshot, edge.Evidence)
		class := ""
		switch {
		case projectEdgeSuggestsIOCTL(edge):
			class = "security_ioctl"
		case projectEdgeSuggestsRPC(edge):
			class = "security_rpc"
		case projectEdgeSuggestsHandles(edge) || projectEdgeSuggestsMemory(edge):
			if projectEdgeSuggestsHandles(edge) {
				class = "security_handles"
			} else {
				class = "security_memory"
			}
		case projectEdgeSuggestsContent(edge):
			class = "asset_config"
		case projectEdgeSuggestsSecurity(edge):
			class = "integrity_security"
		}
		if class != "" {
			add(class, files, graphSymbolsForFiles(index, files), []string{analysisGraphStableID("project", edge.Source, edge.Target, edge.Type)}, class, 55)
		}
	}
	for _, edge := range index.OverlayEdges {
		class := graphClassForOverlayEdge(edge)
		files := graphFilesForSymbolIDs(index, []string{edge.SourceID, edge.TargetID})
		if class != "" {
			add(class, files, []string{edge.SourceID, edge.TargetID}, []string{analysisGraphStableID("overlay", edge.SourceID, edge.TargetID, edge.Type, edge.Domain)}, class, 55)
		}
	}
	return normalizeGraphSeeds(seeds)
}

func expandGraphNeighborhood(index SemanticIndexV2, seed GraphShardSeed, policy GraphExpansionPolicy) AnalysisGraphNeighborhood {
	if policy.MaxNodes <= 0 {
		policy.MaxNodes = 96
	}
	if policy.MaxEdges <= 0 {
		policy.MaxEdges = 128
	}
	nodeSet := map[string]struct{}{}
	fileSet := map[string]struct{}{}
	edgeIDs := []string{}
	edgeTypes := []string{}
	evidenceFiles := []string{}
	for _, symbolID := range seed.Symbols {
		if strings.TrimSpace(symbolID) != "" {
			nodeSet["symbol:"+symbolID] = struct{}{}
		}
	}
	for _, path := range seed.Files {
		if strings.TrimSpace(path) != "" {
			fileSet[path] = struct{}{}
			nodeSet[analysisGraphFileNodeID(path)] = struct{}{}
		}
	}
	addEdge := func(id string, edgeType string, sourceID string, targetID string, evidence []string) {
		if len(edgeIDs) >= policy.MaxEdges {
			return
		}
		touches := false
		if _, ok := nodeSet["symbol:"+sourceID]; ok {
			touches = true
		}
		if _, ok := nodeSet["symbol:"+targetID]; ok {
			touches = true
		}
		if graphEdgeTouchesFiles(evidence, fileSet) {
			touches = true
		}
		if !touches {
			return
		}
		edgeIDs = append(edgeIDs, id)
		edgeTypes = append(edgeTypes, edgeType)
		evidenceFiles = append(evidenceFiles, graphFilesFromEvidenceSet(evidence, fileSet)...)
		if strings.TrimSpace(sourceID) != "" && len(nodeSet) < policy.MaxNodes {
			nodeSet["symbol:"+sourceID] = struct{}{}
		}
		if strings.TrimSpace(targetID) != "" && len(nodeSet) < policy.MaxNodes {
			nodeSet["symbol:"+targetID] = struct{}{}
		}
	}
	for _, edge := range index.CallEdges {
		addEdge(analysisGraphStableID("call", edge.SourceID, edge.TargetID, edge.Type), "call", edge.SourceID, edge.TargetID, edge.Evidence)
	}
	for _, edge := range index.References {
		addEdge(analysisGraphStableID("ref", edge.SourceID, edge.TargetID, edge.TargetPath, edge.Type), "reference", edge.SourceID, edge.TargetID, append(append([]string(nil), edge.Evidence...), edge.SourceFile, edge.TargetPath))
	}
	for _, edge := range index.BuildOwnershipEdges {
		addEdge(analysisGraphStableID("build", edge.SourceID, edge.TargetID, edge.Type), "build_ownership", edge.SourceID, edge.TargetID, edge.Evidence)
	}
	for _, edge := range index.GeneratedCodeEdges {
		addEdge(analysisGraphStableID("generated", edge.SourceFile, edge.TargetID, edge.Type), "generated_code", "", edge.TargetID, append(append([]string(nil), edge.Evidence...), edge.SourceFile))
	}
	for _, edge := range index.OverlayEdges {
		addEdge(analysisGraphStableID("overlay", edge.SourceID, edge.TargetID, edge.Type, edge.Domain), "overlay:"+edge.Type, edge.SourceID, edge.TargetID, edge.Evidence)
	}
	nodeIDs := make([]string, 0, len(nodeSet))
	for nodeID := range nodeSet {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	return AnalysisGraphNeighborhood{
		Policy:        firstNonBlankAnalysisString(policy.Mode, seed.Mode),
		SeedSymbols:   analysisUniqueStrings(seed.Symbols),
		SeedFiles:     analysisUniqueStrings(seed.Files),
		NodeIDs:       limitStrings(nodeIDs, policy.MaxNodes),
		EdgeIDs:       analysisUniqueStrings(edgeIDs),
		Paths:         analysisUniqueStrings(seed.Files),
		EdgeTypes:     analysisUniqueStrings(edgeTypes),
		EvidenceFiles: analysisUniqueStrings(evidenceFiles),
	}
}

func buildAnalysisEvidenceGraph(snapshot ProjectSnapshot, index SemanticIndexV2, unrealGraph UnrealSemanticGraph, overlay SecurityOverlaySummary, packets []EvidencePacket) AnalysisEvidenceGraph {
	graph := AnalysisEvidenceGraph{
		RunID:       index.RunID,
		GeneratedAt: time.Now(),
	}
	nodeSeen := map[string]struct{}{}
	edgeSeen := map[string]struct{}{}
	addNode := func(node AnalysisGraphNode) {
		node.ID = strings.TrimSpace(node.ID)
		node.Type = strings.TrimSpace(node.Type)
		if node.ID == "" || node.Type == "" {
			return
		}
		if _, ok := nodeSeen[node.ID]; ok {
			return
		}
		node.Tags = analysisUniqueStrings(node.Tags)
		graph.Nodes = append(graph.Nodes, node)
		nodeSeen[node.ID] = struct{}{}
	}
	addEdge := func(edge AnalysisGraphEdge) {
		edge.ID = strings.TrimSpace(edge.ID)
		edge.SourceID = strings.TrimSpace(edge.SourceID)
		edge.TargetID = strings.TrimSpace(edge.TargetID)
		edge.Type = strings.TrimSpace(edge.Type)
		if edge.ID == "" || edge.SourceID == "" || edge.TargetID == "" || edge.Type == "" {
			return
		}
		if _, ok := edgeSeen[edge.ID]; ok {
			return
		}
		edge.Evidence = analysisUniqueStrings(edge.Evidence)
		edge.PacketIDs = analysisUniqueStrings(edge.PacketIDs)
		graph.Edges = append(graph.Edges, edge)
		edgeSeen[edge.ID] = struct{}{}
	}
	packetIDsByPath := map[string][]string{}
	packetIDsBySymbol := map[string][]string{}
	requiredPackets := 0
	for _, packet := range packets {
		packetIDsByPath[packet.Path] = append(packetIDsByPath[packet.Path], packet.ID)
		if strings.TrimSpace(packet.SymbolID) != "" {
			packetIDsBySymbol[packet.SymbolID] = append(packetIDsBySymbol[packet.SymbolID], packet.ID)
		}
		if packet.Required || strings.EqualFold(packet.Category, "required") {
			requiredPackets++
		}
	}
	for _, file := range snapshot.Files {
		addNode(AnalysisGraphNode{
			ID:         analysisGraphFileNodeID(file.Path),
			Type:       "file",
			Label:      file.Path,
			Path:       file.Path,
			Confidence: "medium",
			Tags:       append([]string{}, file.ImportanceReasons...),
		})
	}
	for _, ctx := range index.BuildContexts {
		addNode(AnalysisGraphNode{
			ID:         analysisGraphBuildNodeID(ctx.ID),
			Type:       "build_context",
			Label:      firstNonBlankAnalysisString(ctx.Name, ctx.ID),
			Path:       ctx.Source,
			Confidence: firstNonBlankAnalysisString(ctx.Confidence, "medium"),
			Tags:       []string{ctx.Kind, ctx.SourceAdapter, ctx.Compiler},
		})
		for _, path := range ctx.Files {
			if strings.TrimSpace(path) == "" {
				continue
			}
			addEdge(AnalysisGraphEdge{
				ID:         analysisGraphStableID("buildctx", ctx.ID, path),
				SourceID:   analysisGraphBuildNodeID(ctx.ID),
				TargetID:   analysisGraphFileNodeID(path),
				Type:       "build_context_owns_file",
				Domain:     "build",
				Confidence: firstNonBlankAnalysisString(ctx.Confidence, "medium"),
				Evidence:   []string{path},
				PacketIDs:  packetIDsByPath[path],
			})
		}
	}
	for _, symbol := range index.Symbols {
		addNode(AnalysisGraphNode{
			ID:         analysisGraphSymbolNodeID(symbol.ID),
			Type:       "symbol",
			Label:      firstNonBlankAnalysisString(symbol.CanonicalName, symbol.Name),
			Path:       symbol.File,
			SymbolID:   symbol.ID,
			StartLine:  symbol.StartLine,
			EndLine:    symbol.EndLine,
			Confidence: "high",
			Tags:       append([]string{symbol.Kind, symbol.Language, symbol.Module}, symbol.Tags...),
		})
		if strings.TrimSpace(symbol.File) != "" {
			addEdge(AnalysisGraphEdge{
				ID:         analysisGraphStableID("contains", symbol.File, symbol.ID),
				SourceID:   analysisGraphFileNodeID(symbol.File),
				TargetID:   analysisGraphSymbolNodeID(symbol.ID),
				Type:       "file_contains_symbol",
				Domain:     "structure",
				Confidence: "high",
				Evidence:   []string{graphSourceAnchor(symbol.File, symbol.StartLine)},
				PacketIDs:  packetIDsBySymbol[symbol.ID],
			})
		}
	}
	for _, edge := range index.CallEdges {
		addEdge(AnalysisGraphEdge{
			ID:         analysisGraphStableID("call", edge.SourceID, edge.TargetID, edge.Type),
			SourceID:   analysisGraphSymbolNodeID(edge.SourceID),
			TargetID:   analysisGraphSymbolNodeID(edge.TargetID),
			Type:       "call:" + edge.Type,
			Domain:     "code",
			Confidence: firstNonBlankAnalysisString(edge.Confidence, "medium"),
			Evidence:   edge.Evidence,
			PacketIDs:  analysisUniqueStrings(append(packetIDsBySymbol[edge.SourceID], packetIDsBySymbol[edge.TargetID]...)),
		})
	}
	for _, edge := range index.References {
		addEdge(AnalysisGraphEdge{
			ID:         analysisGraphStableID("ref", edge.SourceID, edge.TargetID, edge.TargetPath, edge.Type),
			SourceID:   firstNonBlankAnalysisString(analysisGraphSymbolNodeID(edge.SourceID), analysisGraphFileNodeID(edge.SourceFile)),
			TargetID:   firstNonBlankAnalysisString(analysisGraphSymbolNodeID(edge.TargetID), analysisGraphFileNodeID(edge.TargetPath)),
			Type:       "reference:" + edge.Type,
			Domain:     "code",
			Confidence: firstNonBlankAnalysisString(edge.Confidence, "medium"),
			Evidence:   append(append([]string(nil), edge.Evidence...), edge.SourceFile, edge.TargetPath),
			PacketIDs:  analysisUniqueStrings(append(packetIDsByPath[edge.SourceFile], packetIDsByPath[edge.TargetPath]...)),
		})
	}
	for _, edge := range index.BuildOwnershipEdges {
		addEdge(AnalysisGraphEdge{
			ID:         analysisGraphStableID("build", edge.SourceID, edge.TargetID, edge.Type),
			SourceID:   analysisGraphSymbolNodeID(edge.SourceID),
			TargetID:   analysisGraphSymbolNodeID(edge.TargetID),
			Type:       "build_ownership:" + edge.Type,
			Domain:     "build",
			Confidence: firstNonBlankAnalysisString(edge.Confidence, "medium"),
			Evidence:   edge.Evidence,
			PacketIDs:  analysisUniqueStrings(append(packetIDsBySymbol[edge.SourceID], packetIDsBySymbol[edge.TargetID]...)),
		})
	}
	for _, edge := range index.GeneratedCodeEdges {
		addEdge(AnalysisGraphEdge{
			ID:         analysisGraphStableID("generated", edge.SourceFile, edge.TargetID, edge.Type),
			SourceID:   analysisGraphFileNodeID(edge.SourceFile),
			TargetID:   analysisGraphSymbolNodeID(edge.TargetID),
			Type:       "generated_code:" + edge.Type,
			Domain:     "generated",
			Confidence: firstNonBlankAnalysisString(edge.Confidence, "medium"),
			Evidence:   append(append([]string(nil), edge.Evidence...), edge.SourceFile),
			PacketIDs:  analysisUniqueStrings(append(packetIDsByPath[edge.SourceFile], packetIDsBySymbol[edge.TargetID]...)),
		})
	}
	for _, edge := range index.OverlayEdges {
		addEdge(AnalysisGraphEdge{
			ID:         analysisGraphStableID("overlay", edge.SourceID, edge.TargetID, edge.Type, edge.Domain),
			SourceID:   analysisGraphSymbolNodeID(edge.SourceID),
			TargetID:   analysisGraphSymbolNodeID(edge.TargetID),
			Type:       "semantic_overlay:" + edge.Type,
			Domain:     edge.Domain,
			Confidence: "medium",
			Evidence:   edge.Evidence,
			PacketIDs:  analysisUniqueStrings(append(packetIDsBySymbol[edge.SourceID], packetIDsBySymbol[edge.TargetID]...)),
		})
	}
	for _, node := range overlay.Nodes {
		addNode(AnalysisGraphNode{
			ID:         analysisGraphOverlayNodeID(node.ID),
			Type:       "security_overlay:" + node.Type,
			Label:      node.Label,
			Path:       node.Path,
			SymbolID:   node.SymbolID,
			Confidence: node.Confidence,
			Tags:       node.Tags,
		})
	}
	for _, edge := range overlay.Edges {
		addEdge(AnalysisGraphEdge{
			ID:         analysisGraphStableID("security_overlay", edge.ID),
			SourceID:   analysisGraphOverlayNodeID(edge.SourceID),
			TargetID:   analysisGraphOverlayNodeID(edge.TargetID),
			Type:       "security_overlay:" + edge.Type,
			Domain:     edge.Surface,
			Confidence: edge.Confidence,
			Evidence:   edge.Evidence,
			PacketIDs:  graphPacketIDsForEvidence(packetIDsByPath, edge.Evidence),
		})
	}
	_ = unrealGraph
	graph.Metrics = buildAnalysisEvidenceGraphMetrics(graph, requiredPackets)
	return graph
}

func enrichAnalysisShardsWithGraph(snapshot ProjectSnapshot, index SemanticIndexV2, graph AnalysisEvidenceGraph, overlay SecurityOverlaySummary, shards []AnalysisShard) []AnalysisShard {
	out := append([]AnalysisShard(nil), shards...)
	for i := range out {
		seedSymbols := graphSeedSymbolsForShard(index, out[i])
		out[i].SeedSymbols = analysisUniqueStrings(append(out[i].SeedSymbols, seedSymbols...))
		neighborhood := graphNeighborhoodForShard(graph, out[i], out[i].SeedSymbols)
		out[i].GraphNeighborhood = &neighborhood
		out[i].MissingEvidenceClasses = analysisUniqueStrings(append(out[i].MissingEvidenceClasses, graphMissingEvidenceClassesForShard(out[i])...))
		if len(out[i].RequiredPacketIDs) == 0 {
			out[i].RequiredPacketIDs = graphRequiredPacketIDs(buildEvidencePacketsForShard(snapshot, out[i], analysisEvidencePacketDefaultLimit))
		}
		out[i].SymbolFingerprint = buildShardSymbolFingerprint(index, out[i])
		out[i].EdgeFingerprint = buildShardEdgeFingerprint(graph, out[i])
		out[i].BuildContextFingerprint = buildShardBuildContextFingerprint(snapshot, index, out[i])
		out[i].OverlayFingerprint = buildShardOverlayFingerprint(overlay, out[i])
		out[i].DerivedGraphFingerprint = buildShardGraphFingerprint(out[i])
		out[i].GraphFingerprint = out[i].DerivedGraphFingerprint
		out[i].Fingerprint = buildCombinedShardFingerprint(out[i])
	}
	return out
}

func buildAnalysisGraphShardArtifact(snapshot ProjectSnapshot, index SemanticIndexV2, shards []AnalysisShard) AnalysisGraphShardArtifact {
	summary := []string{}
	for _, shard := range shards {
		if strings.TrimSpace(shard.GraphFingerprint) == "" {
			continue
		}
		summary = append(summary, fmt.Sprintf("%s nodes=%d edges=%d graph=%s", firstNonBlankAnalysisString(shard.Name, shard.ID), graphNeighborhoodNodeCount(shard), graphNeighborhoodEdgeCount(shard), shortAnalysisHash(shard.GraphFingerprint)))
	}
	return AnalysisGraphShardArtifact{
		GeneratedAt: time.Now(),
		Mode:        snapshot.AnalysisMode,
		Seeds:       selectGraphSeeds(snapshot, index, snapshot.AnalysisMode),
		Shards:      shards,
		Summary:     limitStrings(summary, 48),
	}
}

func buildAnalysisGraphReuseReport(previousRun *ProjectAnalysisRun, shards []AnalysisShard) AnalysisGraphReuseReport {
	report := AnalysisGraphReuseReport{
		GeneratedAt:   time.Now(),
		TotalShards:   len(shards),
		Decisions:     []AnalysisGraphReuseDecision{},
		PreviousRunID: "",
	}
	previousByKey := map[string]AnalysisShard{}
	if previousRun != nil {
		report.PreviousRunID = previousRun.Summary.RunID
		for _, shard := range previousRun.Shards {
			previousByKey[primaryFilesKey(shard.PrimaryFiles)] = shard
		}
	}
	for _, shard := range shards {
		decision := AnalysisGraphReuseDecision{
			ShardID:                 shard.ID,
			ShardName:               shard.Name,
			CacheStatus:             shard.CacheStatus,
			InvalidationReason:      shard.InvalidationReason,
			InvalidationClass:       shard.InvalidationClass,
			InvalidationSignals:     append([]string(nil), shard.InvalidationSignals...),
			InvalidationChanges:     append([]InvalidationChange(nil), shard.InvalidationChanges...),
			FileFingerprint:         shard.PrimaryFingerprint,
			SymbolFingerprint:       shard.SymbolFingerprint,
			EdgeFingerprint:         shard.EdgeFingerprint,
			BuildContextFingerprint: shard.BuildContextFingerprint,
			OverlayFingerprint:      shard.OverlayFingerprint,
			GraphFingerprint:        shard.GraphFingerprint,
		}
		if previous, ok := previousByKey[primaryFilesKey(shard.PrimaryFiles)]; ok {
			if change := compareSymbolIncrementalState(previous, shard); strings.TrimSpace(change.Kind) != "" {
				decision.InvalidationChanges = append(decision.InvalidationChanges, change)
				if strings.TrimSpace(decision.InvalidationClass) == "" {
					decision.InvalidationClass = change.Kind
				}
				if strings.TrimSpace(decision.InvalidationReason) == "" || strings.EqualFold(decision.InvalidationReason, "recomputed") {
					decision.InvalidationReason = change.Kind
				}
				if strings.Contains(change.Kind, "symbol") || strings.Contains(change.Kind, "edge") || strings.Contains(change.Kind, "overlay") {
					report.SymbolScopedInvalidation++
				}
			}
		}
		if strings.EqualFold(shard.CacheStatus, "reused") {
			report.ReusedShards++
		} else {
			report.RecomputedShards++
		}
		report.Decisions = append(report.Decisions, decision)
	}
	return report
}

func compareSymbolIncrementalState(previous AnalysisShard, current AnalysisShard) InvalidationChange {
	checks := []struct {
		Kind   string
		Before string
		After  string
	}{
		{"symbol_changed", previous.SymbolFingerprint, current.SymbolFingerprint},
		{"edge_changed", previous.EdgeFingerprint, current.EdgeFingerprint},
		{"build_context_changed", previous.BuildContextFingerprint, current.BuildContextFingerprint},
		{"overlay_changed", previous.OverlayFingerprint, current.OverlayFingerprint},
		{"graph_changed", previous.GraphFingerprint, current.GraphFingerprint},
	}
	for _, check := range checks {
		if strings.TrimSpace(check.Before) == "" && strings.TrimSpace(check.After) == "" {
			continue
		}
		if check.Before != check.After {
			return InvalidationChange{
				Kind:    check.Kind,
				Scope:   "symbol_graph",
				Owner:   firstNonBlankAnalysisString(current.ID, current.Name),
				Subject: firstNonBlankAnalysisString(current.Name, current.ID),
				Before:  check.Before,
				After:   check.After,
				Source:  "analysis_graph_sharding",
			}
		}
	}
	return InvalidationChange{}
}

func buildShardGraphFingerprint(shard AnalysisShard) string {
	parts := []string{
		"symbol=" + shard.SymbolFingerprint,
		"edge=" + shard.EdgeFingerprint,
		"build=" + shard.BuildContextFingerprint,
		"overlay=" + shard.OverlayFingerprint,
		"missing=" + strings.Join(analysisUniqueStrings(shard.MissingEvidenceClasses), "|"),
	}
	if shard.GraphNeighborhood != nil {
		parts = append(parts,
			"nodes="+strings.Join(analysisUniqueStrings(shard.GraphNeighborhood.NodeIDs), "|"),
			"edges="+strings.Join(analysisUniqueStrings(shard.GraphNeighborhood.EdgeIDs), "|"),
		)
	}
	return hashAnalysisText(strings.Join(parts, "\n"))
}

func buildCombinedShardFingerprint(shard AnalysisShard) string {
	parts := []string{
		shard.PrimaryFingerprint,
		shard.ReferenceFingerprint,
		shard.PrimarySemanticFingerprint,
		shard.ReferenceSemanticFingerprint,
		shard.GraphFingerprint,
	}
	return hashAnalysisText(strings.Join(parts, "\n"))
}

func buildShardSymbolFingerprint(index SemanticIndexV2, shard AnalysisShard) string {
	fileSet := graphFileSet(append(append([]string(nil), shard.PrimaryFiles...), shard.ReferenceFiles...))
	seedSet := graphStringSet(shard.SeedSymbols)
	lines := []string{}
	for _, symbol := range index.Symbols {
		_, fileHit := fileSet[symbol.File]
		_, seedHit := seedSet[symbol.ID]
		if !fileHit && !seedHit {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s|%d-%d|%s", symbol.ID, symbol.Name, symbol.Kind, symbol.File, symbol.Signature, symbol.StartLine, symbol.EndLine, strings.Join(analysisUniqueStrings(symbol.Tags), "|")))
	}
	sort.Strings(lines)
	return hashAnalysisText(strings.Join(lines, "\n"))
}

func buildShardEdgeFingerprint(graph AnalysisEvidenceGraph, shard AnalysisShard) string {
	edgeSet := map[string]struct{}{}
	if shard.GraphNeighborhood != nil {
		for _, edgeID := range shard.GraphNeighborhood.EdgeIDs {
			edgeSet[edgeID] = struct{}{}
		}
	}
	lines := []string{}
	for _, edge := range graph.Edges {
		if _, ok := edgeSet[edge.ID]; !ok && !analysisGraphEdgeTouchesShard(edge, shard) {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s|%s", edge.ID, edge.SourceID, edge.TargetID, edge.Type, edge.Domain, strings.Join(analysisUniqueStrings(edge.Evidence), "|")))
	}
	sort.Strings(lines)
	return hashAnalysisText(strings.Join(lines, "\n"))
}

func buildShardBuildContextFingerprint(snapshot ProjectSnapshot, index SemanticIndexV2, shard AnalysisShard) string {
	fileSet := graphFileSet(append(append([]string(nil), shard.PrimaryFiles...), shard.ReferenceFiles...))
	lines := []string{}
	for _, ctx := range index.BuildContexts {
		if !buildContextTouchesFiles(ctx, fileSet) {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s", ctx.ID, ctx.Kind, ctx.Project, ctx.Target, ctx.Module, ctx.Compiler, strings.Join(analysisUniqueStrings(ctx.IncludePaths), "|"), strings.Join(analysisUniqueStrings(ctx.Defines), "|")))
	}
	if len(lines) == 0 {
		for _, ctx := range snapshot.BuildContexts {
			touches := false
			for _, path := range ctx.Files {
				if _, ok := fileSet[path]; ok {
					touches = true
					break
				}
			}
			if !touches {
				continue
			}
			lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s", ctx.ID, ctx.Name, ctx.Project, ctx.Target, strings.Join(analysisUniqueStrings(ctx.Files), "|")))
		}
	}
	sort.Strings(lines)
	return hashAnalysisText(strings.Join(lines, "\n"))
}

func buildShardOverlayFingerprint(overlay SecurityOverlaySummary, shard AnalysisShard) string {
	fileSet := graphFileSet(append(append([]string(nil), shard.PrimaryFiles...), shard.ReferenceFiles...))
	lines := []string{}
	for _, edge := range overlay.Edges {
		if !graphEdgeTouchesFiles(edge.Evidence, fileSet) {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s|%s|%s|%s|%s|%s", edge.ID, edge.SourceID, edge.TargetID, edge.Type, edge.Surface, edge.ValidationState))
	}
	for _, node := range overlay.Nodes {
		if _, ok := fileSet[node.Path]; !ok {
			continue
		}
		lines = append(lines, fmt.Sprintf("node|%s|%s|%s|%s", node.ID, node.Type, node.Path, strings.Join(analysisUniqueStrings(node.Tags), "|")))
	}
	sort.Strings(lines)
	return hashAnalysisText(strings.Join(lines, "\n"))
}

func graphNeighborhoodForShard(graph AnalysisEvidenceGraph, shard AnalysisShard, seedSymbols []string) AnalysisGraphNeighborhood {
	fileSet := graphFileSet(append(append([]string(nil), shard.PrimaryFiles...), shard.ReferenceFiles...))
	nodeSet := map[string]struct{}{}
	edgeIDs := []string{}
	edgeTypes := []string{}
	evidenceFiles := []string{}
	for path := range fileSet {
		nodeSet[analysisGraphFileNodeID(path)] = struct{}{}
	}
	for _, symbolID := range seedSymbols {
		nodeSet[analysisGraphSymbolNodeID(symbolID)] = struct{}{}
	}
	nodePath := map[string]string{}
	for _, node := range graph.Nodes {
		nodePath[node.ID] = node.Path
		if _, ok := fileSet[node.Path]; ok {
			nodeSet[node.ID] = struct{}{}
		}
	}
	for _, edge := range graph.Edges {
		touches := false
		if _, ok := nodeSet[edge.SourceID]; ok {
			touches = true
		}
		if _, ok := nodeSet[edge.TargetID]; ok {
			touches = true
		}
		if graphEdgeTouchesFiles(edge.Evidence, fileSet) {
			touches = true
		}
		if !touches {
			continue
		}
		edgeIDs = append(edgeIDs, edge.ID)
		edgeTypes = append(edgeTypes, edge.Type)
		evidenceFiles = append(evidenceFiles, graphFilesFromEvidenceSet(edge.Evidence, fileSet)...)
		if path := nodePath[edge.SourceID]; path != "" {
			if _, ok := fileSet[path]; ok {
				nodeSet[edge.SourceID] = struct{}{}
			}
		}
		if path := nodePath[edge.TargetID]; path != "" {
			if _, ok := fileSet[path]; ok {
				nodeSet[edge.TargetID] = struct{}{}
			}
		}
	}
	nodeIDs := make([]string, 0, len(nodeSet))
	for nodeID := range nodeSet {
		nodeIDs = append(nodeIDs, nodeID)
	}
	sort.Strings(nodeIDs)
	return AnalysisGraphNeighborhood{
		Policy:        normalizeProjectAnalysisMode(""),
		SeedSymbols:   analysisUniqueStrings(seedSymbols),
		SeedFiles:     append([]string(nil), shard.PrimaryFiles...),
		NodeIDs:       limitStrings(nodeIDs, 160),
		EdgeIDs:       limitStrings(analysisUniqueStrings(edgeIDs), 220),
		Paths:         analysisUniqueStrings(append(append([]string(nil), shard.PrimaryFiles...), shard.ReferenceFiles...)),
		EdgeTypes:     analysisUniqueStrings(edgeTypes),
		EvidenceFiles: analysisUniqueStrings(evidenceFiles),
	}
}

func graphSeedSymbolsForShard(index SemanticIndexV2, shard AnalysisShard) []string {
	fileSet := graphFileSet(shard.PrimaryFiles)
	out := append([]string(nil), shard.SeedSymbols...)
	for _, symbol := range index.Symbols {
		if _, ok := fileSet[symbol.File]; !ok {
			continue
		}
		if graphSymbolMatchesShardClass(symbol, shard.Name) || len(out) < 12 {
			out = append(out, symbol.ID)
		}
	}
	return analysisUniqueStrings(limitStrings(out, 24))
}

func graphMissingEvidenceClassesForSeed(seed GraphShardSeed) []string {
	if strings.TrimSpace(seed.EvidenceClass) == "" {
		return nil
	}
	if len(seed.Files) == 0 && len(seed.Symbols) == 0 {
		return []string{seed.EvidenceClass}
	}
	return nil
}

func graphMissingEvidenceClassesForShard(shard AnalysisShard) []string {
	missing := append([]string(nil), shard.MissingEvidenceClasses...)
	if len(shard.SeedSymbols) == 0 && strings.EqualFold(shard.Type, "graph_community") {
		missing = append(missing, "seed_symbol")
	}
	if shard.GraphNeighborhood == nil || len(shard.GraphNeighborhood.EdgeIDs) == 0 {
		missing = append(missing, "graph_edge")
	}
	return analysisUniqueStrings(missing)
}

func graphShardRequiredEvidenceForClass(class string) []string {
	required := []string{"required evidence packets for selected seed symbols", "graph neighborhood edge evidence", "source anchors for each high-confidence claim"}
	switch class {
	case "security_driver":
		required = append(required, "driver entry, device creation, and dispatch registration evidence")
	case "security_ioctl":
		required = append(required, "IOCTL dispatcher and input validation evidence")
	case "callback_registration":
		required = append(required, "callback registration and runtime activation evidence")
	case "security_handles", "security_memory":
		required = append(required, "handle or memory access sink evidence")
	case "security_rpc", "unreal_network":
		required = append(required, "authority boundary and command/RPC dispatch evidence")
	case "asset_config":
		required = append(required, "asset/config trust boundary evidence")
	case "build_context":
		required = append(required, "build ownership and include resolution evidence")
	case "generated_artifact":
		required = append(required, "generated artifact ownership evidence")
	}
	return analysisUniqueStrings(required)
}

func graphShardSuccessCriteriaForClass(class string) []string {
	criteria := []string{"Required packets are cited by high-confidence claims.", "Unsupported graph gaps are recorded as unknowns or missing evidence classes."}
	switch class {
	case "startup":
		criteria = append(criteria, "Startup handoff is separated from runtime service, driver, or callback activation.")
	case "security_ioctl":
		criteria = append(criteria, "Input source, dispatcher, validation, and privileged sink are described separately.")
	case "callback_registration":
		criteria = append(criteria, "Registration is not confused with initialization unless direct call evidence proves it.")
	case "asset_config":
		criteria = append(criteria, "Config defaults, asset bindings, and runtime load points stay separate.")
	}
	return analysisUniqueStrings(criteria)
}

func graphShardObjectiveForClass(class string) string {
	switch class {
	case "startup":
		return "Analyze the graph-selected startup community and its runtime handoff evidence."
	case "security_driver":
		return "Analyze the graph-selected driver entry, device setup, and dispatch registration community."
	case "security_ioctl":
		return "Analyze the graph-selected IOCTL dispatcher, validation, and privileged handler community."
	case "callback_registration":
		return "Analyze callback/filter registration and runtime activation evidence."
	case "security_handles":
		return "Analyze handle access paths with source-to-sink evidence."
	case "security_memory":
		return "Analyze memory access paths with source-to-sink evidence."
	case "security_rpc":
		return "Analyze service, RPC, IPC, or command boundary evidence."
	case "unreal_network":
		return "Analyze Unreal RPC authority and replication boundary evidence."
	case "asset_config":
		return "Analyze asset and config trust-boundary evidence."
	case "build_context":
		return "Analyze build ownership, include resolution, and compile context evidence."
	case "generated_artifact":
		return "Analyze generated artifact ownership and derived-source evidence."
	default:
		return "Analyze the graph-selected evidence community."
	}
}

func graphShardNameForClass(class string) string {
	switch class {
	case "build_context":
		return "build_graph"
	case "unreal_network":
		return "unreal_network"
	default:
		return class
	}
}

func buildAnalysisEvidenceGraphMetrics(graph AnalysisEvidenceGraph, requiredPackets int) AnalysisEvidenceGraphMetrics {
	edgeTypes := []string{}
	metrics := AnalysisEvidenceGraphMetrics{
		NodeCount:      len(graph.Nodes),
		EdgeCount:      len(graph.Edges),
		RequiredPacket: requiredPackets,
	}
	for _, node := range graph.Nodes {
		switch {
		case node.Type == "file":
			metrics.FileNodes++
		case node.Type == "symbol":
			metrics.SymbolNodes++
		case strings.Contains(node.Type, "build"):
			metrics.BuildNodes++
		case strings.Contains(node.Type, "security_overlay"):
			metrics.OverlayNodes++
		}
	}
	for _, edge := range graph.Edges {
		edgeTypes = append(edgeTypes, edge.Type)
	}
	metrics.EdgeTypes = analysisUniqueStrings(edgeTypes)
	return metrics
}

func normalizeGraphSeeds(seeds []GraphShardSeed) []GraphShardSeed {
	out := []GraphShardSeed{}
	for _, seed := range seeds {
		seed.Files = analysisUniqueStrings(seed.Files)
		seed.Symbols = analysisUniqueStrings(seed.Symbols)
		seed.EdgeIDs = analysisUniqueStrings(seed.EdgeIDs)
		if len(seed.Files) == 0 && len(seed.Symbols) == 0 {
			continue
		}
		out = append(out, seed)
	}
	sort.SliceStable(out, func(i int, j int) bool {
		if out[i].Priority == out[j].Priority {
			if out[i].Class == out[j].Class {
				return out[i].ID < out[j].ID
			}
			return out[i].Class < out[j].Class
		}
		return out[i].Priority < out[j].Priority
	})
	return out
}

func graphShardClassOrder(mode string) []string {
	switch normalizeProjectAnalysisMode(mode) {
	case "security", "surface":
		return []string{"security_driver", "security_ioctl", "callback_registration", "security_handles", "security_memory", "security_rpc", "integrity_security", "unreal_network", "startup", "build_context", "asset_config", "unreal_gameplay", "unreal_ui", "unreal_ability", "generated_artifact"}
	case "trace":
		return []string{"startup", "unreal_network", "build_context", "unreal_gameplay", "asset_config", "integrity_security", "unreal_ui", "unreal_ability", "security_ioctl", "callback_registration", "security_rpc", "generated_artifact", "security_handles", "security_memory"}
	case "impact":
		return []string{"build_context", "startup", "asset_config", "unreal_network", "integrity_security", "unreal_gameplay", "unreal_ui", "unreal_ability", "generated_artifact", "security_ioctl", "callback_registration", "security_handles", "security_memory", "security_rpc"}
	default:
		return []string{"startup", "build_context", "unreal_network", "unreal_ui", "unreal_ability", "asset_config", "integrity_security", "unreal_gameplay", "security_driver", "security_ioctl", "callback_registration", "security_handles", "security_memory", "security_rpc", "generated_artifact"}
	}
}

func graphClassForOverlayEdge(edge OverlayEdge) string {
	corpus := strings.ToLower(strings.Join([]string{edge.Type, edge.Domain, strings.Join(edge.Evidence, " ")}, " "))
	switch {
	case containsAny(corpus, "ioctl", "irp", "devicecontrol"):
		return "security_ioctl"
	case containsAny(corpus, "callback", "notify", "filter"):
		return "callback_registration"
	case containsAny(corpus, "memory", "handle", "process"):
		if containsAny(corpus, "handle", "process") {
			return "security_handles"
		}
		return "security_memory"
	case containsAny(corpus, "rpc", "ipc", "authority", "server", "client"):
		return "security_rpc"
	case containsAny(corpus, "asset", "config"):
		return "asset_config"
	case containsAny(corpus, "build", "generated"):
		return "build_context"
	case containsAny(corpus, "security", "integrity", "tamper"):
		return "integrity_security"
	default:
		return ""
	}
}

func graphRankedFiles(snapshot ProjectSnapshot, files []string, symbols []string) []string {
	files = graphExistingFiles(snapshot, files)
	if len(files) <= 1 {
		return files
	}
	symbolBoost := map[string]int{}
	for _, symbolID := range symbols {
		for _, symbol := range snapshot.StructuralIndex.Symbols {
			if symbol.ID == symbolID && strings.TrimSpace(symbol.File) != "" {
				symbolBoost[symbol.File] += 20
			}
		}
	}
	sort.SliceStable(files, func(i int, j int) bool {
		left := snapshot.FilesByPath[files[i]].ImportanceScore + symbolBoost[files[i]]
		right := snapshot.FilesByPath[files[j]].ImportanceScore + symbolBoost[files[j]]
		if left == right {
			return files[i] < files[j]
		}
		return left > right
	})
	return files
}

func graphExistingFiles(snapshot ProjectSnapshot, files []string) []string {
	out := []string{}
	for _, path := range files {
		path = filepathSlashOrEmpty(path)
		if strings.TrimSpace(path) == "" {
			continue
		}
		if _, ok := snapshot.FilesByPath[path]; ok {
			out = append(out, path)
		}
	}
	return analysisUniqueStrings(out)
}

func graphFilesForSymbolIDs(index SemanticIndexV2, symbols []string) []string {
	symbolSet := graphStringSet(symbols)
	out := []string{}
	for _, symbol := range index.Symbols {
		if _, ok := symbolSet[symbol.ID]; ok && strings.TrimSpace(symbol.File) != "" {
			out = append(out, symbol.File)
		}
	}
	return analysisUniqueStrings(out)
}

func graphSymbolsForFiles(index SemanticIndexV2, files []string) []string {
	fileSet := graphFileSet(files)
	out := []string{}
	for _, symbol := range index.Symbols {
		if _, ok := fileSet[symbol.File]; ok {
			out = append(out, symbol.ID)
		}
	}
	return analysisUniqueStrings(out)
}

func graphSymbolMatchesShardClass(symbol SymbolRecord, shardName string) bool {
	corpus := strings.ToLower(strings.Join([]string{symbol.ID, symbol.Name, symbol.CanonicalName, symbol.Kind, symbol.File, strings.Join(symbol.Tags, " "), shardName}, " "))
	switch {
	case containsAny(strings.ToLower(shardName), "ioctl"):
		return containsAny(corpus, "ioctl", "devicecontrol", "irp", "ctl_code")
	case containsAny(strings.ToLower(shardName), "callback"):
		return containsAny(corpus, "callback", "obregister", "psset", "fltregister", "notify")
	case containsAny(strings.ToLower(shardName), "handle", "memory"):
		return containsAny(corpus, "handle", "memory", "mmcopy", "readprocessmemory", "writeprocessmemory", "scan")
	case containsAny(strings.ToLower(shardName), "rpc"):
		return containsAny(corpus, "rpc", "ipc", "pipe", "server", "client")
	default:
		return true
	}
}

func graphFilesFromEvidence(snapshot ProjectSnapshot, evidence []string) []string {
	out := []string{}
	for _, item := range evidence {
		clean := cleanEvidencePath(item)
		for path := range snapshot.FilesByPath {
			if clean == path || strings.Contains(clean, path) || strings.Contains(item, path) {
				out = append(out, path)
			}
		}
	}
	return analysisUniqueStrings(out)
}

func graphFilesFromEvidenceSet(evidence []string, fileSet map[string]struct{}) []string {
	out := []string{}
	for _, item := range evidence {
		clean := cleanEvidencePath(item)
		for path := range fileSet {
			if clean == path || strings.Contains(clean, path) || strings.Contains(item, path) {
				out = append(out, path)
			}
		}
	}
	return analysisUniqueStrings(out)
}

func graphPacketIDsForEvidence(packetIDsByPath map[string][]string, evidence []string) []string {
	out := []string{}
	for _, item := range evidence {
		clean := cleanEvidencePath(item)
		for path, packetIDs := range packetIDsByPath {
			if clean == path || strings.Contains(clean, path) || strings.Contains(item, path) {
				out = append(out, packetIDs...)
			}
		}
	}
	return analysisUniqueStrings(out)
}

func graphEdgeTouchesFiles(evidence []string, fileSet map[string]struct{}) bool {
	return len(graphFilesFromEvidenceSet(evidence, fileSet)) > 0
}

func analysisGraphEdgeTouchesShard(edge AnalysisGraphEdge, shard AnalysisShard) bool {
	fileSet := graphFileSet(append(append([]string(nil), shard.PrimaryFiles...), shard.ReferenceFiles...))
	return graphEdgeTouchesFiles(edge.Evidence, fileSet)
}

func graphFileSet(files []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, path := range files {
		path = filepathSlashOrEmpty(path)
		if strings.TrimSpace(path) != "" {
			out[path] = struct{}{}
		}
	}
	return out
}

func graphStringSet(values []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func graphMapKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func graphSumLines(snapshot ProjectSnapshot, files []string) int {
	total := 0
	for _, path := range files {
		total += snapshot.FilesByPath[path].LineCount
	}
	return total
}

func graphChunkRemainingFiles(files []ScannedFile, desired int) [][]ScannedFile {
	if desired <= 1 || len(files) <= 1 {
		return [][]ScannedFile{files}
	}
	chunks := make([][]ScannedFile, desired)
	for i, file := range files {
		index := i % desired
		chunks[index] = append(chunks[index], file)
	}
	out := [][]ScannedFile{}
	for _, chunk := range chunks {
		if len(chunk) > 0 {
			out = append(out, chunk)
		}
	}
	return out
}

func analysisGraphStableID(prefix string, parts ...string) string {
	clean := []string{strings.TrimSpace(prefix)}
	for _, part := range parts {
		clean = append(clean, strings.TrimSpace(part))
	}
	return strings.TrimSpace(prefix) + "-" + shortAnalysisHash(hashAnalysisText(strings.Join(clean, "\x00")))
}

func shortAnalysisHash(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 12 {
		return value[:12]
	}
	return value
}

func analysisGraphFileNodeID(path string) string {
	path = filepathSlashOrEmpty(path)
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return "file:" + path
}

func analysisGraphSymbolNodeID(symbolID string) string {
	symbolID = strings.TrimSpace(symbolID)
	if symbolID == "" {
		return ""
	}
	return "symbol:" + symbolID
}

func analysisGraphBuildNodeID(buildContextID string) string {
	buildContextID = strings.TrimSpace(buildContextID)
	if buildContextID == "" {
		return ""
	}
	return "build:" + buildContextID
}

func analysisGraphOverlayNodeID(nodeID string) string {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return ""
	}
	if strings.HasPrefix(nodeID, "security:") {
		return nodeID
	}
	return "security:" + nodeID
}

func graphSourceAnchor(path string, line int) string {
	path = filepathSlashOrEmpty(path)
	if path == "" {
		return ""
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", path, line)
	}
	return path
}

func graphNeighborhoodNodeCount(shard AnalysisShard) int {
	if shard.GraphNeighborhood == nil {
		return 0
	}
	return len(shard.GraphNeighborhood.NodeIDs)
}

func graphNeighborhoodEdgeCount(shard AnalysisShard) int {
	if shard.GraphNeighborhood == nil {
		return 0
	}
	return len(shard.GraphNeighborhood.EdgeIDs)
}

func renderGraphNeighborhoodForPrompt(shard AnalysisShard, limit int) string {
	if shard.GraphNeighborhood == nil {
		return ""
	}
	if limit <= 0 {
		limit = 12
	}
	var b strings.Builder
	b.WriteString("Graph-selected evidence neighborhood:\n")
	if len(shard.SeedSymbols) > 0 {
		fmt.Fprintf(&b, "- seed_symbols: %s\n", strings.Join(limitStrings(shard.SeedSymbols, limit), ", "))
	}
	if len(shard.RequiredPacketIDs) > 0 {
		fmt.Fprintf(&b, "- required_packet_ids: %s\n", strings.Join(limitStrings(shard.RequiredPacketIDs, limit), ", "))
	}
	if len(shard.GraphNeighborhood.EdgeTypes) > 0 {
		fmt.Fprintf(&b, "- edge_types: %s\n", strings.Join(limitStrings(shard.GraphNeighborhood.EdgeTypes, limit), ", "))
	}
	if len(shard.GraphNeighborhood.EdgeIDs) > 0 {
		fmt.Fprintf(&b, "- edge_ids: %s\n", strings.Join(limitStrings(shard.GraphNeighborhood.EdgeIDs, limit), ", "))
	}
	if len(shard.MissingEvidenceClasses) > 0 {
		fmt.Fprintf(&b, "- missing_evidence_classes: %s\n", strings.Join(limitStrings(shard.MissingEvidenceClasses, limit), ", "))
	}
	if strings.TrimSpace(shard.GraphFingerprint) != "" {
		fmt.Fprintf(&b, "- graph_fingerprint: %s\n", shortAnalysisHash(shard.GraphFingerprint))
	}
	return strings.TrimSpace(b.String())
}
