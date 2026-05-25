package main

import "strings"

func (p turnToolExposurePlan) modelToolDefinitions(registry *ToolRegistry, provider string, model string) []ToolDefinition {
	if registry == nil {
		return nil
	}
	defs := registry.DefinitionsExcluding(p.DisabledTools)
	return adaptToolDefinitionsForImageDetailSupport(defs, provider, model)
}

func (p turnToolExposurePlan) toolDisabled(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return true
	}
	return p.DisabledTools[name]
}
