package main

import (
	"encoding/json"
	"path/filepath"
	"sort"
)

// SARIF v2.1.0 最小合规输出

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifMessage   `json:"shortDescription"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLoc        `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLoc struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func relURI(root, file string) string {
	abs := file
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, file)
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil {
		return file
	}
	return filepath.ToSlash(rel)
}

func renderSARIF(rulesPath, root string, findings []*Finding, e *Engine, funcCount int) []byte {
	ruleSeen := map[string]bool{}
	var rules []sarifRule
	for _, s := range e.rules.Sinks {
		if ruleSeen[s.ID] {
			continue
		}
		ruleSeen[s.ID] = true
		desc := s.Desc
		if desc == "" {
			desc = s.ID
		}
		rules = append(rules, sarifRule{
			ID:               s.ID,
			Name:             s.ID,
			ShortDescription: sarifMessage{Text: desc},
			Properties:       map[string]any{"security-severity": "8.1"},
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	var results []sarifResult
	seen := map[string]bool{}
	for _, f := range findings {
		uri := relURI(root, f.File)
		key := f.RuleID + "|" + uri + "|" + itoa(f.Line)
		if seen[key] {
			continue // 同位置同规则只保留一条（不同污点源不重复报）
		}
		seen[key] = true
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   "error",
			Message: sarifMessage{Text: "污点数据（源: " + f.Origin + "）未经充分净化到达汇聚点 " + f.RuleID},
			Locations: []sarifLoc{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: uri},
					Region:           sarifRegion{StartLine: f.Line},
				},
			}},
			PartialFingerprints: map[string]string{
				"primaryLocationLineHash": f.File + ":" + itoa(f.Line) + ":" + f.RuleID,
			},
		})
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "go-taint-ir-analyzer",
				Version:        "1.0.0",
				InformationURI: "internal://security/taint-analyzer",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	data, _ := json.MarshalIndent(log, "", "  ")
	return data
}

// renderLegacyJSON 兼容 eval.py 的旧格式（路径相对分析根）
func renderLegacyJSON(root string, findings []*Finding) []byte {
	type item struct {
		File string `json:"file"`
		Line int    `json:"line"`
		Rule string `json:"rule"`
	}
	var items []item
	seen := map[string]bool{}
	for _, f := range findings {
		uri := relURI(root, f.File)
		key := f.RuleID + "|" + uri + "|" + itoa(f.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		items = append(items, item{File: uri, Line: f.Line, Rule: f.RuleID})
	}
	data, _ := json.MarshalIndent(map[string]any{"findings": items}, "", "  ")
	return data
}
