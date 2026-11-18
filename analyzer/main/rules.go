package main

import (
	"encoding/json"
	"os"
)

type SourceRule struct {
	ID                  string   `json:"id"`
	Pkg                 string   `json:"pkg"`
	Name                string   `json:"name"`
	Method              string   `json:"method"`
	Receiver            string   `json:"receiver"`
	Chain               []string `json:"chain"`
	Names               []string `json:"names"`
	Origin              string   `json:"origin"`
	TaintArgs           []int    `json:"taintArgs"`
	RequiresConfigQuery bool     `json:"requiresConfigQuery"`
	Desc                string   `json:"desc"`
}

type SinkRule struct {
	ID       string   `json:"id"`
	Pkg      string   `json:"pkg"`
	Name     string   `json:"name"`
	Receiver string   `json:"receiver"`
	Names    []string `json:"names"`
	Args     []int    `json:"args"`
	Accept   []string `json:"accept"`
	Desc     string   `json:"desc"`
}

type SanitizerRule struct {
	ID    string   `json:"id"`
	Pkg   string   `json:"pkg"`
	Name  string   `json:"name"`
	Names []string `json:"names"`
	Only  []string `json:"only"`
}

type PropagatorRule struct {
	Ident string `json:"ident"`
	Pkg   string `json:"pkg"`
	Name  string `json:"name"`
	Mode  string `json:"mode"`
}

type DBConfigRule struct {
	Tables              []string `json:"tables"`
	TaintOnDynamicQuery bool     `json:"taint_on_dynamic_query"`
}

type Rules struct {
	Version     int              `json:"version"`
	Sources     []SourceRule     `json:"sources"`
	Sinks       []SinkRule       `json:"sinks"`
	Sanitizers  []SanitizerRule  `json:"sanitizers"`
	Propagators []PropagatorRule `json:"propagators"`
	DBConfig    DBConfigRule     `json:"db_config"`
	Config      map[string]any   `json:"config"`
}

func LoadRules(path string) (*Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Rules
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}
