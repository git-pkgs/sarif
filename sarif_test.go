package sarif

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalLogValidates(t *testing.T) {
	log := &Log{
		Version: "2.1.0",
		Runs:    []Run{},
	}

	if err := Validate(log); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestParseDumpRoundTrip(t *testing.T) {
	log, err := Parse([]byte(`{"version":"2.1.0","runs":[]}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("Version = %q, want 2.1.0", log.Version)
	}

	var out bytes.Buffer
	if err := Dump(log, &out, true); err != nil {
		t.Fatalf("Dump() error = %v", err)
	}
	if !strings.Contains(out.String(), "\n") {
		t.Fatalf("pretty Dump() output did not contain newlines: %q", out.String())
	}

	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("dumped JSON is invalid: %v", err)
	}
	if decoded["version"] != "2.1.0" {
		t.Fatalf("dumped version = %v, want 2.1.0", decoded["version"])
	}
}

func TestParseAppliesSchemaDefaults(t *testing.T) {
	log, err := Parse([]byte(`{
		"version": "2.1.0",
		"runs": [{
			"tool": {"driver": {"name": "test-tool"}},
			"results": [{"message": {"text": "test"}}]
		}]
	}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	result := log.Runs[0].Results[0]
	if result.RuleIndex != -1 {
		t.Fatalf("RuleIndex = %d, want -1", result.RuleIndex)
	}
	if result.Kind != "fail" {
		t.Fatalf("Kind = %q, want fail", result.Kind)
	}
	if result.Level != "warning" {
		t.Fatalf("Level = %q, want warning", result.Level)
	}
	if result.Locations == nil {
		t.Fatal("Locations = nil, want default empty slice")
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.sarif")
	if err := os.WriteFile(path, []byte(`{"version":"2.1.0","runs":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	log, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if log.Version != "2.1.0" {
		t.Fatalf("Version = %q, want 2.1.0", log.Version)
	}
}

func TestResultLogValidates(t *testing.T) {
	log := &Log{
		Version: "2.1.0",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: ToolComponent{
						Name:    "test-linter",
						Version: "1.0.0",
						Rules: []ReportingDescriptor{
							{
								ID:   "no-unused-vars",
								Name: "NoUnusedVars",
								ShortDescription: MultiformatMessageString{
									Text: "Disallow unused variables",
								},
								DefaultConfiguration: ReportingConfiguration{
									Level: "warning",
								},
							},
						},
					},
				},
				Results: []Result{
					{
						RuleID:    "no-unused-vars",
						RuleIndex: 0,
						Level:     "warning",
						Message: Message{
							Text: "Variable 'x' is unused",
						},
						Locations: []Location{
							{
								PhysicalLocation: PhysicalLocation{
									ArtifactLocation: ArtifactLocation{
										URI: "src/main.go",
									},
									Region: Region{
										StartLine:   10,
										StartColumn: 5,
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if err := Validate(log); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	data, err := Marshal(log, false)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !strings.Contains(string(data), `"ruleIndex":0`) {
		t.Fatalf("Marshal() omitted meaningful zero ruleIndex: %s", data)
	}
	if strings.Contains(string(data), `null`) {
		t.Fatalf("Marshal() emitted null default fields: %s", data)
	}
}

func TestValidateRejectsInvalidLog(t *testing.T) {
	log := &Log{
		Version: "2.0.0",
		Runs:    []Run{},
	}

	if err := Validate(log); err == nil {
		t.Fatal("Validate() error = nil, want invalid version error")
	}
}
