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

func TestConstructorsApplySchemaDefaults(t *testing.T) {
	result := NewResult()
	if result.RuleIndex != -1 {
		t.Fatalf("RuleIndex = %d, want -1", result.RuleIndex)
	}
	if result.Rank != -1 {
		t.Fatalf("Rank = %v, want -1", result.Rank)
	}
	if result.Kind != "fail" {
		t.Fatalf("Kind = %q, want fail", result.Kind)
	}
	if result.Level != "warning" {
		t.Fatalf("Level = %q, want warning", result.Level)
	}

	location := NewLocation()
	if location.ID != -1 {
		t.Fatalf("Location.ID = %d, want -1", location.ID)
	}
	artifactLocation := NewArtifactLocation()
	if artifactLocation.Index != -1 {
		t.Fatalf("ArtifactLocation.Index = %d, want -1", artifactLocation.Index)
	}
}

func TestConstructorDefaultsAreOmittedWhenMarshaled(t *testing.T) {
	artifactLocation := NewArtifactLocation()
	artifactLocation.URI = "package-lock.json"
	location := NewLocation()
	location.PhysicalLocation = PhysicalLocation{ArtifactLocation: artifactLocation}
	result := NewResult()
	result.RuleID = "GHSA-0002"
	result.Message = Message{Text: "example vulnerability"}
	result.Locations = []Location{location}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var encoded struct {
		Rank      *float64 `json:"rank"`
		RuleIndex *int     `json:"ruleIndex"`
		Locations []struct {
			ID               *int `json:"id"`
			PhysicalLocation struct {
				ArtifactLocation struct {
					Index *int `json:"index"`
				} `json:"artifactLocation"`
			} `json:"physicalLocation"`
		} `json:"locations"`
	}
	if err := json.Unmarshal(data, &encoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if encoded.Rank != nil || encoded.RuleIndex != nil {
		t.Fatalf("Marshal() emitted unset result defaults: %s", data)
	}
	gotLocation := encoded.Locations[0]
	if gotLocation.ID != nil || gotLocation.PhysicalLocation.ArtifactLocation.Index != nil {
		t.Fatalf("Marshal() emitted unset location defaults: %s", data)
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
	artifactLocation := NewArtifactLocation()
	artifactLocation.URI = "src/main.go"
	region := NewRegion()
	region.StartLine = 10
	region.StartColumn = 5
	location := NewLocation()
	location.PhysicalLocation = PhysicalLocation{
		ArtifactLocation: artifactLocation,
		Region:           region,
	}
	result := NewResult()
	result.RuleID = "no-unused-vars"
	result.RuleIndex = 0
	result.Level = "warning"
	result.Message = Message{Text: "Variable 'x' is unused"}
	result.Locations = []Location{location}
	defaultConfiguration := NewReportingConfiguration()
	defaultConfiguration.Level = "error"

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
								DefaultConfiguration: defaultConfiguration,
							},
						},
					},
				},
				Results: []Result{result},
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
	for _, unexpected := range []string{`"enabled":`, `"rank":`, `"index":`} {
		if strings.Contains(string(data), unexpected) {
			t.Fatalf("Marshal() emitted unset schema-defaulted field %s: %s", unexpected, data)
		}
	}
	var encoded struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					ID *int `json:"id"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &encoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if encoded.Runs[0].Results[0].Locations[0].ID != nil {
		t.Fatalf("Marshal() emitted unset location id: %s", data)
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
