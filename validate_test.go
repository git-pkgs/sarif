//go:build !tinygo

package sarif

import (
	"encoding/json"
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
