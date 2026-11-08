package summary_test

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/git-pkgs/sarif/summary"
)

func TestInspectSummarizesRunsAndResults(t *testing.T) {
	input := `{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "CodeQL",
        "semanticVersion": "2.20.0",
        "rules": [{"id": "js/xss"}, {"id": "js/sql-injection"}]
      },
      "extensions": [{"name": "security-extended", "version": "1.2"}]
    },
    "results": [{
      "ruleId": "js/xss",
      "level": "error",
      "baselineState": "new",
      "occurrenceCount": 2,
      "message": {"text": "finding"},
      "suppressions": [{"kind": "inSource", "state": "accepted"}],
      "taxa": [{"id": "CWE-79"}]
    }, {
      "ruleIndex": 1,
      "message": {"text": "uses default warning level"}
    }]
  }]
}`

	got, err := summary.Inspect(strings.NewReader(input), summary.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "2.1.0" || got.Runs != 1 || got.Results != 2 || got.Occurrences != 3 ||
		got.SuppressedResults != 1 || got.Truncated {
		t.Fatalf("summary = %#v", got)
	}
	wantTools := []summary.Tool{
		{Name: "CodeQL", SemanticVersion: "2.20.0"},
		{Name: "security-extended", Version: "1.2"},
	}
	if len(got.Tools) != len(wantTools) {
		t.Fatalf("tools = %#v", got.Tools)
	}
	for index := range wantTools {
		if got.Tools[index] != wantTools[index] {
			t.Errorf("tool %d = %#v, want %#v", index, got.Tools[index], wantTools[index])
		}
	}
	assertCounts(t, got.Levels, map[string]int{"error": 1, "warning": 1})
	assertCounts(t, got.BaselineStates, map[string]int{"new": 1})
	assertCounts(t, got.Rules, map[string]int{"js/sql-injection": 1, "js/xss": 1})
	assertCounts(t, got.Taxa, map[string]int{"CWE-79": 1})
	assertCounts(t, got.Suppressions, map[string]int{"inSource/accepted": 1})
}

func TestInspectResolvesRuleIndexesWhenResultsPrecedeTool(t *testing.T) {
	input := `{
  "runs": [{
    "results": [{"ruleIndex": 0, "message": {"text": "finding"}}],
    "tool": {"driver": {"name": "scanner", "rules": [{
      "id": "RULE-1",
      "defaultConfiguration": {"level": "error"}
    }]}}
  }],
  "version": "2.1.0"
}`
	got, err := summary.Inspect(strings.NewReader(input), summary.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCounts(t, got.Rules, map[string]int{"RULE-1": 1})
	assertCounts(t, got.Levels, map[string]int{"error": 1})
}

func TestInspectResolvesEffectiveLevels(t *testing.T) {
	input := `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "CodeQL", "rules": [
      {"id": "error-rule", "defaultConfiguration": {"level": "error"}},
      {"id": "note-rule", "defaultConfiguration": {"level": "note"}},
      {"id": "default-rule"}
    ]}},
    "results": [
      {"ruleIndex": 0, "message": {"text": "index"}},
      {"ruleId": "note-rule", "message": {"text": "id"}},
      {"ruleId": "error-rule", "ruleIndex": -1, "message": {"text": "invalid index"}},
      {"ruleId": "default-rule", "message": {"text": "SARIF default"}},
      {"ruleId": "error-rule", "kind": "pass", "level": "error", "message": {"text": "pass"}},
      {"ruleId": "note-rule", "level": "error", "message": {"text": "explicit"}}
    ]
  }]
}`

	got, err := summary.Inspect(strings.NewReader(input), summary.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCounts(t, got.Levels, map[string]int{
		"error":   3,
		"none":    1,
		"note":    1,
		"warning": 1,
	})
}

func TestInspectResolvesReportingDescriptorReferences(t *testing.T) {
	input := `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "scanner", "rules": [
      {"id": "by-id", "defaultConfiguration": {"level": "error"}},
      {"id": "by-index", "defaultConfiguration": {"level": "note"}}
    ]}},
    "results": [
      {"rule": {"id": "by-id"}, "message": {"text": "id"}},
      {"rule": {"index": 1}, "message": {"text": "index"}}
    ]
  }]
}`

	got, err := summary.Inspect(strings.NewReader(input), summary.Options{})
	if err != nil {
		t.Fatal(err)
	}
	assertCounts(t, got.Rules, map[string]int{"by-id": 1, "by-index": 1})
	assertCounts(t, got.Levels, map[string]int{"error": 1, "note": 1})
}

func TestInspectCountsEffectiveSuppressions(t *testing.T) {
	input := `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "scanner"}},
    "results": [
      {"ruleId": "one", "message": {"text": "accepted"}, "suppressions": [{"kind": "inSource", "status": "accepted"}]},
      {"ruleId": "two", "message": {"text": "implicit"}, "suppressions": [{"kind": "external"}]},
      {"ruleId": "three", "message": {"text": "review"}, "suppressions": [{"kind": "external", "status": "underReview"}]},
      {"ruleId": "four", "message": {"text": "rejected"}, "suppressions": [{"kind": "inSource", "status": "rejected"}]},
      {"ruleId": "five", "message": {"text": "legacy state"}, "suppressions": [{"kind": "inSource", "state": "accepted"}]}
    ]
  }]
}`

	got, err := summary.Inspect(strings.NewReader(input), summary.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got.SuppressedResults != 3 {
		t.Fatalf("suppressed results = %d, want 3", got.SuppressedResults)
	}
	assertCounts(t, got.Suppressions, map[string]int{
		"external":             1,
		"external/underReview": 1,
		"inSource/accepted":    2,
		"inSource/rejected":    1,
	})
}

func TestInspectBoundsUniqueValuesAndTools(t *testing.T) {
	input := `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "driver", "rules": [
      {"id": "one", "defaultConfiguration": {"level": "error"}},
      {"id": "two", "defaultConfiguration": {"level": "warning"}}
    ]}, "extensions": [{"name": "one"}, {"name": "two"}]},
    "results": [
      {"ruleIndex": 0, "message": {"text": "one"}},
      {"ruleIndex": 1, "message": {"text": "two"}}
    ]
  }]
}`
	got, err := summary.Inspect(strings.NewReader(input), summary.Options{MaxUniqueValues: 1, MaxTools: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || len(got.Tools) != 1 || len(got.Rules) != 1 || len(got.Levels) != 1 {
		t.Fatalf("bounded summary = %#v", got)
	}
}

func TestInspectDeduplicatesToolsAtLimit(t *testing.T) {
	input := `{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "scanner"}, "extensions": [
      {"name": "scanner"}, {"name": "scanner"}
    ]}
  }]
}`
	got, err := summary.Inspect(strings.NewReader(input), summary.Options{MaxTools: 1})
	if err != nil {
		t.Fatal(err)
	}
	if got.Truncated || len(got.Tools) != 1 {
		t.Fatalf("tools = %#v, truncated = %t", got.Tools, got.Truncated)
	}
}

func TestInspectEnforcesInputLimit(t *testing.T) {
	input := `{"version":"2.1.0","runs":[]}`
	_, err := summary.Inspect(strings.NewReader(input), summary.Options{MaxBytes: int64(len(input) - 1)})
	if !errors.Is(err, summary.ErrLimit) {
		t.Fatalf("Inspect() error = %v, want ErrLimit", err)
	}

	got, err := summary.Inspect(strings.NewReader(input), summary.Options{MaxBytes: int64(len(input))})
	if err != nil || got.Version != "2.1.0" {
		t.Fatalf("exact-limit Inspect() = %#v, %v", got, err)
	}
}

func TestInspectSurfacesReaderAndSyntaxErrors(t *testing.T) {
	readErr := errors.New("read failed")
	_, err := summary.Inspect(io.MultiReader(
		strings.NewReader(`{"version":"2.1.0",`),
		errorReader{err: readErr},
	), summary.Options{})
	if !errors.Is(err, readErr) {
		t.Fatalf("Inspect() error = %v, want read error", err)
	}

	if _, err := summary.Inspect(strings.NewReader(`{"version":`), summary.Options{}); !errors.Is(err, summary.ErrInvalid) {
		t.Fatalf("malformed SARIF error = %v, want ErrInvalid", err)
	}
	if _, err := summary.Inspect(strings.NewReader(`{}`), summary.Options{}); !errors.Is(err, summary.ErrInvalid) {
		t.Fatalf("incomplete SARIF error = %v, want ErrInvalid", err)
	}
}

func assertCounts(t *testing.T, got, want map[string]int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("counts = %#v, want %#v", got, want)
	}
	for name, count := range want {
		if got[name] != count {
			t.Errorf("count %q = %d, want %d", name, got[name], count)
		}
	}
}

type errorReader struct {
	err error
}

func (reader errorReader) Read([]byte) (int, error) {
	return 0, reader.err
}
