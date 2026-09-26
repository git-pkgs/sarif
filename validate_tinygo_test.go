//go:build tinygo

package sarif_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/git-pkgs/sarif"
)

func TestTinyGoValidationUnsupported(t *testing.T) {
	input := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test-linter"}},"results":[{"ruleId":"unused-variable","message":{"text":"Variable x is unused"}}]}]}`)
	log, err := sarif.Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := sarif.Validate(log); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Validate error = %v, want errors.ErrUnsupported", err)
	}
	if sarif.Valid(log) {
		t.Fatal("Valid returned true without schema validation")
	}

	for _, pretty := range []bool{false, true} {
		var out bytes.Buffer
		if err := sarif.Dump(log, &out, pretty); err != nil {
			t.Fatal(err)
		}
		decoded, err := sarif.Parse(out.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Version != log.Version || len(decoded.Runs) != 1 || len(decoded.Runs[0].Results) != 1 {
			t.Fatalf("round-trip changed the log: %s", out.Bytes())
		}
		run := decoded.Runs[0]
		result := run.Results[0]
		if run.Tool.Driver.Name != "test-linter" || result.RuleID != "unused-variable" || result.Message.Text != "Variable x is unused" {
			t.Fatalf("round-trip changed the finding: %s", out.Bytes())
		}
		if result.Level != "warning" || result.Kind != "fail" || result.RuleIndex != -1 {
			t.Fatalf("round-trip changed the defaults: %+v", result)
		}
	}

	if err := sarif.Validate(nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Validate(nil) error = %v, want errors.ErrUnsupported", err)
	}
}
