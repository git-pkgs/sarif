package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestWriteTypeGeneratesSchemaDefaultConstructor(t *testing.T) {
	node := &schemaNode{
		Properties: map[string]*schemaNode{
			"index": {
				Type:    "integer",
				Default: float64(-1),
			},
			"name": {Type: "string"},
			"rank": {
				Type:    "number",
				Default: float64(-1),
			},
		},
	}

	var output bytes.Buffer
	writeType(&output, "Example", "An example type.", node)
	generated := output.String()

	for _, expected := range []string{
		"// Use NewExample when constructing a value so schema defaults are initialized.",
		"func NewExample() Example {",
		"Index: -1,",
		"Rank: float64(-1),",
		"includeNonDefault(v.Rank, float64(-1))",
		"tmp := alias(NewExample())",
	} {
		if !strings.Contains(generated, expected) {
			t.Fatalf("generated type missing %q:\n%s", expected, generated)
		}
	}
}
