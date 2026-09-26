//go:build !tinygo

package sarif

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed schema/sarif-schema-2.1.0.json
var schemaFS embed.FS

const schemaPath = "schema/sarif-schema-2.1.0.json"

var (
	compiledSchema     *jsonschema.Schema
	compiledSchemaErr  error
	compiledSchemaOnce sync.Once
)

// Validate validates a SARIF log against the bundled SARIF 2.1.0 schema.
func Validate(log *Log) error {
	schema, err := Schema()
	if err != nil {
		return err
	}

	data, err := json.Marshal(log)
	if err != nil {
		return fmt.Errorf("validate sarif: %w", err)
	}

	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("validate sarif: %w", err)
	}

	if err := schema.Validate(value); err != nil {
		return fmt.Errorf("validate sarif: %w", err)
	}
	return nil
}

// Schema returns the compiled bundled SARIF 2.1.0 JSON schema.
// It is unavailable under TinyGo.
func Schema() (*jsonschema.Schema, error) {
	compiledSchemaOnce.Do(func() {
		data, err := schemaFS.ReadFile(schemaPath)
		if err != nil {
			compiledSchemaErr = fmt.Errorf("compile sarif schema: %w", err)
			return
		}

		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft7)
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		if err != nil {
			compiledSchemaErr = fmt.Errorf("compile sarif schema: %w", err)
			return
		}
		if err := compiler.AddResource(schemaPath, doc); err != nil {
			compiledSchemaErr = fmt.Errorf("compile sarif schema: %w", err)
			return
		}

		compiledSchema, compiledSchemaErr = compiler.Compile(schemaPath)
		if compiledSchemaErr != nil {
			compiledSchemaErr = fmt.Errorf("compile sarif schema: %w", compiledSchemaErr)
		}
	})
	return compiledSchema, compiledSchemaErr
}
