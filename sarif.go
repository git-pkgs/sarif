package sarif

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
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

// Load reads a SARIF log from path.
func Load(path string) (*Log, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load sarif: %w", err)
	}
	return Parse(data)
}

// Parse decodes a SARIF log from JSON.
func Parse(data []byte) (*Log, error) {
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("parse sarif: %w", err)
	}
	return &log, nil
}

// Marshal encodes a SARIF log to JSON.
func Marshal(log *Log, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(log, "", "  ")
	}
	return json.Marshal(log)
}

// Dump writes a SARIF log to w.
func Dump(log *Log, w io.Writer, pretty bool) error {
	data, err := Marshal(log, pretty)
	if err != nil {
		return fmt.Errorf("dump sarif: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("dump sarif: %w", err)
	}
	return nil
}

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

// Valid reports whether log validates against the bundled SARIF 2.1.0 schema.
func Valid(log *Log) bool {
	return Validate(log) == nil
}

func includeNonZero(value any) bool {
	return !reflect.ValueOf(value).IsZero()
}

func includeNonDefault(value any, defaultValue any) bool {
	valueRef := reflect.ValueOf(value)
	defaultRef := reflect.ValueOf(defaultValue)
	if !valueRef.IsValid() {
		return false
	}
	if defaultRef.IsValid() && defaultRef.Kind() == reflect.Slice {
		if valueRef.Kind() != reflect.Slice || valueRef.IsNil() {
			return false
		}
		if defaultRef.Len() == 0 {
			return valueRef.Len() > 0
		}
		return !reflect.DeepEqual(value, defaultValue)
	}
	if defaultRef.IsValid() && defaultRef.Kind() == reflect.String && valueRef.IsZero() {
		return false
	}
	return !reflect.DeepEqual(value, defaultValue)
}

// Schema returns the compiled bundled SARIF 2.1.0 JSON schema.
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
