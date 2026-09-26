//go:build tinygo

package sarif

import "errors"

// Validate returns errors.ErrUnsupported because schema validation is
// unavailable under TinyGo.
func Validate(log *Log) error {
	return errors.ErrUnsupported
}
