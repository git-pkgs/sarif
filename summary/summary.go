// Package summary extracts bounded aggregate evidence from SARIF logs.
package summary

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

const (
	DefaultMaxBytes        = 64 << 20
	DefaultMaxUniqueValues = 10_000
	DefaultMaxTools        = 1_000
)

var (
	ErrInvalid = errors.New("invalid SARIF")
	ErrLimit   = errors.New("sarif summary limit exceeded")
)

type Options struct {
	MaxBytes        int64
	MaxUniqueValues int
	MaxTools        int
}

type Tool struct {
	Name            string
	Version         string
	SemanticVersion string
}

type ruleDefinition struct {
	ID    string
	Level string
}

type ruleReference struct {
	ID       string
	Index    int
	HasIndex bool
}

type suppression struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
	State  string `json:"state"`
}

type Summary struct {
	Version           string
	Runs              int
	Results           int
	Occurrences       int
	SuppressedResults int
	Tools             []Tool
	Levels            map[string]int
	BaselineStates    map[string]int
	Rules             map[string]int
	Taxa              map[string]int
	Suppressions      map[string]int
	Truncated         bool
	toolSet           map[Tool]struct{}
}

func Inspect(reader io.Reader, options Options) (Summary, error) {
	options, err := options.defaults()
	if err != nil {
		return Summary{}, err
	}
	if reader == nil {
		return Summary{}, errors.New("inspect SARIF: nil reader")
	}

	limited := &limitReader{reader: reader, remaining: options.MaxBytes}
	decoder := json.NewDecoder(limited)
	summary := newSummary()
	if err := inspectLog(decoder, &summary, options); err != nil {
		return finishSummary(summary), inspectError(err, limited)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return finishSummary(summary), inspectError(err, limited)
		}
		return finishSummary(summary), fmt.Errorf("inspect SARIF: %w: unexpected trailing token %v", ErrInvalid, token)
	}
	return finishSummary(summary), nil
}

func finishSummary(summary Summary) Summary {
	slices.SortFunc(summary.Tools, func(left, right Tool) int {
		if compared := strings.Compare(left.Name, right.Name); compared != 0 {
			return compared
		}
		if compared := strings.Compare(left.SemanticVersion, right.SemanticVersion); compared != 0 {
			return compared
		}
		return strings.Compare(left.Version, right.Version)
	})
	summary.toolSet = nil
	return summary
}

func inspectError(err error, reader *limitReader) error {
	switch {
	case errors.Is(err, ErrLimit):
		return fmt.Errorf("inspect SARIF: %w", err)
	case reader.readErr != nil:
		return fmt.Errorf("inspect SARIF: %w", reader.readErr)
	default:
		return fmt.Errorf("inspect SARIF: %w: %v", ErrInvalid, err)
	}
}

func (options Options) defaults() (Options, error) {
	if options.MaxBytes < 0 || options.MaxUniqueValues < 0 || options.MaxTools < 0 {
		return Options{}, errors.New("SARIF summary limits must not be negative")
	}
	if options.MaxBytes == 0 {
		options.MaxBytes = DefaultMaxBytes
	}
	if options.MaxUniqueValues == 0 {
		options.MaxUniqueValues = DefaultMaxUniqueValues
	}
	if options.MaxTools == 0 {
		options.MaxTools = DefaultMaxTools
	}
	return options, nil
}

func newSummary() Summary {
	return Summary{
		Levels:         make(map[string]int),
		BaselineStates: make(map[string]int),
		Rules:          make(map[string]int),
		Taxa:           make(map[string]int),
		Suppressions:   make(map[string]int),
		toolSet:        make(map[Tool]struct{}),
	}
}

func inspectLog(decoder *json.Decoder, summary *Summary, options Options) error {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return err
	}
	hasRuns := false
	for decoder.More() {
		name, err := objectName(decoder)
		if err != nil {
			return err
		}
		switch name {
		case "version":
			err = decoder.Decode(&summary.Version)
		case "runs":
			hasRuns = true
			err = inspectRuns(decoder, summary, options)
		default:
			err = skipValue(decoder)
		}
		if err != nil {
			return err
		}
	}
	if err := expectDelimiter(decoder, '}'); err != nil {
		return err
	}
	if summary.Version == "" {
		return fmt.Errorf("%w: missing version", ErrInvalid)
	}
	if !hasRuns {
		return fmt.Errorf("%w: missing runs", ErrInvalid)
	}
	return nil
}

func inspectRuns(decoder *json.Decoder, summary *Summary, options Options) error {
	if err := expectDelimiter(decoder, '['); err != nil {
		return err
	}
	for decoder.More() {
		summary.Runs++
		if err := inspectRun(decoder, summary, options); err != nil {
			return err
		}
	}
	return expectDelimiter(decoder, ']')
}

func inspectRun(decoder *json.Decoder, summary *Summary, options Options) error {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return err
	}
	var driverRules []ruleDefinition
	indexedRules := make(map[int]int)
	pendingLevels := make(map[ruleReference]int)
	for decoder.More() {
		name, err := objectName(decoder)
		if err != nil {
			return err
		}
		switch name {
		case "tool":
			driverRules, err = inspectTool(decoder, summary, options)
		case "results":
			err = inspectResults(decoder, summary, indexedRules, pendingLevels, options)
		default:
			err = skipValue(decoder)
		}
		if err != nil {
			return err
		}
	}
	if err := expectDelimiter(decoder, '}'); err != nil {
		return err
	}
	for index, count := range indexedRules {
		if index >= 0 && index < len(driverRules) && driverRules[index].ID != "" {
			addCount(summary.Rules, driverRules[index].ID, count, options.MaxUniqueValues, &summary.Truncated)
		} else {
			addCount(summary.Rules, "<unresolved>", count, options.MaxUniqueValues, &summary.Truncated)
		}
	}
	resolveResultLevels(summary, driverRules, pendingLevels, options.MaxUniqueValues)
	return nil
}

func inspectTool(decoder *json.Decoder, summary *Summary, options Options) ([]ruleDefinition, error) {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return nil, err
	}
	var driverRules []ruleDefinition
	for decoder.More() {
		name, err := objectName(decoder)
		if err != nil {
			return nil, err
		}
		switch name {
		case "driver":
			var tool Tool
			tool, driverRules, err = inspectToolComponent(decoder, true, options.MaxUniqueValues, &summary.Truncated)
			addTool(summary, tool, options.MaxTools)
		case "extensions":
			err = inspectToolExtensions(decoder, summary, options.MaxTools)
		default:
			err = skipValue(decoder)
		}
		if err != nil {
			return nil, err
		}
	}
	return driverRules, expectDelimiter(decoder, '}')
}

func inspectToolExtensions(decoder *json.Decoder, summary *Summary, limit int) error {
	if err := expectDelimiter(decoder, '['); err != nil {
		return err
	}
	for decoder.More() {
		tool, _, err := inspectToolComponent(decoder, false, 0, nil)
		if err != nil {
			return err
		}
		addTool(summary, tool, limit)
	}
	return expectDelimiter(decoder, ']')
}

func inspectToolComponent(
	decoder *json.Decoder,
	rules bool,
	maxRules int,
	truncated *bool,
) (Tool, []ruleDefinition, error) {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return Tool{}, nil, err
	}
	var tool Tool
	var ruleDefinitions []ruleDefinition
	for decoder.More() {
		name, err := objectName(decoder)
		if err != nil {
			return Tool{}, nil, err
		}
		switch name {
		case "name":
			err = decoder.Decode(&tool.Name)
		case "version":
			err = decoder.Decode(&tool.Version)
		case "semanticVersion":
			err = decoder.Decode(&tool.SemanticVersion)
		case "rules":
			if rules {
				ruleDefinitions, err = inspectRuleDefinitions(decoder, maxRules, truncated)
			} else {
				err = skipValue(decoder)
			}
		default:
			err = skipValue(decoder)
		}
		if err != nil {
			return Tool{}, nil, err
		}
	}
	return tool, ruleDefinitions, expectDelimiter(decoder, '}')
}

func inspectRuleDefinitions(decoder *json.Decoder, limit int, truncated *bool) ([]ruleDefinition, error) {
	if err := expectDelimiter(decoder, '['); err != nil {
		return nil, err
	}
	var definitions []ruleDefinition
	for decoder.More() {
		var rule struct {
			ID                   string `json:"id"`
			DefaultConfiguration struct {
				Level string `json:"level"`
			} `json:"defaultConfiguration"`
		}
		if err := decoder.Decode(&rule); err != nil {
			return nil, err
		}
		if len(definitions) < limit {
			definitions = append(definitions, ruleDefinition{ID: rule.ID, Level: rule.DefaultConfiguration.Level})
		} else if truncated != nil {
			*truncated = true
		}
	}
	return definitions, expectDelimiter(decoder, ']')
}

func inspectResults(
	decoder *json.Decoder,
	summary *Summary,
	indexedRules map[int]int,
	pendingLevels map[ruleReference]int,
	options Options,
) error {
	if err := expectDelimiter(decoder, '['); err != nil {
		return err
	}
	for decoder.More() {
		var result struct {
			Kind      string `json:"kind"`
			Level     string `json:"level"`
			RuleID    string `json:"ruleId"`
			RuleIndex *int   `json:"ruleIndex"`
			Rule      struct {
				ID    string `json:"id"`
				Index *int   `json:"index"`
			} `json:"rule"`
			BaselineState   string        `json:"baselineState"`
			OccurrenceCount int           `json:"occurrenceCount"`
			Suppressions    []suppression `json:"suppressions"`
			Taxa            []struct {
				ID string `json:"id"`
			} `json:"taxa"`
		}
		if err := decoder.Decode(&result); err != nil {
			return err
		}

		summary.Results++
		occurrences := max(1, result.OccurrenceCount)
		summary.Occurrences += occurrences
		ruleID := result.RuleID
		if ruleID == "" {
			ruleID = result.Rule.ID
		}
		ruleIndex := result.RuleIndex
		if ruleIndex == nil {
			ruleIndex = result.Rule.Index
		}
		switch {
		case result.Kind != "" && result.Kind != "fail":
			addCount(summary.Levels, "none", 1, options.MaxUniqueValues, &summary.Truncated)
		case result.Level != "":
			addCount(summary.Levels, result.Level, 1, options.MaxUniqueValues, &summary.Truncated)
		default:
			reference := ruleReference{ID: ruleID}
			if ruleIndex != nil {
				reference.Index = *ruleIndex
				reference.HasIndex = true
			}
			addRuleReferenceCount(pendingLevels, reference, options.MaxUniqueValues, &summary.Truncated)
		}
		if result.BaselineState != "" {
			addCount(summary.BaselineStates, result.BaselineState, 1, options.MaxUniqueValues, &summary.Truncated)
		}
		switch {
		case ruleID != "":
			addCount(summary.Rules, ruleID, 1, options.MaxUniqueValues, &summary.Truncated)
		case ruleIndex != nil:
			addIndexCount(indexedRules, *ruleIndex, options.MaxUniqueValues, &summary.Truncated)
		default:
			addCount(summary.Rules, "<unresolved>", 1, options.MaxUniqueValues, &summary.Truncated)
		}
		if resultSuppressed(result.Suppressions) {
			summary.SuppressedResults++
		}
		for _, suppression := range result.Suppressions {
			value := suppression.Kind
			if status := suppression.reviewStatus(); status != "" {
				value += "/" + status
			}
			addCount(summary.Suppressions, value, 1, options.MaxUniqueValues, &summary.Truncated)
		}
		for _, taxon := range result.Taxa {
			if taxon.ID != "" {
				addCount(summary.Taxa, taxon.ID, 1, options.MaxUniqueValues, &summary.Truncated)
			}
		}
	}
	return expectDelimiter(decoder, ']')
}

func resultSuppressed(suppressions []suppression) bool {
	for _, suppression := range suppressions {
		status := suppression.reviewStatus()
		if status == "" || status == "accepted" {
			return true
		}
	}
	return false
}

func (suppression suppression) reviewStatus() string {
	if suppression.Status != "" {
		return suppression.Status
	}
	return suppression.State
}

func resolveResultLevels(
	summary *Summary,
	rules []ruleDefinition,
	pending map[ruleReference]int,
	limit int,
) {
	rulesByID := make(map[string]string, len(rules))
	for _, rule := range rules {
		if rule.ID != "" {
			rulesByID[rule.ID] = rule.Level
		}
	}
	for reference, count := range pending {
		level := ""
		if reference.HasIndex && reference.Index >= 0 && reference.Index < len(rules) {
			level = rules[reference.Index].Level
		}
		if level == "" && reference.ID != "" {
			level = rulesByID[reference.ID]
		}
		if level == "" {
			level = "warning"
		}
		addCount(summary.Levels, level, count, limit, &summary.Truncated)
	}
}

func addRuleReferenceCount(
	counts map[ruleReference]int,
	reference ruleReference,
	limit int,
	truncated *bool,
) {
	if _, exists := counts[reference]; exists || len(counts) < limit {
		counts[reference]++
		return
	}
	*truncated = true
}

func addIndexCount(counts map[int]int, index, limit int, truncated *bool) {
	if _, exists := counts[index]; exists || len(counts) < limit {
		counts[index]++
		return
	}
	*truncated = true
}

func addTool(summary *Summary, tool Tool, limit int) {
	if tool.Name == "" {
		return
	}
	if _, exists := summary.toolSet[tool]; exists {
		return
	}
	if len(summary.Tools) >= limit {
		summary.Truncated = true
		return
	}
	summary.toolSet[tool] = struct{}{}
	summary.Tools = append(summary.Tools, tool)
}

func addCount(values map[string]int, value string, count, limit int, truncated *bool) {
	if _, ok := values[value]; !ok && len(values) >= limit {
		*truncated = true
		return
	}
	values[value] += count
}

func objectName(decoder *json.Decoder) (string, error) {
	token, err := decoder.Token()
	if err != nil {
		return "", err
	}
	name, ok := token.(string)
	if !ok {
		return "", fmt.Errorf("expected object name, got %v", token)
	}
	return name, nil
}

func expectDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != expected {
		return fmt.Errorf("expected %q, got %v", expected, token)
	}
	return nil
}

func skipValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		for decoder.More() {
			if _, err := objectName(decoder); err != nil {
				return err
			}
			if err := skipValue(decoder); err != nil {
				return err
			}
		}
		return expectDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := skipValue(decoder); err != nil {
				return err
			}
		}
		return expectDelimiter(decoder, ']')
	default:
		return fmt.Errorf("unexpected delimiter %q", delimiter)
	}
}

type limitReader struct {
	reader    io.Reader
	remaining int64
	err       error
	readErr   error
}

func (reader *limitReader) Read(buffer []byte) (int, error) {
	if reader.err != nil {
		return 0, reader.err
	}
	if reader.remaining == 0 {
		var probe [1]byte
		count, err := reader.reader.Read(probe[:])
		if count > 0 {
			reader.err = ErrLimit
			return 0, reader.err
		}
		reader.err = err
		if err != io.EOF {
			reader.readErr = err
		}
		return 0, err
	}
	if int64(len(buffer)) > reader.remaining {
		buffer = buffer[:reader.remaining]
	}
	count, err := reader.reader.Read(buffer)
	reader.remaining -= int64(count)
	reader.err = err
	if err != nil && err != io.EOF {
		reader.readErr = err
	}
	return count, err
}
