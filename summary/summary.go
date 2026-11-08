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
	GUID  string
	Level string
}

type ruleComponent struct {
	tool  Tool
	GUID  string
	Rules []ruleDefinition
}

type ruleComponents struct {
	Driver     ruleComponent
	Extensions []ruleComponent
}

type componentReference struct {
	Name     string
	GUID     string
	Index    int
	HasIndex bool
}

type ruleReference struct {
	ID        string
	GUID      string
	Index     int
	HasIndex  bool
	Component componentReference
}

type suppression struct {
	Kind   string `json:"kind"`
	Status string `json:"status"`
	State  string `json:"state"`
}

type resultRule struct {
	ID            string `json:"id"`
	GUID          string `json:"guid"`
	Index         *int   `json:"index"`
	ToolComponent struct {
		Name  string `json:"name"`
		GUID  string `json:"guid"`
		Index *int   `json:"index"`
	} `json:"toolComponent"`
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
	var components ruleComponents
	pendingRules := make(map[ruleReference]int)
	pendingLevels := make(map[ruleReference]int)
	for decoder.More() {
		name, err := objectName(decoder)
		if err != nil {
			return err
		}
		switch name {
		case "tool":
			components, err = inspectTool(decoder, summary, options)
		case "results":
			err = inspectResults(decoder, summary, pendingRules, pendingLevels, options)
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
	resolveResultRules(summary, components, pendingRules, options.MaxUniqueValues)
	resolveResultLevels(summary, components, pendingLevels, options.MaxUniqueValues)
	return nil
}

func inspectTool(decoder *json.Decoder, summary *Summary, options Options) (ruleComponents, error) {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return ruleComponents{}, err
	}
	var components ruleComponents
	remainingRules := options.MaxUniqueValues
	for decoder.More() {
		name, err := objectName(decoder)
		if err != nil {
			return ruleComponents{}, err
		}
		switch name {
		case "driver":
			components.Driver, err = inspectToolComponent(decoder, remainingRules, &summary.Truncated)
			remainingRules -= len(components.Driver.Rules)
			addTool(summary, components.Driver.tool, options.MaxTools)
		case "extensions":
			components.Extensions, err = inspectToolExtensions(
				decoder, summary, options.MaxTools, &remainingRules, &summary.Truncated,
			)
		default:
			err = skipValue(decoder)
		}
		if err != nil {
			return ruleComponents{}, err
		}
	}
	return components, expectDelimiter(decoder, '}')
}

func inspectToolExtensions(
	decoder *json.Decoder,
	summary *Summary,
	toolLimit int,
	remainingRules *int,
	truncated *bool,
) ([]ruleComponent, error) {
	if err := expectDelimiter(decoder, '['); err != nil {
		return nil, err
	}
	var components []ruleComponent
	for decoder.More() {
		retain := len(components) < toolLimit
		maxRules := 0
		if retain {
			maxRules = *remainingRules
		}
		component, err := inspectToolComponent(decoder, maxRules, truncated)
		if err != nil {
			return nil, err
		}
		if retain {
			*remainingRules -= len(component.Rules)
			components = append(components, component)
		} else {
			*truncated = true
		}
		addTool(summary, component.tool, toolLimit)
	}
	return components, expectDelimiter(decoder, ']')
}

func inspectToolComponent(
	decoder *json.Decoder,
	maxRules int,
	truncated *bool,
) (ruleComponent, error) {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return ruleComponent{}, err
	}
	var component ruleComponent
	var tool Tool
	for decoder.More() {
		name, err := objectName(decoder)
		if err != nil {
			return ruleComponent{}, err
		}
		switch name {
		case "name":
			err = decoder.Decode(&tool.Name)
		case "guid":
			err = decoder.Decode(&component.GUID)
		case "version":
			err = decoder.Decode(&tool.Version)
		case "semanticVersion":
			err = decoder.Decode(&tool.SemanticVersion)
		case "rules":
			component.Rules, err = inspectRuleDefinitions(decoder, maxRules, truncated)
		default:
			err = skipValue(decoder)
		}
		if err != nil {
			return ruleComponent{}, err
		}
	}
	component.tool = tool
	return component, expectDelimiter(decoder, '}')
}

func inspectRuleDefinitions(decoder *json.Decoder, limit int, truncated *bool) ([]ruleDefinition, error) {
	if err := expectDelimiter(decoder, '['); err != nil {
		return nil, err
	}
	var definitions []ruleDefinition
	for decoder.More() {
		var rule struct {
			ID                   string `json:"id"`
			GUID                 string `json:"guid"`
			DefaultConfiguration struct {
				Level string `json:"level"`
			} `json:"defaultConfiguration"`
		}
		if err := decoder.Decode(&rule); err != nil {
			return nil, err
		}
		if len(definitions) < limit {
			definitions = append(definitions, ruleDefinition{
				ID: rule.ID, GUID: rule.GUID, Level: rule.DefaultConfiguration.Level,
			})
		} else if truncated != nil {
			*truncated = true
		}
	}
	return definitions, expectDelimiter(decoder, ']')
}

func inspectResults(
	decoder *json.Decoder,
	summary *Summary,
	pendingRules map[ruleReference]int,
	pendingLevels map[ruleReference]int,
	options Options,
) error {
	if err := expectDelimiter(decoder, '['); err != nil {
		return err
	}
	for decoder.More() {
		var result struct {
			Kind            string        `json:"kind"`
			Level           string        `json:"level"`
			RuleID          string        `json:"ruleId"`
			RuleIndex       *int          `json:"ruleIndex"`
			Rule            resultRule    `json:"rule"`
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
		reference := makeRuleReference(result.RuleID, result.RuleIndex, result.Rule)
		switch {
		case result.Kind != "" && result.Kind != "fail":
			addCount(summary.Levels, "none", 1, options.MaxUniqueValues, &summary.Truncated)
		case result.Level != "":
			addCount(summary.Levels, result.Level, 1, options.MaxUniqueValues, &summary.Truncated)
		default:
			addRuleReferenceCount(pendingLevels, reference, options.MaxUniqueValues, &summary.Truncated)
		}
		if result.BaselineState != "" {
			addCount(summary.BaselineStates, result.BaselineState, 1, options.MaxUniqueValues, &summary.Truncated)
		}
		switch {
		case reference.ID != "":
			addCount(summary.Rules, reference.ID, 1, options.MaxUniqueValues, &summary.Truncated)
		case reference.HasIndex || reference.GUID != "":
			addRuleReferenceCount(pendingRules, reference, options.MaxUniqueValues, &summary.Truncated)
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

func makeRuleReference(ruleID string, ruleIndex *int, rule resultRule) ruleReference {
	if ruleID == "" {
		ruleID = rule.ID
	}
	if ruleIndex == nil {
		ruleIndex = rule.Index
	}
	reference := ruleReference{
		ID:   ruleID,
		GUID: rule.GUID,
		Component: componentReference{
			Name: rule.ToolComponent.Name,
			GUID: rule.ToolComponent.GUID,
		},
	}
	if ruleIndex != nil && *ruleIndex >= 0 {
		reference.Index = *ruleIndex
		reference.HasIndex = true
	}
	if componentIndex := rule.ToolComponent.Index; componentIndex != nil && *componentIndex >= 0 {
		reference.Component.Index = *componentIndex
		reference.Component.HasIndex = true
	}
	return reference
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

func resolveResultRules(
	summary *Summary,
	components ruleComponents,
	pending map[ruleReference]int,
	limit int,
) {
	for reference, count := range pending {
		rule, found := resolveRule(components, reference)
		if !found || rule.ID == "" {
			addCount(summary.Rules, "<unresolved>", count, limit, &summary.Truncated)
			continue
		}
		addCount(summary.Rules, rule.ID, count, limit, &summary.Truncated)
	}
}

func resolveResultLevels(
	summary *Summary,
	components ruleComponents,
	pending map[ruleReference]int,
	limit int,
) {
	for reference, count := range pending {
		rule, _ := resolveRule(components, reference)
		level := rule.Level
		if level == "" {
			level = "warning"
		}
		addCount(summary.Levels, level, count, limit, &summary.Truncated)
	}
}

func resolveRule(components ruleComponents, reference ruleReference) (ruleDefinition, bool) {
	rules, found := componentRules(components, reference.Component)
	if !found {
		return ruleDefinition{}, false
	}
	if reference.HasIndex && reference.Index >= 0 && reference.Index < len(rules) {
		return rules[reference.Index], true
	}
	if reference.ID != "" {
		for _, rule := range rules {
			if rule.ID == reference.ID {
				return rule, true
			}
		}
	}
	if reference.GUID != "" {
		for _, rule := range rules {
			if rule.GUID == reference.GUID {
				return rule, true
			}
		}
	}
	return ruleDefinition{}, false
}

func componentRules(components ruleComponents, reference componentReference) ([]ruleDefinition, bool) {
	if !reference.HasIndex && reference.Name == "" && reference.GUID == "" {
		return components.Driver.Rules, true
	}
	if reference.HasIndex {
		if reference.Index >= 0 && reference.Index < len(components.Extensions) {
			return components.Extensions[reference.Index].Rules, true
		}
		return nil, false
	}
	if reference.GUID != "" {
		if components.Driver.GUID == reference.GUID {
			return components.Driver.Rules, true
		}
		for _, component := range components.Extensions {
			if component.GUID == reference.GUID {
				return component.Rules, true
			}
		}
		return nil, false
	}
	if components.Driver.tool.Name == reference.Name {
		return components.Driver.Rules, true
	}
	for _, component := range components.Extensions {
		if component.tool.Name == reference.Name {
			return component.Rules, true
		}
	}
	return nil, false
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
