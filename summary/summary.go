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

type Taxon struct {
	ID           string
	GUID         string
	TaxonomyName string
	TaxonomyGUID string
	Count        int
}

type ruleDefinition struct {
	ID           string
	GUID         string
	Level        string
	ImplicitTaxa []ruleReference
}

type ruleComponent struct {
	tool  Tool
	GUID  string
	Rules []ruleDefinition
	Taxa  []ruleDefinition
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

type levelReference struct {
	Rule            ruleReference
	InvocationIndex int
}

type ruleTaxonReference struct {
	Rule  ruleReference
	Taxon ruleReference
}

type ruleIdentity struct {
	Component int
	ID        string
	GUID      string
}

type ruleTaxonIdentity struct {
	Rule  ruleIdentity
	Taxon taxonIdentity
}

type ruleOverride struct {
	Rule  ruleReference
	Level string
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
	Taxa              []Taxon
	Suppressions      map[string]int
	Truncated         bool
	toolSet           map[Tool]struct{}
	taxonCounts       map[taxonIdentity]int
}

type taxonIdentity struct {
	ID           string
	GUID         string
	TaxonomyName string
	TaxonomyGUID string
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
	for identity, count := range summary.taxonCounts {
		summary.Taxa = append(summary.Taxa, Taxon{
			ID:           identity.ID,
			GUID:         identity.GUID,
			TaxonomyName: identity.TaxonomyName,
			TaxonomyGUID: identity.TaxonomyGUID,
			Count:        count,
		})
	}
	slices.SortFunc(summary.Taxa, func(left, right Taxon) int {
		if compared := strings.Compare(left.TaxonomyName, right.TaxonomyName); compared != 0 {
			return compared
		}
		if compared := strings.Compare(left.TaxonomyGUID, right.TaxonomyGUID); compared != 0 {
			return compared
		}
		if compared := strings.Compare(left.ID, right.ID); compared != 0 {
			return compared
		}
		return strings.Compare(left.GUID, right.GUID)
	})
	summary.toolSet = nil
	summary.taxonCounts = nil
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
		Suppressions:   make(map[string]int),
		toolSet:        make(map[Tool]struct{}),
		taxonCounts:    make(map[taxonIdentity]int),
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
	var taxonomies []ruleComponent
	var invocations [][]ruleOverride
	remainingTaxa := options.MaxUniqueValues
	pendingRules := make(map[ruleReference]int)
	pendingLevels := make(map[levelReference]int)
	pendingTaxa := make(map[ruleReference]int)
	pendingResultRules := make(map[ruleReference]int)
	explicitRuleTaxa := make(map[ruleTaxonReference]int)
	for decoder.More() {
		name, err := objectName(decoder)
		if err != nil {
			return err
		}
		switch name {
		case "tool":
			components, err = inspectTool(decoder, summary, options, &remainingTaxa)
		case "taxonomies":
			taxonomies, err = inspectTaxonomies(
				decoder, options.MaxTools, &remainingTaxa, &summary.Truncated,
			)
		case "invocations":
			invocations, err = inspectInvocations(
				decoder, options.MaxUniqueValues, &summary.Truncated,
			)
		case "results":
			err = inspectResults(
				decoder,
				summary,
				pendingRules,
				pendingLevels,
				pendingTaxa,
				pendingResultRules,
				explicitRuleTaxa,
				options,
			)
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
	resolveResultLevels(summary, components, invocations, pendingLevels, options.MaxUniqueValues)
	resolveImplicitResultTaxa(
		summary,
		components,
		taxonomies,
		pendingResultRules,
		explicitRuleTaxa,
		pendingTaxa,
		options.MaxUniqueValues,
	)
	resolveResultTaxa(summary, components, taxonomies, pendingTaxa, options.MaxUniqueValues)
	return nil
}

func inspectTool(
	decoder *json.Decoder,
	summary *Summary,
	options Options,
	remainingTaxa *int,
) (ruleComponents, error) {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return ruleComponents{}, err
	}
	var components ruleComponents
	remainingRules := options.MaxUniqueValues
	remainingRelationships := options.MaxUniqueValues
	for decoder.More() {
		name, err := objectName(decoder)
		if err != nil {
			return ruleComponents{}, err
		}
		switch name {
		case "driver":
			components.Driver, err = inspectToolComponent(
				decoder, remainingRules, remainingRelationships, *remainingTaxa, &summary.Truncated,
			)
			remainingRules -= len(components.Driver.Rules)
			remainingRelationships -= implicitTaxaCount(components.Driver.Rules)
			*remainingTaxa -= len(components.Driver.Taxa)
			addTool(summary, components.Driver.tool, options.MaxTools)
		case "extensions":
			components.Extensions, err = inspectToolExtensions(
				decoder,
				summary,
				options.MaxTools,
				&remainingRules,
				&remainingRelationships,
				remainingTaxa,
				&summary.Truncated,
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
	remainingRelationships *int,
	remainingTaxa *int,
	truncated *bool,
) ([]ruleComponent, error) {
	if err := expectDelimiter(decoder, '['); err != nil {
		return nil, err
	}
	var components []ruleComponent
	for decoder.More() {
		retain := len(components) < toolLimit
		maxRules := 0
		maxRelationships := 0
		maxTaxa := 0
		if retain {
			maxRules = *remainingRules
			maxRelationships = *remainingRelationships
			maxTaxa = *remainingTaxa
		}
		component, err := inspectToolComponent(
			decoder, maxRules, maxRelationships, maxTaxa, truncated,
		)
		if err != nil {
			return nil, err
		}
		if retain {
			*remainingRules -= len(component.Rules)
			*remainingRelationships -= implicitTaxaCount(component.Rules)
			*remainingTaxa -= len(component.Taxa)
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
	maxRelationships int,
	maxTaxa int,
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
			component.Rules, err = inspectRuleDefinitions(
				decoder, maxRules, maxRelationships, truncated,
			)
		case "taxa":
			component.Taxa, err = inspectRuleDefinitions(decoder, maxTaxa, -1, truncated)
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

func inspectTaxonomies(
	decoder *json.Decoder,
	componentLimit int,
	remainingTaxa *int,
	truncated *bool,
) ([]ruleComponent, error) {
	if err := expectDelimiter(decoder, '['); err != nil {
		return nil, err
	}
	var components []ruleComponent
	for decoder.More() {
		retain := len(components) < componentLimit
		maxTaxa := 0
		if retain {
			maxTaxa = *remainingTaxa
		}
		component, err := inspectToolComponent(decoder, 0, 0, maxTaxa, truncated)
		if err != nil {
			return nil, err
		}
		if retain {
			*remainingTaxa -= len(component.Taxa)
			components = append(components, component)
		} else {
			*truncated = true
		}
	}
	return components, expectDelimiter(decoder, ']')
}

func inspectInvocations(
	decoder *json.Decoder,
	limit int,
	truncated *bool,
) ([][]ruleOverride, error) {
	if err := expectDelimiter(decoder, '['); err != nil {
		return nil, err
	}
	var invocations [][]ruleOverride
	remainingOverrides := limit
	for decoder.More() {
		retain := len(invocations) < limit
		maxOverrides := 0
		if retain {
			maxOverrides = remainingOverrides
		}
		overrides, err := inspectInvocation(decoder, maxOverrides, truncated)
		if err != nil {
			return nil, err
		}
		if retain {
			remainingOverrides -= len(overrides)
			invocations = append(invocations, overrides)
		} else {
			*truncated = true
		}
	}
	return invocations, expectDelimiter(decoder, ']')
}

func inspectInvocation(
	decoder *json.Decoder,
	limit int,
	truncated *bool,
) ([]ruleOverride, error) {
	if err := expectDelimiter(decoder, '{'); err != nil {
		return nil, err
	}
	var overrides []ruleOverride
	for decoder.More() {
		name, err := objectName(decoder)
		if err != nil {
			return nil, err
		}
		if name == "ruleConfigurationOverrides" {
			overrides, err = inspectRuleOverrides(decoder, limit, truncated)
		} else {
			err = skipValue(decoder)
		}
		if err != nil {
			return nil, err
		}
	}
	return overrides, expectDelimiter(decoder, '}')
}

func inspectRuleOverrides(
	decoder *json.Decoder,
	limit int,
	truncated *bool,
) ([]ruleOverride, error) {
	if err := expectDelimiter(decoder, '['); err != nil {
		return nil, err
	}
	var overrides []ruleOverride
	for decoder.More() {
		var override struct {
			Configuration struct {
				Level string `json:"level"`
			} `json:"configuration"`
			Descriptor resultRule `json:"descriptor"`
		}
		if err := decoder.Decode(&override); err != nil {
			return nil, err
		}
		if len(overrides) >= limit {
			*truncated = true
			continue
		}
		level := override.Configuration.Level
		if level == "" {
			level = "warning"
		}
		overrides = append(overrides, ruleOverride{
			Rule:  makeRuleReference("", nil, override.Descriptor),
			Level: level,
		})
	}
	return overrides, expectDelimiter(decoder, ']')
}

func inspectRuleDefinitions(
	decoder *json.Decoder,
	limit int,
	relationshipLimit int,
	truncated *bool,
) ([]ruleDefinition, error) {
	if err := expectDelimiter(decoder, '['); err != nil {
		return nil, err
	}
	var definitions []ruleDefinition
	remainingRelationships := relationshipLimit
	for decoder.More() {
		var rule struct {
			ID                   string `json:"id"`
			GUID                 string `json:"guid"`
			DefaultConfiguration struct {
				Level string `json:"level"`
			} `json:"defaultConfiguration"`
			Relationships []struct {
				Target resultRule `json:"target"`
				Kinds  []string   `json:"kinds"`
			} `json:"relationships"`
		}
		if err := decoder.Decode(&rule); err != nil {
			return nil, err
		}
		if len(definitions) >= limit {
			if truncated != nil {
				*truncated = true
			}
			continue
		}
		definition := ruleDefinition{
			ID: rule.ID, GUID: rule.GUID, Level: rule.DefaultConfiguration.Level,
		}
		if relationshipLimit < 0 {
			definitions = append(definitions, definition)
			continue
		}
		for _, relationship := range rule.Relationships {
			if !implicitTaxonRelationship(relationship.Kinds) {
				continue
			}
			if remainingRelationships == 0 {
				if truncated != nil {
					*truncated = true
				}
				continue
			}
			definition.ImplicitTaxa = append(
				definition.ImplicitTaxa,
				makeRuleReference("", nil, relationship.Target),
			)
			remainingRelationships--
		}
		definitions = append(definitions, definition)
	}
	return definitions, expectDelimiter(decoder, ']')
}

func implicitTaxaCount(rules []ruleDefinition) int {
	count := 0
	for _, rule := range rules {
		count += len(rule.ImplicitTaxa)
	}
	return count
}

func implicitTaxonRelationship(kinds []string) bool {
	return slices.Contains(kinds, "equal") || slices.Contains(kinds, "superset")
}

func inspectResults(
	decoder *json.Decoder,
	summary *Summary,
	pendingRules map[ruleReference]int,
	pendingLevels map[levelReference]int,
	pendingTaxa map[ruleReference]int,
	pendingResultRules map[ruleReference]int,
	explicitRuleTaxa map[ruleTaxonReference]int,
	options Options,
) error {
	present, err := beginNullableArray(decoder)
	if err != nil || !present {
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
			Taxa            []resultRule  `json:"taxa"`
			Provenance      struct {
				InvocationIndex *int `json:"invocationIndex"`
			} `json:"provenance"`
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
			invocationIndex := -1
			if result.Provenance.InvocationIndex != nil && *result.Provenance.InvocationIndex >= 0 {
				invocationIndex = *result.Provenance.InvocationIndex
			}
			addLevelReferenceCount(
				pendingLevels,
				levelReference{Rule: reference, InvocationIndex: invocationIndex},
				options.MaxUniqueValues,
				&summary.Truncated,
			)
		}
		addRuleReferenceCount(
			pendingResultRules, reference, options.MaxUniqueValues, &summary.Truncated,
		)
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
			taxonReference := makeRuleReference("", nil, taxon)
			addRuleReferenceCount(
				pendingTaxa,
				taxonReference,
				options.MaxUniqueValues,
				&summary.Truncated,
			)
			addRuleTaxonReferenceCount(
				explicitRuleTaxa,
				ruleTaxonReference{Rule: reference, Taxon: taxonReference},
				options.MaxUniqueValues,
				&summary.Truncated,
			)
		}
	}
	return expectDelimiter(decoder, ']')
}

func beginNullableArray(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	if token == nil {
		return false, nil
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '[' {
		return false, fmt.Errorf("expected %q or null, got %v", '[', token)
	}
	return true, nil
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
	invocations [][]ruleOverride,
	pending map[levelReference]int,
	limit int,
) {
	overrides := resolveInvocationRuleLevels(components, invocations)
	for reference, count := range pending {
		rule, identity, found := resolveRuleIdentity(components, reference.Rule)
		level := rule.Level
		if found && reference.InvocationIndex >= 0 && reference.InvocationIndex < len(overrides) {
			if override, overridden := overrides[reference.InvocationIndex][identity]; overridden {
				level = override
			}
		}
		if level == "" {
			level = "warning"
		}
		addCount(summary.Levels, level, count, limit, &summary.Truncated)
	}
}

func resolveInvocationRuleLevels(
	components ruleComponents,
	invocations [][]ruleOverride,
) []map[ruleIdentity]string {
	levels := make([]map[ruleIdentity]string, len(invocations))
	for invocationIndex, invocation := range invocations {
		levels[invocationIndex] = make(map[ruleIdentity]string)
		for _, override := range invocation {
			_, identity, found := resolveRuleIdentity(components, override.Rule)
			if !found {
				continue
			}
			if _, exists := levels[invocationIndex][identity]; !exists {
				levels[invocationIndex][identity] = override.Level
			}
		}
	}
	return levels
}

func resolveImplicitResultTaxa(
	summary *Summary,
	components ruleComponents,
	taxonomies []ruleComponent,
	resultRules map[ruleReference]int,
	explicitRuleTaxa map[ruleTaxonReference]int,
	pendingTaxa map[ruleReference]int,
	limit int,
) {
	ruleCounts := make(map[ruleIdentity]int)
	rules := make(map[ruleIdentity]ruleDefinition)
	for reference, count := range resultRules {
		rule, identity, found := resolveRuleIdentity(components, reference)
		if !found {
			continue
		}
		ruleCounts[identity] += count
		rules[identity] = rule
	}
	explicitCounts := make(map[ruleTaxonIdentity]int)
	for pair, count := range explicitRuleTaxa {
		_, ruleID, found := resolveRuleIdentity(components, pair.Rule)
		if !found {
			continue
		}
		taxon := resolveTaxonIdentity(components, taxonomies, pair.Taxon)
		explicitCounts[ruleTaxonIdentity{Rule: ruleID, Taxon: taxon}] += count
	}
	for ruleID, count := range ruleCounts {
		for _, reference := range rules[ruleID].ImplicitTaxa {
			taxon := resolveTaxonIdentity(components, taxonomies, reference)
			explicit := explicitCounts[ruleTaxonIdentity{Rule: ruleID, Taxon: taxon}]
			missing := count - min(count, explicit)
			if missing > 0 {
				addRuleReferenceCounts(
					pendingTaxa, reference, missing, limit, &summary.Truncated,
				)
			}
		}
	}
}

func resolveResultTaxa(
	summary *Summary,
	components ruleComponents,
	taxonomies []ruleComponent,
	pending map[ruleReference]int,
	limit int,
) {
	for reference, count := range pending {
		addTaxonCount(summary, resolveTaxonIdentity(components, taxonomies, reference), count, limit)
	}
}

func resolveTaxonIdentity(
	components ruleComponents,
	taxonomies []ruleComponent,
	reference ruleReference,
) taxonIdentity {
	identity := taxonIdentity{
		ID:           reference.ID,
		GUID:         reference.GUID,
		TaxonomyName: reference.Component.Name,
		TaxonomyGUID: reference.Component.GUID,
	}
	component, found := taxonComponent(components, taxonomies, reference.Component)
	if found {
		identity.TaxonomyName = component.tool.Name
		identity.TaxonomyGUID = component.GUID
		if taxon, resolved := resolveDescriptor(component.Taxa, reference); resolved {
			identity.ID = taxon.ID
			identity.GUID = taxon.GUID
		}
	}
	if identity.ID == "" && identity.GUID == "" {
		identity.ID = "<unresolved>"
	}
	return identity
}

func resolveRule(components ruleComponents, reference ruleReference) (ruleDefinition, bool) {
	rule, _, found := resolveRuleIdentity(components, reference)
	return rule, found
}

func resolveRuleIdentity(
	components ruleComponents,
	reference ruleReference,
) (ruleDefinition, ruleIdentity, bool) {
	rules, component, found := componentRules(components, reference.Component)
	if !found {
		return ruleDefinition{}, ruleIdentity{}, false
	}
	rule, found := resolveDescriptor(rules, reference)
	if !found {
		return ruleDefinition{}, ruleIdentity{}, false
	}
	return rule, ruleIdentity{Component: component, ID: rule.ID, GUID: rule.GUID}, true
}

func resolveDescriptor(definitions []ruleDefinition, reference ruleReference) (ruleDefinition, bool) {
	if reference.HasIndex && reference.Index >= 0 && reference.Index < len(definitions) {
		return definitions[reference.Index], true
	}
	if reference.ID != "" {
		for _, rule := range definitions {
			if rule.ID == reference.ID {
				return rule, true
			}
		}
	}
	if reference.GUID != "" {
		for _, rule := range definitions {
			if rule.GUID == reference.GUID {
				return rule, true
			}
		}
	}
	return ruleDefinition{}, false
}

func taxonComponent(
	components ruleComponents,
	taxonomies []ruleComponent,
	reference componentReference,
) (ruleComponent, bool) {
	if !reference.HasIndex && reference.Name == "" && reference.GUID == "" {
		return components.Driver, true
	}
	if reference.HasIndex {
		if reference.Index >= 0 && reference.Index < len(components.Extensions) {
			return components.Extensions[reference.Index], true
		}
		return ruleComponent{}, false
	}
	if reference.GUID != "" {
		if components.Driver.GUID == reference.GUID {
			return components.Driver, true
		}
		for _, component := range components.Extensions {
			if component.GUID == reference.GUID {
				return component, true
			}
		}
		for _, component := range taxonomies {
			if component.GUID == reference.GUID {
				return component, true
			}
		}
		return ruleComponent{}, false
	}
	if components.Driver.tool.Name == reference.Name {
		return components.Driver, true
	}
	for _, component := range components.Extensions {
		if component.tool.Name == reference.Name {
			return component, true
		}
	}
	for _, component := range taxonomies {
		if component.tool.Name == reference.Name {
			return component, true
		}
	}
	return ruleComponent{}, false
}

func componentRules(
	components ruleComponents,
	reference componentReference,
) ([]ruleDefinition, int, bool) {
	if !reference.HasIndex && reference.Name == "" && reference.GUID == "" {
		return components.Driver.Rules, -1, true
	}
	if reference.HasIndex {
		if reference.Index >= 0 && reference.Index < len(components.Extensions) {
			return components.Extensions[reference.Index].Rules, reference.Index, true
		}
		return nil, 0, false
	}
	if reference.GUID != "" {
		if components.Driver.GUID == reference.GUID {
			return components.Driver.Rules, -1, true
		}
		for index, component := range components.Extensions {
			if component.GUID == reference.GUID {
				return component.Rules, index, true
			}
		}
		return nil, 0, false
	}
	if components.Driver.tool.Name == reference.Name {
		return components.Driver.Rules, -1, true
	}
	for index, component := range components.Extensions {
		if component.tool.Name == reference.Name {
			return component.Rules, index, true
		}
	}
	return nil, 0, false
}

func addRuleReferenceCount(
	counts map[ruleReference]int,
	reference ruleReference,
	limit int,
	truncated *bool,
) {
	addRuleReferenceCounts(counts, reference, 1, limit, truncated)
}

func addRuleReferenceCounts(
	counts map[ruleReference]int,
	reference ruleReference,
	count int,
	limit int,
	truncated *bool,
) {
	if _, exists := counts[reference]; exists || len(counts) < limit {
		counts[reference] += count
		return
	}
	*truncated = true
}

func addLevelReferenceCount(
	counts map[levelReference]int,
	reference levelReference,
	limit int,
	truncated *bool,
) {
	if _, exists := counts[reference]; exists || len(counts) < limit {
		counts[reference]++
		return
	}
	*truncated = true
}

func addRuleTaxonReferenceCount(
	counts map[ruleTaxonReference]int,
	reference ruleTaxonReference,
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

func addTaxonCount(summary *Summary, taxon taxonIdentity, count, limit int) {
	if _, ok := summary.taxonCounts[taxon]; !ok && len(summary.taxonCounts) >= limit {
		summary.Truncated = true
		return
	}
	summary.taxonCounts[taxon] += count
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
