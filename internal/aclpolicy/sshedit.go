package aclpolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

const (
	sshActionAccept = string(TestAccept)
	sshActionCheck  = "check"

	// sshCheckPeriodAlways is the one non-duration checkPeriod the pinned
	// client accepts. It round-trips through the sentinel
	// tailscale.CheckPeriodAlways, which is the duration -1, so a period must
	// be validated by its authored text rather than by its parsed sign alone.
	sshCheckPeriodAlways = "always"
)

// SSHRuleSpec is the typed input shared by the ssh add and ssh remove
// commands. CheckPeriodSet is intentionally separate from CheckPeriod: a
// check rule without a checkPeriod is not the same authored rule as one with
// an explicit period.
type SSHRuleSpec struct {
	Action          string
	Source          []string
	Destination     []string
	Users           []string
	CheckPeriod     string
	CheckPeriodSet  bool
	Recorder        []string
	EnforceRecorder bool
}

// SSHRuleEdit describes a comment-preserving SSH rule edit. Callers apply
// Operations with WritePatch after loading the complete typed policy.
type SSHRuleEdit struct {
	RuleIndex  int
	Rule       SSHRule
	Operations []PatchOperation
}

// Changed reports whether the edit has file operations to apply.
func (e SSHRuleEdit) Changed() bool { return len(e.Operations) != 0 }

// AddSSHRule adds a semantically absent SSH rule. Selector order does not
// affect identity, but the first authored order is retained in the file.
func AddSSHRule(policy *Policy, spec SSHRuleSpec) (SSHRuleEdit, error) {
	rule, checkPeriodSet, err := sshRuleFromSpec(spec)
	if err != nil {
		return SSHRuleEdit{}, err
	}
	key, err := sshRuleSemanticKey(rule, checkPeriodSet)
	if err != nil {
		return SSHRuleEdit{}, err
	}
	for index := range policy.SSH {
		existingKey, keyErr := sshRuleSemanticKey(ruleAt(policy, index), sshCheckPeriodPresent(policy, index))
		if keyErr != nil {
			return SSHRuleEdit{}, keyErr
		}
		if existingKey == key {
			return SSHRuleEdit{RuleIndex: index, Rule: policy.SSH[index]}, nil
		}
	}

	edit := SSHRuleEdit{RuleIndex: len(policy.SSH), Rule: rule}
	if policy.SSH == nil {
		edit.Operations = append(edit.Operations, PatchAdd([]SSHRule{rule}, "ssh"))
	} else {
		edit.Operations = append(edit.Operations, PatchAdd(rule, "ssh", "-"))
	}
	policy.SSH = append(policy.SSH, rule)
	policy.sshCheckPeriodPresent = append(policy.sshCheckPeriodPresent, checkPeriodSet)
	return edit, nil
}

// RemoveSSHRule removes every duplicate of a semantic SSH rule. Operations
// are emitted from the end of the array so indexes remain valid.
func RemoveSSHRule(policy *Policy, spec SSHRuleSpec) (SSHRuleEdit, error) {
	rule, checkPeriodSet, err := sshRuleFromSpec(spec)
	if err != nil {
		return SSHRuleEdit{}, err
	}
	want, err := sshRuleSemanticKey(rule, checkPeriodSet)
	if err != nil {
		return SSHRuleEdit{}, err
	}

	edit := SSHRuleEdit{RuleIndex: -1, Rule: rule}
	for index := range policy.SSH {
		got, keyErr := sshRuleSemanticKey(ruleAt(policy, index), sshCheckPeriodPresent(policy, index))
		if keyErr != nil {
			return SSHRuleEdit{}, keyErr
		}
		if got != want {
			continue
		}
		if edit.RuleIndex < 0 {
			edit.RuleIndex = index
		}
		edit.Operations = append(edit.Operations, PatchRemove("ssh", strconv.Itoa(index)))
	}
	for i, j := 0, len(edit.Operations)-1; i < j; i, j = i+1, j-1 {
		edit.Operations[i], edit.Operations[j] = edit.Operations[j], edit.Operations[i]
	}
	if len(edit.Operations) != 0 {
		edit.Operations = append(edit.Operations, PatchPruneEmpty("ssh"))
	}
	return edit, nil
}

// RemoveSSHRuleAt removes one SSH rule by its zero-based index.
func RemoveSSHRuleAt(policy *Policy, index int) (SSHRuleEdit, error) {
	if index < 0 || index >= len(policy.SSH) {
		return SSHRuleEdit{}, fmt.Errorf(
			"ssh index %d is out of range; policy has %d ssh rules", index, len(policy.SSH),
		)
	}
	return SSHRuleEdit{
		RuleIndex:  index,
		Rule:       policy.SSH[index],
		Operations: []PatchOperation{PatchRemove("ssh", strconv.Itoa(index)), PatchPruneEmpty("ssh")},
	}, nil
}

func sshRuleFromSpec(spec SSHRuleSpec) (SSHRule, bool, error) {
	action := strings.ToLower(strings.TrimSpace(spec.Action))
	if action != sshActionAccept && action != sshActionCheck {
		return SSHRule{}, false, fmt.Errorf("ssh action %q is invalid; use accept or check", spec.Action)
	}
	source, err := requiredSSHSelectors("src", spec.Source)
	if err != nil {
		return SSHRule{}, false, err
	}
	destination, err := requiredSSHSelectors("dst", spec.Destination)
	if err != nil {
		return SSHRule{}, false, err
	}
	users, err := requiredSSHSelectors("user", spec.Users)
	if err != nil {
		return SSHRule{}, false, err
	}
	recorder, err := optionalSSHSelectors("recorder", spec.Recorder)
	if err != nil {
		return SSHRule{}, false, err
	}
	if spec.EnforceRecorder && len(recorder) == 0 {
		return SSHRule{}, false, errors.New("ssh --enforce-recorder requires at least one --recorder")
	}
	checkPeriodText := strings.TrimSpace(spec.CheckPeriod)
	checkPeriodSet := spec.CheckPeriodSet || checkPeriodText != ""
	if action == sshActionAccept && checkPeriodSet {
		return SSHRule{}, false, errors.New("ssh --check-period applies only to action check")
	}
	var checkPeriod tailscale.SSHCheckPeriod
	if checkPeriodSet {
		if checkPeriodText == "" {
			return SSHRule{}, false, errors.New("ssh --check-period must not be empty")
		}
		if periodErr := checkPeriod.UnmarshalText([]byte(checkPeriodText)); periodErr != nil {
			return SSHRule{}, false, fmt.Errorf("invalid ssh check period %q: %w", spec.CheckPeriod, periodErr)
		}
		// Guarding the parsed value alone is not enough in either direction:
		// -1ns parses to the "always" sentinel and would be written back as a
		// stricter rule than the operator asked for, and any other negative
		// duration is written back verbatim as a period nobody can have meant.
		if checkPeriodText != sshCheckPeriodAlways && checkPeriod <= 0 {
			return SSHRule{}, false, fmt.Errorf(
				"ssh --check-period %q must be a positive duration or %q",
				spec.CheckPeriod, sshCheckPeriodAlways,
			)
		}
	}
	return SSHRule{
		Action:          action,
		Source:          source,
		Destination:     destination,
		Users:           users,
		CheckPeriod:     checkPeriod,
		Recorder:        recorder,
		EnforceRecorder: spec.EnforceRecorder}, checkPeriodSet, nil
}

func requiredSSHSelectors(name string, values []string) ([]string, error) {
	values, err := optionalSSHSelectors(name, values)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("ssh add/remove requires at least one --%s", name)
	}
	return values, nil
}

func optionalSSHSelectors(name string, values []string) ([]string, error) {
	trimmed := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil, fmt.Errorf("ssh --%s must not be empty", name)
		}
		if _, duplicate := seen[value]; duplicate {
			continue
		}
		seen[value] = struct{}{}
		trimmed = append(trimmed, value)
	}
	return trimmed, nil
}

func sshRuleSemanticKey(rule SSHRule, checkPeriodSet bool) (string, error) {
	canonical := struct {
		Action          string   `json:"action"`
		Source          []string `json:"src"`
		Destination     []string `json:"dst"`
		Users           []string `json:"users"`
		CheckPeriod     any      `json:"checkPeriod,omitempty"`
		Recorder        []string `json:"recorder"`
		EnforceRecorder bool     `json:"enforceRecorder"`
	}{
		Action:          rule.Action,
		Source:          canonicalSSHSelectors(rule.Source),
		Destination:     canonicalSSHSelectors(rule.Destination),
		Users:           canonicalSSHSelectors(rule.Users),
		Recorder:        canonicalSSHSelectors(rule.Recorder),
		EnforceRecorder: rule.EnforceRecorder,
	}
	if checkPeriodSet {
		canonical.CheckPeriod = rule.CheckPeriod
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("canonicalizing ssh rule: %w", err)
	}
	return string(encoded), nil
}

func canonicalSSHSelectors(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	values = slices.Clone(values)
	slices.Sort(values)
	return slices.Compact(values)
}

func ruleAt(policy *Policy, index int) SSHRule { return policy.SSH[index] }

func sshCheckPeriodPresent(policy *Policy, index int) bool {
	if index < len(policy.sshCheckPeriodPresent) {
		return policy.sshCheckPeriodPresent[index]
	}
	return policy.SSH[index].CheckPeriod != 0
}
