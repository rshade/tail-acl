package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rshade/tail-acl/pkg/policycore/sanitize"
	"github.com/rshade/tail-acl/pkg/policycore/sanitize/sanitizetest"
)

func TestMutationMessagesSanitizeEditedIdentities(t *testing.T) {
	t.Parallel()

	const (
		empty         = "{\n\t\"grants\": [],\n}\n"
		hostName      = "SecretDB"
		hostAddress   = "100.64.0.10"
		tagName       = "tag:SecretTag"
		owner         = "carol@example.com"
		routeAdd      = "10.30.0.0/16"
		routeRemove   = "10.20.0.0/16"
		groupAdd      = "group:NewTeam"
		groupMember   = "bob@example.com"
		groupRemove   = "group:SecretTeam"
		ipsetAdd      = "ipset:NewNet"
		ipsetMember   = "10.8.0.0/16"
		ipsetRemove   = "ipset:SecretNet"
		postureAdd    = "posture:NewPosture"
		postureRemove = "posture:SecretPosture"
		postureExpr   = `node:tsReleaseTrack == "stable"`
	)
	object := func(body string) string {
		return "{\n\t" + body + ",\n}\n"
	}
	cases := []struct {
		name        string
		changed     string
		noop        string
		args        []string
		hidden      []string
		operational []string
		alsoAbsent  []string
	}{
		{
			name: "host set", changed: empty,
			noop:   object(fmt.Sprintf(`"hosts": {%q: %q}`, hostName, hostAddress)),
			args:   []string{"host", "set", hostName, hostAddress},
			hidden: []string{hostName, hostAddress},
		},
		{
			name: "tag-owner add", changed: empty,
			noop:        object(fmt.Sprintf(`"tagOwners": {%q: [%q]}`, tagName, owner)),
			args:        []string{"tag-owner", "add", tagName, owner},
			hidden:      []string{owner},
			operational: []string{tagName},
		},
		{
			name: "auto-approver add", changed: empty,
			noop: object(fmt.Sprintf(
				`"autoApprovers": {"routes": {%q: [%q]}}`, routeAdd, tagName,
			)),
			args:   []string{"auto-approver", "add", "--route", routeAdd, "--approver", tagName},
			hidden: []string{routeAdd},
		},
		{
			name: "auto-approver remove",
			changed: object(fmt.Sprintf(
				`"autoApprovers": {"routes": {%q: [%q]}}`, routeRemove, tagName,
			)),
			noop:   empty,
			args:   []string{"auto-approver", "remove", "--route", routeRemove, "--approver", tagName},
			hidden: []string{routeRemove},
		},
		{
			name: "group add", changed: empty,
			noop:        object(fmt.Sprintf(`"groups": {%q: [%q]}`, groupAdd, groupMember)),
			args:        []string{"group", "add", "--name", groupAdd, "--member", groupMember},
			operational: []string{groupAdd},
			alsoAbsent:  []string{groupMember},
		},
		{
			name:        "group remove",
			changed:     object(fmt.Sprintf(`"groups": {%q: [%q]}`, groupRemove, groupMember)),
			noop:        empty,
			args:        []string{"group", "remove", "--name", groupRemove},
			operational: []string{groupRemove},
			alsoAbsent:  []string{groupMember},
		},
		{
			name: "ipset add", changed: empty,
			noop:        object(fmt.Sprintf(`"ipsets": {%q: [%q]}`, ipsetAdd, ipsetMember)),
			args:        []string{"ipset", "add", "--name", ipsetAdd, "--member", ipsetMember},
			operational: []string{ipsetAdd},
			alsoAbsent:  []string{ipsetMember},
		},
		{
			name:        "ipset remove",
			changed:     object(fmt.Sprintf(`"ipsets": {%q: [%q]}`, ipsetRemove, ipsetMember)),
			noop:        empty,
			args:        []string{"ipset", "remove", "--name", ipsetRemove},
			operational: []string{ipsetRemove},
			alsoAbsent:  []string{ipsetMember},
		},
		{
			name: "posture set", changed: empty,
			noop:        object(fmt.Sprintf(`"postures": {%q: [%q]}`, postureAdd, postureExpr)),
			args:        []string{"posture", "set", postureAdd, postureExpr},
			operational: []string{postureAdd},
		},
		{
			name:        "posture remove",
			changed:     object(fmt.Sprintf(`"postures": {%q: [%q]}`, postureRemove, postureExpr)),
			noop:        empty,
			args:        []string{"posture", "remove", postureRemove},
			operational: []string{postureRemove},
		},
	}

	for _, testCase := range cases {
		for _, outcome := range []struct {
			name   string
			policy string
			status string
		}{
			{name: "changed", policy: testCase.changed, status: statusOK},
			{name: "noop", policy: testCase.noop, status: statusNoChanges},
		} {
			for _, level := range []sanitize.Level{sanitize.Off, sanitize.Identity, sanitize.Strict} {
				for _, format := range []string{formatJSON, formatHuman} {
					t.Run(testCase.name+"/"+outcome.name+"/"+string(level)+"/"+format, func(t *testing.T) {
						t.Parallel()
						assertMutationMessage(t, mutationMessageCase{
							policy: outcome.policy, status: outcome.status, args: testCase.args,
							level: level, format: format,
							hidden: testCase.hidden, operational: testCase.operational,
							alsoAbsent: testCase.alsoAbsent,
						})
					})
				}
			}
		}
	}
}

type mutationMessageCase struct {
	policy      string
	status      string
	args        []string
	level       sanitize.Level
	format      string
	hidden      []string
	operational []string
	alsoAbsent  []string
}

func assertMutationMessage(t *testing.T, testCase mutationMessageCase) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, testCase.policy)
	args := mutationArgs(testCase.level, testCase.format, testCase.args)
	stdout, err := runTailACL(t, path, args...)
	if err != nil {
		t.Fatalf("run: %v\n%s", err, stdout)
	}
	if testCase.format == formatJSON {
		if got := decodeStatus(t, stdout); got != testCase.status {
			t.Fatalf("status = %q, want %q\n%s", got, testCase.status, stdout)
		}
		assertEnvelopeOmitsEdited(t, stdout)
	}
	switch testCase.level {
	case sanitize.Off:
		for _, value := range append([]string{path}, append(testCase.hidden, testCase.operational...)...) {
			if !strings.Contains(stdout, value) {
				t.Errorf("unsanitized output missing %q\n%s", value, stdout)
			}
		}
	case sanitize.Identity:
		sanitizetest.AssertNoIdentityLeaks(t, []byte(stdout), append(
			[]string{path}, append(testCase.hidden, testCase.alsoAbsent...)...,
		))
		for _, value := range testCase.operational {
			if !strings.Contains(stdout, value) {
				t.Errorf("identity output hid operational name %q\n%s", value, stdout)
			}
		}
	case sanitize.Strict:
		sanitizetest.AssertNoIdentityLeaks(t, []byte(stdout), append(
			[]string{path}, append(append(testCase.hidden, testCase.alsoAbsent...), testCase.operational...)...,
		))
	}
}

func mutationArgs(level sanitize.Level, format string, command []string) []string {
	prefix := []string{}
	if level != sanitize.Off {
		prefix = append(prefix, "--sanitize", string(level))
	}
	if level != sanitize.Off || format != formatJSON {
		prefix = append(prefix, "-format", format)
	}
	return append(prefix, command...)
}

func assertEnvelopeOmitsEdited(t *testing.T, stdout string) {
	t.Helper()
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, stdout)
	}
	if _, ok := envelope["edited"]; ok {
		t.Errorf("JSON envelope serialized edited identities:\n%s", stdout)
	}
}
