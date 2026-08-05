package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

func TestTestAddCreatesEntry(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)

	res, err := runTestEditJSON(t, path, subAdd,
		"--src", "alice@example.com",
		"--deny", "tag:db:5432",
		"--accept", "tag:web:443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != statusOK || res.TestIndex == nil || *res.TestIndex != 0 {
		t.Errorf("result = %#v", res)
	}
	wantIDs := []string{"tests[0].deny[0]", "tests[0].accept[0]"}
	if !reflect.DeepEqual(res.AssertionIDs, wantIDs) {
		t.Errorf("assertion IDs = %#v, want %#v", res.AssertionIDs, wantIDs)
	}

	policy, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(policy.Tests) != 1 || policy.Tests[0].Source != "alice@example.com" ||
		!reflect.DeepEqual(policy.Tests[0].Deny, []string{"tag:db:5432"}) ||
		!reflect.DeepEqual(policy.Tests[0].Accept, []string{"tag:web:443"}) ||
		policy.Tests[0].User != "" || policy.Tests[0].Allow != nil {
		t.Errorf("tests = %#v", policy.Tests)
	}
}

func TestTestAddCreatesMultipleSameExpectationWithoutDuplicates(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)

	if _, err := runTestEditJSON(t, path, subAdd,
		"--src", "alice@example.com",
		"--deny", "tag:db:5432",
		"--deny", "tag:cache:6379",
	); err != nil {
		t.Fatal(err)
	}
	policy, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	want := []string{"tag:db:5432", "tag:cache:6379"}
	if len(policy.Tests) != 1 || !reflect.DeepEqual(policy.Tests[0].Deny, want) {
		t.Errorf("tests = %#v, want deny %#v", policy.Tests, want)
	}
}

func TestTestAddMergesLegacyEntryPreservesCommentsAndIsIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{
		// policy comment
		"tests": [
			{
				"src": "alice@example.com",
				"accept": ["tag:posture-only:443"],
				"srcPostureAttrs": {"node:os": "linux"},
			},
			// legacy entry comment
			{
				"user": "alice@example.com",
				"allow": ["tag:web:443"],
			},
		],
	}`)

	res, err := runTestEditJSON(t, path, subAdd,
		"--src", "alice@example.com",
		"--deny", "tag:db:5432",
		"--accept", "tag:api:8443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.TestIndex == nil || *res.TestIndex != 1 {
		t.Errorf("test index = %v, want 1", res.TestIndex)
	}
	policy, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(policy.Tests) != 2 {
		t.Fatalf("tests = %#v", policy.Tests)
	}
	legacy := policy.Tests[1]
	if legacy.Source != "" || legacy.User != "alice@example.com" || legacy.Accept != nil ||
		!reflect.DeepEqual(legacy.Allow, []string{"tag:web:443", "tag:api:8443"}) ||
		!reflect.DeepEqual(legacy.Deny, []string{"tag:db:5432"}) {
		t.Errorf("legacy test = %#v", legacy)
	}
	first, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, comment := range []string{"// policy comment", "// legacy entry comment"} {
		if !bytes.Contains(first, []byte(comment)) {
			t.Errorf("edited policy lost %q:\n%s", comment, first)
		}
	}

	res, err = runTestEditJSON(t, path, subAdd,
		"--src", "alice@example.com",
		"--deny", "tag:db:5432",
		"--accept", "tag:api:8443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != statusNoChanges {
		t.Errorf("status = %q, want %q", res.Status, statusNoChanges)
	}
	second, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("idempotent add changed file:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestTestAddRejectsPortlessDestinationWithoutWriting(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	original := []byte("{\n\t// untouched\n}\n")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := runTestEditJSON(t, path, subAdd,
		"--src", "alice@example.com", "--deny", "tag:db",
	)
	if code := exitCode(err); code != exitUsage {
		t.Fatalf("exit code = %d, want %d (error %v)", code, exitUsage, err)
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, original) {
		t.Errorf("rejected edit changed file:\n%s", after)
	}
}

func TestTestAddThenTestEvaluatesNewAssertion(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)
	if _, err := runTestEditJSON(t, path, subAdd,
		"--src", "alice@example.com", "--deny", "tag:db:5432",
	); err != nil {
		t.Fatal(err)
	}

	var stdout strings.Builder
	err := run(
		context.Background(),
		[]string{"--file", path, "-format", formatJSON, cmdTest},
		func(string) string { return "" },
		http.DefaultClient,
		"",
		&stdout,
		io.Discard,
	)
	if !errors.Is(err, errAssertionsFailed) {
		t.Fatalf("error = %v, want an assertion failure", err)
	}
	if !strings.Contains(stdout.String(), `"id": "tests[0].deny[0]"`) ||
		!strings.Contains(stdout.String(), `"status": "fail"`) {
		t.Errorf("test output = %s", stdout.String())
	}
}

func TestTestRemovePrunesEmptyEntryAndIsIdempotent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{
		"tests": [
			{
				"src": "alice@example.com",
				"accept": ["tag:web:443", "tag:api:8443"],
				"deny": ["tag:db:5432"],
			},
			// retained sibling
			{"src": "bob@example.com", "deny": ["tag:db:5432"]},
		],
	}`)

	res, err := runTestEditJSON(t, path, subRemove,
		"--src", "alice@example.com",
		"--deny", "tag:db:5432",
		"--accept", "tag:web:443",
		"--accept", "tag:api:8443",
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != statusOK || res.TestIndex == nil || *res.TestIndex != 0 {
		t.Errorf("result = %#v", res)
	}
	policy, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(policy.Tests) != 1 || policy.Tests[0].Source != "bob@example.com" {
		t.Errorf("tests = %#v", policy.Tests)
	}
	first, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Contains(first, []byte("// retained sibling")) {
		t.Errorf("remove lost sibling comment:\n%s", first)
	}

	res, err = runTestEditJSON(t, path, subRemove,
		"--src", "alice@example.com", "--deny", "tag:db:5432",
	)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != statusNoChanges || res.TestIndex != nil || len(res.AssertionIDs) != 0 {
		t.Errorf("idempotent remove result = %#v", res)
	}
	second, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("idempotent remove changed file")
	}
}

func TestTestRemoveDropsEmptyAssertionKey(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{
		"tests": [{
			"src": "alice@example.com",
			"accept": ["tag:web:443"],
			"deny": ["tag:db:5432"],
		}],
	}`)

	if _, err := runTestEditJSON(t, path, subRemove,
		"--src", "alice@example.com", "--deny", "tag:db:5432",
	); err != nil {
		t.Fatal(err)
	}
	policy, loadErr := aclpolicy.Load(path)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(policy.Tests) != 1 || policy.Tests[0].Deny != nil ||
		!reflect.DeepEqual(policy.Tests[0].Accept, []string{"tag:web:443"}) {
		t.Errorf("tests = %#v", policy.Tests)
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if bytes.Contains(raw, []byte(`"deny"`)) {
		t.Errorf("empty deny key was not pruned:\n%s", raw)
	}
}

func TestTestEditMissingAssertionFlagNamesDenyFirst(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.json")
	writeTestPolicy(t, path, `{}`)
	for _, verb := range []string{subAdd, subRemove} {
		_, err := runTestEditJSON(t, path, verb, "--src", "alice@example.com")
		if err == nil || !strings.Contains(err.Error(), "at least one --deny or --accept") {
			t.Errorf("test %s error = %v", verb, err)
		}
	}
}

func runTestEditJSON(t *testing.T, path, verb string, args ...string) (result, error) {
	t.Helper()
	command := []string{"--file", path, "-format", formatJSON, cmdTest, verb}
	command = append(command, args...)
	var stdout strings.Builder
	err := run(
		context.Background(), command, func(string) string { return "" },
		http.DefaultClient, "", &stdout, io.Discard,
	)
	if stdout.Len() == 0 {
		return result{}, err
	}
	var res result
	if decodeErr := json.Unmarshal([]byte(stdout.String()), &res); decodeErr != nil {
		t.Fatalf("decode result: %v\n%s", decodeErr, stdout.String())
	}
	return res, err
}
