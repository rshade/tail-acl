package main

import (
	"context"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rshade/tsacl/internal/aclpolicy"
)

const ipsetMemberFixture = `{
	// Keep this comment while ipset add writes member forms.
	"hosts": {"gw": "10.9.0.1"},
	"ipsets": {"ipset:base": ["10.0.0.0/8"]},
	"tagOwners": {"tag:web": ["autogroup:admin"]},
	"grants": [{"src": ["tag:web"], "dst": ["ipset:trimmed"], "ip": ["tcp:80"]}],
}`

func TestIPSetAddMemberFormsRoundTrip(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, ipsetMemberFixture)

	_, err := runTSACL(t, path, cmdIPSet, subAdd, "--name", "ipset:trimmed",
		"--member", "ipset:base", "--member", "host:gw",
		"--member", "add 10.0.0.0/8", "--member", "remove 10.1.0.0/16")
	if err == nil {
		t.Fatal("implicit members beside a remove were accepted")
	}
	if code := exitCode(err); code != exitUsage {
		t.Errorf("mixed set exit code = %d, want %d", code, exitUsage)
	}
	want := `ipset member "ipset:base" needs an explicit operation because the set contains "remove 10.1.0.0/16": ` +
		`write it as "add ipset:base"`
	if !strings.Contains(err.Error(), want) {
		t.Errorf("mixed set error = %q, want %q", err, want)
	}
	if got := readPolicy(t, path); got != ipsetMemberFixture {
		t.Errorf("rejected add modified the file:\n%s", got)
	}

	if _, err = runTSACL(t, path, cmdIPSet, subAdd, "--name", "ipset:trimmed",
		"--member", "add ipset:base", "--member", "add host:gw",
		"--cidr", "10.5.1.2/16", "--member", "add 10.0.0.0/8", "--member", "remove 10.1.0.0/16"); err == nil {
		t.Fatal("a --cidr member beside a remove was accepted")
	} else if !strings.Contains(err.Error(), `ipset member "10.5.0.0/16" needs an explicit operation`) {
		t.Errorf("--cidr beside remove error = %q", err)
	}

	stdout, err := runTSACL(t, path, cmdIPSet, subAdd, "--name", "ipset:trimmed",
		"--member", "add ipset:base", "--member", "add host:gw",
		"--member", "add 10.0.0.0/8", "--member", "remove 10.1.0.0/16")
	if err != nil {
		t.Fatalf("explicit set: %v", err)
	}
	if status := decodeStatus(t, stdout); status != statusOK {
		t.Errorf("status = %s, want %s", status, statusOK)
	}
	policy, err := aclpolicy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	wantMembers := []string{"add ipset:base", "add host:gw", "add 10.0.0.0/8", "remove 10.1.0.0/16"}
	if !slices.Equal(policy.IPSets["ipset:trimmed"], wantMembers) {
		t.Errorf("ipset:trimmed = %q, want %q", policy.IPSets["ipset:trimmed"], wantMembers)
	}
	if !strings.Contains(readPolicy(t, path), "// Keep this comment") {
		t.Error("ipset add lost the policy comment")
	}

	written := readPolicy(t, path)
	stdout, err = runTSACL(t, path, cmdIPSet, subAdd, "--name", "ipset:trimmed",
		"--member", "add  ipset:base", "--member", "remove 10.1.2.3/16")
	if err != nil {
		t.Fatalf("repeat add: %v", err)
	}
	if status := decodeStatus(t, stdout); status != statusNoChanges {
		t.Errorf("repeat status = %s, want %s", status, statusNoChanges)
	}
	if got := readPolicy(t, path); got != written {
		t.Errorf("idempotent add changed the file:\n%s\nwant:\n%s", got, written)
	}

	if _, err = runTSACL(t, path, cmdLint); err != nil {
		t.Errorf("lint after an all-explicit set = %v", err)
	}
	if _, err = runTSACL(t, path, cmdIPSet, subRemove, "--name", "ipset:base"); err == nil ||
		!strings.Contains(err.Error(), "ipsets[ipset:trimmed][0]") {
		t.Errorf("removing a nested ipset = %v, want refusal naming ipsets[ipset:trimmed][0]", err)
	}
}

func TestIPSetAddCIDRFlagIsUnchanged(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, ipsetMemberFixture)
	_, err := runTSACL(t, path, cmdIPSet, subAdd, "--name", "ipset:base", "--cidr", "host:gw")
	if err == nil {
		t.Fatal("--cidr accepted a host: alias")
	}
	want := `ipset member "host:gw" is not a CIDR prefix: netip.ParsePrefix("host:gw"): no '/'`
	if !strings.Contains(err.Error(), want) || exitCode(err) != exitUsage {
		t.Errorf("--cidr host: error = %v (exit %d), want %q exit %d", err, exitCode(err), want, exitUsage)
	}
	if got := readPolicy(t, path); got != ipsetMemberFixture {
		t.Errorf("rejected --cidr modified the file:\n%s", got)
	}
}

// TestIPSetAddCIDRWritesBytesIdenticalToMain pins two existing --cidr
// invocations to the exact bytes the tsacl on main (978aef8) wrote for
// them, captured before --member existed: merging canonicalized prefixes into
// an existing ipset, and creating the ipsets object with a comment.
func TestIPSetAddCIDRWritesBytesIdenticalToMain(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, file, before, after string
		args                      []string
	}{
		{
			name: "merge into an existing ipset",
			file: "existing.hujson",
			before: "{\n\t// office network\n" +
				"\t\"ipsets\": {\"ipset:office\": [\"10.0.0.0/8\"]},\n" +
				"\t\"grants\": [{\"src\": [\"autogroup:member\"], \"dst\": [\"ipset:office\"], \"ip\": [\"tcp:443\"]}],\n}\n",
			args: []string{"--name", "ipset:office", "--cidr", "10.1.2.3/8", "--cidr", "192.168.0.0/16",
				"--cidr", "192.168.5.0/16"},
			after: "{\n\t// office network\n" +
				"\t\"ipsets\": {\"ipset:office\": [\"10.0.0.0/8\", \"192.168.0.0/16\"]},\n" +
				"\t\"grants\": [{\n\t\t\"src\": [\"autogroup:member\"],\n\t\t\"dst\": [\"ipset:office\"],\n" +
				"\t\t\"ip\":  [\"tcp:443\"],\n\t}],\n}\n",
		},
		{
			name:   "create the ipsets object with a comment",
			file:   "fresh.json",
			before: "{\"tagOwners\": {\"tag:web\": [\"autogroup:admin\"]}}\n",
			args:   []string{"--name", "ipset:lab", "--cidr", "100.64.0.0/10", "--comment", "Lab"},
			after: "{\"tagOwners\": {\"tag:web\": [\"autogroup:admin\"]}, \"ipsets\": {\n" +
				"\t// Lab\n\t\"ipset:lab\": [\n\t\t\"100.64.0.0/10\",\n\t],\n}}\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), test.file)
			writeTestPolicy(t, path, test.before)
			if _, err := runTSACL(t, path, append([]string{cmdIPSet, subAdd}, test.args...)...); err != nil {
				t.Fatal(err)
			}
			if got := readPolicy(t, path); got != test.after {
				t.Errorf("--cidr output differs from main:\n got: %q\nwant: %q", got, test.after)
			}
		})
	}
}

func TestIPSetAddLintsHandWrittenMixedSet(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "acl.hujson")
	writeTestPolicy(t, path, `{
		"ipsets": {
			"ipset:base": ["10.0.0.0/8"],
			"ipset:mixed": ["ipset:base", "remove 10.1.0.0/16"],
		},
		"tagOwners": {"tag:web": ["autogroup:admin"]},
		"grants": [{"src": ["tag:web"], "dst": ["ipset:mixed"], "ip": ["tcp:80"]}],
	}`)
	stdout, err := runTSACL(t, path, cmdLint)
	if err == nil {
		t.Fatal("lint passed a mixed ipset")
	}
	if code := exitCode(err); code != exitFailed {
		t.Errorf("lint exit code = %d, want %d", code, exitFailed)
	}
	for _, want := range []string{`"id": "ipset-mixed-operations"`, `"rule": "ipsets[ipset:mixed]"`, `"value": "ipset:base"`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("lint output lacks %s:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, `"id": "unused-ipset"`) {
		t.Errorf("lint reported the nested ipset:base as unused:\n%s", stdout)
	}
}

func TestIPSetAddHelpDescribesMemberForms(t *testing.T) {
	t.Parallel()
	var stdout strings.Builder
	err := run(context.Background(), []string{cmdIPSet, subAdd, "--help"},
		func(string) string { return "" }, http.DefaultClient, "", &stdout, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--member", "--cidr", "host:ALIAS", "ipset:NAME", "add|remove"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("help lacks %q:\n%s", want, stdout.String())
		}
	}
}
