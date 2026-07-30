// Command tail-acl makes typed edits to a Tailscale policy file and can merge,
// validate, test, check, lint, plan, or upload it with Tailscale's policy-file API.
//
// Output contract (AX conventions, see ../../CLAUDE.md): the command result is
// written to stdout — human text by default, or a versioned JSON envelope with
// -format json — while logs and errors go to stderr. Exit codes: 0 success,
// 1 the operation or an assertion failed, 2 usage/input/collection failed, and
// 10 the question could not be settled from the policy file alone.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
	"github.com/rshade/tailscale-utils/tail-acl/internal/buildinfo"
	"github.com/rshade/tailscale-utils/tail-acl/internal/tailapi"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

// schemaVersion versions the JSON result envelope and the -schema document.
// Bump it on any breaking change to either shape.
const schemaVersion = "1"

// Exit codes, documented in usage() and the -schema output.
const (
	exitOK     = 0
	exitFailed = 1 // a valid operation or policy assertion failed
	exitUsage  = 2 // usage, input, credentials, or collection failed
	// exitIndeterminate is a per-scenario code from the AX scheme's reserved
	// 10+ range. check uses it for a question the policy file alone cannot
	// settle, which is neither a denial (exit 1) nor a caller mistake (exit 2).
	exitIndeterminate = 10
)

// Result statuses reported in the envelope's "status" field.
const (
	statusOK            = "ok"
	statusFailed        = "failed"
	statusNoChanges     = "no_changes"
	statusChangesFound  = "changes_found"
	statusIndeterminate = "indeterminate"
	verdictReachable    = "reachable"
	verdictNotReachable = "not reachable"
	// verdictIndeterminate names the third answer in human output. It reads as
	// a verdict rather than an error because the policy is well-formed and the
	// question is well-posed; the fact needed to settle it just is not here.
	verdictIndeterminate = "indeterminate"
)

// Command and sub-command names, output formats, and the tool name.
const (
	toolName = "tail-acl"

	cmdGrant    = "grant"
	cmdTagOwner = "tag-owner"
	cmdHost     = "host"
	cmdPosture  = "posture"
	cmdMerge    = "merge"
	cmdValidate = "validate"
	cmdTest     = "test"
	cmdCheck    = "check"
	cmdLint     = "lint"
	cmdPlan     = "plan"
	cmdUpload   = "upload"

	subAdd    = "add"
	subRemove = "remove"
	subSet    = "set"

	formatHuman = "human"
	formatJSON  = "json"

	commandGrantAdd      = "grant add"
	commandGrantRemove   = "grant remove"
	commandTagOwnerAdd   = "tag-owner add"
	commandHostSet       = "host set"
	commandPostureSet    = "posture set"
	commandPostureRemove = "posture remove"

	policyFormatHuJSON = "hujson"
)

// httpTimeout bounds every Tailscale API request.
const httpTimeout = 30 * time.Second

type options struct {
	file    string
	tailnet string
	apiKey  string
	ifMatch string
	strict  bool
}

// result is the versioned envelope every command returns. Human rendering emits
// Message (and Diff, when present); JSON rendering emits the whole struct.
type result struct {
	SchemaVersion string `json:"schema_version"`
	Tool          string `json:"tool"`
	Command       string `json:"command"`
	Status        string `json:"status"`
	Message       string `json:"message"`
	File          string `json:"file,omitempty"`
	Tailnet       string `json:"tailnet,omitempty"`
	ETag          string `json:"etag,omitempty"`
	Diff          string `json:"diff,omitempty"`
	Changed       *bool  `json:"changed,omitempty"`
	GrantIndex    *int   `json:"grant_index,omitempty"`
	ACLIndex      *int   `json:"acl_index,omitempty"`
	MergedFiles   *int   `json:"merged_files,omitempty"`
	// Access is the three-state reachability verdict. Allowed is the older
	// two-state field and is emitted only for a definite answer: an
	// indeterminate result omits it rather than serializing false, which a
	// consumer reading just that key would misread as a denial.
	Access      aclpolicy.Access   `json:"access,omitempty"`
	Allowed     *bool              `json:"allowed,omitempty"`
	Source      string             `json:"source,omitempty"`
	Destination string             `json:"destination,omitempty"`
	Port        *uint16            `json:"port,omitempty"`
	Protocol    aclpolicy.Protocol `json:"protocol,omitempty"`
	Evidence    string             `json:"evidence,omitempty"`
	Trace       []string           `json:"trace,omitempty"`
	// Assertions is a pointer so a test run with no declared tests still emits
	// "assertions": [] rather than dropping the key, while every other command
	// omits it — the same absent-versus-zero split as Changed and MergedFiles.
	Assertions *[]aclpolicy.AssertionResult `json:"assertions,omitempty"`
	// Skipped is an exception list, so absent genuinely means "nothing skipped"
	// and a plain omitempty slice is right here.
	Skipped []aclpolicy.RuleSkip `json:"skipped,omitempty"`
	// SSHTestsSkipped counts top-level sshTests assertions that were loaded but
	// not evaluated. It is a plain omitempty int for the same reason as Skipped:
	// absent genuinely means none were skipped, so a consumer never has to
	// distinguish zero from unset.
	SSHTestsSkipped int                    `json:"ssh_tests_skipped,omitempty"`
	TestSummary     *aclpolicy.TestSummary `json:"test_summary,omitempty"`
	// Findings is a pointer for the same reason as Assertions: a lint run with a
	// clean policy still emits "findings": [] rather than dropping the key, while
	// every other command omits it.
	Findings    *[]aclpolicy.LintFinding `json:"findings,omitempty"`
	LintSummary *aclpolicy.LintSummary   `json:"lint_summary,omitempty"`
}

var (
	errAssertionsFailed   = errors.New("one or more policy assertions failed")
	errReachabilityDenied = errors.New("policy does not allow the requested reachability")
	errLintFindings       = errors.New("policy lint found issues at or above the severity threshold")
	// errReachabilityIndeterminate carries exit 10. It is deliberately not a
	// usageError: the caller did nothing wrong and the policy is not at fault —
	// the answer simply is not derivable from a policy file.
	errReachabilityIndeterminate = errors.New("reachability cannot be determined from the policy file alone")
)

// usageError marks an error as an invocation problem (exit 2) rather than an
// operation failure (exit 1), so exitCode can tell "you called it wrong" from
// "it tried and failed".
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func usagef(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }

func main() {
	client := &http.Client{Timeout: httpTimeout}
	apiURL := os.Getenv("TAILSCALE_API_URL")
	if apiURL == "" {
		apiURL = tailapi.DefaultBaseURL
	}
	err := run(context.Background(), os.Args[1:], os.Getenv, client, apiURL, os.Stdout, os.Stderr)
	if err != nil && !errors.Is(err, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "tail-acl:", err)
	}
	os.Exit(exitCode(err))
}

// exitCode maps a run error onto the documented exit-code scheme.
func exitCode(err error) int {
	var ue usageError
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.Is(err, errReachabilityIndeterminate):
		return exitIndeterminate
	case errors.As(err, &ue):
		return exitUsage
	default:
		return exitFailed
	}
}

func run(
	ctx context.Context,
	args []string,
	getenv func(string) string,
	httpClient *http.Client,
	apiURL string,
	stdout, stderr io.Writer,
) error {
	root := flag.NewFlagSet(toolName, flag.ContinueOnError)
	root.SetOutput(stderr)
	var opts options
	root.StringVar(
		&opts.file,
		"file",
		"acl.json",
		"policy file (typed edits preserve comments in JSON and HuJSON)",
	)
	root.StringVar(
		&opts.tailnet,
		"tailnet",
		getenv("TAILSCALE_TAILNET"),
		"tailnet name or ID (default: TAILSCALE_TAILNET)",
	)
	root.StringVar(&opts.apiKey, "api-key", "", "Tailscale API access token (default: TAILSCALE_API_KEY)")
	root.StringVar(&opts.ifMatch, "if-match", "", "optional ETag required for upload")
	root.BoolVar(
		&opts.strict,
		"strict",
		false,
		"test/check: reject a policy containing an unparseable rule instead of warning",
	)
	format := root.String("format", formatHuman, "output format: human|json")
	verbose := root.Bool("verbose", false, "log operational detail to stderr")
	showVersion := root.Bool("version", false, "print version and exit")
	showSchema := root.Bool("schema", false, "print the machine-readable tool schema (JSON) and exit")
	root.Usage = func() { usage(stderr, root) }

	if err := root.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err}
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, buildinfo.Version(toolName, version))
		return err
	}
	if *showSchema {
		return printSchema(stdout, root)
	}
	if opts.apiKey == "" {
		opts.apiKey = getenv("TAILSCALE_API_KEY")
	}
	if *format != formatHuman && *format != formatJSON {
		return usagef("unknown -format %q; want human or json", *format)
	}

	logger := newLogger(stderr, *verbose)
	remaining := root.Args()
	if len(remaining) == 0 {
		root.Usage()
		return usageError{errors.New("a command is required")}
	}

	res, dispatchErr := dispatch(ctx, remaining, opts, httpClient, apiURL, logger)
	if res != nil {
		if err := render(stdout, *format, res); err != nil {
			return err
		}
	}
	return dispatchErr
}

func newLogger(w io.Writer, verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

func dispatch(
	ctx context.Context,
	args []string,
	opts options,
	httpClient *http.Client,
	apiURL string,
	logger *slog.Logger,
) (*result, error) {
	command := args[0]
	logger.DebugContext(ctx, "dispatching command", "command", command, "file", opts.file)
	switch command {
	case cmdGrant:
		return runGrant(opts.file, args[1:])
	case cmdTagOwner:
		return runTagOwner(opts.file, args[1:])
	case cmdHost:
		return runHost(opts.file, args[1:])
	case cmdPosture:
		return runPosture(opts.file, args[1:])
	case cmdMerge:
		return runMerge(opts.file, args[1:])
	case cmdValidate:
		return runValidate(ctx, opts, httpClient, apiURL, args[1:])
	case cmdTest:
		return runTest(ctx, opts, args[1:], logger)
	case cmdCheck:
		return runCheck(ctx, opts, args[1:], logger)
	case cmdLint:
		return runLint(ctx, opts, args[1:], logger)
	case cmdPlan:
		return runPlan(ctx, opts, httpClient, apiURL, args[1:])
	case cmdUpload:
		return runUpload(ctx, opts, httpClient, apiURL, args[1:])
	default:
		return nil, usagef("unknown command %q", command)
	}
}

func newResult(command, status, message string) *result {
	return &result{
		SchemaVersion: schemaVersion,
		Tool:          toolName,
		Command:       command,
		Status:        status,
		Message:       message,
	}
}

// render writes the result to stdout in the requested format. Human output
// prints the diff (when present) followed by the summary line; JSON output
// emits the versioned envelope.
func render(w io.Writer, format string, res *result) error {
	if format == formatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	if res.Diff != "" {
		if _, err := io.WriteString(w, res.Diff); err != nil {
			return err
		}
	}
	if res.Assertions != nil {
		for _, assertion := range *res.Assertions {
			if _, err := fmt.Fprintf(
				w,
				"%s %s %s -> %s (expected %s, got %s; %s)\n",
				strings.ToUpper(string(assertion.Status)),
				assertion.ID,
				assertion.Source,
				assertion.Destination,
				assertion.Expected,
				assertion.Actual,
				assertion.Evidence,
			); err != nil {
				return err
			}
		}
	}
	if res.Findings != nil {
		for _, finding := range *res.Findings {
			locator := finding.Rule
			if finding.Value != "" {
				locator = finding.Rule + " " + finding.Value
			}
			if _, err := fmt.Fprintf(
				w,
				"%s %s %s: %s\n",
				strings.ToUpper(string(finding.Severity)),
				finding.ID,
				locator,
				finding.Evidence,
			); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintln(w, "tail-acl:", res.Message)
	return err
}

func runGrant(path string, args []string) (*result, error) {
	if len(args) == 0 {
		return nil, usagef("grant requires add or remove")
	}
	switch args[0] {
	case subAdd:
		return runGrantAdd(path, args[1:])
	case subRemove:
		return runGrantRemove(path, args[1:])
	default:
		return nil, usagef("unknown grant command %q", args[0])
	}
}

// parseGrantAddArgs returns the grant "grant add" was asked to author, plus the
// comment to attach to it and whether that comment replaces existing ones.
func parseGrantAddArgs(args []string) (tailscale.Grant, string, bool, error) {
	fs := flag.NewFlagSet("tail-acl grant add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var source, destination, ip, srcPosture stringListFlag
	fs.Var(&source, "src", "grant source; may be repeated")
	fs.Var(&destination, "dst", "grant destination; may be repeated")
	fs.Var(&ip, "ip", "IP protocol and port expression; may be repeated")
	fs.Var(&srcPosture, "src-posture", "required device posture (posture:NAME); may be repeated")
	text, overwrite := registerCommentFlags(fs)
	if err := fs.Parse(args); err != nil {
		return tailscale.Grant{}, "", false, usageError{err}
	}
	if len(fs.Args()) != 0 {
		return tailscale.Grant{}, "", false,
			usagef("unexpected grant add arguments: %s", strings.Join(fs.Args(), " "))
	}
	comment, overwriteComment, err := commentText(fs, text, overwrite)
	if err != nil {
		return tailscale.Grant{}, "", false, err
	}
	for _, posture := range srcPosture {
		if postureErr := aclpolicy.ValidatePostureReference(posture); postureErr != nil {
			return tailscale.Grant{}, "", false, usageError{postureErr}
		}
	}
	if len(source) == 0 || len(destination) == 0 || len(ip) == 0 {
		return tailscale.Grant{}, "", false,
			usagef("grant add requires at least one --src, --dst, and --ip")
	}
	grant := tailscale.Grant{
		Source:      []string(source),
		Destination: []string(destination),
		IP:          []string(ip),
		SrcPosture:  []string(srcPosture),
	}
	return grant, comment, overwriteComment, nil
}

func runGrantAdd(path string, args []string) (*result, error) {
	grant, comment, overwriteComment, err := parseGrantAddArgs(args)
	if err != nil {
		return nil, err
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	grantKey, err := aclpolicy.GrantSemanticKey(grant)
	if err != nil {
		return nil, err
	}
	var matchingGrants []int
	for i := range policy.Grants {
		existingKey, keyErr := aclpolicy.GrantSemanticKey(policy.Grants[i])
		if keyErr != nil {
			return nil, keyErr
		}
		if existingKey == grantKey {
			// Without a comment there is no syntax-tree node to choose, so keep
			// the established idempotent behavior even when lint would report
			// duplicate grants.
			if comment == "" {
				return commentExistingGrant(path, comment, overwriteComment, i)
			}
			matchingGrants = append(matchingGrants, i)
		}
	}
	if len(matchingGrants) > 1 {
		return nil, fmt.Errorf(
			"cannot comment grant: duplicate grants match at indexes %v; remove duplicates first",
			matchingGrants,
		)
	}
	if len(matchingGrants) == 1 {
		return commentExistingGrant(path, comment, overwriteComment, matchingGrants[0])
	}
	grantsPresent := policy.Grants != nil
	policy.Grants = append(policy.Grants, grant)
	operation := aclpolicy.PatchAdd(policy.Grants, "grants")
	if grantsPresent {
		operation = aclpolicy.PatchAdd(grant, "grants", "-")
	}
	operations := []aclpolicy.PatchOperation{operation}
	if comment != "" {
		// "-" names the last element after the patch, which is the appended
		// grant whether the operation created the block or added into it.
		operations = append(operations, commentPatch(comment, overwriteComment, "grants", "-"))
	}
	if err = aclpolicy.WritePatch(path, operations...); err != nil {
		return nil, err
	}
	index := len(policy.Grants) - 1
	return grantResult(commandGrantAdd, statusOK,
		fmt.Sprintf("added grant %d to %s", index, path), path, index), nil
}

// commentExistingGrant handles "grant add" for a grant the policy already
// carries. A comment is the only thing such a call can still change: a grant's
// identity is its selectors, and tailscale.Grant has no comment field, so
// comment state lives in the syntax tree alone.
func commentExistingGrant(path, comment string, overwrite bool, index int) (*result, error) {
	operations, err := commentOperations(path, comment, overwrite, "grants", strconv.Itoa(index))
	if err != nil {
		return nil, err
	}
	if len(operations) == 0 {
		return grantResult(commandGrantAdd, statusNoChanges,
			fmt.Sprintf("grant %d already exists in %s", index, path), path, index), nil
	}
	if err = aclpolicy.WritePatch(path, operations...); err != nil {
		return nil, err
	}
	return grantResult(commandGrantAdd, statusOK,
		fmt.Sprintf("added comment to grant %d in %s", index, path), path, index), nil
}

func runGrantRemove(path string, args []string) (*result, error) {
	fs := flag.NewFlagSet("tail-acl grant remove", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	index := fs.Int("index", -1, "zero-based grant index")
	if err := fs.Parse(args); err != nil {
		return nil, usageError{err}
	}
	if len(fs.Args()) != 0 {
		return nil, usagef("unexpected grant remove arguments: %s", strings.Join(fs.Args(), " "))
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	if *index < 0 || *index >= len(policy.Grants) {
		return nil, usagef("grant index %d is out of range; policy has %d grants", *index, len(policy.Grants))
	}
	// Remove the element, never the whole "grants" key: dropping the key would
	// carry its comments out with it, which is the data loss this command
	// exists to avoid. An empty array reloads as an empty slice.
	if err = aclpolicy.WritePatch(path, aclpolicy.PatchRemove("grants", strconv.Itoa(*index))); err != nil {
		return nil, err
	}
	return grantResult(commandGrantRemove, statusOK,
		fmt.Sprintf("removed grant %d from %s", *index, path), path, *index), nil
}

func grantResult(command, status, message, path string, index int) *result {
	res := newResult(command, status, message)
	res.File = path
	res.GrantIndex = &index
	return res
}

func runTagOwner(path string, args []string) (*result, error) {
	fs := flag.NewFlagSet("tail-acl tag-owner add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	text, overwrite := registerCommentFlags(fs)
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, err
	}
	if len(positional) != 3 || positional[0] != subAdd {
		return nil, usagef("usage: tail-acl tag-owner add TAG OWNER")
	}
	comment, overwriteComment, err := commentText(fs, text, overwrite)
	if err != nil {
		return nil, err
	}
	tag, owner := positional[1], positional[2]
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	if index := slices.Index(policy.TagOwners[tag], owner); index >= 0 {
		return commentExistingOwner(path, comment, overwriteComment, tag, owner, index)
	}
	var operation aclpolicy.PatchOperation
	switch owners := policy.TagOwners[tag]; {
	case policy.TagOwners == nil:
		operation = aclpolicy.PatchAdd(map[string][]string{tag: {owner}}, "tagOwners")
	case owners == nil:
		operation = aclpolicy.PatchAdd([]string{owner}, "tagOwners", tag)
	default:
		operation = aclpolicy.PatchAdd(owner, "tagOwners", tag, "-")
	}
	operations := []aclpolicy.PatchOperation{operation}
	if comment != "" {
		// "-" names the last element once the patch has run, which is where all
		// three branches above leave the new owner.
		operations = append(operations, commentPatch(comment, overwriteComment, "tagOwners", tag, "-"))
	}
	if err = aclpolicy.WritePatch(path, operations...); err != nil {
		return nil, err
	}
	res := newResult(commandTagOwnerAdd, statusOK, fmt.Sprintf("added owner %s to %s in %s", owner, tag, path))
	res.File = path
	return res, nil
}

// commentExistingOwner handles "tag-owner add" for an owner the tag already
// has. Without a comment that stays the no-op it has always been; with one, the
// comment alone is the edit.
func commentExistingOwner(path, comment string, overwrite bool, tag, owner string, index int) (*result, error) {
	operations, err := commentOperations(path, comment, overwrite, "tagOwners", tag, strconv.Itoa(index))
	if err != nil {
		return nil, err
	}
	res := newResult(commandTagOwnerAdd, statusNoChanges,
		fmt.Sprintf("owner %s already owns %s in %s", owner, tag, path))
	if len(operations) > 0 {
		if err = aclpolicy.WritePatch(path, operations...); err != nil {
			return nil, err
		}
		res = newResult(commandTagOwnerAdd, statusOK,
			fmt.Sprintf("added comment to owner %s of %s in %s", owner, tag, path))
	}
	res.File = path
	return res, nil
}

func runHost(path string, args []string) (*result, error) {
	fs := flag.NewFlagSet("tail-acl host set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	text, overwrite := registerCommentFlags(fs)
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, err
	}
	if len(positional) != 3 || positional[0] != subSet {
		return nil, usagef("usage: tail-acl host set NAME ADDRESS")
	}
	comment, overwriteComment, err := commentText(fs, text, overwrite)
	if err != nil {
		return nil, err
	}
	name, address := positional[1], positional[2]
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	// Skip the value operation when the address already matches, so a
	// comment-only edit really is comment-only and a repeat is reported as such.
	var operations []aclpolicy.PatchOperation
	if existing, present := policy.Hosts[name]; !present || existing != address {
		operation := aclpolicy.PatchAdd(map[string]string{name: address}, "hosts")
		if policy.Hosts != nil {
			operation = aclpolicy.PatchAdd(address, "hosts", name)
		}
		operations = append(operations, operation)
	}
	commentOps, err := commentOperations(path, comment, overwriteComment, "hosts", name)
	if err != nil {
		return nil, err
	}
	operations = append(operations, commentOps...)

	res := newResult(commandHostSet, statusNoChanges,
		fmt.Sprintf("host %s already set to %s in %s", name, address, path))
	if len(operations) > 0 {
		if err = aclpolicy.WritePatch(path, operations...); err != nil {
			return nil, err
		}
		res = newResult(commandHostSet, statusOK, fmt.Sprintf("set host %s to %s in %s", name, address, path))
	}
	res.File = path
	return res, nil
}

func runPosture(path string, args []string) (*result, error) {
	if len(args) == 0 {
		return nil, usagef("posture requires set or remove")
	}
	switch args[0] {
	case subSet:
		return runPostureSet(path, args[1:])
	case subRemove:
		return runPostureRemove(path, args[1:])
	default:
		return nil, usagef("unknown posture command %q", args[0])
	}
}

func runPostureSet(path string, args []string) (*result, error) {
	fs := flag.NewFlagSet("tail-acl posture set", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	text, overwrite := registerCommentFlags(fs)
	positional, err := parseInterspersed(fs, args)
	if err != nil {
		return nil, err
	}
	if len(positional) < 2 { //nolint:mnd // NAME and at least one EXPR required
		return nil, usagef("usage: tail-acl posture set NAME EXPR [EXPR ...]")
	}
	comment, overwriteComment, err := commentText(fs, text, overwrite)
	if err != nil {
		return nil, err
	}
	canonical, err := aclpolicy.NormalizePostureName(positional[0])
	if err != nil {
		return nil, usageError{err}
	}
	exprs := positional[1:]
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	// Order-sensitive equality is the conservative reading: nothing else in the
	// tool treats a posture's expression list as an unordered set, so reordering
	// it stays a real edit.
	var operations []aclpolicy.PatchOperation
	if existing, present := policy.Postures[canonical]; !present || !slices.Equal(existing, exprs) {
		operation := aclpolicy.PatchAdd(map[string][]string{canonical: slices.Clone(exprs)}, "postures")
		if policy.Postures != nil {
			operation = aclpolicy.PatchAdd(slices.Clone(exprs), "postures", canonical)
		}
		operations = append(operations, operation)
	}
	commentOps, err := commentOperations(path, comment, overwriteComment, "postures", canonical)
	if err != nil {
		return nil, err
	}
	operations = append(operations, commentOps...)

	res := newResult(commandPostureSet, statusNoChanges,
		fmt.Sprintf("posture %s already set in %s", canonical, path))
	if len(operations) > 0 {
		if err = aclpolicy.WritePatch(path, operations...); err != nil {
			return nil, err
		}
		res = newResult(commandPostureSet, statusOK, fmt.Sprintf("set posture %s in %s", canonical, path))
	}
	res.File = path
	return res, nil
}

func runPostureRemove(path string, args []string) (*result, error) {
	if len(args) != 1 {
		return nil, usagef("usage: tail-acl posture remove NAME")
	}
	canonical, err := aclpolicy.NormalizePostureName(args[0])
	if err != nil {
		return nil, usageError{err}
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	if _, ok := policy.Postures[canonical]; !ok {
		res := newResult(commandPostureRemove, statusNoChanges,
			fmt.Sprintf("posture %s not present in %s", canonical, path))
		res.File = path
		return res, nil
	}
	// Remove the member, never the whole "postures" key — see runGrantRemove.
	if err = aclpolicy.WritePatch(path, aclpolicy.PatchRemove("postures", canonical)); err != nil {
		return nil, err
	}
	res := newResult(commandPostureRemove, statusOK,
		fmt.Sprintf("removed posture %s from %s", canonical, path))
	res.File = path
	return res, nil
}

// loadForEdit validates the complete typed policy before a raw HuJSON patch is
// selected and written. DisallowUnknownFields makes this the data-loss guard:
// an edit cannot silently discard policy data the pinned schema does not model.
func loadForEdit(path string) (*aclpolicy.Policy, error) {
	return aclpolicy.Load(path)
}

// Comment flags are registered per command rather than globally. Only the typed
// authoring commands can name the node a comment belongs to, and a global flag
// would be quietly accepted by every command that cannot.
const (
	commentFlagName   = "comment"
	overwriteFlagName = "overwrite-comment"
)

func registerCommentFlags(fs *flag.FlagSet) (*string, *bool) {
	text := fs.String(commentFlagName, "", "attach TEXT to the authored entry as a leading // comment")
	overwrite := fs.Bool(overwriteFlagName, false,
		"replace the entry's existing comments instead of appending to them")
	return text, overwrite
}

// commentText returns the validated comment body and whether it replaces the
// entry's existing comments.
//
// fs.Visit is what distinguishes an unset flag from --comment "": the empty
// string asks for a comment, and "// " is an edit nobody requested.
// --overwrite-comment alone is rejected rather than ignored, because doing
// nothing quietly would read as "the overwrite happened".
func commentText(fs *flag.FlagSet, text *string, overwrite *bool) (string, bool, error) {
	var set bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == commentFlagName {
			set = true
		}
	})
	if !set {
		if *overwrite {
			return "", false, usagef("--%s requires --%s", overwriteFlagName, commentFlagName)
		}
		return "", false, nil
	}
	if err := aclpolicy.ValidateCommentText(*text); err != nil {
		return "", false, usageError{err}
	}
	return strings.TrimSpace(*text), *overwrite, nil
}

// commentPatch builds the operation that authors comment onto a node the same
// call is creating. It needs no duplicate check: a node that does not exist yet
// cannot already carry a comment.
func commentPatch(comment string, overwrite bool, segments ...string) aclpolicy.PatchOperation {
	if overwrite {
		return aclpolicy.PatchCommentOverwrite(comment, segments...)
	}
	return aclpolicy.PatchComment(comment, segments...)
}

// commentOperations returns the operation that authors comment onto an entry
// that already exists, or none when the entry already reads that way.
//
// Whether this is a change is decided from the same LeadingComments the writer
// suppresses duplicates with, so a command cannot report a change for a write
// that changed nothing.
func commentOperations(path, comment string, overwrite bool, segments ...string) ([]aclpolicy.PatchOperation, error) {
	if comment == "" {
		return nil, nil
	}
	existing, err := aclpolicy.LeadingComments(path, segments...)
	if err != nil {
		return nil, err
	}
	unchanged := slices.Contains(existing, comment)
	if overwrite {
		unchanged = slices.Equal(existing, []string{comment})
	}
	if unchanged {
		return nil, nil
	}
	return []aclpolicy.PatchOperation{commentPatch(comment, overwrite, segments...)}, nil
}

// parseInterspersed parses registered flags appearing anywhere among positional
// arguments and returns the positionals in order.
//
// Go's flag package stops at the first non-flag argument, but the documented
// form puts the flag last:
//
//	tail-acl --file acl.json host set web 100.64.0.10 --comment "..."
//
// so parsing has to resume after each positional. Only registered flags are
// parsed: posture expressions are opaque strings and may legitimately begin
// with "-", such as "-1 < custom:score". A bare "--" stops flag recognition so
// even an expression named like a registered flag can be passed literally.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for len(args) > 0 {
		arg := args[0]
		if arg == "--" {
			return append(positional, args[1:]...), nil
		}

		nameValue := strings.TrimPrefix(arg, "-")
		nameValue = strings.TrimPrefix(nameValue, "-")
		name, _, hasValue := strings.Cut(nameValue, "=")
		registered := fs.Lookup(name)
		if registered == nil || !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			args = args[1:]
			continue
		}

		flagArgs := args[:1]
		consumed := 1
		boolFlag, isBoolFlag := registered.Value.(interface{ IsBoolFlag() bool })
		if !hasValue && (!isBoolFlag || !boolFlag.IsBoolFlag()) {
			if len(args) < 2 { //nolint:mnd // flag name plus its required value
				err := fs.Parse(flagArgs)
				if err == nil {
					err = fmt.Errorf("flag needs an argument: -%s", name)
				}
				return nil, usageError{err}
			}
			flagArgs = args[:2]
			consumed = 2
		}
		if err := fs.Parse(flagArgs); err != nil {
			return nil, usageError{err}
		}
		args = args[consumed:]
	}
	return positional, nil
}

func runMerge(path string, args []string) (*result, error) {
	fs := flag.NewFlagSet("tail-acl merge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var dirs stringListFlag
	fs.Var(&dirs, "dir", "directory containing ACL files; may be repeated")
	if err := fs.Parse(args); err != nil {
		return nil, usageError{err}
	}
	if len(fs.Args()) != 0 {
		return nil, usagef("unexpected merge arguments: %s", strings.Join(fs.Args(), " "))
	}
	if len(dirs) == 0 {
		return nil, usagef("merge requires at least one --dir")
	}
	data, paths, err := aclpolicy.MergeDirectories([]string(dirs), path)
	if err != nil {
		return nil, err
	}
	if err = aclpolicy.WriteRaw(path, data); err != nil {
		return nil, err
	}
	merged := len(paths)
	res := newResult(cmdMerge, statusOK, fmt.Sprintf("merged %d ACL files into %s", merged, path))
	res.File = path
	res.MergedFiles = &merged
	return res, nil
}

func runValidate(
	ctx context.Context,
	opts options,
	httpClient *http.Client,
	apiURL string,
	args []string,
) (*result, error) {
	if len(args) != 0 {
		return nil, usagef("validate does not accept arguments")
	}
	client, err := apiClient(opts, httpClient, apiURL)
	if err != nil {
		return nil, err
	}
	if err = tailapi.ValidateFile(ctx, client, opts.file); err != nil {
		return nil, err
	}
	res := newResult(cmdValidate, statusOK, fmt.Sprintf("%s is valid", opts.file))
	res.File = opts.file
	res.Tailnet = opts.tailnet
	return res, nil
}

func runTest(ctx context.Context, opts options, args []string, logger *slog.Logger) (*result, error) {
	if len(args) != 0 {
		return nil, usagef("test does not accept arguments")
	}
	path := opts.file
	policy, err := aclpolicy.Load(path)
	if err != nil {
		return nil, usagef("could not load policy tests: %v", err)
	}
	report, err := aclpolicy.EvaluateTests(&policy.ACL, aclpolicy.TestOptions{Strict: opts.strict})
	if err != nil {
		return nil, usagef("could not evaluate policy tests: %v", err)
	}
	// A skipped rule can never match, so it may have silently decided a verdict
	// below. Warn without -verbose: this is exactly the collection failure the
	// AX conventions forbid swallowing.
	for _, skip := range report.Skipped {
		logger.WarnContext(ctx, "skipping unparseable policy rule", "rule", skip.Rule,
			"value", skip.Value, "reason", skip.Reason)
	}
	// sshTests are loaded so typed edits preserve them, but this evaluator is
	// network-only. Warn for the same reason as the skipped rules above: a run
	// reporting "0 failed" must never imply assertions it never evaluated.
	if len(policy.SSHTests) != 0 {
		logger.WarnContext(ctx, "sshTests are preserved but not evaluated",
			"ssh_tests", len(policy.SSHTests))
	}
	for _, assertion := range report.Assertions {
		for _, decision := range assertion.Trace {
			logger.DebugContext(
				ctx,
				"policy test decision",
				"assertion",
				assertion.ID,
				"decision",
				decision,
			)
		}
	}

	status := statusOK
	message := fmt.Sprintf(
		"%d assertions: %d passed, %d failed",
		report.Summary.Total,
		report.Summary.Passed,
		report.Summary.Failed,
	)
	if report.Summary.Indeterminate != 0 {
		message += fmt.Sprintf(", %d indeterminate", report.Summary.Indeterminate)
	}
	if report.Summary.Total == 0 {
		message = fmt.Sprintf("no policy tests declared in %s", path)
	}
	// Without this the zero-network-test message reads "no policy tests
	// declared" for a policy whose only assertions are sshTests, which is the
	// opposite of true.
	if sshTests := len(policy.SSHTests); sshTests != 0 {
		message += fmt.Sprintf(" (%d sshTests preserved but not evaluated)", sshTests)
	}
	res := newResult(cmdTest, status, message)
	res.File = path
	res.Assertions = &report.Assertions
	res.Skipped = report.Skipped
	res.SSHTestsSkipped = len(policy.SSHTests)
	res.TestSummary = &report.Summary
	// A real disagreement outranks an unsettled one: a failing assertion is a
	// definite finding, so it decides the exit code even when another assertion
	// could not be evaluated.
	if report.Summary.Failed != 0 {
		res.Status = statusFailed
		return res, errAssertionsFailed
	}
	if report.Summary.Indeterminate != 0 {
		res.Status = statusIndeterminate
		return res, errReachabilityIndeterminate
	}
	return res, nil
}

func runCheck(ctx context.Context, opts options, args []string, logger *slog.Logger) (*result, error) {
	source, target, protocol, err := parseCheckArgs(args)
	if err != nil {
		return nil, err
	}
	policy, err := aclpolicy.Load(opts.file)
	if err != nil {
		return nil, usagef("could not load policy for check: %v", err)
	}
	decision, err := aclpolicy.EvaluateReachability(
		&policy.ACL,
		source,
		target,
		aclpolicy.ReachabilityOptions{Strict: opts.strict, Protocol: protocol},
	)
	if err != nil {
		return nil, usagef("could not evaluate reachability: %v", err)
	}
	for _, skip := range decision.Skipped {
		logger.WarnContext(ctx, "skipping unparseable policy rule", "rule", skip.Rule,
			"value", skip.Value, "reason", skip.Reason)
	}
	for _, trace := range decision.Trace {
		logger.DebugContext(ctx, "reachability decision", "decision", trace)
	}

	res := newCheckResult(opts.file, decision)
	switch decision.Access {
	case aclpolicy.AccessAllow:
		return res, nil
	case aclpolicy.AccessIndeterminate:
		return res, errReachabilityIndeterminate
	case aclpolicy.AccessDeny:
		return res, errReachabilityDenied
	default:
		return res, errReachabilityDenied
	}
}

func parseCheckArgs(args []string) (string, string, aclpolicy.Protocol, error) {
	fs := flag.NewFlagSet("tail-acl check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	source := fs.String("src", "", "source user, group, tag, host, IP, or CIDR")
	destination := fs.String("dst", "", "destination selector, optionally with :port")
	port := fs.Int("port", -1, "destination port (alternative to including it in --dst)")
	protocol := fs.String("proto", string(aclpolicy.ProtocolAny), "IP protocol to ask about: tcp|udp|any")
	if err := fs.Parse(args); err != nil {
		return "", "", "", usageError{err}
	}
	if len(fs.Args()) != 0 {
		return "", "", "", usagef("unexpected check arguments: %s", strings.Join(fs.Args(), " "))
	}
	sourceValue := strings.TrimSpace(*source)
	destinationValue := strings.TrimSpace(*destination)
	if sourceValue == "" || destinationValue == "" {
		return "", "", "", usagef("check requires --src and --dst")
	}
	protocolValue := aclpolicy.Protocol(strings.ToLower(strings.TrimSpace(*protocol)))
	switch protocolValue {
	case aclpolicy.ProtocolAny, aclpolicy.ProtocolTCP, aclpolicy.ProtocolUDP:
	default:
		return "", "", "", usagef(
			"unknown --proto %q; want %s, %s, or %s",
			*protocol, aclpolicy.ProtocolTCP, aclpolicy.ProtocolUDP, aclpolicy.ProtocolAny,
		)
	}
	portSet := false
	fs.Visit(func(f *flag.Flag) {
		portSet = portSet || f.Name == "port"
	})
	if portSet && (*port < 0 || *port > 65535) {
		return "", "", "", usagef("--port %d is out of range; want 0-65535", *port)
	}

	target := destinationValue
	if portSet {
		normalizedDestination, err := checkDestinationWithoutPort(destinationValue)
		if err != nil {
			return "", "", "", err
		}
		// Brackets make selectors containing colons (tags and IPv6 addresses)
		// unambiguous to the shared host:port parser.
		target = fmt.Sprintf("[%s]:%d", normalizedDestination, *port)
	}
	return sourceValue, target, protocolValue, nil
}

func checkDestinationWithoutPort(value string) (string, error) {
	original := value
	if strings.HasPrefix(value, "[") || strings.HasSuffix(value, "]") {
		if len(value) < 3 || value[0] != '[' || value[len(value)-1] != ']' {
			return "", usagef("--dst %q has malformed brackets", original)
		}
		value = value[1 : len(value)-1]
		if value == "" || strings.ContainsAny(value, "[]") {
			return "", usagef("--dst %q has malformed brackets", original)
		}
	}
	if _, err := netip.ParseAddr(value); err == nil {
		return value, nil
	}
	if _, err := netip.ParsePrefix(value); err == nil {
		return value, nil
	}

	separator := strings.LastIndexByte(value, ':')
	if separator < 0 {
		return value, nil
	}
	if separator == 0 || separator == len(value)-1 {
		return "", usagef("--dst %q is malformed", value)
	}
	if isDecimal(value[separator+1:]) {
		return "", usagef("--dst %q already includes a port; do not also use --port", value)
	}
	if strings.Contains(value[:separator], ":") {
		return "", usagef("--dst %q is ambiguous; bracket IPv6 addresses and specify the port once", value)
	}
	return value, nil
}

func isDecimal(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func newCheckResult(path string, decision aclpolicy.ReachabilityResult) *result {
	verdict, status := verdictNotReachable, statusFailed
	switch decision.Access {
	case aclpolicy.AccessAllow:
		verdict, status = verdictReachable, statusOK
	case aclpolicy.AccessIndeterminate:
		verdict, status = verdictIndeterminate, statusIndeterminate
	case aclpolicy.AccessDeny:
	}
	message := fmt.Sprintf(
		"%s: %s -> %s:%d (%s)",
		verdict,
		decision.Source,
		decision.Destination,
		decision.Port,
		decision.Evidence,
	)
	res := newResult(cmdCheck, status, message)
	res.File = path
	res.Access = decision.Access
	res.Protocol = decision.Protocol
	// Already nil for an indeterminate answer; see aclpolicy.ReachabilityResult.
	res.Allowed = decision.Allowed
	res.Source = decision.Source
	res.Destination = decision.Destination
	res.Port = &decision.Port
	res.Evidence = decision.Evidence
	res.Trace = decision.Trace
	res.Skipped = decision.Skipped
	if decision.Rule != nil {
		index := decision.Rule.Index
		switch decision.Rule.Kind {
		case aclpolicy.RuleGrant:
			res.GrantIndex = &index
		case aclpolicy.RuleACL:
			res.ACLIndex = &index
		}
	}
	return res
}

func runLint(ctx context.Context, opts options, args []string, logger *slog.Logger) (*result, error) {
	lintOpts, threshold, err := parseLintArgs(args)
	if err != nil {
		return nil, err
	}
	policy, err := aclpolicy.Load(opts.file)
	if err != nil {
		return nil, usagef("could not load policy for lint: %v", err)
	}
	report, err := aclpolicy.EvaluatePolicyLint(policy, lintOpts)
	if err != nil {
		return nil, usagef("could not lint policy: %v", err)
	}
	for _, finding := range report.Findings {
		for _, decision := range finding.Trace {
			logger.DebugContext(ctx, "lint decision",
				"finding", finding.ID, "rule", finding.Rule, "decision", decision)
		}
	}

	res := newLintResult(opts.file, report)
	if report.CountAtLeast(threshold) > 0 {
		res.Status = statusFailed
		return res, errLintFindings
	}
	return res, nil
}

func parseLintArgs(args []string) (aclpolicy.LintOptions, aclpolicy.LintSeverity, error) {
	fs := flag.NewFlagSet("tail-acl lint", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	severity := fs.String("severity", string(aclpolicy.LintWarn),
		"minimum finding severity that sets a non-zero exit: info|warn|error")
	wildcard := fs.String("wildcard", string(aclpolicy.WildcardAnyToAny),
		"over-broad wildcard policy: any-to-any|any|off")
	if err := fs.Parse(args); err != nil {
		return aclpolicy.LintOptions{}, "", usageError{err}
	}
	if len(fs.Args()) != 0 {
		return aclpolicy.LintOptions{}, "", usagef("unexpected lint arguments: %s", strings.Join(fs.Args(), " "))
	}
	threshold, ok := aclpolicy.ParseLintSeverity(*severity)
	if !ok {
		return aclpolicy.LintOptions{}, "", usagef("unknown -severity %q; want info, warn, or error", *severity)
	}
	wildcardPolicy, ok := aclpolicy.ParseWildcardPolicy(*wildcard)
	if !ok {
		return aclpolicy.LintOptions{}, "", usagef("unknown -wildcard %q; want any-to-any, any, or off", *wildcard)
	}
	return aclpolicy.LintOptions{Wildcard: wildcardPolicy}, threshold, nil
}

func newLintResult(path string, report aclpolicy.LintReport) *result {
	message := fmt.Sprintf(
		"%d findings: %d error, %d warn, %d info",
		report.Summary.Total,
		report.Summary.Error,
		report.Summary.Warn,
		report.Summary.Info,
	)
	if report.Summary.Total == 0 {
		message = fmt.Sprintf("no policy hygiene findings in %s", path)
	}
	res := newResult(cmdLint, statusOK, message)
	res.File = path
	res.Findings = &report.Findings
	res.LintSummary = &report.Summary
	return res
}

func runPlan(
	ctx context.Context,
	opts options,
	httpClient *http.Client,
	apiURL string,
	args []string,
) (*result, error) {
	if len(args) != 0 {
		return nil, usagef("plan does not accept arguments")
	}
	client, err := apiClient(opts, httpClient, apiURL)
	if err != nil {
		return nil, err
	}
	plan, err := tailapi.PlanFile(ctx, client, opts.file)
	if err != nil {
		return nil, err
	}
	status, changeText := statusNoChanges, "no changes"
	if plan.Changed {
		status, changeText = statusChangesFound, "changes found"
	}
	message := fmt.Sprintf("plan valid; %s for tailnet %s", changeText, opts.tailnet)
	if plan.ETag != "" {
		message += fmt.Sprintf(" (ETag %s)", plan.ETag)
	}
	res := newResult(cmdPlan, status, message)
	res.File = opts.file
	res.Tailnet = opts.tailnet
	res.ETag = plan.ETag
	changed := plan.Changed
	res.Changed = &changed
	if plan.Changed {
		res.Diff = plan.Diff
	}
	return res, nil
}

func runUpload(
	ctx context.Context,
	opts options,
	httpClient *http.Client,
	apiURL string,
	args []string,
) (*result, error) {
	if len(args) != 0 {
		return nil, usagef("upload does not accept arguments")
	}
	client, err := apiClient(opts, httpClient, apiURL)
	if err != nil {
		return nil, err
	}
	if err = tailapi.UploadFile(ctx, client, opts.file, opts.ifMatch); err != nil {
		return nil, err
	}
	res := newResult(cmdUpload, statusOK, fmt.Sprintf("uploaded %s to tailnet %s", opts.file, opts.tailnet))
	res.File = opts.file
	res.Tailnet = opts.tailnet
	return res, nil
}

func apiClient(opts options, httpClient *http.Client, apiURL string) (*tailscale.Client, error) {
	if opts.tailnet == "" {
		return nil, usagef("--tailnet or TAILSCALE_TAILNET is required")
	}
	if opts.apiKey == "" {
		return nil, usagef("--api-key or TAILSCALE_API_KEY is required")
	}
	return tailapi.NewClient(tailapi.Config{
		APIKey:  opts.apiKey,
		Tailnet: opts.tailnet,
		BaseURL: apiURL,
		HTTP:    httpClient,
	})
}

type schemaFlag struct {
	Name    string `json:"name"`
	Usage   string `json:"usage"`
	Default string `json:"default"`
}

type schemaCommand struct {
	Name    string `json:"name"`
	Summary string `json:"summary"`
	Usage   string `json:"usage"`
}

type schemaCapabilities struct {
	TypedEdits schemaTypedEditCapability `json:"typed_edits"`
}

type schemaTypedEditCapability struct {
	Formats           []string `json:"formats"`
	PreservesComments bool     `json:"preserves_comments"`
	AuthorsComments   bool     `json:"authors_comments"`
}

// commandCatalog is the single source of truth for the command list, shared by
// usage() and the -schema document so a human and an agent see the same set.
func commandCatalog() []schemaCommand {
	return []schemaCommand{
		{
			commandGrantAdd,
			"Append a grant to the policy",
			"grant add --src SRC --dst DST --ip PROTO:PORT [--src-posture posture:NAME] [--comment TEXT]",
		},
		{commandGrantRemove, "Remove a grant by zero-based index", "grant remove --index N"},
		{commandTagOwnerAdd, "Add an owner to a tag", "tag-owner add TAG OWNER [--comment TEXT]"},
		{commandHostSet, "Set a host alias to an address", "host set NAME ADDRESS [--comment TEXT]"},
		{
			commandPostureSet,
			"Add or replace a posture's expression list",
			"posture set NAME EXPR [EXPR ...] [--comment TEXT]",
		},
		{commandPostureRemove, "Remove a posture definition", "posture remove NAME"},
		{cmdMerge, "Compile ACL sources in directories into one policy", "merge --dir DIR [--dir DIR ...]"},
		{cmdValidate, "Validate the policy via the Tailscale API", cmdValidate},
		{
			cmdTest,
			"Run network tests locally; sshTests are preserved but not evaluated (-strict rejects unparseable rules)",
			cmdTest,
		},
		{
			cmdCheck,
			"Answer one reachability question locally",
			"check --src SRC (--dst DST:PORT | --dst DST --port PORT) [--proto tcp|udp|any]",
		},
		{
			cmdLint,
			"Statically lint policy hygiene (dead grants, undefined refs, over-broad *)",
			"lint [-severity info|warn|error] [-wildcard any-to-any|any|off]",
		},
		{cmdPlan, "Diff the policy against the live tailnet (read-only)", cmdPlan},
		{cmdUpload, "Upload the policy to the tailnet", cmdUpload},
	}
}

// printSchema emits a machine-readable description of the tool — how to invoke
// it (global flags), what it does (the command catalog), and its exit-code
// contract — so an agent can discover and drive it the way a human reads --help.
func printSchema(w io.Writer, fs *flag.FlagSet) error {
	var flags []schemaFlag
	fs.VisitAll(func(f *flag.Flag) {
		flags = append(flags, schemaFlag{Name: f.Name, Usage: f.Usage, Default: f.DefValue})
	})
	doc := struct {
		Name          string                `json:"name"`
		Version       string                `json:"version"`
		SchemaVersion string                `json:"schema_version"`
		Description   string                `json:"description"`
		Flags         []schemaFlag          `json:"flags"`
		Commands      []schemaCommand       `json:"commands"`
		Capabilities  schemaCapabilities    `json:"capabilities"`
		LintFindings  []aclpolicy.LintCheck `json:"lint_findings"`
		ExitCodes     map[string]string     `json:"exit_codes"`
	}{
		Name:          toolName,
		Version:       version,
		SchemaVersion: schemaVersion,
		Description:   "Make typed edits to a Tailscale policy file and merge, validate, test, check, lint, plan, or upload it.",
		Flags:         flags,
		Commands:      commandCatalog(),
		Capabilities: schemaCapabilities{
			TypedEdits: schemaTypedEditCapability{
				Formats:           []string{formatJSON, policyFormatHuJSON},
				PreservesComments: true,
				AuthorsComments:   true,
			},
		},
		LintFindings: aclpolicy.LintCatalog(),
		ExitCodes: map[string]string{
			"0":  "success or reachable",
			"1":  "operation or policy assertion failed, or not reachable",
			"2":  "usage, input, or collection error",
			"10": "indeterminate: check could not settle the question, or test had an unsettleable assertion",
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintln(w, "tail-acl — edit, merge, validate, test, check, lint, plan, and upload a Tailscale ACL policy.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "The result is written to stdout (human text, or a versioned JSON envelope")
	fmt.Fprintln(w, "with -format json); logs and errors go to stderr.")
	fmt.Fprintf(w, "\nUsage:\n  %s [global flags] COMMAND [command flags]\n", filepath.Base(os.Args[0]))
	fmt.Fprintln(w, "\nCommands:")
	for _, c := range commandCatalog() {
		fmt.Fprintf(w, "  %-14s %s\n", c.Name, c.Summary)
	}
	fmt.Fprintln(w, "\nGlobal flags:")
	fs.PrintDefaults()
	fmt.Fprintln(w, "\nExamples:")
	fmt.Fprintln(w, "  tail-acl --file acl.json grant add --src autogroup:member --dst tag:web --ip tcp:443")
	fmt.Fprintln(w, "  tail-acl --file acl.hujson tag-owner add tag:web autogroup:admin  # comments preserved")
	fmt.Fprintln(w, "  tail-acl --file acl.json posture set posture:labCompliant \"custom:labCompliant == true\"")
	fmt.Fprintln(w, "  tail-acl --file acl.json host set web 100.64.0.10 --comment \"Legacy monitoring endpoint\"")
	//nolint:golines // example line needs to be intact
	fmt.Fprintln(w, "  tail-acl --file acl.json grant add --src autogroup:member --dst tag:web --ip tcp:443 --src-posture posture:labCompliant")
	fmt.Fprintln(w, "  tail-acl --file acl/acl.generated.json merge --dir initial-30 --dir peer-relay-internal")
	fmt.Fprintln(w, "  tail-acl --file acl/acl.generated.json test        # run native policy assertions locally")
	fmt.Fprintln(w, "  tail-acl --file acl/acl.generated.json check --src alice@example.com --dst tag:web:443")
	fmt.Fprintln(w, "  tail-acl --file acl/acl.generated.json check --src tag:app --dst tag:db --port 5432")
	fmt.Fprintln(w, "  tail-acl --file acl/acl.generated.json check --src tag:app --dst tag:dns:53 --proto udp")
	fmt.Fprintln(w, "  tail-acl --file acl/acl.generated.json lint         # static policy hygiene findings")
	fmt.Fprintln(w, "  tail-acl -strict --file acl/acl.generated.json test # fail if any rule is unparseable")
	fmt.Fprintln(w, "  tail-acl --file acl/acl.generated.json plan        # diff against the live tailnet")
	fmt.Fprintln(w, "  tail-acl -schema                                   # machine-readable schema")
	fmt.Fprintln(w, "\nExit codes:")
	fmt.Fprintln(w, "  0  success; check reports reachable")
	fmt.Fprintln(w, "  1  operation or policy assertion failed; check reports not reachable")
	fmt.Fprintln(w, "  2  usage, input, or collection error")
	fmt.Fprintln(w, "  10 indeterminate: a rule would have applied but depends on a fact absent from")
	fmt.Fprintln(w, "     the policy file (device posture, via routing, or a role autogroup such as")
	fmt.Fprintln(w, "     autogroup:admin). Not a denial - verify it another way. Also returned by")
	fmt.Fprintln(w, "     test when an assertion could not be settled.")
}

type stringListFlag []string

func (f *stringListFlag) Set(value string) error {
	if value == "" {
		return errors.New("value cannot be empty")
	}
	*f = append(*f, value)
	return nil
}

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}
