// Command tail-acl makes typed edits to a Tailscale policy file and can merge,
// validate, plan, or upload it with Tailscale's policy-file API.
//
// Output contract (AX conventions, see ../../CLAUDE.md): the command result is
// written to stdout — human text by default, or a versioned JSON envelope with
// -format json — while logs and errors go to stderr. Exit codes: 0 success,
// 1 the operation failed, 2 the invocation was wrong (flags, args, credentials).
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
	"os"
	"path/filepath"
	"slices"
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
	exitFailed = 1 // a valid invocation whose operation failed
	exitUsage  = 2 // the invocation itself was wrong (flags, args, credentials)
)

// Result statuses reported in the envelope's "status" field.
const (
	statusOK           = "ok"
	statusNoChanges    = "no_changes"
	statusChangesFound = "changes_found"
)

// Command and sub-command names, output formats, and the tool name.
const (
	toolName = "tail-acl"

	cmdGrant    = "grant"
	cmdTagOwner = "tag-owner"
	cmdHost     = "host"
	cmdMerge    = "merge"
	cmdValidate = "validate"
	cmdPlan     = "plan"
	cmdUpload   = "upload"

	subAdd    = "add"
	subRemove = "remove"
	subSet    = "set"

	formatHuman = "human"
	formatJSON  = "json"
)

// httpTimeout bounds every Tailscale API request.
const httpTimeout = 30 * time.Second

type options struct {
	file    string
	tailnet string
	apiKey  string
	ifMatch string
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
	MergedFiles   *int   `json:"merged_files,omitempty"`
}

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
		"policy file (typed edits require .json; other commands accept HuJSON)",
	)
	root.StringVar(
		&opts.tailnet,
		"tailnet",
		getenv("TAILSCALE_TAILNET"),
		"tailnet name or ID (default: TAILSCALE_TAILNET)",
	)
	root.StringVar(&opts.apiKey, "api-key", "", "Tailscale API access token (default: TAILSCALE_API_KEY)")
	root.StringVar(&opts.ifMatch, "if-match", "", "optional ETag required for upload")
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

	res, err := dispatch(ctx, remaining, opts, httpClient, apiURL, logger)
	if err != nil {
		return err
	}
	return render(stdout, *format, res)
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
	case cmdMerge:
		return runMerge(opts.file, args[1:])
	case cmdValidate:
		return runValidate(ctx, opts, httpClient, apiURL, args[1:])
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

func runGrantAdd(path string, args []string) (*result, error) {
	fs := flag.NewFlagSet("tail-acl grant add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var source, destination, ip stringListFlag
	fs.Var(&source, "src", "grant source; may be repeated")
	fs.Var(&destination, "dst", "grant destination; may be repeated")
	fs.Var(&ip, "ip", "IP protocol and port expression; may be repeated")
	if err := fs.Parse(args); err != nil {
		return nil, usageError{err}
	}
	if len(fs.Args()) != 0 {
		return nil, usagef("unexpected grant add arguments: %s", strings.Join(fs.Args(), " "))
	}
	if len(source) == 0 || len(destination) == 0 || len(ip) == 0 {
		return nil, usagef("grant add requires at least one --src, --dst, and --ip")
	}
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	grant := tailscale.Grant{
		Source:      []string(source),
		Destination: []string(destination),
		IP:          []string(ip),
	}
	grantKey, err := grantSemanticKey(grant)
	if err != nil {
		return nil, err
	}
	for i := range policy.Grants {
		existingKey, keyErr := grantSemanticKey(policy.Grants[i])
		if keyErr != nil {
			return nil, keyErr
		}
		if existingKey == grantKey {
			return grantResult("grant add", statusNoChanges,
				fmt.Sprintf("grant %d already exists in %s", i, path), path, i), nil
		}
	}
	policy.Grants = append(policy.Grants, grant)
	if err = aclpolicy.Write(path, policy); err != nil {
		return nil, err
	}
	index := len(policy.Grants) - 1
	return grantResult("grant add", statusOK,
		fmt.Sprintf("added grant %d to %s", index, path), path, index), nil
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
	policy.Grants = slices.Delete(policy.Grants, *index, *index+1)
	if err = aclpolicy.Write(path, policy); err != nil {
		return nil, err
	}
	return grantResult("grant remove", statusOK,
		fmt.Sprintf("removed grant %d from %s", *index, path), path, *index), nil
}

func grantResult(command, status, message, path string, index int) *result {
	res := newResult(command, status, message)
	res.File = path
	res.GrantIndex = &index
	return res
}

// grantSemanticKey treats grant selector lists as sets, so repeated add
// commands remain idempotent even when their flags are supplied in a different
// order. JSON encoding also treats omitted and explicitly empty optional fields
// alike through the Grant type's omitempty tags.
func grantSemanticKey(grant tailscale.Grant) (string, error) {
	grant.Source = sortedStrings(grant.Source)
	grant.Destination = sortedStrings(grant.Destination)
	grant.IP = sortedStrings(grant.IP)
	grant.SrcPosture = sortedStrings(grant.SrcPosture)
	grant.Via = sortedStrings(grant.Via)

	encoded, err := json.Marshal(grant)
	if err != nil {
		return "", fmt.Errorf("canonicalizing grant: %w", err)
	}
	return string(encoded), nil
}

func sortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	result := slices.Clone(values)
	slices.Sort(result)
	return result
}

func runTagOwner(path string, args []string) (*result, error) {
	if len(args) != 3 || args[0] != subAdd {
		return nil, usagef("usage: tail-acl tag-owner add TAG OWNER")
	}
	tag, owner := args[1], args[2]
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	if policy.TagOwners == nil {
		policy.TagOwners = make(map[string][]string)
	}
	status, message := statusOK, fmt.Sprintf("added owner %s to %s in %s", owner, tag, path)
	if slices.Contains(policy.TagOwners[tag], owner) {
		status = statusNoChanges
		message = fmt.Sprintf("owner %s already owns %s in %s", owner, tag, path)
	} else {
		policy.TagOwners[tag] = append(policy.TagOwners[tag], owner)
	}
	if err = aclpolicy.Write(path, policy); err != nil {
		return nil, err
	}
	res := newResult("tag-owner add", status, message)
	res.File = path
	return res, nil
}

func runHost(path string, args []string) (*result, error) {
	if len(args) != 3 || args[0] != subSet {
		return nil, usagef("usage: tail-acl host set NAME ADDRESS")
	}
	name, address := args[1], args[2]
	policy, err := loadForEdit(path)
	if err != nil {
		return nil, err
	}
	if policy.Hosts == nil {
		policy.Hosts = make(map[string]string)
	}
	policy.Hosts[name] = address
	if err = aclpolicy.Write(path, policy); err != nil {
		return nil, err
	}
	res := newResult("host set", statusOK, fmt.Sprintf("set host %s to %s in %s", name, address, path))
	res.File = path
	return res, nil
}

func requireJSONEditTarget(path string) error {
	if !strings.EqualFold(filepath.Ext(path), ".json") {
		return usagef(
			"typed edits require a .json file; refusing to rewrite %q because HuJSON comments and formatting would be lost",
			path,
		)
	}
	return nil
}

// loadForEdit enforces the .json-only guard and loads the policy so every typed
// edit shares one place that prevents rewriting HuJSON as comment-stripped JSON.
func loadForEdit(path string) (*tailscale.ACL, error) {
	if err := requireJSONEditTarget(path); err != nil {
		return nil, err
	}
	return aclpolicy.Load(path)
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

// commandCatalog is the single source of truth for the command list, shared by
// usage() and the -schema document so a human and an agent see the same set.
func commandCatalog() []schemaCommand {
	return []schemaCommand{
		{"grant add", "Append a grant to the policy", "grant add --src SRC --dst DST --ip PROTO:PORT"},
		{"grant remove", "Remove a grant by zero-based index", "grant remove --index N"},
		{"tag-owner add", "Add an owner to a tag", "tag-owner add TAG OWNER"},
		{"host set", "Set a host alias to an address", "host set NAME ADDRESS"},
		{cmdMerge, "Compile ACL sources in directories into one policy", "merge --dir DIR [--dir DIR ...]"},
		{cmdValidate, "Validate the policy via the Tailscale API", cmdValidate},
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
		Name          string            `json:"name"`
		Version       string            `json:"version"`
		SchemaVersion string            `json:"schema_version"`
		Description   string            `json:"description"`
		Flags         []schemaFlag      `json:"flags"`
		Commands      []schemaCommand   `json:"commands"`
		ExitCodes     map[string]string `json:"exit_codes"`
	}{
		Name:          toolName,
		Version:       version,
		SchemaVersion: schemaVersion,
		Description:   "Make typed edits to a Tailscale policy file and merge, validate, plan, or upload it via Tailscale's policy-file API.",
		Flags:         flags,
		Commands:      commandCatalog(),
		ExitCodes: map[string]string{
			"0": "success",
			"1": "operation failed",
			"2": "usage or input error",
		},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintln(w, "tail-acl — edit, merge, validate, plan, and upload a Tailscale ACL policy.")
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
	fmt.Fprintln(w, "  tail-acl --file acl/acl.generated.json merge --dir initial-30 --dir peer-relay-internal")
	fmt.Fprintln(w, "  tail-acl --file acl/acl.generated.json plan        # diff against the live tailnet")
	fmt.Fprintln(w, "  tail-acl -schema                                   # machine-readable schema")
	fmt.Fprintln(w, "\nExit codes:")
	fmt.Fprintln(w, "  0  success")
	fmt.Fprintln(w, "  1  operation failed (API rejected the policy, network error, unreadable file)")
	fmt.Fprintln(w, "  2  usage or input error (bad flags, missing command, missing credentials)")
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
