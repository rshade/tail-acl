// Command hujson2json converts a HuJSON policy file to standard JSON.
//
//	hujson2json --file acl.hujson | jq '.grants[]'
//	hujson2json < acl.hujson | jq 'paths'
//
// HuJSON's comments and trailing commas — the reason the format exists, and the
// thing the authoring commands work hardest to preserve — make a policy file
// unreadable to every standard JSON tool. This bridges that gap so `jq`, `gron`,
// and friends can answer structural questions about a policy that tail-acl has
// no dedicated command for.
//
// The result goes to stdout and nothing else does, so the output is safe to
// pipe. Diagnostics go to stderr.
//
// This is a thin prototype of the `tail-acl normalize` command proposed in
// issue 168; when that lands, this binary becomes redundant.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/tailscale/hujson"

	"github.com/rshade/tailscale-utils/policycore/cliflags"
	"github.com/rshade/tailscale-utils/tail-acl/internal/buildinfo"
)

// toolName is the binary's name as it appears in --help, --version, and the
// machine-readable schema.
const toolName = "hujson2json"

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

type options struct {
	file       string
	compact    bool
	showSchema bool
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "hujson2json:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts := &options{}
	root := newRootCommand(opts)
	root.RunE = func(cmd *cobra.Command, positional []string) error {
		return runConvert(cmd, positional, stdin, stdout, stderr, opts)
	}
	root.SetArgs(cliflags.Normalize(root, args))
	root.SetOut(stdout)
	root.SetErr(stderr)
	return root.Execute()
}

func newRootCommand(opts *options) *cobra.Command {
	root := &cobra.Command{
		Use:     toolName,
		Short:   "Convert a HuJSON policy file to standard JSON.",
		Version: buildinfo.Version(toolName, version),
		// Diagnostics and usage are written explicitly; cobra stays silent.
		SilenceErrors: true,
		SilenceUsage:  true,
		// Positional arguments are rejected in the body to keep the
		// diagnostic wording stable now that cobra's completion command
		// makes this a parent command.
		Args: cobra.ArbitraryArgs,
	}
	root.SetVersionTemplate("{{.Version}}\n")

	flags := root.Flags()
	flags.StringVar(&opts.file, "file", "", "HuJSON policy file; defaults to stdin")
	flags.BoolVar(&opts.compact, "compact", false, "emit one line instead of indented JSON")
	// Registered but unbound: cobra's own Version-triggered handling reads this
	// flag and short-circuits before RunE ever runs, so no field here observes
	// it. Registering it under this exact name and usage string is still
	// required — it is what makes InitDefaultVersionFlag skip adding its own
	// "version for hujson2json" flag.
	flags.Bool("version", false, "print version and exit")
	flags.BoolVar(&opts.showSchema, "schema", false, "print the machine-readable tool schema (JSON) and exit")
	root.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		usage(cmd.OutOrStdout(), cmd.Flags())
	})
	root.InitDefaultHelpFlag()
	return root
}

func runConvert(
	cmd *cobra.Command,
	positional []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	opts *options,
) error {
	if opts.showSchema {
		return printSchema(stdout, cmd.Flags())
	}
	if len(positional) != 0 {
		usage(stderr, cmd.Flags())
		return fmt.Errorf("unexpected positional arguments: %v; use --file", positional)
	}

	raw, source, err := readInput(opts.file, stdin)
	if err != nil {
		return err
	}
	out, err := standardize(raw, source, opts.compact)
	if err != nil {
		return err
	}
	_, err = stdout.Write(out)
	return err
}

// readInput returns the bytes to convert and a name for them suitable for an
// error message. An empty file selects stdin so the tool composes in a pipe.
func readInput(file string, stdin io.Reader) ([]byte, string, error) {
	if file == "" {
		raw, err := io.ReadAll(stdin)
		if err != nil {
			return nil, "", fmt.Errorf("reading stdin: %w", err)
		}
		return raw, "stdin", nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, "", err
	}
	return raw, file, nil
}

// standardize converts HuJSON to standard JSON.
//
// hujson.Standardize blanks comments to spaces rather than removing them, so
// its output is valid JSON carrying the original document's whitespace. Passing
// it through [json.Indent] or [json.Compact] reflows that into something readable.
// Both operate on raw bytes rather than decoding, so object member order — which
// a map round-trip would destroy — is preserved exactly.
func standardize(raw []byte, source string, compact bool) ([]byte, error) {
	standard, err := hujson.Standardize(raw)
	if err != nil {
		return nil, fmt.Errorf("standardizing %s: %w", source, err)
	}
	var buf bytes.Buffer
	if compact {
		if err = json.Compact(&buf, standard); err != nil {
			return nil, fmt.Errorf("compacting %s: %w", source, err)
		}
	} else if err = json.Indent(&buf, standard, "", "\t"); err != nil {
		return nil, fmt.Errorf("indenting %s: %w", source, err)
	}
	return append(buf.Bytes(), '\n'), nil
}

type schemaFlag struct {
	Name    string `json:"name"`
	Usage   string `json:"usage"`
	Default string `json:"default"`
}

// printSchema emits a machine-readable description of the tool so an agent can
// discover and drive it the way a human reads --help.
func printSchema(w io.Writer, fs *pflag.FlagSet) error {
	var flags []schemaFlag
	fs.VisitAll(func(f *pflag.Flag) {
		flags = append(flags, schemaFlag{Name: f.Name, Usage: f.Usage, Default: f.DefValue})
	})
	doc := struct {
		Name        string       `json:"name"`
		Version     string       `json:"version"`
		Description string       `json:"description"`
		Flags       []schemaFlag `json:"flags"`
	}{
		Name:        toolName,
		Version:     version,
		Description: "Convert a HuJSON policy file to standard JSON so general-purpose JSON tools can read it.",
		Flags:       flags,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func usage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintln(w, "hujson2json: convert a HuJSON policy file to standard JSON.")
	fmt.Fprintln(w, "\nUsage:")
	fmt.Fprintln(w, "  hujson2json [--file FILE] [--compact]")
	fmt.Fprintln(w, "\nFlags:")
	// PrintDefaults writes to the FlagSet's own configured output (stderr by
	// default), not to w, so point it at w explicitly before calling it.
	fs.SetOutput(w)
	fs.PrintDefaults()
	fmt.Fprintln(w, "\nExamples:")
	fmt.Fprintln(w, "  hujson2json --file acl.hujson | jq '.grants[]'")
	fmt.Fprintln(w, "  hujson2json < acl.hujson | jq -r 'paths as $p")
	fmt.Fprintln(w, "    | select($p[-1]==\"routes\") | \"\\($p|join(\".\"))\\t\\(getpath($p)|type)\"'")
	fmt.Fprintln(w, "\nExit codes: 0 success; 1 failure (bad flags, unreadable input, or invalid HuJSON).")
}
