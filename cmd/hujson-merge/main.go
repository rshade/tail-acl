// Command hujson-merge deep-merges HuJSON policy files.
//
//	hujson-merge --base initial-30/acl.hujson --add peer-relay-internal/peer-relay.acl.hujson
//	hujson-merge --dir initial-30 --dir peer-relay-internal
//
// The first form merges one snippet into a base policy, preserving the base
// file's comments and formatting. The second form merges all ACL JSON and
// HuJSON files in the listed directories and writes standard JSON to acl.json.
//
// Merge rules, applied recursively:
//   - objects: merge members by key (recurse into keys present in both, append
//     keys only in the snippet)
//   - arrays:  append the snippet's elements to the base's (so a new grant or ssh
//     rule is added, not replaced)
//   - scalars: the snippet's value overwrites the base's
//
// This lets an ACL snippet contribute a tagOwners entry (object merge) and a
// grant (array append) without hand-editing the base policy or losing its docs.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/rshade/tsacl/internal/aclpolicy"
	"github.com/rshade/tsacl/internal/buildinfo"
	"github.com/rshade/tsacl/pkg/policycore/cliflags"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

type options struct {
	base       string
	add        string
	dirs       stringListFlag
	out        string
	showSchema bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "hujson-merge:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	opts := &options{}
	root := newRootCommand(opts)
	root.RunE = func(cmd *cobra.Command, positional []string) error {
		return runMerge(cmd, positional, stdout, stderr, opts)
	}
	root.SetArgs(cliflags.Normalize(root, args))
	root.SetOut(stdout)
	root.SetErr(stderr)
	return root.Execute()
}

func newRootCommand(opts *options) *cobra.Command {
	root := &cobra.Command{
		Use:     "hujson-merge",
		Short:   "Deep-merge HuJSON policy files.",
		Version: buildinfo.Version("hujson-merge", version),
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
	flags.StringVar(&opts.base, "base", "", "base HuJSON policy file (merged into)")
	flags.StringVar(&opts.add, "add", "", "HuJSON snippet to merge in")
	flags.Var(&opts.dirs, "dir", "directory containing ACL files; may be repeated")
	flags.StringVar(&opts.out, "out", "", "output path; defaults to --base, or acl.json with --dir; '-' is stdout")
	// Registered but unbound: cobra's own Version-triggered handling reads this
	// flag and short-circuits before RunE ever runs, so no field here observes
	// it. Registering it under this exact name and usage string is still
	// required — it is what makes InitDefaultVersionFlag skip adding its own
	// "version for hujson-merge" flag.
	flags.Bool("version", false, "print version and exit")
	flags.BoolVar(&opts.showSchema, "schema", false, "print the machine-readable tool schema (JSON) and exit")
	root.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		usage(cmd.OutOrStdout(), cmd.Flags())
	})
	root.InitDefaultHelpFlag()
	return root
}

func runMerge(cmd *cobra.Command, positional []string, stdout, stderr io.Writer, opts *options) error {
	if opts.showSchema {
		return printSchema(stdout, cmd.Flags())
	}

	if len(opts.dirs) != 0 {
		if opts.base != "" || opts.add != "" {
			return errors.New("--dir cannot be combined with --base or --add")
		}
		if len(positional) != 0 {
			return fmt.Errorf(
				"unexpected positional arguments: %s; use --dir for each directory",
				strings.Join(positional, " "),
			)
		}
		dst := opts.out
		if dst == "" {
			dst = "acl.json"
		}
		return mergeDirectories([]string(opts.dirs), dst, stdout, stderr)
	}

	if len(positional) != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(positional, " "))
	}
	if opts.base == "" || opts.add == "" {
		usage(stderr, cmd.Flags())
		return errors.New("--base and --add are required unless --dir is used")
	}

	data, err := aclpolicy.MergePair(opts.base, opts.add)
	if err != nil {
		return err
	}

	dst := opts.out
	if dst == "" {
		dst = opts.base
	}
	if err = writeOutput(dst, data, stdout); err != nil {
		return err
	}
	if dst != "-" {
		if _, err = fmt.Fprintf(stderr, "hujson-merge: merged %s into %s\n", opts.add, dst); err != nil {
			return err
		}
	}
	return nil
}

type stringListFlag []string

func (f *stringListFlag) Set(value string) error {
	if value == "" {
		return errors.New("directory cannot be empty")
	}
	*f = append(*f, value)
	return nil
}

func (f *stringListFlag) String() string {
	return strings.Join(*f, ",")
}

// Type satisfies pflag.Value. The name appears in --help as the flag's
// argument placeholder.
func (f *stringListFlag) Type() string { return "stringList" }

func mergeDirectories(dirs []string, dst string, stdout, stderr io.Writer) error {
	data, paths, err := aclpolicy.MergeDirectories(dirs, dst)
	if err != nil {
		return err
	}
	if err = writeOutput(dst, data, stdout); err != nil {
		return err
	}
	if dst != "-" {
		if _, err = fmt.Fprintf(stderr, "hujson-merge: merged %d ACL files into %s\n", len(paths), dst); err != nil {
			return err
		}
	}
	return nil
}

func writeOutput(dst string, data []byte, stdout io.Writer) error {
	if dst == "-" {
		_, err := stdout.Write(data)
		return err
	}
	return aclpolicy.WriteRaw(dst, data)
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
		Name:        "hujson-merge",
		Version:     version,
		Description: "Deep-merge HuJSON policy files: one snippet into a base, or every ACL file in one or more directories.",
		Flags:       flags,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func usage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintln(w, "hujson-merge: deep-merge HuJSON policy files.")
	fmt.Fprintln(w, "\nUsage:")
	fmt.Fprintln(w, "  hujson-merge --base FILE --add FILE [--out FILE|-]")
	fmt.Fprintln(w, "  hujson-merge --dir DIR [--dir DIR ...] [--out FILE|-]")
	fmt.Fprintln(w, "\nFlags:")
	// PrintDefaults writes to the FlagSet's own configured output (stderr by
	// default), not to w, so point it at w explicitly before calling it.
	fs.SetOutput(w)
	fs.PrintDefaults()
	fmt.Fprintln(w, "\nExamples:")
	fmt.Fprintln(w, "  hujson-merge --base acl.hujson --add web.acl.hujson")
	fmt.Fprintln(w, "  hujson-merge --dir base --dir overlays --out acl.json")
	fmt.Fprintln(w, "\nExit codes: 0 success; 1 failure (bad flags, unreadable input, invalid HuJSON, or write error).")
}
