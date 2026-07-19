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
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
	"github.com/rshade/tailscale-utils/tail-acl/internal/buildinfo"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "hujson-merge:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("hujson-merge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	base := fs.String("base", "", "base HuJSON policy file (merged into)")
	add := fs.String("add", "", "HuJSON snippet to merge in")
	var dirs stringListFlag
	fs.Var(&dirs, "dir", "directory containing ACL files; may be repeated")
	out := fs.String("out", "", "output path; defaults to --base, or acl.json with --dir; '-' is stdout")
	showVersion := fs.Bool("version", false, "print version and exit")
	showSchema := fs.Bool("schema", false, "print the machine-readable tool schema (JSON) and exit")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "usage:")
		_, _ = fmt.Fprintln(stderr, "  hujson-merge --base FILE --add FILE [--out FILE|-]")
		_, _ = fmt.Fprintln(stderr, "  hujson-merge --dir DIR [--dir DIR ...] [--out FILE|-]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, buildinfo.Version("hujson-merge", version))
		return err
	}
	if *showSchema {
		return printSchema(stdout, fs)
	}

	if len(dirs) != 0 {
		if *base != "" || *add != "" {
			return errors.New("--dir cannot be combined with --base or --add")
		}
		if len(fs.Args()) != 0 {
			return fmt.Errorf(
				"unexpected positional arguments: %s; use --dir for each directory",
				strings.Join(fs.Args(), " "),
			)
		}
		dst := *out
		if dst == "" {
			dst = "acl.json"
		}
		return mergeDirectories([]string(dirs), dst, stdout, stderr)
	}

	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *base == "" || *add == "" {
		fs.Usage()
		return errors.New("--base and --add are required unless --dir is used")
	}

	data, err := aclpolicy.MergePair(*base, *add)
	if err != nil {
		return err
	}

	dst := *out
	if dst == "" {
		dst = *base
	}
	if err = writeOutput(dst, data, stdout); err != nil {
		return err
	}
	if dst != "-" {
		if _, err = fmt.Fprintf(stderr, "hujson-merge: merged %s into %s\n", *add, dst); err != nil {
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
func printSchema(w io.Writer, fs *flag.FlagSet) error {
	var flags []schemaFlag
	fs.VisitAll(func(f *flag.Flag) {
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
