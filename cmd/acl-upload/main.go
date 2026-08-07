// Command acl-upload uploads a JSON or HuJSON policy file to a Tailscale
// tailnet using the policy-file API.
//
//	TAILSCALE_API_KEY=tskey-api-... TAILSCALE_TAILNET=example.com acl-upload
//	acl-upload --file acl.json --tailnet example.com --api-key tskey-api-...
//
// It is a focused single-purpose helper; `tail-acl upload` is the same operation
// inside the AX-conformant flagship CLI (JSON envelope, exit-code scheme). The
// upload confirmation is written to stdout; logs and errors go to stderr.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/rshade/tailscale-utils/policycore/cliflags"
	"github.com/rshade/tailscale-utils/tail-acl/internal/buildinfo"
	"github.com/rshade/tailscale-utils/tail-acl/internal/tailapi"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

const defaultAPIURL = tailapi.DefaultBaseURL

// httpTimeout bounds the upload request.
const httpTimeout = 30 * time.Second

type options struct {
	file       string
	tailnet    string
	apiKey     string
	ifMatch    string
	showSchema bool
}

func main() {
	client := &http.Client{Timeout: httpTimeout}
	if err := run(
		context.Background(),
		os.Args[1:],
		os.Getenv,
		client,
		defaultAPIURL,
		os.Stdout,
		os.Stderr,
	); err != nil {
		fmt.Fprintln(os.Stderr, "acl-upload:", err)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	args []string,
	getenv func(string) string,
	client *http.Client,
	apiURL string,
	stdout, stderr io.Writer,
) error {
	opts := &options{}
	root := newRootCommand(getenv, opts)
	root.RunE = func(cmd *cobra.Command, positional []string) error {
		return runUpload(ctx, cmd, positional, getenv, client, apiURL, stdout, opts)
	}
	root.SetArgs(cliflags.Normalize(root, args))
	root.SetOut(stdout)
	root.SetErr(stderr)
	return root.Execute()
}

func newRootCommand(getenv func(string) string, opts *options) *cobra.Command {
	root := &cobra.Command{
		Use:     "acl-upload",
		Short:   "Upload a JSON or HuJSON policy file to a Tailscale tailnet.",
		Version: buildinfo.Version("acl-upload", version),
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
	flags.StringVar(&opts.file, "file", "acl.json", "JSON or HuJSON policy file to upload")
	flags.StringVar(
		&opts.tailnet,
		"tailnet",
		getenv("TAILSCALE_TAILNET"),
		"tailnet name or ID (default: TAILSCALE_TAILNET)",
	)
	flags.StringVar(&opts.apiKey, "api-key", "", "Tailscale API access token (default: TAILSCALE_API_KEY)")
	flags.StringVar(&opts.ifMatch, "if-match", "", "optional ETag required for the update")
	// Registered but unbound: cobra's own Version-triggered handling reads this
	// flag and short-circuits before RunE ever runs, so no field here observes
	// it. Registering it under this exact name and usage string is still
	// required — it is what makes InitDefaultVersionFlag skip adding its own
	// "version for acl-upload" flag.
	flags.Bool("version", false, "print version and exit")
	flags.BoolVar(&opts.showSchema, "schema", false, "print the machine-readable tool schema (JSON) and exit")
	root.SetHelpFunc(func(cmd *cobra.Command, _ []string) {
		usage(cmd.OutOrStdout(), cmd.Flags())
	})
	root.InitDefaultHelpFlag()
	return root
}

func runUpload(
	ctx context.Context,
	cmd *cobra.Command,
	positional []string,
	getenv func(string) string,
	client *http.Client,
	apiURL string,
	stdout io.Writer,
	opts *options,
) error {
	if opts.showSchema {
		return printSchema(stdout, cmd.Flags())
	}
	if opts.apiKey == "" {
		opts.apiKey = getenv("TAILSCALE_API_KEY")
	}
	if len(positional) != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(positional, " "))
	}
	if opts.tailnet == "" {
		return errors.New("--tailnet or TAILSCALE_TAILNET is required")
	}
	if opts.apiKey == "" {
		return errors.New("--api-key or TAILSCALE_API_KEY is required")
	}

	apiClient, err := tailapi.NewClient(tailapi.Config{
		APIKey:  opts.apiKey,
		Tailnet: opts.tailnet,
		BaseURL: apiURL,
		HTTP:    client,
	})
	if err != nil {
		return err
	}
	if _, err = tailapi.UploadFile(ctx, apiClient, opts.file, opts.ifMatch); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "acl-upload: uploaded %s to tailnet %s\n", opts.file, opts.tailnet)
	return err
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
		Name:        "acl-upload",
		Version:     version,
		Description: "Upload a JSON or HuJSON policy file to a Tailscale tailnet via the policy-file API.",
		Flags:       flags,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func usage(w io.Writer, fs *pflag.FlagSet) {
	fmt.Fprintln(w, "acl-upload — upload a policy file to a Tailscale tailnet.")
	fmt.Fprintln(w, "\nUsage: acl-upload [--file acl.json] [--tailnet TAILNET] [--api-key TOKEN] [--if-match ETAG]")
	fmt.Fprintln(w, "\nFlags:")
	// PrintDefaults writes to the FlagSet's own configured output (stderr by
	// default), not to w, so point it at w explicitly before calling it.
	fs.SetOutput(w)
	fs.PrintDefaults()
	fmt.Fprintln(w, "\nExit codes: 0 success; 1 failure (bad flags, missing credentials, or API error).")
}
