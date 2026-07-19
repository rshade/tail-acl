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
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rshade/tailscale-utils/tail-acl/internal/buildinfo"
	"github.com/rshade/tailscale-utils/tail-acl/internal/tailapi"
)

// version is overridden at build time via -ldflags "-X main.version=vX.Y.Z".
var version = "dev"

const defaultAPIURL = tailapi.DefaultBaseURL

// httpTimeout bounds the upload request.
const httpTimeout = 30 * time.Second

type options struct {
	file    string
	tailnet string
	apiKey  string
	ifMatch string
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
		if errors.Is(err, flag.ErrHelp) {
			return
		}
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
	fs := flag.NewFlagSet("acl-upload", flag.ContinueOnError)
	fs.SetOutput(stderr)
	opts := options{}
	fs.StringVar(&opts.file, "file", "acl.json", "JSON or HuJSON policy file to upload")
	fs.StringVar(
		&opts.tailnet,
		"tailnet",
		getenv("TAILSCALE_TAILNET"),
		"tailnet name or ID (default: TAILSCALE_TAILNET)",
	)
	fs.StringVar(&opts.apiKey, "api-key", "", "Tailscale API access token (default: TAILSCALE_API_KEY)")
	fs.StringVar(&opts.ifMatch, "if-match", "", "optional ETag required for the update")
	showVersion := fs.Bool("version", false, "print version and exit")
	showSchema := fs.Bool("schema", false, "print the machine-readable tool schema (JSON) and exit")
	fs.Usage = func() { usage(stderr, fs) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintln(stdout, buildinfo.Version("acl-upload", version))
		return err
	}
	if *showSchema {
		return printSchema(stdout, fs)
	}
	if opts.apiKey == "" {
		opts.apiKey = getenv("TAILSCALE_API_KEY")
	}
	if len(fs.Args()) != 0 {
		return fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
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
	if err = tailapi.UploadFile(ctx, apiClient, opts.file, opts.ifMatch); err != nil {
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
		Name:        "acl-upload",
		Version:     version,
		Description: "Upload a JSON or HuJSON policy file to a Tailscale tailnet via the policy-file API.",
		Flags:       flags,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintln(w, "acl-upload — upload a policy file to a Tailscale tailnet.")
	fmt.Fprintln(w, "\nUsage: acl-upload [--file acl.json] [--tailnet TAILNET] [--api-key TOKEN] [--if-match ETAG]")
	fmt.Fprintln(w, "\nFlags:")
	fs.PrintDefaults()
	fmt.Fprintln(w, "\nExit codes: 0 success; 1 failure (bad flags, missing credentials, or API error).")
}
