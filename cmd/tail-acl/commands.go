package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/rshade/tailscale-utils/tail-acl/internal/aclpolicy"
)

// commandDeps carries what every subcommand constructor needs. result is a
// pointer to run's result slot: a command body assigns through it so run can
// render the envelope after Execute returns, whatever the command was.
type commandDeps struct {
	opts       *options
	result     **result
	httpClient *http.Client
	apiURL     string
	stdout     io.Writer
	stderr     io.Writer
	format     *string
	verbose    *bool
}

func (d *commandDeps) logger() *slog.Logger { return newLogger(d.stderr, *d.verbose) }

// addSubcommands registers the leaf commands, grouping the four that share
// a noun (grant, tag-owner, host, posture) under a parent command.
func addSubcommands(ctx context.Context, root *cobra.Command, deps *commandDeps) {
	grant := &cobra.Command{Use: cmdGrant, Short: "Manage grants", RunE: runParentCommand}
	grant.AddCommand(newGrantAddCommand(deps), newGrantRemoveCommand(deps))

	tagOwner := &cobra.Command{Use: cmdTagOwner, Short: "Manage tag owners", RunE: runParentCommand}
	tagOwner.AddCommand(newTagOwnerAddCommand(deps))

	host := &cobra.Command{Use: cmdHost, Short: "Manage host aliases", RunE: runParentCommand}
	host.AddCommand(newHostSetCommand(deps))

	posture := &cobra.Command{Use: cmdPosture, Short: "Manage posture definitions", RunE: runParentCommand}
	posture.AddCommand(newPostureSetCommand(deps), newPostureRemoveCommand(deps))

	root.AddCommand(
		grant, tagOwner, host, posture,
		newMergeCommand(deps),
		newValidateCommand(ctx, deps),
		newTestCommand(ctx, deps),
		newCheckCommand(ctx, deps),
		newLintCommand(ctx, deps),
		newPullCommand(ctx, deps),
		newPlanCommand(ctx, deps),
		newUploadCommand(ctx, deps),
	)
}

// runParentCommand is RunE for the four grouping commands (grant, tag-owner,
// host, posture). Without an explicit RunE, cobra treats a command with only
// subcommands as non-runnable and returns [flag.ErrHelp] before ValidateArgs or
// PersistentPreRunE ever run — for *any* leftover args, not just none — so
// "tail-acl grant bogus" printed help and exited 0 exactly like a bare
// "tail-acl grant". Splitting the two here restores the documented exit-code
// scheme (2 = usage error) for a real mistake while keeping the bare case at
// exit 0: printing help and exiting 0 for a bare parent is what git remote,
// gh repo, and docker network all do, and is more useful than an error for a
// caller who is legitimately exploring the command tree.
func runParentCommand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		parentUsage(cmd.OutOrStdout(), cmd)
		return nil
	}
	return usagef("unknown %s command %q", cmd.Name(), args[0])
}

// parentUsage prints cmd's own short description and child verbs. cmd.Usage()
// would work too (nothing here overrides UsageFunc, so it resolves cobra's
// own per-command default correctly scoped to cmd rather than root's), but
// UsageString's non-nil-error path funnels through cobra.CheckErr, which
// calls [os.Exit] — not a risk worth taking for a [bytes.Buffer] write that in
// practice cannot fail. This keeps the same [io.Writer]-based style as usage()
// and stays entirely in code this package controls.
func parentUsage(w io.Writer, cmd *cobra.Command) {
	fmt.Fprintf(w, "%s\n\n", cmd.Short)
	fmt.Fprintf(w, "Usage:\n  %s [command]\n\n", cmd.CommandPath())
	fmt.Fprintln(w, "Available commands:")
	for _, sub := range cmd.Commands() {
		fmt.Fprintf(w, "  %-8s %s\n", sub.Name(), sub.Short)
	}
	fmt.Fprintf(w, "\nUse \"%s [command] --help\" for more information.\n", cmd.CommandPath())
}

func newGrantAddCommand(deps *commandDeps) *cobra.Command {
	var source, destination, ip, srcPosture stringListFlag
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subAdd,
		Short: "Append a grant to the policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := runGrantAdd(
				deps.opts.file,
				[]string(source), []string(destination), []string(ip), []string(srcPosture),
				comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().Var(&source, "src", "grant source; may be repeated")
	cmd.Flags().Var(&destination, "dst", "grant destination; may be repeated")
	cmd.Flags().Var(&ip, "ip", "IP protocol and port expression; may be repeated")
	cmd.Flags().Var(&srcPosture, "src-posture", "required device posture (posture:NAME); may be repeated")
	cmd.Flags().StringVar(&comment, commentFlagName, "", "attach TEXT to the authored entry as a leading // comment")
	cmd.Flags().BoolVar(&overwriteComment, overwriteFlagName, false,
		"replace the entry's existing comments instead of appending to them")
	return cmd
}

func newGrantRemoveCommand(deps *commandDeps) *cobra.Command {
	var index int
	cmd := &cobra.Command{
		Use:   subRemove,
		Short: "Remove a grant by index",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runGrantRemove(deps.opts.file, index)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().IntVar(&index, "index", -1, "index of the grant to remove")
	return cmd
}

// newTagOwnerAddCommand parses --comment/--overwrite-comment with pflag like
// every other command; the tradeoff is that TAG or OWNER beginning with "-"
// needs a "--" terminator before it (POSIX Utility Syntax Guideline 10), and
// --comment must be supplied before that terminator. This replaced
// DisableFlagParsing plus a hand-rolled interspersed scanner: that scanner let
// --help reach RunE as a raw positional instead of triggering cobra's help
// path, and let an unrecognized flag such as a typo'd "--commnet" silently
// become a positional and get written into the policy. Root's TraverseChildren
// still parses --file and the other global flags before this command is
// reached.
func newTagOwnerAddCommand(deps *commandDeps) *cobra.Command {
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subAdd + " TAG OWNER",
		Short: "Add an owner to a tag",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := runTagOwnerAdd(
				deps.opts.file, args, comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

// newHostSetCommand: see newTagOwnerAddCommand for why an ADDRESS beginning
// with "-" needs a "--" terminator.
func newHostSetCommand(deps *commandDeps) *cobra.Command {
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subSet + " NAME ADDRESS",
		Short: "Set a host alias to an address",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := runHostSet(
				deps.opts.file, args, comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

// newPostureSetCommand: see newTagOwnerAddCommand for why an EXPR beginning
// with "-" (e.g. "-1 < custom:score") needs a "--" terminator, and --comment
// must precede it.
func newPostureSetCommand(deps *commandDeps) *cobra.Command {
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subSet + " NAME EXPR [EXPR ...]",
		Short: "Add or replace a posture's expression list",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, err := runPostureSet(
				deps.opts.file, args, comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

func newPostureRemoveCommand(deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   subRemove + " NAME",
		Short: "Remove a posture definition",
		RunE: func(_ *cobra.Command, args []string) error {
			out, err := runPostureRemove(deps.opts.file, args)
			*deps.result = out
			return err
		},
	}
}

func newMergeCommand(deps *commandDeps) *cobra.Command {
	var dirs stringListFlag
	cmd := &cobra.Command{
		Use:   cmdMerge,
		Short: "Compile ACL sources in directories into one policy",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runMerge(deps.opts.file, []string(dirs))
			*deps.result = out
			return err
		},
	}
	cmd.Flags().Var(&dirs, "dir", "directory containing ACL files; may be repeated")
	return cmd
}

func newValidateCommand(ctx context.Context, deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   cmdValidate,
		Short: "Validate the policy via the Tailscale API",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runValidate(ctx, *deps.opts, deps.httpClient, deps.apiURL, deps.logger())
			*deps.result = out
			return err
		},
	}
}

func newTestCommand(ctx context.Context, deps *commandDeps) *cobra.Command {
	var watch bool
	var interval time.Duration
	cmd := &cobra.Command{
		Use: cmdTest,
		Short: "Run network tests locally; sshTests are preserved but not evaluated " +
			"(-strict rejects unparseable rules; --indeterminate controls only test's exit; " +
			"--watch re-runs on change and never exits non-zero for a verdict)",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flags().Changed("interval") && !watch {
				return usagef("--interval applies only to --watch; nothing polls without it")
			}
			if interval <= 0 {
				return usagef("--interval must be positive, got %s", interval)
			}
			out, err := runTest(
				ctx, *deps.opts, testOptions{watch: watch, interval: interval}, deps.logger(),
				newStreamEmitter(deps.stdout, *deps.format),
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().BoolVar(&watch, "watch", false,
		"re-run the assertions whenever the policy file changes; never exits non-zero for a verdict")
	cmd.Flags().DurationVar(&interval, "interval", defaultWatchInterval, "polling interval for --watch")
	cmd.AddCommand(newTestAddCommand(deps), newTestRemoveCommand(deps))
	return cmd
}

func newTestAddCommand(deps *commandDeps) *cobra.Command {
	var source string
	var deny, accept stringListFlag
	cmd := &cobra.Command{
		Use:   subAdd,
		Short: "Add deny or accept policy test assertions without evaluating them",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runTestAdd(deps.opts.file, source, []string(deny), []string(accept))
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&source, "src", "", "assertion source")
	cmd.Flags().Var(&deny, "deny", "denied destination in DST:PORT form; may be repeated")
	cmd.Flags().Var(&accept, "accept", "accepted destination in DST:PORT form; may be repeated")
	return cmd
}

func newTestRemoveCommand(deps *commandDeps) *cobra.Command {
	var source string
	var deny, accept stringListFlag
	cmd := &cobra.Command{
		Use:   subRemove,
		Short: "Remove deny or accept policy test assertions; may renumber later assertion IDs",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runTestRemove(deps.opts.file, source, []string(deny), []string(accept))
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&source, "src", "", "assertion source")
	cmd.Flags().Var(&deny, "deny", "denied destination in DST:PORT form; may be repeated")
	cmd.Flags().Var(&accept, "accept", "accepted destination in DST:PORT form; may be repeated")
	return cmd
}

func newCheckCommand(ctx context.Context, deps *commandDeps) *cobra.Command {
	var source, destination, protocol string
	var port int
	cmd := &cobra.Command{
		Use:   cmdCheck,
		Short: "Answer one reachability question locally",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			src, target, proto, err := resolveCheckTarget(
				source, destination, cmd.Flags().Changed("port"), port, protocol,
			)
			if err != nil {
				return err
			}
			out, err := runCheck(ctx, *deps.opts, src, target, proto, deps.logger())
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&source, "src", "", "source user, group, tag, host, IP, or CIDR")
	cmd.Flags().StringVar(&destination, "dst", "", "destination selector, optionally with :port")
	cmd.Flags().IntVar(&port, "port", -1, "destination port (alternative to including it in --dst)")
	cmd.Flags().StringVar(&protocol, "proto", string(aclpolicy.ProtocolAny),
		"IP protocol to ask about: tcp|udp|sctp|any")
	return cmd
}

func newLintCommand(ctx context.Context, deps *commandDeps) *cobra.Command {
	var severity, wildcard string
	cmd := &cobra.Command{
		Use:   cmdLint,
		Short: lintSummary,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			lintOpts, threshold, err := resolveLintOptions(severity, wildcard)
			if err != nil {
				return err
			}
			out, err := runLint(ctx, *deps.opts, lintOpts, threshold, deps.logger())
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&severity, "severity", string(aclpolicy.LintWarn),
		"minimum finding severity that sets a non-zero exit: info|warn|error")
	cmd.Flags().StringVar(&wildcard, "wildcard", string(aclpolicy.WildcardAnyToAny),
		"over-broad wildcard policy: any-to-any|any|off")
	return cmd
}

func newPlanCommand(ctx context.Context, deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   cmdPlan,
		Short: "Diff the policy against the live tailnet (read-only)",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runPlan(ctx, *deps.opts, deps.httpClient, deps.apiURL, deps.logger())
			*deps.result = out
			return err
		},
	}
}

func newPullCommand(ctx context.Context, deps *commandDeps) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   cmdPull,
		Short: "Bootstrap a local policy from the live tailnet",
		Long: "Bootstrap a local policy from the live tailnet. This is an adoption step, not a routine sync; " +
			"an existing --file is preserved unless --force is supplied.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runPull(ctx, *deps.opts, force, deps.httpClient, deps.apiURL)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing --file (use only for an intentional refresh)")
	return cmd
}

func newUploadCommand(ctx context.Context, deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   cmdUpload,
		Short: "Upload the policy to the tailnet",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runUpload(ctx, *deps.opts, deps.httpClient, deps.apiURL)
			*deps.result = out
			return err
		},
	}
}
