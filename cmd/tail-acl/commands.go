package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
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

// addSubcommands registers the leaf commands, grouping the five that share
// a noun (grant, tag-owner, host, posture, auto-approver) under a parent command.
func addSubcommands(ctx context.Context, root *cobra.Command, deps *commandDeps) {
	grant := &cobra.Command{Use: cmdGrant, Short: "Manage grants", RunE: runParentCommand}
	grant.AddCommand(newGrantAddCommand(deps), newGrantRemoveCommand(deps))

	tagOwner := &cobra.Command{Use: cmdTagOwner, Short: "Manage tag owners", RunE: runParentCommand}
	tagOwner.AddCommand(newTagOwnerAddCommand(deps))

	host := &cobra.Command{Use: cmdHost, Short: "Manage host aliases", RunE: runParentCommand}
	host.AddCommand(newHostSetCommand(deps))

	posture := &cobra.Command{Use: cmdPosture, Short: "Manage posture definitions", RunE: runParentCommand}
	posture.AddCommand(newPostureSetCommand(deps), newPostureRemoveCommand(deps))

	autoApprover := &cobra.Command{
		Use:   cmdAutoApprover,
		Short: "Manage route and exit-node auto-approvers",
		RunE:  runParentCommand,
	}
	autoApprover.AddCommand(newAutoApproverAddCommand(deps), newAutoApproverRemoveCommand(deps))

	root.AddCommand(
		grant, tagOwner, host, posture, autoApprover,
		newInitCommand(deps),
		newMergeCommand(deps),
		newNormalizeCommand(deps),
		newValidateCommand(ctx, deps),
		newTestCommand(ctx, deps),
		newCheckCommand(ctx, deps),
		newLintCommand(ctx, deps),
		newJQCommand(ctx, deps),
		newPullCommand(ctx, deps),
		newPlanCommand(ctx, deps),
		newUploadCommand(ctx, deps),
	)
}

func newNormalizeCommand(deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   cmdNormalize,
		Short: "Emit the policy as standard JSON for general-purpose JSON tools",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runNormalize(deps.opts.file)
			*deps.result = out
			return err
		},
	}
}

// splitCommaList flattens a repeatable stringListFlag into a single list,
// splitting each value on commas and dropping empties, so --scim-domains accepts
// both "--scim-domains a.com,b.com" and repeated "--scim-domains a.com
// --scim-domains b.com".
func splitCommaList(values stringListFlag) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		for part := range strings.SplitSeq(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

func newInitCommand(deps *commandDeps) *cobra.Command {
	return &cobra.Command{
		Use:   cmdInit,
		Short: "Initialize an empty policy for typed authoring",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runInit(deps.opts.file)
			*deps.result = out
			return err
		},
	}
}

// runParentCommand is RunE for the five grouping commands (grant, tag-owner,
// host, posture, auto-approver). Without an explicit RunE, cobra treats a command with only
// subcommands as non-runnable and returns [flag.ErrHelp] before ValidateArgs or
// PersistentPreRunE ever run — for *any* leftover args, not just none — so
// "tail-acl grant bogus" printed help and exited 0 exactly like a bare
// "tail-acl grant". Splitting the two here restores the documented exit-code
// scheme (2 = usage error) for a real mistake while keeping the bare case at
// exit 0: printing help and exiting 0 for a bare parent is what git remote,
// gh repo, and docker network all do, and is more useful than an error for a
// caller who is legitimately exploring the command tree.
// A bare parent prints the same page its own --help does, rather than a
// second hand-written rendering of the same facts.
func runParentCommand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		commandHelp(cmd)
		return nil
	}
	return usagef("unknown %s command %q", cmd.Name(), args[0])
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

// newAutoApproverAddCommand takes the section as flags rather than as
// positionals the way tag-owner add does because exitNode has no key: one
// positional grammar cannot name both "the 10.0.0.0/8 entry" and "the flat
// list" without a sentinel value.
func newAutoApproverAddCommand(deps *commandDeps) *cobra.Command {
	var route string
	var exitNode bool
	var approvers stringListFlag
	var comment string
	var overwriteComment bool
	cmd := &cobra.Command{
		Use:   subAdd,
		Short: "Add auto-approvers for a route or the exit-node list",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := runAutoApproverAdd(
				deps.opts.file, route, exitNode, []string(approvers),
				comment, cmd.Flags().Changed(commentFlagName), overwriteComment,
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&route, "route", "", "CIDR whose approver list to edit (autoApprovers.routes)")
	cmd.Flags().BoolVar(&exitNode, "exit-node", false,
		"edit the exit-node approver list instead (autoApprovers.exitNode)")
	cmd.Flags().Var(&approvers, "approver",
		"approver selector (user, group, tag, or autogroup); may be repeated")
	registerCommentFlags(cmd.Flags(), &comment, &overwriteComment)
	return cmd
}

func newAutoApproverRemoveCommand(deps *commandDeps) *cobra.Command {
	var route string
	var exitNode bool
	var approvers stringListFlag
	cmd := &cobra.Command{
		Use:   subRemove,
		Short: "Remove auto-approvers, pruning an emptied route key",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			out, err := runAutoApproverRemove(deps.opts.file, route, exitNode, []string(approvers))
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&route, "route", "", "CIDR whose approver list to edit (autoApprovers.routes)")
	cmd.Flags().BoolVar(&exitNode, "exit-node", false,
		"edit the exit-node approver list instead (autoApprovers.exitNode)")
	cmd.Flags().Var(&approvers, "approver",
		"approver selector (user, group, tag, or autogroup); may be repeated")
	return cmd
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
	var validate bool
	var interval time.Duration
	cmd := &cobra.Command{
		Use:   cmdTest,
		Short: testSummary,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if validate && !watch {
				return usagef("--validate applies only to --watch; use the validate command for a single server check")
			}
			if cmd.Flags().Changed("interval") && !watch {
				return usagef("--interval applies only to --watch; nothing polls without it")
			}
			if interval <= 0 {
				return usagef("--interval must be positive, got %s", interval)
			}
			out, err := runTest(
				ctx, *deps.opts, testOptions{watch: watch, validate: validate, interval: interval}, deps.logger(),
				newStreamEmitter(deps.stdout, *deps.format), deps.httpClient, deps.apiURL,
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().BoolVar(&watch, "watch", false,
		"re-run the assertions whenever the policy file changes; never exits non-zero for a verdict")
	cmd.Flags().BoolVar(&validate, "validate", false,
		"with --watch, validate each stable snapshot using the read-only Tailscale API")
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
	var severity, wildcard, configPath string
	var strictSCIMGroups bool
	var scimDomains stringListFlag
	cmd := &cobra.Command{
		Use:   cmdLint,
		Short: lintSummary,
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			lintOpts, threshold, err := resolveLintOptions(
				severity, wildcard, strictSCIMGroups, scimDomains,
			)
			if err != nil {
				return err
			}
			out, err := runLint(ctx, *deps.opts, lintOpts, threshold, configPath, deps.logger())
			*deps.result = out
			return err
		},
	}
	cmd.Flags().StringVar(&severity, "severity", string(aclpolicy.LintWarn),
		"lowest finding severity to report and fail on: advice|info|warn|error")
	cmd.Flags().StringVar(&wildcard, "wildcard", string(aclpolicy.WildcardAnyToAny),
		"over-broad wildcard policy: any-to-any|any|off")
	cmd.Flags().StringVar(&configPath, "config", "",
		"HuJSON lint config path (currently broad-rule-untested allowBroad exclusions)")
	cmd.Flags().BoolVar(&strictSCIMGroups, "strict-scim-groups", false,
		"error on undeclared SCIM/IdP-synced groups (group:<name>@<domain>) instead of exempting them")
	cmd.Flags().Var(&scimDomains, "scim-domains",
		"narrow the SCIM-group exemption to these @domains (comma-separated; may be repeated)")
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
	var acceptRemoteChanges bool
	cmd := &cobra.Command{
		Use:   cmdUpload,
		Short: "Upload the policy to the tailnet",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := runUpload(
				ctx,
				*deps.opts,
				cmd.Flags().Changed("if-match"),
				acceptRemoteChanges,
				deps.httpClient,
				deps.apiURL,
			)
			*deps.result = out
			return err
		},
	}
	cmd.Flags().BoolVar(&acceptRemoteChanges, "accept-remote-changes", false,
		"upload without If-Match, explicitly accepting remote changes not present in --file")
	return cmd
}
