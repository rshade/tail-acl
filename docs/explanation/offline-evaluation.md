# Offline evaluation and safety

`tsacl test` and `tsacl check` evaluate the candidate policy without
credentials or network access. This makes results deterministic for unchanged
policy bytes and useful before a tailnet is available, but a policy file does
not contain every fact that can affect access.

## Three possible answers

A local query can be allowed, denied, or indeterminate. A denial is reported
only after every relevant rule has been proved inapplicable. If a rule could
apply but depends on missing or unreadable information, the result is
indeterminate rather than a confident denial.

Examples of information absent from the policy file include:

- current device posture;
- `via` routing state;
- role autogroups such as `autogroup:admin` and `autogroup:owner`;
- the device-to-tag relationship needed to settle some selectors.

An unreadable destination, protocol, or port expression creates the same
boundary when it overlaps the query. With `--strict`, `test` and `check` reject
the whole policy instead of producing narrowed verdicts.

## What the evaluator understands

The evaluator handles network grants and legacy ACLs, groups, hosts, IP sets,
literal IP addresses and CIDRs, tags and exact selectors, supported autogroups,
and single, list, or range port expressions. Application-only capabilities do
not grant network access.

A port-only `check` with the default `--proto any` asks whether any
port-carrying protocol permits access. The supported set is TCP, UDP, and SCTP.
Use `--proto` when protocol identity matters.

A policy with neither a `grants` nor an `acls` section receives the implicit
default-allow behavior. An explicitly empty section denies access.

## Tests and skipped policy content

`test` evaluates each top-level network test destination as a stable assertion
with status, evidence, and a decision trace. A deny assertion passes only when
every rule is proved inapplicable.

Top-level `sshTests` are loaded and preserved but not evaluated. Human output
warns about them; JSON reports `ssh_tests_skipped`.

Network-rule syntax is scanned before assertions run. Unparseable rules are
reported in the JSON `skipped` array. Without `--strict`, only an assertion
whose evaluation path reaches such a rule becomes indeterminate; unrelated
assertions can still be proved.

## References require separate checks

Local evaluation assumes policy references are valid. An undefined group, host,
tag, or IP set matches nothing locally even though the control plane can reject
the policy. Run `lint` to find dangling references and `validate` to check the
complete candidate server-side.

`validate` is also the authoritative option when the verdict needs live
control-plane semantics. `check` never silently falls back to the network.

## Machine-readable verdicts

For `check`, branch on the three-state `access` field. The compatibility field
`allowed` is present only for definite answers and is omitted for an
indeterminate result.

`grant_index` or `acl_index` identifies the rule that decided the answer. For an
indeterminate result, that is the rule whose unevaluable condition blocked the
verdict; it is not evidence that the rule allowed access.

Decision-trace wording is explanatory rather than a stable interface. Machine
consumers should branch on `status` or `access` and use structured `evidence`
instead of matching trace text.
