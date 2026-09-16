# Public API reference

This page describes the exported selector-matching API and ipset member
grammar in `policycore`, the shared `policycore/addrspace` address primitives,
the `policycore/sanitize` output contract, and the `policycore/hujsonedit`
comment-preserving document editor, plus the `policycore/alpha` inventory and
shared policy models for features modeled ahead of the pinned SDK.

## Alpha feature inventory

`alpha.RepositoryFeatures()` returns a fresh copy of the canonical inventory
of alpha or unreleased Tailscale features this repository hand-models. Each
`alpha.Feature` records its `Name`, upstream `DocURL`, `ModeledDate`, and
pipeline `Stage` (`StageAlpha`, `StageBeta`, or `StageGA`). Add new entries to
the slice returned by that function in `policycore/alpha/alpha.go`.

`alpha.NewRegistry()` returns an empty, caller-owned validation and lookup
container. `Registry.Register` rejects missing fields, unknown stages, and
duplicate names; it does not update `alpha.RepositoryFeatures()`.
`Registry.Lookup` reads one entry and `Registry.List` returns entries sorted by
name.

`alpha.AlphaHint` is the string `alpha-hint`, the `SourceRef.confidence` value
for an editorial pointer associated with one of these unstable or unreleased
features. It complements `derived` and `hint`; it does not relax the rule that
a source package pointer must resolve when one exists.

### Declarative node sharing

`alpha.ExternalTailnets` maps a policy-local alias to an
`ExternalTailnetConfig`. The config records the other tailnet's stable ID,
whether incoming connections are allowed, and the local groups or tags that
tailnet may reference. The alpha docs do not establish an omission default for
`allowIncomingConnections`; the model preserves an explicit `false` and does
not assign a semantic default.

`alpha.ParseExternalSelector` parses `group://<alias>/<name>` and
`tag://<alias>/<name>` into an `ExternalSelector{Kind, Alias, Name}`. Ordinary
same-tailnet selectors such as `group:engineering`, missing aliases or names,
and extra path segments are rejected.

Whitespace and non-printable characters are rejected anywhere in an alias or
name, not only around them: an interior space, newline, NUL, or zero-width
character can never match a real `externalTailnets` key, so accepting one would
turn an authoring typo into a silent non-match surfacing far from its cause.

A name must also omit the `group:` or `tag:` prefix, which `Kind` already
carries. The sibling `AllowExternalReferencesTo` field holds *prefixed* local
selectors, so `group://partner/group:engineering` is the natural mistake rather
than an exotic one, and it is refused rather than parsed into a name nothing
resolves.

This is syntax modeling only; `Matcher` does not yet resolve cross-tailnet
membership.

`alpha.NewVerifierRegistry(features)` returns an empty `VerifierRegistry`
backed by a `*Registry`. `RegisterVerifier(featureName, fn)` ties a
`LiveVerifyFunc` (`func(context.Context) error`) to a feature already present
in `features`, rejecting a nil `fn`, an unregistered feature name, or a
duplicate. `RunAll(ctx)` runs every registered verifier and returns one
`VerifyResult{FeatureName, Err}` per registered verifier, sorted by name. It
returns an empty slice when no verifiers have been registered, even if the
backing feature registry is populated. See
[Live-verifying an alpha feature](../README.md#live-verifying-an-alpha-feature)
for the opt-in, credentialed workflow that invokes this.

## Address-space primitives

`addrspace.Overlaps` reports whether two CIDR prefixes or bare addresses share
any address. `addrspace.OverlappingPairs` applies the same comparison to a list,
returning stable index pairs while isolating malformed entries in a per-index
error map.

`addrspace.IsViaPrefix` reports whether a parseable CIDR lies in Tailscale's
4via6 range. It intentionally recognizes range members whose prefix length or
site ID is invalid, allowing a caller to distinguish a malformed via route from
an ordinary route. `addrspace.SiteID` performs the full validation and returns
the embedded 16-bit site ID only for valid `/96` through `/128` via prefixes.

## Subnet arithmetic

`ipcalc.Split` divides a parent CIDR into equal-sized child prefixes of a target
bit length. It works for both IPv4 and IPv6 and returns the children alongside
the exact child count as a `*big.Int` — since IPv6 splitting can exceed uint64
range, the count is always computed this way even when the full list cannot be
materialized. When the count would exceed `MaxMaterializedChildren` (65536),
`Split` returns `(nil, count, ErrTooManyChildren)` so the caller can report the
count without enumerating all children.

`ipcalc.Unmap4In6` rewrites an IPv4-mapped IPv6 prefix (`::ffff:a.b.c.d/n`) to
its equivalent plain IPv4 prefix. `ok` is false if the prefix is not a 4-in-6
address, or if its bit length is too short to represent a valid IPv4 prefix
once the 96-bit mapping prefix is removed. A caller that supports IPv6 can
preserve the original prefix when `ok` is false.

`ipcalc.Info` reports the classic block facts for an IPv4 prefix — network
address, broadcast address, usable host range, and usable-host count — as a
`BlockInfo`. Host bits are masked off first, so an address inside a block
yields the facts for its containing block. `Broadcast` is the zero `netip.Addr`
(`IsValid() == false`) for a `/31` (RFC 3021 point-to-point) and a `/32`
(host route), which reserve no network or broadcast address; for both, every
address in the block is usable. `UsableHosts` is a `*big.Int`, like `Split`'s
count, so an IPv6 extension cannot change the field's type. A non-IPv4 prefix
returns `ErrIPv6NotSupported` — including a 4-in-6 prefix, which callers must
normalize with `Unmap4In6` before calling.

## Output sanitization

`sanitize.ParseLevel` accepts `off`, `identity`, and `strict`.
`sanitize.Resolve` applies the shared precedence rule: a non-`off`
`TAILSCALE_SANITIZE` value wins over `--sanitize`; an unknown environment or
flag value is an error. `Resolution.Notice` produces the required identity-free
stderr notice.

`sanitize.New` creates an invocation allocator. With no key it uses fresh
cryptographic randomness and marks output as artifact-scoped. A 64-character
hexadecimal `TAILSCALE_SANITIZE_KEY` generated from 32 random bytes produces
stable tailnet-scoped HMAC placeholders and a non-secret key identifier,
allowing compatible retained
reports to establish that they share a correlation domain. It never falls back
to an unkeyed hash.

`Sanitizer.Pseudonym` replaces a structured value without retaining it;
`Sanitizer.Value` additionally registers a structured value for later prose replacement;
`Sanitizer.Text` replaces registered exact values in prose;
`Sanitizer.Time` quantizes strict timestamps to a UTC day; and
`Sanitizer.Metadata` supplies the versioned output marker. Tools use
`UnhandledFields` in reflection-guard tests to require a decision whenever an
output struct grows.

The `sanitize/sanitizetest` subpackage holds the other test-facing half:
`AssertNoIdentityLeaks` scans rendered output for a fixture's real values and
reports every one it finds. It matches ASCII case-insensitively and as a plain
substring, deliberately dropping the token-boundary rule `Sanitizer.Text`
applies — a value that reaches rendered output has leaked whatever surrounds
it. It takes a minimal `TestingT`, so it adds no dependency beyond the standard
library.

## HuJSON editing

`hujsonedit` provides schema-agnostic, comment-preserving RFC 6902 edits to
HuJSON documents. It carries no knowledge of any particular document's
fields — callers own that; the package owns only the AST/patch mechanics.
Extracted from `tail-acl/internal/aclpolicy` once `tail-ipam` needed the same
mechanics and the generic layer was already visibly separable from
ACL-specific code.

`hujsonedit.PatchAdd(value, segments...)` and
`hujsonedit.PatchRemove(segments...)` build `PatchOperation` values;
`hujsonedit.WritePatch(path, resolve, operations...)` applies them to the
document at `path` in order, then authors any comments those operations
carry, then reformats. `resolve` (a `ResolveKey`) bridges alternate
top-level key spellings before a path's first segment is resolved against
the parsed document — pass `nil` when the schema has none.

```go
err := hujsonedit.WritePatch(path, nil,
    hujsonedit.PatchAdd(entry, "acls", "-"),
    hujsonedit.PatchComment("added by tail-acl grant add", "acls", "-"),
)
```

`hujsonedit.PatchComment(text, segments...)` authors a leading `//`-prefixed
line comment on the node at `segments`, naming it as it exists *after* every
operation in the same call has applied, and appends after any comment
already there; `PatchCommentOverwrite` replaces them instead.
`hujsonedit.LeadingComments(path, resolve, segments...)` reads the comments
already attached to a node, which lets a caller detect a no-op edit before
writing. `hujsonedit.ValidateCommentText` rejects text that cannot render as
one line comment (a carriage return, a newline, or invalid UTF-8).

`hujsonedit.ParseFile` reads and parses a JSON or HuJSON document.
`hujsonedit.WriteRaw` atomically writes raw bytes, preserving an existing
file's permissions and defaulting new files to `0644`. `hujsonedit.JSONPointer`
renders an RFC 6901 pointer for path segments, escaping `~` and `/` so a
user-controlled segment cannot change the location an edit targets.

## `Matcher`

`Matcher` holds the policy document and optional live user-role facts:

```go
type Matcher struct {
    Policy    *tailscale.ACL
    Roles     map[string]tailscale.UserRole
    HaveRoles bool
}
```

`Roles` maps lowercased login names to tailnet roles. `HaveRoles` asserts that
the map came from a complete, authoritative roster. An empty complete roster is
different from an unavailable roster.

## Boolean matching

`Matches(selector, query, source)` reports whether one selector names a query.
`AnyMatches(selectors, query, source)` reports whether any selector does.
`source` is used to resolve `autogroup:self`; pass an empty string when it is
not relevant.

```go
if matcher.Matches("group:eng", "ada@example.com", "") {
    // group:eng resolves, directly or through nested groups, to this login.
}
```

`SelectorMatches` is the roster-blind convenience entry point:

```go
matched := policycore.SelectorMatches(
    "group:eng",
    "ada@example.com",
    policy,
    "",
)
```

Role autogroups cannot match through this convenience function because it has
no user roster.

## Tri-state matching

`MatchesTri` returns one of:

| Result | Meaning |
| --- | --- |
| `Matched` | The selector definitely names the query. |
| `NoMatch` | The selector definitely does not name the query. |
| `Unresolvable` | A decision requires live state the matcher does not hold. |

```go
switch matcher.MatchesTri(selector, query, source) {
case policycore.Matched:
    // Apply matched behavior.
case policycore.NoMatch:
    // The selector is decidable and does not match.
case policycore.Unresolvable:
    // Report incomplete evidence instead of a definite non-match.
}
```

`AnyMatchesTri` returns the result plus the first unresolvable selector when no
selector matches. A definite match takes precedence over an earlier
unresolvable selector.

## Recognition helpers

- `Matcher.Recognized` reports whether a non-match is conclusive with the
  matcher's available facts.
- `KnownAutogroup` reports whether the package implements an autogroup form.
- `IsRoleAutogroup` identifies autogroups that depend on the user roster.
- `AutogroupResolvable` checks roster-blind resolvability for a query shape.
- `LooksLikeUser` identifies selector strings treated as login names.

## Roster-blind tri-state entry points

`SelectorMatchesTri` and `AnySelectorMatchesTri` resolve without a roster. They
are the zero-roster `Matcher` case, so they cannot drift from the methods
above. `AnySelectorMatchesTri` returns `Unresolvable` together with the first
selector it could not decide, which callers surface as the reason.

## Roster loading

`ParseRoster` decodes a login-to-role file into the map `Matcher.Roles`
expects, lowercasing logins to match how lookups are performed. A successful
parse always returns a non-nil map, including for an empty roster, so a
complete-but-empty roster stays distinguishable from one that was never read.
Set `HaveRoles` from that distinction, not from the map's length.

## Policy-shape and address helpers

- `ContainsLiteralWildcard` reports whether a selector list contains a
  port-stripped literal `*`. It deliberately does not treat any autogroup as a
  wildcard: `autogroup:tagged` can name most of a live fleet, but only
  control-plane state settles that, so it belongs to a live-fleet check rather
  than a static advisory.
- `ExpandAddressSelector` resolves a selector through `Hosts` and `IPSets` to
  the addresses or prefixes it names: a `Hosts` alias is followed
  transitively, and an `IPSets` entry is materialized through `ResolveIPSet`
  and rendered as prefix strings, or expands to nothing when it cannot be
  materialized. A value that names neither is returned unchanged.
- `AddressContains` reports whether a selector covers a query, where either may
  be an address or a prefix.
- `IsPublicAddress` reports whether a value resolves to a publicly routable
  address, which is what `autogroup:internet` selects.

## ipset member grammar

`ParseIPSetMember` classifies one raw ipset member using the control plane's
grammar and returns an `IPSetMember{Operation, Kind, Target}`. A member is an
optional `add` or `remove` operation word followed by one target: a CIDR
prefix, a bare address, an inclusive range `A-B`, a `host:<alias>` reference,
or an `ipset:<name>` reference. `Target` is canonical for the address-bearing
kinds — the prefix masked, an address or a range's ends rendered from their
parsed form, a bare address never promoted to a `/32` — and kept as written
for `host:` and `ipset:` references. `IPSetMember.String` renders the
canonical spelling, which is what an authoring tool compares for idempotence.
Whether a referenced host or ipset exists is the caller's question; the parser
has no policy.

`ValidateIPSetOperations` enforces the explicit-operation rule over a raw
member list: once any member is a `remove`, every member must be an explicit
`add` or `remove`. It classifies by the operation word alone, so a linter can
report the rule even when a target does not parse. The
`IPSetImplicitMemberError` it returns names the first implicit member and the
first `remove`, and its message says to write the member as `add <member>`.

## ipset materialization

`ResolveIPSet(name, policy)` materializes one `IPSets` entry into the address
space its members cover and returns it as the minimal sorted prefix covering.
Members are applied in list order under the grammar above: an implicit member
and an `add` contribute their target's address space, and a `remove` withdraws
it from whatever earlier members contributed, so a later `add` re-contributes
space an earlier `remove` withdrew. A `host:` reference is one `Hosts` lookup
whose value must be a literal address or prefix, a range contributes every
address between its ends, and an `ipset:` reference recurses. Nested
references are memoized within a call, so a set reached through two paths is
resolved once and is not a cycle. This is the shape the control plane
enforces: a `remove` withdraws a `host:` alias's address like any other, and a
node compiles a range into the same covering.

A set that cannot be materialized is an error naming the set and the member,
never a partial set: a member that does not parse (which includes
`autogroup:internet` until the grammar learns it), an implicit member beside
a `remove` (the rule `ValidateIPSetOperations` enforces), a `host:` alias that is
undefined or whose `Hosts` value names something other than an address or
prefix, an `ipset:` reference that is undefined or already on the current
resolution path, nesting deeper than 128 levels, or an expansion past 65536
prefixes. Dropping an unreadable member would either hide address space or,
for a failed `remove`, silently widen the set.

`ExpandAddressSelector` materializes an `IPSets` entry through `ResolveIPSet`,
and `Matcher` treats a set it cannot materialize as undecidable:
`MatchesTri` reports `Unresolvable` for a selector that names or reaches one,
and `Recognized` reports `false` for it, so a consumer reports indeterminate
evidence rather than a confident denial. A set that materializes to no
address space is decidable — a query against it is `NoMatch`. A bare host
alias written directly as a member (`"gw"` rather than `"host:gw"`) is not a
form the control plane accepts, so it makes the set unmaterializable rather
than resolving by accident.

## Resolution boundaries

Nested groups, `Hosts`, and `IPSets` are expanded with cycle guards. Undefined
groups and `Hosts` cycles do not become missing live state. An `IPSets` entry
is the exception: a cycle through `ipset:` references, like any other reason
the set cannot be materialized, makes every selector that reaches it
`Unresolvable`, because the alternative is a settled non-match the policy
does not support. A complete roster can settle a user query for a role
autogroup, but it cannot map a bare device address to its owner; that query
remains `Unresolvable`.
