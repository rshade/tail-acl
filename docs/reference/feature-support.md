# Feature support

This page lists which Tailscale policy features `tail-acl` and the
`policycore` library handle, and how completely. It is documentation, not a
versioning contract: Tailscale moves features between alpha, beta, and general
availability on its own schedule, and this project's version numbers do not
follow those labels. A feature's upstream stage is recorded with the date it
was checked, so you can judge how fresh the entry is.

## How to read the table

- **Modeled** means the policy field is parsed into a typed value (through the
  pinned `tailscale.com/client/tailscale/v2` SDK) and the linter, the editor,
  or the local evaluator can act on it.
- **Partial** means the feature is understood for some operations and
  deliberately left undecided for others. Where the tool cannot decide, it says
  so instead of guessing.

| Feature | Support | What is and is not covered | Tailscale stage (checked) |
| --- | --- | --- | --- |
| Declarative node sharing (`externalTailnets`) | Partial | The field is modeled through the SDK. `group://<alias>/<name>` and `tag://<alias>/<name>` selectors are parsed, linted, and editable with the external-tailnet commands. A cross-tailnet selector is otherwise undecidable from the local policy: the only case the matcher settles is a well-formed selector whose alias the policy does not declare. | Alpha (2026-11-03), per [Tailscale's feature page](https://tailscale.com/docs/features/declarative-node-sharing) |
| Policy keys the pinned SDK does not know | Reported, not interpreted | An unknown top-level key is reported as `not modeled by this build` instead of as an invalid key, because Tailscale ships policy keys ahead of the SDK. The tool neither rejects nor evaluates it. | Not applicable |
| Device posture | Partial | Posture expressions are validated offline and evaluated locally when every attribute the expression needs is known. A posture that depends on an attribute the tool does not know is left undecided. The local test evaluator reports `uses unsupported srcPosture` when it cannot judge a rule's posture requirement. | Not checked |
| `via` routing in the local test evaluator | Not evaluated | The evaluator reports `unsupported via routing` rather than deciding a rule that uses it. | Not checked |

## When this page changes

Add a row when a feature gains support or loses it, and update the checked date
when you re-read the upstream page. Do not encode the upstream stage in an
exported type, a package name, or machine-readable output: those would tie this
module's compatibility to a label Tailscale can change.
