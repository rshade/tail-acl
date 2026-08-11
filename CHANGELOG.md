# Changelog

## 0.1.0 (2026-08-07)


### ⚠ BREAKING CHANGES

* **tail-acl:** stop /acl/validate false passes and false failures
* **policycore,tail-acl:** `test` previously exited 0 when an unparseable rule lay on an assertion's evaluation path, treating it as unable to match and passing the deny. It now exits 10 by default; set `--indeterminate=ignore` to keep the old exit code for one release while the policy is repaired. In the same situation `check` previously reported `access: "deny"` with exit 1 and now reports `access: "indeterminate"` with exit 10, omitting the legacy `allowed` field rather than serializing false. There is deliberately no opt-out for `check`, whose three-state verdict is its product. Separately, SCTP joining TCP and UDP as port-carrying widens the protocol-agnostic default, so a capability such as `sctp:5432` that previously answered no port question now answers it: `check` flips from not reachable to reachable, an `accept` assertion over it from fail to pass, and a `deny` assertion from pass to fail.
* **tail-acl:** `test` previously exited 0 when an unparseable rule lay on an assertion's evaluation path, treating it as unable to match and passing the deny. It now exits 10 by default; set `--indeterminate=ignore` to keep the old exit code for one release while the policy is repaired. In the same situation `check` previously reported `access: "deny"` with exit 1 and now reports `access: "indeterminate"` with exit 10, omitting the legacy `allowed` field rather than serializing false. There is deliberately no opt-out for `check`, whose three-state verdict is its product.

### Features

* add grant-dst-widespread live-fleet breadth check
* add live audit report scripts and tail-acl init
* add policy advisories and retained report workflows
* **policycore:** three-state resolution for roster-bearing matchers
* **tail-acl:** add --comment to typed authoring commands
* **tail-acl:** add --roster to resolve role autogroups from a login-to-role file
* **tail-acl:** add check subcommand for local reachability queries
* **tail-acl:** add lint subcommand for static policy hygiene
* **tail-acl:** add posture authoring commands
* **tail-acl:** add test subcommand with local policy assertion evaluator
* **tail-acl:** author policy test assertions with test add and test remove
* **tail-acl:** opt-in server validation for test --watch
* **tail-acl:** pull the deployed policy and fix portless grants dst linting
* **tail-acl:** re-run the test suite on change with test --watch
* **tailnet-audit:** add acl-coverage-gap check with shared policycore module
* **tailnet-audit:** add read-only control-plane hygiene classifier
* **tailnet-audit:** pin OpenAPI contract and property gaps


### Bug Fixes

* **tail-acl:** align service-reference counting and online lookup coverage, reject services in SSH node-selector fields, guard SCIM/local group-name collisions, and clarify online warning severity gating
* **ci:** keep release branches current
* **cli:** enforce ASCII-safe stdout and print the audit verdict
* **deps:** update github.com/tailscale/hujson digest to b80ff77
* **deps:** update module tailscale.com to v1.102.2
* lint issues
* **policycore,tail-acl:** never emit a deny the evaluator could not prove
* **tail-acl:** add indeterminate verdict so check never guesses a deny
* **tail-acl:** load sshTests and ssh[].acceptEnv policy fields
* **tail-acl:** never pass a deny assertion the evaluator could not prove
* **tail-acl:** preserve HuJSON comments in typed edits
* **tail-acl:** stop /acl/validate false passes and false failures
