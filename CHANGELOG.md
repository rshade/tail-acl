# Changelog

## [0.4.0](https://github.com/rshade/tail-acl/compare/v0.3.0...v0.4.0) (2026-11-03)


### Features

* **tail-acl:** add external-tailnet commands ([#438](https://github.com/rshade/tail-acl/issues/438)) ([3bf3c13](https://github.com/rshade/tail-acl/commit/3bf3c1346205f1d72a433f3b97d8e3a01f8b2fc5)), closes [#276](https://github.com/rshade/tail-acl/issues/276)
* **tail-acl:** advise on shared via site IDs ([#440](https://github.com/rshade/tail-acl/issues/440)) ([527f414](https://github.com/rshade/tail-acl/commit/527f414515cd9def1ffe229fccccadcf80e4ff8e)), closes [#228](https://github.com/rshade/tail-acl/issues/228)
* **tail-acl:** count externalTailnets allow-list uses ([#434](https://github.com/rshade/tail-acl/issues/434)) ([28d9f73](https://github.com/rshade/tail-acl/commit/28d9f73b1ecf45189fcc8a3c39e596d5cc1b97fa)), closes [#275](https://github.com/rshade/tail-acl/issues/275)
* **tail-acl:** lint autoapprover-route-overlap ([#439](https://github.com/rshade/tail-acl/issues/439)) ([ee505a3](https://github.com/rshade/tail-acl/commit/ee505a3ed65870d3d55e56d48810cf87ff3fc905)), closes [#227](https://github.com/rshade/tail-acl/issues/227)
* **tail-acl:** lint invalid ipset members ([#441](https://github.com/rshade/tail-acl/issues/441)) ([4117a50](https://github.com/rshade/tail-acl/commit/4117a50c68841e7396eccec3f6e1dfd237c91015)), closes [#373](https://github.com/rshade/tail-acl/issues/373)
* **tail-acl:** lint unknown external tailnet aliases ([#435](https://github.com/rshade/tail-acl/issues/435)) ([de4049a](https://github.com/rshade/tail-acl/commit/de4049a6254a28bb4297764341513c3cba0b7d1e))
* **tail-acl:** warn when grant sharing is closed ([#436](https://github.com/rshade/tail-acl/issues/436)) ([220668a](https://github.com/rshade/tail-acl/commit/220668a2a688fd2b25ac55990f850d1ed4cc836e)), closes [#279](https://github.com/rshade/tail-acl/issues/279)


### Bug Fixes

* **ci:** approve every parked run on the release PR ([7b3c164](https://github.com/rshade/tail-acl/commit/7b3c164aa88e6898be6bf6cdb43b799e84dd139d))
* **ci:** drop the release-please component from the branch name ([ff48f39](https://github.com/rshade/tail-acl/commit/ff48f39bdb7a1b36c77a70ddeb8232f420691710))
* **ci:** gate live-verify on main behind a protected environment ([d0b05fe](https://github.com/rshade/tail-acl/commit/d0b05feb0ab5d773527b3f963fe2d02473917718))
* **deps:** update module tailscale.com to v1.104.2 ([#418](https://github.com/rshade/tail-acl/issues/418)) ([3a28f06](https://github.com/rshade/tail-acl/commit/3a28f0692929c2e3df031d602c7ee77a934f70ff))
* **deps:** update module tailscale.com to v1.104.4 ([#454](https://github.com/rshade/tail-acl/issues/454)) ([7711883](https://github.com/rshade/tail-acl/commit/771188387134bd3bb791a9cccbcd4f96cd4c6eba))
* **deps:** update module tailscale.com/client/tailscale/v2 to v2.12.0 ([#426](https://github.com/rshade/tail-acl/issues/426)) ([04b9382](https://github.com/rshade/tail-acl/commit/04b9382335ea3b8288800e3529f70d10b7d2071c))
* **policycore:** reject non-literal host aliases ([#459](https://github.com/rshade/tail-acl/issues/459)) ([7d723ab](https://github.com/rshade/tail-acl/commit/7d723abd36b86a20e0042db5d03b3618687af690)), closes [#374](https://github.com/rshade/tail-acl/issues/374)
* **tail-acl:** sanitize names in mutation messages ([#455](https://github.com/rshade/tail-acl/issues/455)) ([aa1d2e0](https://github.com/rshade/tail-acl/commit/aa1d2e04650199e3b38e4159be7a0e0a7b50d8a4)), closes [#451](https://github.com/rshade/tail-acl/issues/451)

## 0.3.0 (2026-10-22)


### ⚠ BREAKING CHANGES

* **policycore:** `Matcher.Policy` is now `*policycore.Policy`, a container embedding `*tailscale.ACL` alongside the policy fields the pinned SDK does not model. `policycore` is not enrolled in release-please and carries no tag, so no released version is stranded; both in-repo consumers are updated here and leave `HaveExternalTailnets` false until their loaders land.

### Features

* add tail-ipam module and sanitize output levels
* **policycore:** resolve cross-tailnet selectors
* **tail-acl:** accept every ipset member form in ipset add
* **tail-acl:** authenticate with scoped OAuth credentials
* **tail-acl:** evaluate posture locally in test and check
* **tail-acl:** lint posture references and unused postures
* **tail-acl:** nodeattr authoring and reference-walk fix
* **tail-acl:** validate posture expressions offline


### Bug Fixes

* **deps:** update go4.org/netipx digest to 3075585
* **deps:** update module github.com/jaxxstorm/tscli to v0.10.0
* **deps:** update module golang.org/x/oauth2 to v0.37.0
* **deps:** update module golang.org/x/term to v0.46.0
* **deps:** update module golang.org/x/term to v0.47.0
* **deps:** update module tailscale.com to v1.102.3
* **deps:** update module tailscale.com to v1.102.4
* **deps:** update module tailscale.com to v1.102.5
* **deps:** update module tailscale.com/client/tailscale/v2 to v2.11.0
* **policycore:** resolve ipset ops, ranges, and host: refs
* **tail-acl:** honor defaultSrcPosture in local evaluation
* **tailnet-audit:** sweep ACL port hosts from sanitized prose

## 0.2.0 (2026-08-12)


### ⚠ BREAKING CHANGES

* **tail-acl:** when `-severity` is explicitly set, `lint` filters the findings shown in human output and uses that value as the failure threshold. When the flag is omitted, lint shows all findings and fails on `warn` or `error`. JSON output always retains the complete `findings` array; `lint_summary` counts the whole policy and `lint_severity_threshold` records the resolved threshold. Pass `-severity advice` to show all findings and make advice findings fail the run.

### Features

* **tail-acl:** -severity filters findings, not just exit code
* **tail-acl:** add normalize command emitting standard JSON
* **tail-acl:** auto-approver add / remove
* **tail-acl:** check SCIM group sync and subdomain scope
* **tail-acl:** colorize human lint output
* **tail-acl:** embedded jq query engine
* **tail-acl:** recognize svc: services, add online check
* **tail-acl:** report all unknown policy keys at once
* **tail-acl:** typed group, ipset, and ssh authoring


### Bug Fixes

* codex review fixes
* **scripts:** stop sanitize-policy leaking host names
* **tail-acl:** exempt SCIM groups from undefined-reference
* **tail-acl:** lint shows all findings unless -severity is set

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
