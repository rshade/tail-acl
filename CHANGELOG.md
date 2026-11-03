# Changelog

## [0.5.0](https://github.com/rshade/tsacl/compare/v0.4.0...v0.5.0) (2026-11-03)


### ⚠ BREAKING CHANGES

* the pkg/policycore/alpha package is removed, including AlphaHint, Stage, Feature, Registry, RepositoryFeatures, and VerifierRegistry. ExternalSelector and its parse functions now live in pkg/policycore.
* **policycore:** `Matcher.Policy` is now `*policycore.Policy`, a container embedding `*tailscale.ACL` alongside the policy fields the pinned SDK does not model. `policycore` is not enrolled in release-please and carries no tag, so no released version is stranded; both in-repo consumers are updated here and leave `HaveExternalTailnets` false until their loaders land.
* **tail-acl:** `lint` no longer reports findings below `-severity`. At the default `warn` threshold the JSON `findings` array omits the `info` and `advice` entries it previously carried, and the human output omits their lines. `lint_summary` still counts the whole policy and the new `lint_severity_threshold` field records the threshold that filtered the array, so a consumer can detect the filter; pass `-severity advice` to restore the previous contents.
* **tail-acl:** stop /acl/validate false passes and false failures ([#65](https://github.com/rshade/tsacl/issues/65))
* **policycore,tail-acl:** `test` previously exited 0 when an unparseable rule lay on an assertion's evaluation path, treating it as unable to match and passing the deny. It now exits 10 by default; set `--indeterminate=ignore` to keep the old exit code for one release while the policy is repaired. In the same situation `check` previously reported `access: "deny"` with exit 1 and now reports `access: "indeterminate"` with exit 10, omitting the legacy `allowed` field rather than serializing false. There is deliberately no opt-out for `check`, whose three-state verdict is its product. Separately, SCTP joining TCP and UDP as port-carrying widens the protocol-agnostic default, so a capability such as `sctp:5432` that previously answered no port question now answers it: `check` flips from not reachable to reachable, an `accept` assertion over it from fail to pass, and a `deny` assertion from pass to fail.
* **tail-acl:** `test` previously exited 0 when an unparseable rule lay on an assertion's evaluation path, treating it as unable to match and passing the deny. It now exits 10 by default; set `--indeterminate=ignore` to keep the old exit code for one release while the policy is repaired. In the same situation `check` previously reported `access: "deny"` with exit 1 and now reports `access: "indeterminate"` with exit 10, omitting the legacy `allowed` field rather than serializing false. There is deliberately no opt-out for `check`, whose three-state verdict is its product.

### Features

* add grant-dst-widespread live-fleet breadth check ([#105](https://github.com/rshade/tsacl/issues/105)) ([6ad5b55](https://github.com/rshade/tsacl/commit/6ad5b557e14c0722069422c0fb55d7f91eb653f8)), closes [#101](https://github.com/rshade/tsacl/issues/101) [#102](https://github.com/rshade/tsacl/issues/102) [#54](https://github.com/rshade/tsacl/issues/54)
* add live audit report scripts and tail-acl init ([#113](https://github.com/rshade/tsacl/issues/113)) ([8036b96](https://github.com/rshade/tsacl/commit/8036b9636f67fb4b92205bf6792d53893b8a175a))
* add policy advisories and retained report workflows ([#103](https://github.com/rshade/tsacl/issues/103)) ([3f213ee](https://github.com/rshade/tsacl/commit/3f213ee5e1d7de3ca7a48257741bd469debe482a)), closes [#101](https://github.com/rshade/tsacl/issues/101) [#102](https://github.com/rshade/tsacl/issues/102)
* add tail-ipam module and sanitize output levels ([#229](https://github.com/rshade/tsacl/issues/229)) ([b947dae](https://github.com/rshade/tsacl/commit/b947daede86dd9c0de305f4b416d7fb5ce7716cf)), closes [#224](https://github.com/rshade/tsacl/issues/224)
* **policycore:** 4via6 site-ID derivation primitive ([#239](https://github.com/rshade/tsacl/issues/239)) ([0b333df](https://github.com/rshade/tsacl/commit/0b333df461b33dfe3fbcc56dca5c06c868a35cff))
* **policycore:** add addrspace CIDR-overlap primitive ([#231](https://github.com/rshade/tsacl/issues/231)) ([9245e5f](https://github.com/rshade/tsacl/commit/9245e5f5119f7dce8c96d847d8e9a1d995bbcc3f)), closes [#225](https://github.com/rshade/tsacl/issues/225)
* **policycore:** add alpha subpackage for unreleased features ([#291](https://github.com/rshade/tsacl/issues/291)) ([fd29570](https://github.com/rshade/tsacl/commit/fd29570cd95a595e9bf797fc0d5c90645af7bb7f)), closes [#271](https://github.com/rshade/tsacl/issues/271)
* **policycore:** add ipset member grammar ([#364](https://github.com/rshade/tsacl/issues/364)) ([fd9a538](https://github.com/rshade/tsacl/commit/fd9a538e06726e2273594edd10046e83d1c7fe1f)), closes [#346](https://github.com/rshade/tsacl/issues/346)
* **policycore:** add live-verify tier for alpha features ([#292](https://github.com/rshade/tsacl/issues/292)) ([fd48f47](https://github.com/rshade/tsacl/commit/fd48f477aec5c0851c81641459b80e28c754c454)), closes [#272](https://github.com/rshade/tsacl/issues/272)
* **policycore:** model declarative node-sharing types ([#308](https://github.com/rshade/tsacl/issues/308)) ([335569b](https://github.com/rshade/tsacl/commit/335569b4eafc743a69ce3c38b4120b7e7848adb7))
* **policycore:** posture expressions and effective src posture ([#407](https://github.com/rshade/tsacl/issues/407)) ([9afd36d](https://github.com/rshade/tsacl/commit/9afd36d6cddbac8f94250f9bf42d61bac8d8f606))
* **policycore:** resolve cross-tailnet selectors ([#335](https://github.com/rshade/tsacl/issues/335)) ([f673ad5](https://github.com/rshade/tsacl/commit/f673ad554ff033b27aede2671cb2109ffdee5761)), closes [#274](https://github.com/rshade/tsacl/issues/274)
* **policycore:** three-state resolution for roster-bearing matchers ([732b3c5](https://github.com/rshade/tsacl/commit/732b3c523d9f0b6c56a43dd3637684caa8425227)), closes [#50](https://github.com/rshade/tsacl/issues/50)
* replace the alpha package with a neutral selector API ([#46](https://github.com/rshade/tsacl/issues/46)) ([69853e8](https://github.com/rshade/tsacl/commit/69853e8e27efe9e8b881dd512e628f3a52b7b2c1))
* **repo:** adopt OpenSpec across all modules ([#316](https://github.com/rshade/tsacl/issues/316)) ([005051c](https://github.com/rshade/tsacl/commit/005051c7838116b14991a7390b67cf36b942ab43))
* **tail-acl:** -severity filters findings, not just exit code ([92e8d10](https://github.com/rshade/tsacl/commit/92e8d100ab0f62f767ebdc56746cf1b408bc25f5))
* **tail-acl:** accept every ipset member form in ipset add ([#365](https://github.com/rshade/tsacl/issues/365)) ([d6ef1b3](https://github.com/rshade/tsacl/commit/d6ef1b3bcf69f0c85d1c67fa5520002a120c7916)), closes [#346](https://github.com/rshade/tsacl/issues/346)
* **tail-acl:** add --comment to typed authoring commands ([#61](https://github.com/rshade/tsacl/issues/61)) ([e9791ec](https://github.com/rshade/tsacl/commit/e9791ec862f23562442aa39d898db0505522e974))
* **tail-acl:** add --roster to resolve role autogroups from a login-to-role file ([#97](https://github.com/rshade/tsacl/issues/97)) ([56eb470](https://github.com/rshade/tsacl/commit/56eb4702b49a21dd395556c2b37c3aa30411e18f)), closes [#62](https://github.com/rshade/tsacl/issues/62)
* **tail-acl:** add check subcommand for local reachability queries ([1d634e1](https://github.com/rshade/tsacl/commit/1d634e10581b15bbaa257319f7cd38f65c556f12)), closes [#16](https://github.com/rshade/tsacl/issues/16)
* **tail-acl:** add external-tailnet commands ([#438](https://github.com/rshade/tsacl/issues/438)) ([3bf3c13](https://github.com/rshade/tsacl/commit/3bf3c1346205f1d72a433f3b97d8e3a01f8b2fc5)), closes [#276](https://github.com/rshade/tsacl/issues/276)
* **tail-acl:** add lint subcommand for static policy hygiene ([17c3a64](https://github.com/rshade/tsacl/commit/17c3a64164a48ac426be21312f3c3a9978f2104e)), closes [#17](https://github.com/rshade/tsacl/issues/17)
* **tail-acl:** add normalize command emitting standard JSON ([#173](https://github.com/rshade/tsacl/issues/173)) ([ff27d7b](https://github.com/rshade/tsacl/commit/ff27d7b5829d1c99ffad00b60509da6160df07f3)), closes [#168](https://github.com/rshade/tsacl/issues/168)
* **tail-acl:** add posture authoring commands ([d326334](https://github.com/rshade/tsacl/commit/d3263345d273b6810edf55517a18a996c68755af)), closes [#20](https://github.com/rshade/tsacl/issues/20)
* **tail-acl:** add test subcommand with local policy assertion evaluator ([925f5a3](https://github.com/rshade/tsacl/commit/925f5a3ef3e7b8722c4553f748bb355d03666165)), closes [#14](https://github.com/rshade/tsacl/issues/14)
* **tail-acl:** advise on shared via site IDs ([#440](https://github.com/rshade/tsacl/issues/440)) ([527f414](https://github.com/rshade/tsacl/commit/527f414515cd9def1ffe229fccccadcf80e4ff8e)), closes [#228](https://github.com/rshade/tsacl/issues/228)
* **tail-acl:** authenticate with scoped OAuth credentials ([#199](https://github.com/rshade/tsacl/issues/199)) ([43ff822](https://github.com/rshade/tsacl/commit/43ff82287f2673d9fb981f503ad486b6eeb3a2a0)), closes [#126](https://github.com/rshade/tsacl/issues/126)
* **tail-acl:** author policy test assertions with test add and test remove ([#98](https://github.com/rshade/tsacl/issues/98)) ([44736bd](https://github.com/rshade/tsacl/commit/44736bd3f215efd2069143f263f4d25e55b0c857)), closes [#55](https://github.com/rshade/tsacl/issues/55)
* **tail-acl:** auto-approver add / remove ([#176](https://github.com/rshade/tsacl/issues/176)) ([7492559](https://github.com/rshade/tsacl/commit/7492559dc072f71ab68e7a454e46c71fc52e5a0e)), closes [#122](https://github.com/rshade/tsacl/issues/122)
* **tail-acl:** check SCIM group sync and subdomain scope ([0e0573f](https://github.com/rshade/tsacl/commit/0e0573f71ebfdf3f67eaf25fd11ba3644fb8fe4d))
* **tail-acl:** colorize human lint output ([33f03aa](https://github.com/rshade/tsacl/commit/33f03aa8db74762e422e1856b32fb76f658b2e05))
* **tail-acl:** count externalTailnets allow-list uses ([#434](https://github.com/rshade/tsacl/issues/434)) ([28d9f73](https://github.com/rshade/tsacl/commit/28d9f73b1ecf45189fcc8a3c39e596d5cc1b97fa)), closes [#275](https://github.com/rshade/tsacl/issues/275)
* **tail-acl:** embedded jq query engine ([#174](https://github.com/rshade/tsacl/issues/174)) ([2162f9c](https://github.com/rshade/tsacl/commit/2162f9c475015a8ca3a8217d5b99c38475aca96b)), closes [#169](https://github.com/rshade/tsacl/issues/169)
* **tail-acl:** evaluate posture locally in test and check ([#416](https://github.com/rshade/tsacl/issues/416)) ([691a434](https://github.com/rshade/tsacl/commit/691a43460345b33dbd2e34aa1bc1f20974e05bc8))
* **tail-acl:** lint autoapprover-route-overlap ([#439](https://github.com/rshade/tsacl/issues/439)) ([ee505a3](https://github.com/rshade/tsacl/commit/ee505a3ed65870d3d55e56d48810cf87ff3fc905)), closes [#227](https://github.com/rshade/tsacl/issues/227)
* **tail-acl:** lint invalid ipset members ([#441](https://github.com/rshade/tsacl/issues/441)) ([4117a50](https://github.com/rshade/tsacl/commit/4117a50c68841e7396eccec3f6e1dfd237c91015)), closes [#373](https://github.com/rshade/tsacl/issues/373)
* **tail-acl:** lint posture references and unused postures ([#409](https://github.com/rshade/tsacl/issues/409)) ([0f9237d](https://github.com/rshade/tsacl/commit/0f9237d33507e7fe01609b9adf3579197caab9fa))
* **tail-acl:** lint unknown external tailnet aliases ([#435](https://github.com/rshade/tsacl/issues/435)) ([de4049a](https://github.com/rshade/tsacl/commit/de4049a6254a28bb4297764341513c3cba0b7d1e))
* **tail-acl:** nodeattr authoring and reference-walk fix ([#205](https://github.com/rshade/tsacl/issues/205)) ([0bdab43](https://github.com/rshade/tsacl/commit/0bdab4301c9e39747ae47db8d6ac0e64d8c209f3)), closes [#201](https://github.com/rshade/tsacl/issues/201) [#202](https://github.com/rshade/tsacl/issues/202)
* **tail-acl:** opt-in server validation for test --watch ([#106](https://github.com/rshade/tsacl/issues/106)) ([57ca233](https://github.com/rshade/tsacl/commit/57ca2333c95f1f751c64e40e9ea9d374b7832e11)), closes [#104](https://github.com/rshade/tsacl/issues/104)
* **tail-acl:** pull the deployed policy and fix portless grants dst linting ([#93](https://github.com/rshade/tsacl/issues/93)) ([ca8928a](https://github.com/rshade/tsacl/commit/ca8928acc7d32f4da5236a696fbbb3d9001ff831)), closes [#91](https://github.com/rshade/tsacl/issues/91) [#92](https://github.com/rshade/tsacl/issues/92)
* **tail-acl:** re-run the test suite on change with test --watch ([#87](https://github.com/rshade/tsacl/issues/87)) ([d725b1e](https://github.com/rshade/tsacl/commit/d725b1e6f1d61be6b285adf9dc6ed0da69bd7095)), closes [#56](https://github.com/rshade/tsacl/issues/56)
* **tail-acl:** recognize svc: services, add online check ([c52c28a](https://github.com/rshade/tsacl/commit/c52c28af4ffde85950e6cc1fae0db18044f2eff1))
* **tail-acl:** report all unknown policy keys at once ([#191](https://github.com/rshade/tsacl/issues/191)) ([14ca85a](https://github.com/rshade/tsacl/commit/14ca85a574ecc6b073da83a0bdf710602640f334)), closes [#170](https://github.com/rshade/tsacl/issues/170)
* **tail-acl:** typed group, ipset, and ssh authoring ([#197](https://github.com/rshade/tsacl/issues/197)) ([8590066](https://github.com/rshade/tsacl/commit/859006679b271e3b2c82f4ec8f9feb865cb42797)), closes [#124](https://github.com/rshade/tsacl/issues/124) [#123](https://github.com/rshade/tsacl/issues/123)
* **tail-acl:** validate posture expressions offline ([#410](https://github.com/rshade/tsacl/issues/410)) ([960b320](https://github.com/rshade/tsacl/commit/960b320903b1adef71ee346aa2dafb33bd12f9bc))
* **tail-acl:** warn when grant sharing is closed ([#436](https://github.com/rshade/tsacl/issues/436)) ([220668a](https://github.com/rshade/tsacl/commit/220668a2a688fd2b25ac55990f850d1ed4cc836e)), closes [#279](https://github.com/rshade/tsacl/issues/279)
* **tail-ipam:** add calc info block-facts subcommand ([#300](https://github.com/rshade/tsacl/issues/300)) ([135c337](https://github.com/rshade/tsacl/commit/135c3376f1d98ee474c48d4ab654ba8b0e88fd15)), closes [#250](https://github.com/rshade/tsacl/issues/250)
* **tail-ipam:** add IPv4 CIDR aggregation ([efd7ceb](https://github.com/rshade/tsacl/commit/efd7cebbcf5c12e6454ff047f13bf3eddaa82c1b)), closes [#252](https://github.com/rshade/tsacl/issues/252)
* **tail-ipam:** add IPv4 CIDR aggregation ([#328](https://github.com/rshade/tsacl/issues/328)) ([efd7ceb](https://github.com/rshade/tsacl/commit/efd7cebbcf5c12e6454ff047f13bf3eddaa82c1b))
* **tail-ipam:** add IPv4 next-free allocation ([#326](https://github.com/rshade/tsacl/issues/326)) ([9f892a0](https://github.com/rshade/tsacl/commit/9f892a0d559d160c67abec120682245d803e8d9e)), closes [#256](https://github.com/rshade/tsacl/issues/256)
* **tail-ipam:** add IPv6 calc info ([#327](https://github.com/rshade/tsacl/issues/327)) ([2abd8d3](https://github.com/rshade/tsacl/commit/2abd8d34d85b605403459d60c11e3f57e65cccc7)), closes [#251](https://github.com/rshade/tsacl/issues/251)
* **tail-ipam:** calc split for IPv4 subnet division ([#259](https://github.com/rshade/tsacl/issues/259)) ([8d946db](https://github.com/rshade/tsacl/commit/8d946dbff1401a5b8f2e922efbba9d715ae9130f)), closes [#248](https://github.com/rshade/tsacl/issues/248)
* **tail-ipam:** extend calc aggregate to IPv6 ([#332](https://github.com/rshade/tsacl/issues/332)) ([86cf58b](https://github.com/rshade/tsacl/commit/86cf58b251805c384addf344dd01ecf2747ffff8)), closes [#253](https://github.com/rshade/tsacl/issues/253)
* **tail-ipam:** extend calc next-free to IPv6 ([#334](https://github.com/rshade/tsacl/issues/334)) ([9db4c80](https://github.com/rshade/tsacl/commit/9db4c80711dd8fa55c39cf8d0fd2c991616c08cd))
* **tail-ipam:** extend calc split to IPv6 ([#269](https://github.com/rshade/tsacl/issues/269)) ([92c010a](https://github.com/rshade/tsacl/commit/92c010a8c16fb54221a6bdfd928dd8f66da4e339)), closes [#249](https://github.com/rshade/tsacl/issues/249) [#261](https://github.com/rshade/tsacl/issues/261)
* **tailnet-audit:** add acl-coverage-gap check with shared policycore module ([991cf39](https://github.com/rshade/tsacl/commit/991cf39a267df274b0118c8afb94704fcbcd88c0)), closes [#29](https://github.com/rshade/tsacl/issues/29)
* **tailnet-audit:** add dns-hygiene check and DNS collector expansion ([c23449d](https://github.com/rshade/tsacl/commit/c23449daf0635bd295317bba21985472ce0dc838)), closes [#31](https://github.com/rshade/tsacl/issues/31)
* **tailnet-audit:** add read-only control-plane hygiene classifier ([1d788fb](https://github.com/rshade/tsacl/commit/1d788fb19f7a800110fb46e3044684aadd71c4ef)), closes [#15](https://github.com/rshade/tsacl/issues/15)
* **tailnet-audit:** pin OpenAPI contract and property gaps ([#158](https://github.com/rshade/tsacl/issues/158)) ([ef90178](https://github.com/rshade/tsacl/commit/ef901781600f882c8f574616b854c0d3aa2149bb)), closes [#130](https://github.com/rshade/tsacl/issues/130) [#155](https://github.com/rshade/tsacl/issues/155) [#156](https://github.com/rshade/tsacl/issues/156)
* **tailnet-audit:** resolve role autogroups in acl-coverage-gap ([#37](https://github.com/rshade/tsacl/issues/37)) ([bb0a92c](https://github.com/rshade/tsacl/commit/bb0a92c78547cf0e5c1112fe597492fa40173f2d))


### Bug Fixes

* **ci:** approve every parked run on the release PR ([7b3c164](https://github.com/rshade/tsacl/commit/7b3c164aa88e6898be6bf6cdb43b799e84dd139d))
* **ci:** drop the release-please component from the branch name ([ff48f39](https://github.com/rshade/tsacl/commit/ff48f39bdb7a1b36c77a70ddeb8232f420691710))
* **ci:** gate live-verify on main behind a protected environment ([d0b05fe](https://github.com/rshade/tsacl/commit/d0b05feb0ab5d773527b3f963fe2d02473917718))
* **ci:** keep release branches current ([#160](https://github.com/rshade/tsacl/issues/160)) ([b4f1f2b](https://github.com/rshade/tsacl/commit/b4f1f2bccd56b1f51bd743665223aea7c645959d))
* **cli:** enforce ASCII-safe stdout and print the audit verdict ([#159](https://github.com/rshade/tsacl/issues/159)) ([b017cea](https://github.com/rshade/tsacl/commit/b017cea5fa1adc85c8e2ce345dd49b28b13daf11)), closes [#132](https://github.com/rshade/tsacl/issues/132) [#140](https://github.com/rshade/tsacl/issues/140) [#143](https://github.com/rshade/tsacl/issues/143) [#144](https://github.com/rshade/tsacl/issues/144) [#142](https://github.com/rshade/tsacl/issues/142)
* codex review fixes ([edef20c](https://github.com/rshade/tsacl/commit/edef20cb3c2568152eb0eb95d9d89734f2441548))
* **deps:** update github.com/tailscale/hujson digest to b80ff77 ([#71](https://github.com/rshade/tsacl/issues/71)) ([fcf6bc6](https://github.com/rshade/tsacl/commit/fcf6bc608167310310f4e65a97d234fd64271f61))
* **deps:** update go4.org/netipx digest to 3075585 ([#389](https://github.com/rshade/tsacl/issues/389)) ([b22f21c](https://github.com/rshade/tsacl/commit/b22f21ca0c258a705de070816707dc793961781f))
* **deps:** update module github.com/itchyny/gojq to v0.12.20 ([0e4171e](https://github.com/rshade/tsacl/commit/0e4171e53552ddbf54e28bb238bb0d3217b5ecbf))
* **deps:** update module github.com/jaxxstorm/tscli to v0.10.0 ([#265](https://github.com/rshade/tsacl/issues/265)) ([d0cc76c](https://github.com/rshade/tsacl/commit/d0cc76c2cf8b1350ee52b753f705bfa9a2ce01cb))
* **deps:** update module github.com/jaxxstorm/tscli to v0.12.0 ([a1a68f1](https://github.com/rshade/tsacl/commit/a1a68f17a877cc844f713f6f149e4f748438189e))
* **deps:** update module golang.org/x/oauth2 to v0.37.0 ([#312](https://github.com/rshade/tsacl/issues/312)) ([378e23a](https://github.com/rshade/tsacl/commit/378e23abc9b84bc23d15f7b023613c0e7066339d))
* **deps:** update module golang.org/x/term to v0.46.0 ([#314](https://github.com/rshade/tsacl/issues/314)) ([bbcd93a](https://github.com/rshade/tsacl/commit/bbcd93aea4c8eca0729b04dc306cccac6018381a))
* **deps:** update module golang.org/x/term to v0.47.0 ([#425](https://github.com/rshade/tsacl/issues/425)) ([47bd06a](https://github.com/rshade/tsacl/commit/47bd06a856dba615ea0d992e2a7dfc7619f6e189))
* **deps:** update module tailscale.com to v1.102.2 ([#95](https://github.com/rshade/tsacl/issues/95)) ([8ee676f](https://github.com/rshade/tsacl/commit/8ee676fafb168bc1275a7988c5cc7f0627e26156))
* **deps:** update module tailscale.com to v1.102.3 ([#218](https://github.com/rshade/tsacl/issues/218)) ([fbeb22c](https://github.com/rshade/tsacl/commit/fbeb22c5cefc82cfc88bec9a89691ce173e27798))
* **deps:** update module tailscale.com to v1.102.4 ([#343](https://github.com/rshade/tsacl/issues/343)) ([ddf6247](https://github.com/rshade/tsacl/commit/ddf6247925be1fff60aa64e63c6d7d86e13a79c6))
* **deps:** update module tailscale.com to v1.102.5 ([#402](https://github.com/rshade/tsacl/issues/402)) ([c051d46](https://github.com/rshade/tsacl/commit/c051d461d6989082a9a60ab82e16b9d19b726d28))
* **deps:** update module tailscale.com to v1.104.2 ([#418](https://github.com/rshade/tsacl/issues/418)) ([3a28f06](https://github.com/rshade/tsacl/commit/3a28f0692929c2e3df031d602c7ee77a934f70ff))
* **deps:** update module tailscale.com to v1.104.4 ([#454](https://github.com/rshade/tsacl/issues/454)) ([7711883](https://github.com/rshade/tsacl/commit/771188387134bd3bb791a9cccbcd4f96cd4c6eba))
* **deps:** update module tailscale.com to v1.104.5 ([44a6ac8](https://github.com/rshade/tsacl/commit/44a6ac896d01e7932d85c5a2fa02cb52b094a1b0))
* **deps:** update module tailscale.com/client/tailscale/v2 to v2.11.0 ([#404](https://github.com/rshade/tsacl/issues/404)) ([69553a3](https://github.com/rshade/tsacl/commit/69553a337c4abfa5639212855807228e1291fb74))
* **deps:** update module tailscale.com/client/tailscale/v2 to v2.12.0 ([#426](https://github.com/rshade/tsacl/issues/426)) ([04b9382](https://github.com/rshade/tsacl/commit/04b9382335ea3b8288800e3529f70d10b7d2071c))
* lint issues ([e286c74](https://github.com/rshade/tsacl/commit/e286c7475fa17a2a0f8ad6d77d50c4700feed52d))
* **policycore,tail-acl:** never emit a deny the evaluator could not prove ([28eb6ea](https://github.com/rshade/tsacl/commit/28eb6ea2c3b84bb9f84b797d613941c0e794a0d7)), closes [#49](https://github.com/rshade/tsacl/issues/49) [#50](https://github.com/rshade/tsacl/issues/50)
* **policycore:** reject non-literal host aliases ([#459](https://github.com/rshade/tsacl/issues/459)) ([7d723ab](https://github.com/rshade/tsacl/commit/7d723abd36b86a20e0042db5d03b3618687af690)), closes [#374](https://github.com/rshade/tsacl/issues/374)
* **policycore:** resolve ipset ops, ranges, and host: refs ([#386](https://github.com/rshade/tsacl/issues/386)) ([c4b1ae9](https://github.com/rshade/tsacl/commit/c4b1ae9fc1998b1e47dfdde6233d0772ee64062d)), closes [#366](https://github.com/rshade/tsacl/issues/366)
* **scripts:** stop sanitize-policy leaking host names ([35dbf22](https://github.com/rshade/tsacl/commit/35dbf2258544d1df5ea9e4c83febb10ec0ab4000))
* **tail-acl:** add indeterminate verdict so check never guesses a deny ([7773dde](https://github.com/rshade/tsacl/commit/7773ddec7f63ad0b439c3119615db6bfe5cd9468)), closes [#16](https://github.com/rshade/tsacl/issues/16)
* **tail-acl:** exempt SCIM groups from undefined-reference ([0b0acd3](https://github.com/rshade/tsacl/commit/0b0acd32e228fa5e15a6c4b3cae815b6abe0de11))
* **tail-acl:** honor defaultSrcPosture in local evaluation ([#408](https://github.com/rshade/tsacl/issues/408)) ([7af0938](https://github.com/rshade/tsacl/commit/7af0938fe5e40e065ac389b7680e696bd4169678))
* **tail-acl:** lint shows all findings unless -severity is set ([#183](https://github.com/rshade/tsacl/issues/183)) ([9bfda67](https://github.com/rshade/tsacl/commit/9bfda678848ec69305c690ad0f5d1f7bc5b4dc84))
* **tail-acl:** load sshTests and ssh[].acceptEnv policy fields ([#58](https://github.com/rshade/tsacl/issues/58)) ([fd33b8d](https://github.com/rshade/tsacl/commit/fd33b8dcca53d902e545073e2405ae5f6b77603c)), closes [#47](https://github.com/rshade/tsacl/issues/47)
* **tail-acl:** never pass a deny assertion the evaluator could not prove ([1764d99](https://github.com/rshade/tsacl/commit/1764d99a5575ee02b38237c1d033c92f0de72032)), closes [#49](https://github.com/rshade/tsacl/issues/49)
* **tail-acl:** preserve HuJSON comments in typed edits ([#60](https://github.com/rshade/tsacl/issues/60)) ([c5fae7d](https://github.com/rshade/tsacl/commit/c5fae7d1c8736b69be32336b92c2d5bb04046fbd)), closes [#48](https://github.com/rshade/tsacl/issues/48)
* **tail-acl:** sanitize names in mutation messages ([#455](https://github.com/rshade/tsacl/issues/455)) ([aa1d2e0](https://github.com/rshade/tsacl/commit/aa1d2e04650199e3b38e4159be7a0e0a7b50d8a4)), closes [#451](https://github.com/rshade/tsacl/issues/451)
* **tail-acl:** stop /acl/validate false passes and false failures ([#65](https://github.com/rshade/tsacl/issues/65)) ([e4c0ad4](https://github.com/rshade/tsacl/commit/e4c0ad4e747272015f6f277a79412d9fd50dd385)), closes [#52](https://github.com/rshade/tsacl/issues/52)
* **tail-ipam:** harden registry load, reserve, and release paths ([#304](https://github.com/rshade/tsacl/issues/304)) ([a906b37](https://github.com/rshade/tsacl/commit/a906b377262e2a206699df58207f1b73c7b30bf9))
* **tailnet-audit:** sweep ACL port hosts from sanitized prose ([#303](https://github.com/rshade/tsacl/issues/303)) ([58999ea](https://github.com/rshade/tsacl/commit/58999eaace2b07b24651171569f6a09678737e28)), closes [#215](https://github.com/rshade/tsacl/issues/215)
* **tailnet-flow:** pseudonymize flow identities, no retention ([#309](https://github.com/rshade/tsacl/issues/309)) ([138662b](https://github.com/rshade/tsacl/commit/138662b90f4ffcc27f91e5a8fb2686863f616d7e)), closes [#207](https://github.com/rshade/tsacl/issues/207)

## [0.4.0](https://github.com/rshade/tail-acl/compare/v0.3.0...v0.4.0) (2026-11-03)


### Features

* **tail-acl:** add external-tailnet commands
* **tail-acl:** advise on shared via site IDs
* **tail-acl:** count externalTailnets allow-list uses
* **tail-acl:** lint autoapprover-route-overlap
* **tail-acl:** lint invalid ipset members
* **tail-acl:** lint unknown external tailnet aliases
* **tail-acl:** warn when grant sharing is closed


### Bug Fixes

* **ci:** approve every parked run on the release PR ([7b3c164](https://github.com/rshade/tail-acl/commit/7b3c164aa88e6898be6bf6cdb43b799e84dd139d))
* **ci:** drop the release-please component from the branch name ([ff48f39](https://github.com/rshade/tail-acl/commit/ff48f39bdb7a1b36c77a70ddeb8232f420691710))
* **ci:** gate live-verify on main behind a protected environment ([d0b05fe](https://github.com/rshade/tail-acl/commit/d0b05feb0ab5d773527b3f963fe2d02473917718))
* **deps:** update module tailscale.com to v1.104.2
* **deps:** update module tailscale.com to v1.104.4
* **deps:** update module tailscale.com/client/tailscale/v2 to v2.12.0
* **policycore:** reject non-literal host aliases
* **tail-acl:** sanitize names in mutation messages

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
