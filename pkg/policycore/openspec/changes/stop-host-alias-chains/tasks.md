# Tasks

## 1. Stop following host values

- [x] 1.1 Return a `Hosts` value unchanged from `expandAddressSelectorSeen`.
  Do not recurse. A literal is not looked up as another host name.
- [x] 1.2 Update `ExpandAddressSelector` tests: an alias chain returns the
  immediate value, a literal CIDR or IP is unchanged, and a cycle returns
  `["b"]`.

## 2. Report a non-literal host as undecidable

- [x] 2.1 Add a host materialization check next to `ipsetMaterializes` for
  `selectorResolvable` and `Recognized`.
- [x] 2.2 Test `MatchesTri` and `Recognized` for an alias chain, a tag
  value, and a literal host (match and miss).

## 3. Document the helper

- [x] 3.1 Correct the `ExpandAddressSelector` godoc and the public API note
  that still says a host alias is followed transitively.
