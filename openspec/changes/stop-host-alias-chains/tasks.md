# Tasks

## 1. Reject a non-address in host set

- [x] 1.1 Validate the ADDRESS with `ParsePrefix` or `ParseAddr` before
  writing. Exit 2 and name the value as not an address, including the
  `ParseAddr` error.
- [x] 1.2 Keep `res.Edited` as the hostname plus the selector on the
  success and no-change paths.
- [x] 1.3 Test `host set a b` and `host set gw tag:web` (exit 2, file
  unchanged) and `host set web 100.64.0.10` and `host set web 10.1.0.0/16`
  (written).

## 2. Lint both rejected shapes

- [x] 2.1 Add a `host-not-address` case for `a` -> `b` -> `10.10.20.1`
  beside the existing tag case. Severity stays error.
