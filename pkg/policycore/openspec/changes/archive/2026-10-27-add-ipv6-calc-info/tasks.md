# Tasks: add-ipv6-calc-info

## 1. IPv6 block-fact calculation

- [x] 1.1 Extend `Info` to derive IPv6 network, top address, usable range,
      and exact `*big.Int` count while retaining IPv4 behavior; verify with
      `cd policycore && go test ./ipcalc`.
- [x] 1.2 Replace IPv6-rejection coverage with table-driven `/48`, `/64`,
      `/127`, `/128`, and host-bit-masking cases that assert absent broadcast
      and exact counts; verify `cd policycore && go test ./...` passes.

## 2. Specification validation

- [x] 2.1 Validate the change artifacts and implementation together with
      `cd policycore && openspec validate add-ipv6-calc-info && go test ./...`.
