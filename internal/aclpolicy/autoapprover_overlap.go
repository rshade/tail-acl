package aclpolicy

import (
	"fmt"
	"maps"
	"slices"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tail-acl/pkg/policycore/addrspace"
)

func lintAutoApproverRouteOverlap(policy *tailscale.ACL) []LintFinding {
	if policy == nil || policy.AutoApprovers == nil || len(policy.AutoApprovers.Routes) < 2 {
		return nil
	}
	keys := slices.Sorted(maps.Keys(policy.AutoApprovers.Routes))
	var findings []LintFinding
	for left := range keys {
		for right := left + 1; right < len(keys); right++ {
			if finding, ok := autoApproverRouteOverlapFinding(keys[left], keys[right]); ok {
				findings = append(findings, finding)
			}
		}
	}
	return findings
}

func autoApproverRouteOverlapFinding(left, right string) (LintFinding, bool) {
	if addrspace.IsViaPrefix(left) && addrspace.IsViaPrefix(right) {
		return LintFinding{}, false
	}
	leftCIDR, leftErr := NormalizeAutoApproverRoute(left)
	rightCIDR, rightErr := NormalizeAutoApproverRoute(right)
	if leftErr != nil || rightErr != nil {
		return LintFinding{}, false
	}
	if leftCIDR == rightCIDR {
		return routeOverlapFinding(left, right, leftCIDR, true), true
	}
	overlaps, err := addrspace.Overlaps(leftCIDR, rightCIDR)
	if err != nil || !overlaps {
		return LintFinding{}, false
	}
	return routeOverlapFinding(left, right, leftCIDR+" overlaps "+rightCIDR, false), true
}

func routeOverlapFinding(left, right, value string, same bool) LintFinding {
	evidence := fmt.Sprintf("routes %q and %q overlap", left, right)
	if same {
		evidence = fmt.Sprintf("routes %q and %q mask to the same CIDR %s", left, right, value)
	}
	return LintFinding{
		ID:       LintAutoApproverRouteOverlap,
		Severity: LintWarn,
		Rule:     fmt.Sprintf("autoApprovers.routes[%s], autoApprovers.routes[%s]", left, right),
		Value:    value,
		Evidence: evidence,
		Remediation: "keep a single autoApprovers.routes entry for the shared address space, " +
			"or narrow the prefixes so they do not overlap",
		Trace: []string{
			fmt.Sprintf("autoApprovers.routes[%s]", left),
			fmt.Sprintf("autoApprovers.routes[%s]", right),
			evidence,
		},
	}
}
