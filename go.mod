module github.com/rshade/tailscale-utils/tail-acl

go 1.26.5

require (
	github.com/hexops/gotextdiff v1.0.3
	github.com/rshade/tailscale-utils/policycore v0.0.0
	github.com/tailscale/hujson v0.0.0-20260302212456-ecc657c15afd
	tailscale.com v1.78.3
	tailscale.com/client/tailscale/v2 v2.10.1
)

require golang.org/x/oauth2 v0.34.0 // indirect

replace github.com/rshade/tailscale-utils/policycore => ../policycore
