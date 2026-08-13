module github.com/rshade/tailscale-utils/tail-acl

go 1.26.5

require (
	github.com/hexops/gotextdiff v1.0.3
	github.com/itchyny/gojq v0.12.19
	github.com/rshade/tailscale-utils/policycore v0.0.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	tailscale.com v1.102.2
	tailscale.com/client/tailscale/v2 v2.10.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/itchyny/timefmt-go v0.1.8 // indirect
)

replace github.com/rshade/tailscale-utils/policycore => ../policycore
