package integration_test

import (
	"errors"
	"fmt"
	"net/url"

	tailscale "tailscale.com/client/tailscale/v2"

	"github.com/rshade/tsacl/internal/tailapi"
)

// errShape describes an error by type and HTTP status only. Live tests run
// against a real tailnet and `go test -v` output lands in Actions logs, so an
// error's own text must not be printed: it can carry the request URL (which
// embeds the tailnet name), a service name, or another user's login.
func errShape(err error) string {
	if err == nil {
		return "<nil>"
	}
	if apiErr, ok := errors.AsType[tailscale.APIError](err); ok {
		return fmt.Sprintf("tailscale.APIError status=%d", apiErr.Status)
	}
	if validationErr, ok := errors.AsType[*tailapi.ValidationError](err); ok {
		return fmt.Sprintf("*tailapi.ValidationError status=%d details=%d",
			validationErr.Status, len(validationErr.Data))
	}
	if unavailable, ok := errors.AsType[*tailapi.ValidationUnavailableError](err); ok {
		return fmt.Sprintf("*tailapi.ValidationUnavailableError status=%d", unavailable.Status)
	}
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		return fmt.Sprintf("transport error op=%s", urlErr.Op)
	}
	return fmt.Sprintf("%T", err)
}
