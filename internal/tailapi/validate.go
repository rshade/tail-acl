package tailapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	tailscale "tailscale.com/client/tailscale/v2"
)

var errValidationResponseNull = errors.New("got JSON null")

// ValidationDetail preserves the structured diagnostics returned by
// /acl/validate. Warnings is owned here because the pinned v2 client's
// APIErrorData drops that documented field.
type ValidationDetail struct {
	User     string   `json:"user,omitempty"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// ValidationResult is the additive CLI-facing validation summary. Its slices
// are always initialized so JSON output distinguishes a completed clean
// validation from a command that never reached the validation endpoint.
type ValidationResult struct {
	Message  string             `json:"message,omitempty"`
	Failures []ValidationDetail `json:"failures"`
	Warnings []ValidationDetail `json:"warnings"`
}

// ValidationError is the typed control-plane rejection. Data retains the
// server's per-user errors and warnings so [errors.As] callers do not have to
// parse a formatted message.
type ValidationError struct {
	Status  int
	Message string
	Data    []ValidationDetail
}

// ValidationUnavailableError reports that the control plane never judged the
// policy: authentication, rate limiting, a server fault, a redirect away from
// the endpoint, or a transport failure answered instead of a verdict. It is
// deliberately a distinct type from [ValidationError] so no caller reports a
// policy as invalid on the strength of a request that never read it. Status is
// zero when no HTTP response arrived at all.
type ValidationUnavailableError struct {
	Status     int
	Message    string
	Err        error
	RetryAfter string
}

// ValidationIndeterminateError reports a response this client cannot prove
// clean. Two shapes reach it, and neither has been observed in a capture:
//
//   - Every detail carried warnings and no errors, yet the server also sent a
//     message. Reporting it valid would risk a false green on a rejection whose
//     reason lived only in the message; reporting it invalid would fail every
//     warning-bearing policy if the server routinely narrates warnings there.
//   - A detail carried neither errors nor warnings, so this client cannot read
//     what the server was reporting. The pinned v2 client already dropped one
//     documented per-detail field, so an unreadable entry is evidence the
//     response shape moved — not evidence the policy is bad.
//
// Callers report both as indeterminate rather than guessing which.
type ValidationIndeterminateError struct {
	Message    string
	Unreadable []ValidationDetail
}

func (err *ValidationError) Error() string {
	var details []string
	for _, detail := range err.Data {
		prefix := detail.User
		for _, message := range detail.Errors {
			details = append(details, validationDetailText(prefix, "error", message))
		}
		for _, message := range detail.Warnings {
			details = append(details, validationDetailText(prefix, "warning", message))
		}
		if len(detail.Errors) == 0 && len(detail.Warnings) == 0 && prefix != "" {
			details = append(details, "detail for "+prefix)
		}
	}

	message := err.Message
	if message == "" && len(details) != 0 {
		message = strings.Join(details, "; ")
	} else if len(details) != 0 {
		message += "; " + strings.Join(details, "; ")
	}
	if message == "" {
		message = statusFallbackText(err.Status,
			"server returned validation detail with no message or per-user text")
	}
	if err.Status != 0 && err.Status != http.StatusOK {
		return fmt.Sprintf("ACL validation failed: %s (HTTP %d)", message, err.Status)
	}
	return "ACL validation failed: " + message
}

// statusFallbackText names a failure that carried no text of its own.
// [http.StatusText] is only honest when the status is itself the reason:
// rendering an HTTP 200 rejection as "OK" would report the failure as a
// success, and status 0 means no response ever arrived to have one.
func statusFallbackText(status int, none string) string {
	if status == 0 || status == http.StatusOK {
		return none
	}
	if text := http.StatusText(status); text != "" {
		return text
	}
	return fmt.Sprintf("HTTP status %d", status)
}

func (err *ValidationUnavailableError) Error() string {
	message := err.Message
	if message == "" && err.Err != nil {
		message = err.Err.Error()
	}
	if message == "" {
		message = statusFallbackText(err.Status, "no response from the control plane")
	}
	// A transport failure never reached a status, so rendering one would invent
	// an answer the request never got.
	if err.Status == 0 {
		return "ACL validation unavailable: " + message
	}
	return fmt.Sprintf("ACL validation unavailable: %s (HTTP %d)", message, err.Status)
}

func (err *ValidationUnavailableError) Unwrap() error { return err.Err }

func (err *ValidationIndeterminateError) Error() string {
	if len(err.Unreadable) != 0 {
		return fmt.Sprintf(
			"ACL validation is indeterminate: the server sent detail for %s carrying neither "+
				"errors nor warnings, which this client cannot read as a verdict",
			strings.Join(unreadableDetailNames(err.Unreadable), ", "),
		)
	}
	return fmt.Sprintf(
		"ACL validation is indeterminate: the server returned warnings with no errors "+
			"alongside the message %q, which does not prove the policy valid",
		err.Message,
	)
}

// unreadableDetailNames labels each unreadable entry for the error text. An
// entry with no user is still counted, because dropping it would understate how
// much of the response this client could not read.
func unreadableDetailNames(details []ValidationDetail) []string {
	names := make([]string, 0, len(details))
	for _, detail := range details {
		if detail.User == "" {
			names = append(names, "an unnamed entry")
			continue
		}
		names = append(names, detail.User)
	}
	return names
}

// ValidationOutcome names what a validation error proves about the policy. It
// is the single place the three typed errors are triaged: callers that need an
// exit code, an envelope status, or a "did the server judge this at all"
// answer all switch on it, so adding a fourth outcome cannot silently keep the
// old answer at one of those sites.
type ValidationOutcome int

const (
	// ValidationNotAttempted means err is not about validation at all — a
	// missing file, a usage mistake, or a failure before the request was built.
	ValidationNotAttempted ValidationOutcome = iota
	// ValidationClean means the control plane judged the policy and found
	// nothing that blocks it. Warnings may still have been reported.
	ValidationClean
	// ValidationRejected means the control plane judged the policy and refused
	// it, with detail to back the refusal.
	ValidationRejected
	// ValidationIndeterminate means a response arrived that cannot be read as
	// either verdict, so reporting one would assert what was never observed.
	ValidationIndeterminate
	// ValidationUnavailable means the control plane never judged the policy.
	ValidationUnavailable
)

// ClassifyValidation triages a validation error into the outcome it proves.
func ClassifyValidation(err error) ValidationOutcome {
	var validationErr *ValidationError
	var unavailableErr *ValidationUnavailableError
	var indeterminateErr *ValidationIndeterminateError
	switch {
	case err == nil:
		return ValidationClean
	case errors.As(err, &indeterminateErr):
		return ValidationIndeterminate
	case errors.As(err, &unavailableErr):
		return ValidationUnavailable
	case errors.As(err, &validationErr):
		return ValidationRejected
	default:
		return ValidationNotAttempted
	}
}

// Judged reports whether the control plane actually reached this outcome, as
// opposed to a request that never produced one.
func (outcome ValidationOutcome) Judged() bool {
	return outcome == ValidationRejected || outcome == ValidationIndeterminate
}

func validationDetailText(user, kind, message string) string {
	if user == "" {
		return kind + ": " + message
	}
	return user + " " + kind + ": " + message
}

type validationResponse struct {
	Message string             `json:"message"`
	Data    []ValidationDetail `json:"data"`
}

// ValidatePolicy calls /acl/validate directly because PolicyFile().Validate
// cannot represent valid-with-warnings and discards warning text and typed data
// on HTTP 200. This implementation follows the documented protocol rather than
// copying Tailscale source; cmd/gitops-pusher's testNewACLs is corroborating
// evidence for checking both message and data.
func ValidatePolicy(
	ctx context.Context,
	client *tailscale.Client,
	raw []byte,
) (ValidationResult, error) {
	// Resource access triggers the client's own initialization. That preserves
	// its BaseURL, default tailnet, User-Agent, timeout, and auth-wrapped HTTP
	// client instead of reimplementing OAuth or identity federation here.
	_ = client.PolicyFile()

	endpoint := client.BaseURL.JoinPath(
		"/api/v2", "tailnet", url.PathEscape(client.Tailnet), "acl", "validate",
	)
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint.String(),
		bytes.NewReader(raw),
	)
	if err != nil {
		return newValidationResult(), fmt.Errorf("building ACL validation request: %w", err)
	}
	request.Header.Set("Content-Type", "application/hujson")
	if client.UserAgent != "" {
		request.Header.Set("User-Agent", client.UserAgent)
	}
	if client.APIKey != "" {
		request.SetBasicAuth(client.APIKey, "")
	}

	// A transport failure never reached the control plane, so it is a collection
	// failure rather than a verdict: typing it keeps an unreachable API from
	// exiting as "policy invalid".
	response, err := client.HTTP.Do(request)
	if err != nil {
		return newValidationResult(), &ValidationUnavailableError{
			Message: fmt.Sprintf("calling ACL validation endpoint: %v", err),
			Err:     err,
		}
	}
	defer response.Body.Close()
	// Go rewrites a 301, 302, or 303 POST into a GET and drops the body, so the
	// policy never reaches the redirect target. Whatever that target returns
	// describes some other resource, and an empty-looking answer would otherwise
	// classify as a clean validation the control plane never performed. A 307 or
	// 308 replays the method and body, so it is left alone.
	if final := methodRewrittenBy(request, response); final != "" {
		return newValidationResult(), &ValidationUnavailableError{
			Status: response.StatusCode,
			Message: "validation request was redirected to " + final +
				" as a GET, so the policy was never submitted",
		}
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return newValidationResult(), &ValidationUnavailableError{
			Status:  response.StatusCode,
			Message: fmt.Sprintf("reading ACL validation response: %v", err),
			Err:     err,
		}
	}
	result, classifyErr := classifyValidationResponse(response.StatusCode, body)
	var unavailable *ValidationUnavailableError
	if errors.As(classifyErr, &unavailable) {
		unavailable.RetryAfter = response.Header.Get("Retry-After")
	}
	return result, classifyErr
}

// methodRewrittenBy returns the final URL when a redirect changed the method
// away from the one sent — the case that silently discards the request body —
// and "" otherwise. The query and any userinfo are dropped so a redirect target
// carrying a token cannot reach the log through the error text.
func methodRewrittenBy(request *http.Request, response *http.Response) string {
	if response.Request == nil || response.Request.URL == nil {
		return ""
	}
	if response.Request.Method == request.Method {
		return ""
	}
	final := *response.Request.URL
	final.User = nil
	final.RawQuery = ""
	final.Fragment = ""
	return final.String()
}

func classifyValidationResponse(status int, body []byte) (ValidationResult, error) {
	if len(body) == 0 {
		result := newValidationResult()
		if status == http.StatusOK {
			return result, nil
		}
		return result, validationStatusError(status, validationResponse{})
	}

	// A body this client cannot decode carries no verdict, whatever the status
	// said. Typing it as unavailable rather than returning a bare error keeps an
	// HTML error page — the ordinary shape of a gateway 502 or an SSO-intercepted
	// 401 — from exiting as "policy invalid". Decoding into a pointer is what
	// separates a JSON object from `null`, an array, or a bare scalar: only an
	// object leaves it non-nil without erroring.
	var decoded *validationResponse
	if err := json.Unmarshal(body, &decoded); err != nil || decoded == nil {
		if err == nil {
			err = errValidationResponseNull
		}
		return newValidationResult(), validationDecodeUnavailable(status, err)
	}
	result := summarizeValidation(*decoded)
	if status != http.StatusOK {
		return result, validationStatusError(status, *decoded)
	}

	// Ordered most-provable first. The arms are disjoint by construction: an
	// entry is unreadable only when it carries neither field, so by the third
	// arm every entry that exists carries warnings and nothing else.
	unreadable := unreadableDetails(decoded.Data)
	switch {
	case detailsCarryErrors(decoded.Data):
		// A stated error is proof, so it outranks anything beside it.
		return result, &ValidationError{Status: status, Message: decoded.Message, Data: decoded.Data}
	case len(unreadable) != 0:
		return result, &ValidationIndeterminateError{Message: decoded.Message, Unreadable: unreadable}
	case decoded.Message == "":
		// Warnings at most, and the server said nothing else: clean.
		return result, nil
	case len(decoded.Data) != 0:
		// Warnings plus a message — the pairing no capture has settled.
		return result, &ValidationIndeterminateError{Message: decoded.Message}
	default:
		// A message with no detail at all: the captured parse-error shape, where
		// message is the failure channel in its own right.
		return result, &ValidationError{Status: status, Message: decoded.Message, Data: decoded.Data}
	}
}

func validationDecodeUnavailable(status int, err error) error {
	return &ValidationUnavailableError{
		Status:  status,
		Message: fmt.Sprintf("decoding ACL validation response: expected a JSON object: %v", err),
		Err:     err,
	}
}

// validationStatusError types a non-200 response as either a rejection the
// server reached or a request that never got that far. Every captured rejection
// arrives as HTTP 200 with a message — including the parse error in
// validate_d_parse_error.json — so 400 counts as a verdict only when it carries
// per-user detail to back one. A bare 400 is the generic "your request was
// wrong": this code always sends Content-Type: application/hujson, so a
// server-side tightening of content negotiation would arrive that way and must
// not print "your policy is invalid". Authentication, rate limiting, and the
// 5xx family mean the policy was never read, so calling it invalid would assert
// something the tool did not observe.
func validationStatusError(status int, decoded validationResponse) error {
	if status == http.StatusOK || (status == http.StatusBadRequest && len(decoded.Data) != 0) {
		return &ValidationError{Status: status, Message: decoded.Message, Data: decoded.Data}
	}
	return &ValidationUnavailableError{Status: status, Message: decoded.Message}
}

func newValidationResult() ValidationResult {
	return ValidationResult{
		Failures: []ValidationDetail{},
		Warnings: []ValidationDetail{},
	}
}

func summarizeValidation(response validationResponse) ValidationResult {
	result := newValidationResult()
	result.Message = response.Message
	for _, detail := range response.Data {
		if len(detail.Errors) != 0 {
			result.Failures = append(result.Failures, ValidationDetail{
				User:   detail.User,
				Errors: detail.Errors,
			})
		}
		if len(detail.Warnings) != 0 {
			result.Warnings = append(result.Warnings, ValidationDetail{
				User:     detail.User,
				Warnings: detail.Warnings,
			})
		}
	}
	return result
}

// unreadableDetails returns the entries carrying neither an error nor a
// warning. They are deliberately absent from [ValidationResult.Failures]: an
// entry with no error text is no evidence of one, and filing it as a failure
// would name an identity in the envelope with nothing to back the accusation.
// The verdict they produce is indeterminate, and the error text names them.
func unreadableDetails(details []ValidationDetail) []ValidationDetail {
	var unreadable []ValidationDetail
	for _, detail := range details {
		if len(detail.Errors) == 0 && len(detail.Warnings) == 0 {
			unreadable = append(unreadable, detail)
		}
	}
	return unreadable
}

func detailsCarryErrors(details []ValidationDetail) bool {
	for _, detail := range details {
		if len(detail.Errors) != 0 {
			return true
		}
	}
	return false
}
