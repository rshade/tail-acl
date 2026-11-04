package integration_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rshade/tsacl/internal/tailapi"
)

// servicePolicySelectorPrefix is the prefix a policy uses to name a Tailscale
// Service. [tailapi.LookupService] is handed a policy selector verbatim, so this
// is the exact spelling production asks the control plane about.
const servicePolicySelectorPrefix = "svc:"

// TestLiveServiceLookupNameSpelling settles, against the live control plane,
// which name spelling ServicesResource.Get accepts — the question every offline
// test in this repo begs by asserting the same path the code builds.
//
// The stakes are one-sided and silent. The Get endpoint answers
// 404 "service not found" for every unmatched name, malformed or merely absent
// alike, so a wrong spelling is indistinguishable from a genuinely missing
// service: [tailapi.LookupService] would report Exists=false for every service
// that does exist, and lint --online-validation would emit svc-unknown across an
// entirely valid policy. Nothing in the response says which of the two happened,
// which is why only a service known to exist can decide it.
//
// The expected spelling is therefore *derived* from List rather than named here:
// hard-coding a service would tie the test to one tailnet and re-create the same
// self-agreement it exists to break. Two assertions carry the verdict, and they
// fail independently. The wire name must resolve, which proves List and Get
// speak one vocabulary; and the svc:-prefixed policy-selector form must resolve,
// which is what production actually sends. If Get wanted bare names while List
// returned prefixed ones the first catches it; if List ever returned bare names
// the second still holds production's contract to account.
//
// Assertions report shape, never content: a service name is live tailnet
// inventory, and t.Errorf output is what gets pasted into a bug report.
func TestLiveServiceLookupNameSpelling(t *testing.T) {
	t.Parallel()

	credentials := liveValidateCredentials(t)
	baseURL := liveValidateBaseURL(t)
	transport := newServiceReadOnlyTransport(baseURL, credentials.tailnet, http.DefaultTransport)
	httpClient := &http.Client{Transport: transport, Timeout: liveValidateTimeout}
	client, err := tailapi.NewClient(tailapi.Config{
		APIKey:  credentials.apiKey,
		Tailnet: credentials.tailnet,
		BaseURL: baseURL.String(),
		HTTP:    httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, cancel := context.WithTimeout(t.Context(), liveValidateTimeout)
	defer cancel()

	services, err := client.Services().List(requestCtx)
	if err != nil {
		t.Fatalf("list tailnet services: %v", err)
	}
	if len(services) == 0 {
		t.Skipf("the tailnet reachable with these credentials advertises no services, so %s cannot "+
			"observe a Get that succeeds; run it against a tailnet with at least one service",
			t.Name())
	}

	wire := services[0].Name
	if wire == "" {
		t.Fatal("the first listed service has an empty name; " +
			"the control plane returned no spelling to derive from")
	}
	bare, prefixed := serviceNameSpellings(wire)
	hasPrefix := strings.HasPrefix(wire, servicePolicySelectorPrefix)
	t.Logf("List returned %d service(s); the first name is %d bytes with has_svc_prefix=%t",
		len(services), len(wire), hasPrefix)

	wireLookup, err := tailapi.LookupService(requestCtx, client, wire)
	if err != nil {
		t.Fatalf("look up the wire name exactly as List returned it: %v", err)
	}
	if !wireLookup.Exists {
		t.Errorf("LookupService(<name exactly as List returned it>).Exists = false, want true; "+
			"Get does not accept the spelling List emits (has_svc_prefix=%t)", hasPrefix)
	}

	selectorLookup, err := tailapi.LookupService(requestCtx, client, prefixed)
	if err != nil {
		t.Fatalf("look up the svc:-prefixed policy-selector spelling: %v", err)
	}
	if !selectorLookup.Exists {
		t.Error(`LookupService("svc:<name>").Exists = false, want true; every service a policy ` +
			"references would be reported svc-unknown by lint --online-validation")
	}

	// The bare spelling is an observation, not a verdict: a control plane that
	// accepts both is not a defect, and failing on it would make this test
	// assert an API guarantee Tailscale never offered.
	bareLookup, err := tailapi.LookupService(requestCtx, client, bare)
	if err != nil {
		t.Logf("observed: looking up the bare spelling was unavailable: %v", err)
	} else {
		t.Logf("observed: the bare spelling without the svc: prefix resolves = %t", bareLookup.Exists)
	}

	transport.assertReadOnly(t)
}

// serviceNameSpellings splits a control-plane service name into the two
// spellings a caller could plausibly send: bare, and svc:-prefixed. It is
// idempotent, so it derives the same pair whether the API returns "svc:name" or
// "name" — the property that lets the live test assert production's contract
// without knowing in advance which form it will be handed.
func serviceNameSpellings(name string) (string, string) {
	bare := strings.TrimPrefix(name, servicePolicySelectorPrefix)
	return bare, servicePolicySelectorPrefix + bare
}

func TestServiceNameSpellings(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name         string
		wire         string
		wantBare     string
		wantPrefixed string
	}{
		{"prefixed", "svc:example", "example", "svc:example"},
		{"bare", "example", "example", "svc:example"},
		{"hyphenated", "svc:my-service-1", "my-service-1", "svc:my-service-1"},
		{"prefix only", "svc:", "", "svc:"},
		{"empty", "", "", "svc:"},
		{"inner colon is not a prefix", "a:svc:b", "a:svc:b", "svc:a:svc:b"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			bare, prefixed := serviceNameSpellings(testCase.wire)
			if bare != testCase.wantBare || prefixed != testCase.wantPrefixed {
				t.Errorf("serviceNameSpellings(%q) = (%q, %q), want (%q, %q)",
					testCase.wire, bare, prefixed, testCase.wantBare, testCase.wantPrefixed)
			}
			// Idempotence: re-deriving from the prefixed form yields the same
			// pair, so the live assertions never depend on which spelling the
			// control plane happened to return.
			reBare, rePrefixed := serviceNameSpellings(prefixed)
			if reBare != bare || rePrefixed != prefixed {
				t.Errorf("serviceNameSpellings(%q) is not idempotent: got (%q, %q), want (%q, %q)",
					prefixed, reBare, rePrefixed, bare, prefixed)
			}
		})
	}
}

// serviceReadOnlyTransport permits only GETs against the tailnet's services
// collection and the single-name resources directly below it. ServicesResource
// exposes CreateOrUpdate and Delete against those very paths, so the read-only
// posture is enforced structurally rather than by convention: a regression that
// reaches for a mutating method fails here instead of on the live tailnet.
type serviceReadOnlyTransport struct {
	base           http.RoundTripper
	host           string
	collectionPath string

	mu       sync.Mutex
	requests []string
}

func newServiceReadOnlyTransport(
	baseURL *url.URL,
	tailnet string,
	base http.RoundTripper,
) *serviceReadOnlyTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	collectionURL := baseURL.JoinPath("/api/v2", "tailnet", url.PathEscape(tailnet), "vip-services")
	return &serviceReadOnlyTransport{
		base:           base,
		host:           baseURL.Host,
		collectionPath: requestEscapedPath(collectionURL),
	}
}

func (transport *serviceReadOnlyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	path := request.URL.EscapedPath()
	transport.mu.Lock()
	transport.requests = append(transport.requests, request.Method+" "+path)
	transport.mu.Unlock()

	hostMatch := request.URL.Host == transport.host
	pathMatch := transport.allowsPath(path)
	if !hostMatch || request.Method != http.MethodGet || !pathMatch {
		if request.Body != nil {
			_ = request.Body.Close()
		}
		return nil, fmt.Errorf(
			"service read-only gate violation: method=%s host_match=%t path_match=%t",
			request.Method, hostMatch, pathMatch)
	}
	return transport.base.RoundTrip(request)
}

// allowsPath admits the collection itself and exactly one segment below it. A
// bare prefix test would also admit the /devices and /device/{id}/approved
// sub-resources, one of which has a mutating sibling.
func (transport *serviceReadOnlyTransport) allowsPath(path string) bool {
	if path == transport.collectionPath {
		return true
	}
	remainder, ok := strings.CutPrefix(path, transport.collectionPath+"/")
	return ok && remainder != "" && !strings.Contains(remainder, "/")
}

func (transport *serviceReadOnlyTransport) assertReadOnly(t *testing.T) {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.requests) == 0 {
		t.Fatal("service lookup gate made no requests")
	}
	for _, request := range transport.requests {
		if !strings.HasPrefix(request, http.MethodGet+" ") {
			t.Errorf("request = %q, want GET only", request)
		}
	}
}

func TestServiceReadOnlyTransportFailsClosed(t *testing.T) {
	t.Parallel()
	baseURL, err := url.Parse("https://api.example.test/prefix")
	if err != nil {
		t.Fatal(err)
	}
	var forwarded []string
	base := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		forwarded = append(forwarded, request.Method+" "+request.URL.EscapedPath())
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    request,
		}, nil
	})
	transport := newServiceReadOnlyTransport(baseURL, "example.com", base)

	const collection = "/prefix/api/v2/tailnet/example.com/vip-services"
	allowed := []string{collection, collection + "/svc:example", collection + "/example"}
	for _, path := range allowed {
		request, requestErr := http.NewRequest(http.MethodGet, "https://api.example.test"+path, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		response, requestErr := transport.RoundTrip(request)
		if requestErr != nil {
			t.Errorf("allowed request GET %s: %v", path, requestErr)
			continue
		}
		_ = response.Body.Close()
	}

	denied := []struct {
		method string
		url    string
	}{
		{http.MethodPut, "https://api.example.test" + collection + "/svc:example"},
		{http.MethodDelete, "https://api.example.test" + collection + "/svc:example"},
		{http.MethodPost, "https://api.example.test" + collection},
		{http.MethodGet, "https://api.example.test" + collection + "/svc:example/devices"},
		{http.MethodGet, "https://api.example.test/prefix/api/v2/tailnet/example.com/acl"},
		{http.MethodGet, "https://redirected.example.test" + collection},
	}
	for _, request := range denied {
		req, requestErr := http.NewRequest(request.method, request.url, nil)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		if _, requestErr = transport.RoundTrip(req); requestErr == nil {
			t.Errorf("denied request %s %s reached base transport", request.method, request.url)
		}
	}

	want := []string{
		"GET " + collection,
		"GET " + collection + "/svc:example",
		"GET " + collection + "/example",
	}
	if !slices.Equal(forwarded, want) {
		t.Errorf("forwarded = %v, want %v", forwarded, want)
	}
}
