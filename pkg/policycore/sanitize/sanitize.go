// Package sanitize defines the repository-wide output-sanitization contract.
//
// It deliberately knows nothing about any tool's report structs. Each tool
// rebuilds its own output types from zero at the render boundary; this package
// owns only level parsing, precedence, pseudonym allocation, exact-value text
// replacement, timestamp quantization, and envelope metadata.
package sanitize

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"time"
)

// Environment variable names are centralized so every binary documents and
// reads the same spellings.
const (
	LevelEnv = "TAILSCALE_SANITIZE"
	KeyEnv   = "TAILSCALE_SANITIZE_KEY"
)

// Level is the amount of output sanitization requested.
type Level string

const (
	Off      Level = "off"
	Identity Level = "identity"
	Strict   Level = "strict"
)

const (
	schemeHMAC = "hmac-sha256-v1"
	scopeRun   = "artifact"
	scopeKey   = "tailnet"
	keyBytes   = 32
	digestSize = 16
)

// ParseLevel accepts the exact, lower-case public vocabulary. An empty value
// is the unset/default spelling and resolves to off.
func ParseLevel(value string) (Level, error) {
	switch Level(value) {
	case "", Off:
		return Off, nil
	case Identity:
		return Identity, nil
	case Strict:
		return Strict, nil
	default:
		return Off, fmt.Errorf(
			"unknown %s value %q; want off, identity, or strict", LevelEnv, value,
		)
	}
}

// Resolution is the effective level and the information needed for the
// mandatory stderr notice. EnvironmentActive is true only for a non-off env
// instruction; TAILSCALE_SANITIZE=off deliberately does not weaken a flag.
type Resolution struct {
	Level             Level
	EnvironmentActive bool
	OverrodeFlag      bool
	FlagLevel         Level
}

// Resolve applies the repository-wide precedence rule: a non-off environment
// level wins over a flag, while an absent/off environment leaves the flag in
// control. Both inputs are validated before precedence is applied, so an
// unknown value never silently degrades to off.
func Resolve(environmentValue, flagValue string, flagExplicit bool) (Resolution, error) {
	environmentLevel, err := ParseLevel(environmentValue)
	if err != nil {
		return Resolution{}, err
	}
	flagLevel, err := ParseLevel(flagValue)
	if err != nil {
		return Resolution{}, fmt.Errorf("unknown --sanitize value %q; want off, identity, or strict", flagValue)
	}
	if environmentLevel != Off {
		resolution := Resolution{
			Level:             environmentLevel,
			EnvironmentActive: true,
			OverrodeFlag:      flagExplicit && flagLevel != environmentLevel,
		}
		if resolution.OverrodeFlag {
			resolution.FlagLevel = flagLevel
		}
		return resolution, nil
	}
	return Resolution{Level: flagLevel}, nil
}

// Notice is the warn-level diagnostic required whenever the environment
// instruction is active. It contains no identity or key material.
func (r Resolution) Notice(tool string) string {
	if !r.EnvironmentActive {
		return ""
	}
	if r.OverrodeFlag {
		return fmt.Sprintf(
			"%s: %s=%s overrides --sanitize=%s; output is sanitized",
			tool, LevelEnv, r.Level, r.FlagLevel,
		)
	}
	return fmt.Sprintf("%s: %s=%s is active; output is sanitized", tool, LevelEnv, r.Level)
}

// Metadata is embedded in active sanitized output. A nil *Metadata means off,
// including for legacy retained reports which predate this additive field.
type Metadata struct {
	Level  Level  `json:"level"`
	Scheme string `json:"scheme"`
	Scope  string `json:"scope"`
	KeyID  string `json:"key_id,omitempty"`
}

// Active reports whether metadata describes sanitized output.
func (m *Metadata) Active() bool { return m != nil && m.Level != Off }

// Comparable reports whether two point-report metadata values name the same
// stable pseudonym domain. Artifact-scoped reports are intentionally never
// cross-run comparable.
func (m *Metadata) Comparable(other *Metadata) bool {
	if !m.Active() || !other.Active() {
		return !m.Active() && !other.Active()
	}
	return m.comparableDomain() && other.comparableDomain() &&
		*m == *other
}

func (m *Metadata) comparableDomain() bool {
	return (m.Level == Identity || m.Level == Strict) && m.Scheme == schemeHMAC &&
		m.Scope == scopeKey && m.KeyID != ""
}

// Options configures one invocation's pseudonym allocator.
type Options struct {
	Level   Level
	Tool    string
	Tailnet string
	// KeyHex is an optional 64-character hexadecimal encoding of 32 random
	// bytes. Empty selects an ephemeral invocation key.
	KeyHex string
	// Random supplies the ephemeral key. nil selects crypto/rand.Reader.
	Random io.Reader
}

// Sanitizer owns one invocation's value-to-placeholder mapping. It is not
// safe for concurrent use; render paths call it serially.
type Sanitizer struct {
	level       Level
	tool        string
	scope       string
	tailnet     string
	key         []byte
	keyID       string
	byValue     map[string]string
	original    []string
	sortedCache []string
}

// New creates one active sanitizer. Off returns a harmless inactive value so
// callers can keep one code path, though tools normally skip reconstruction
// entirely to retain byte-identical unsanitized output.
func New(options Options) (*Sanitizer, error) {
	if options.Level != Off && options.Level != Identity && options.Level != Strict {
		return nil, fmt.Errorf("invalid sanitization level %q", options.Level)
	}
	s := &Sanitizer{
		level:   options.Level,
		tool:    options.Tool,
		tailnet: options.Tailnet,
		scope:   scopeRun,
		byValue: make(map[string]string),
	}
	if options.Level == Off {
		return s, nil
	}

	var err error
	s.key, s.scope, err = sanitizerKey(options.KeyHex, options.Random)
	if err != nil {
		return nil, err
	}
	if s.scope == scopeKey {
		s.keyID = "sk1_" + s.digest("key-id", options.Tool, options.Tailnet)
	}
	return s, nil
}

func sanitizerKey(keyHex string, randomReader io.Reader) ([]byte, string, error) {
	if keyHex != "" {
		if len(keyHex) != keyBytes*2 {
			return nil, "", fmt.Errorf("%s must be exactly 64 hexadecimal characters", KeyEnv)
		}
		key, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, "", fmt.Errorf("%s must be exactly 64 hexadecimal characters: %w", KeyEnv, err)
		}
		return key, scopeKey, nil
	}
	if randomReader == nil {
		randomReader = rand.Reader
	}
	key := make([]byte, keyBytes)
	if _, err := io.ReadFull(randomReader, key); err != nil {
		return nil, "", fmt.Errorf("generate ephemeral sanitization key: %w", err)
	}
	return key, scopeRun, nil
}

// Level returns the effective level.
func (s *Sanitizer) Level() Level {
	if s == nil {
		return Off
	}
	return s.level
}

// Metadata returns a detached envelope marker, or nil for off.
func (s *Sanitizer) Metadata() *Metadata {
	if s == nil || s.level == Off {
		return nil
	}
	return &Metadata{Level: s.level, Scheme: schemeHMAC, Scope: s.scope, KeyID: s.keyID}
}

// Pseudonym returns a stable placeholder without retaining the real value.
// It is intended for structured output that never needs a later Text pass.
// Unlike Value, the semantic kind is part of the mapping, so callers must use
// the same kind wherever they need the same literal to correlate.
func (s *Sanitizer) Pseudonym(kind, value string) string {
	if s == nil || s.level == Off || value == "" {
		return value
	}
	return placeholderPrefix(kind) + "-" + s.digest("value", kind, value)
}

// Value returns the stable placeholder for one real value in this invocation
// and registers the value for replacement by Text. The first semantic kind
// wins if the same literal is registered through more than one field, making
// the acceptance guarantee literal: the same registered real value maps to the
// same placeholder everywhere it appears.
func (s *Sanitizer) Value(kind, value string) string {
	if s == nil || s.level == Off || value == "" {
		return value
	}
	if placeholder, ok := s.byValue[value]; ok {
		return placeholder
	}
	placeholder := s.Pseudonym(kind, value)
	s.byValue[value] = placeholder
	s.original = append(s.original, value)
	return placeholder
}

func placeholderPrefix(kind string) string {
	kind = strings.TrimSpace(strings.ToLower(kind))
	kind = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			return r
		default:
			return '-'
		}
	}, kind)
	kind = strings.Trim(kind, "-")
	if kind == "" {
		return "value"
	}
	return kind
}

func (s *Sanitizer) digest(parts ...string) string {
	digest := hmac.New(sha256.New, s.key)
	writePart(digest, "tailscale-utils/sanitize/v1")
	writePart(digest, s.tool)
	writePart(digest, s.scope)
	writePart(digest, s.tailnet)
	for _, part := range parts {
		writePart(digest, part)
	}
	sum := digest.Sum(nil)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:digestSize]))
}

func writePart(writer io.Writer, value string) {
	// A uint64-sized decimal length followed by ':' is an unambiguous frame for
	// arbitrary UTF-8 and keeps the construction easy to reproduce elsewhere.
	_, _ = fmt.Fprintf(writer, "%d:%s", len(value), value)
}

// sortedOriginals returns s.original sorted longest-first (ties broken
// lexicographically), recomputing only when a new value has been registered
// since the last call.
func (s *Sanitizer) sortedOriginals() []string {
	if len(s.sortedCache) == len(s.original) {
		return s.sortedCache
	}
	sorted := slices.Clone(s.original)
	slices.SortFunc(sorted, func(left, right string) int {
		if len(left) != len(right) {
			return len(right) - len(left)
		}
		return strings.Compare(left, right)
	})
	s.sortedCache = sorted
	return s.sortedCache
}

// Text replaces every real value already registered with Value in a single
// left-to-right pass. Longer values win at a tied position so an address or
// short hostname cannot partially rewrite a CIDR or FQDN before its full
// placeholder is considered. Matching is case-insensitive (ASCII only —
// identity values here are hostnames, tags, logins, and keys, which are ASCII,
// and a full Unicode case fold could change a match's byte length and misalign
// the boundary check) and always requires a token boundary on both sides, so a
// registered value that is also an ordinary word or a substring of a longer
// word is left alone. Replacements are written to fresh output rather than
// rescanned, so a registered value equal to a placeholder prefix can never
// corrupt an already-inserted placeholder.
func (s *Sanitizer) Text(value string) string {
	if s == nil || s.level == Off || value == "" {
		return value
	}
	originals := s.sortedOriginals()
	if len(originals) == 0 {
		return value
	}
	var result strings.Builder
	result.Grow(len(value))
	for offset := 0; offset < len(value); {
		start, original := earliestDelimitedMatch(value, offset, originals)
		if start < 0 {
			result.WriteString(value[offset:])
			break
		}
		result.WriteString(value[offset:start])
		result.WriteString(s.byValue[original])
		offset = start + len(original)
	}
	return result.String()
}

// earliestDelimitedMatch returns the byte index of the first
// ASCII-case-insensitive, token-boundary-delimited occurrence of any original
// at or after offset, preferring the longest original at a tied position
// (originals are pre-sorted longest-first), or -1 when none matches.
func earliestDelimitedMatch(value string, offset int, originals []string) (int, string) {
	best := -1
	var bestOriginal string
	for _, original := range originals {
		for start := offset; start+len(original) <= len(value); {
			if best >= 0 && start >= best {
				break
			}
			relative := indexFoldASCII(value[start:], original)
			if relative < 0 {
				break
			}
			start += relative
			if best >= 0 && start >= best {
				break
			}
			end := start + len(original)
			if delimitedAt(value, start, end) {
				best, bestOriginal = start, original
				break
			}
			start = end
		}
	}
	return best, bestOriginal
}

// indexFoldASCII returns the byte index of the first ASCII-case-insensitive
// occurrence of substr in s, or -1.
func indexFoldASCII(s, substr string) int {
	if substr == "" || len(substr) > len(s) {
		return -1
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if equalFoldASCII(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func delimitedAt(value string, start, end int) bool {
	return (start == 0 || !tokenByte(value[start-1])) &&
		(end == len(value) || !tokenByte(value[end]))
}

func tokenByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '_'
}

// Strings sanitizes a copy of values as direct structured values.
func (s *Sanitizer) Strings(kind string, values []string) []string {
	if values == nil {
		return nil
	}
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = s.Value(kind, value)
	}
	return result
}

// Time preserves exact timestamps at identity and quantizes strict output to a
// UTC calendar day. Day precision is coarse enough to remove an exact activity
// fingerprint while preserving day-granularity ordering and the operational
// age of findings.
func (s *Sanitizer) Time(value time.Time) time.Time {
	if s == nil || s.level != Strict || value.IsZero() {
		return value
	}
	value = value.UTC()
	return time.Date(value.Year(), value.Month(), value.Day(), 0, 0, 0, 0, time.UTC)
}

// UnhandledFields returns exported struct fields not named in handled. Tests
// use it as the reflection guard for explicit zero-value reconstructions.
func UnhandledFields[T any](handled ...string) []string {
	typeOf := reflect.TypeFor[T]()
	if typeOf.Kind() == reflect.Pointer {
		typeOf = typeOf.Elem()
	}
	wanted := make(map[string]struct{}, len(handled))
	for _, name := range handled {
		wanted[name] = struct{}{}
	}
	var missing []string
	for field := range typeOf.Fields() {
		if !field.IsExported() {
			continue
		}
		if _, ok := wanted[field.Name]; !ok {
			missing = append(missing, field.Name)
		}
	}
	slices.Sort(missing)
	return missing
}

// ErrIncomparable is returned by retained-report consumers when sanitization
// metadata cannot prove that two pseudonyms name the same real subject.
var ErrIncomparable = errors.New("sanitized reports do not share a comparable pseudonym domain")
