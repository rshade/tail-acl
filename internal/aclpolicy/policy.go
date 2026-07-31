// Package aclpolicy provides shared policy-file I/O using Tailscale's public
// ACL schema types.
//
// Rule-syntax skips and indeterminate evaluations deliberately describe
// different scopes. A skip says the policy contains an unreadable element and
// is collected over the whole file. An indeterminate result says one particular
// query reached that element after every readable field on its rule matched.
// A policy may therefore have skips while every evaluated query remains settled.
package aclpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tailscale/hujson"
	tailscale "tailscale.com/client/tailscale/v2"
)

// defaultFileMode is applied to policy files that do not already exist.
const defaultFileMode os.FileMode = 0o644

// Policy extends the pinned Tailscale client schema with policy-file fields the
// client does not yet model.
//
// SSH shadows the promoted ACL.SSH field so acceptEnv can be preserved.
// Callers must treat Policy.SSH as the source of truth if SSH authoring is ever
// added; Load currently mirrors it into ACL.SSH only for read-only evaluators.
// Write enforces that rule rather than trusting it — see checkSSHSourceOfTruth.
type Policy struct {
	tailscale.ACL

	SSH      []SSHRule `json:"ssh,omitempty"`
	SSHTests []SSHTest `json:"sshTests,omitempty"`
}

// PatchOperation is one comment-preserving policy edit: an RFC 6902 operation,
// an authored comment, or both. Construct operations with PatchAdd and
// PatchRemove so the encoded patch has exactly the fields required by that
// operation, and with PatchComment or PatchCommentOverwrite to author a comment.
//
// Operations carry path segments rather than a rendered pointer because
// WritePatch resolves the first segment against the document it is about to
// patch. See resolveTopLevelKey for why that resolution cannot happen here.
//
// A comment carries its own segments because it names the node as it exists
// *after* every operation in the call has been applied, which is not always the
// node the operation targeted: creating an absent block patches the block, while
// the comment belongs to the entry inside it.
type PatchOperation struct {
	op       string
	segments []string
	value    any
	hasValue bool

	comment          string
	commentSegments  []string
	commentOverwrite bool
}

// PatchAdd constructs an RFC 6902 add operation targeting segments. Per RFC
// 6902, add also replaces an existing object member at that location.
func PatchAdd(value any, segments ...string) PatchOperation {
	return PatchOperation{op: "add", segments: segments, value: value, hasValue: true}
}

// PatchRemove constructs an RFC 6902 remove operation targeting segments.
func PatchRemove(segments ...string) PatchOperation {
	return PatchOperation{op: "remove", segments: segments}
}

// JSONPointer returns an RFC 6901 pointer for path segments. Escaping each
// segment here keeps user-controlled tag, host, and posture names from changing
// the location an edit targets.
func JSONPointer(segments ...string) string {
	var pointer strings.Builder
	for _, segment := range segments {
		pointer.WriteByte('/')
		segment = strings.ReplaceAll(segment, "~", "~0")
		segment = strings.ReplaceAll(segment, "/", "~1")
		pointer.WriteString(segment)
	}
	return pointer.String()
}

// resolveTopLevelKey returns the name document actually uses for the top-level
// policy key canonical, which may differ in case.
//
// Load decodes through encoding/json, which matches struct fields
// case-insensitively, so a policy written in Tailscale's legacy capitalized
// style ("Grants", "TagOwners") validates and populates the typed Policy.
// hujson.Patch matches object names exactly. Without this bridge a pointer
// built from the canonical lowercase name misses the member the typed policy
// was decoded from, and the edit fails with "value not found". Resolving here
// keeps the file's own spelling instead of renaming the operator's keys.
//
// An absent key resolves to canonical so a newly created member is spelled the
// documented way.
func resolveTopLevelKey(document hujson.Value, canonical string) string {
	object, ok := document.Value.(*hujson.Object)
	if !ok {
		return canonical
	}
	for i := range object.Members {
		literal, isLiteral := object.Members[i].Name.Value.(hujson.Literal)
		if !isLiteral {
			continue
		}
		if name := literal.String(); strings.EqualFold(name, canonical) {
			return name
		}
	}
	return canonical
}

// checkDuplicateMembers rejects a policy containing the same object member name
// twice at any depth.
//
// Duplicates are not merely untidy here: encoding/json resolves them last-wins
// while hujson resolves them first-wins, so a typed edit would validate against
// one member and patch a different one — reporting success while destroying
// policy the operator was never shown. Refusing the file is the only answer
// that cannot silently pick the wrong one.
func checkDuplicateMembers(document hujson.Value) error {
	switch value := document.Value.(type) {
	case *hujson.Object:
		seen := make(map[string]struct{}, len(value.Members))
		for i := range value.Members {
			literal, isLiteral := value.Members[i].Name.Value.(hujson.Literal)
			if !isLiteral {
				continue
			}
			name := literal.String()
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate object member %q", name)
			}
			seen[name] = struct{}{}
			if err := checkDuplicateMembers(value.Members[i].Value); err != nil {
				return fmt.Errorf("%q: %w", name, err)
			}
		}
	case *hujson.Array:
		for i := range value.Elements {
			if err := checkDuplicateMembers(value.Elements[i]); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
	}
	return nil
}

// ReadRaw reads path and verifies that it contains syntactically valid HuJSON.
func ReadRaw(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if _, err = hujson.Parse(b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, nil
}

// Load reads a JSON or HuJSON policy into the local Policy type. Unknown fields
// are rejected so an edit cannot silently discard policy data that neither the
// pinned Tailscale client nor the local extensions model. Duplicate object
// members are rejected for the same reason — see checkDuplicateMembers.
func Load(path string) (*Policy, error) {
	raw, err := ReadRaw(path)
	if err != nil {
		return nil, err
	}
	document, err := hujson.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err = checkDuplicateMembers(document); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	standard, err := hujson.Standardize(raw)
	if err != nil {
		return nil, fmt.Errorf("standardizing %s: %w", path, err)
	}

	var policy Policy
	decoder := json.NewDecoder(bytes.NewReader(standard))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("decoding %s as a Tailscale policy: %w", path, err)
	}
	if err = ensureEOF(decoder); err != nil {
		return nil, fmt.Errorf("decoding %s as a Tailscale policy: %w", path, err)
	}

	// SSH authoring does not exist, so this one-way copy is safe: Policy.SSH is
	// the decoded and marshaled source of truth. Keep ACL.SSH populated so a
	// read-only evaluator handed &policy.ACL never sees a false empty policy.
	policy.ACL.SSH = policy.sshRules()
	return &policy, nil
}

// sshRules projects Policy.SSH onto the pinned client's shape. It is the only
// conversion from Policy.SSH, so a caller that needs SSH rules can derive them
// from the source of truth rather than trusting ACL.SSH, which is a mirror that
// only Load populates.
func (p *Policy) sshRules() []tailscale.ACLSSH {
	rules := make([]tailscale.ACLSSH, len(p.SSH))
	for i := range p.SSH {
		rules[i] = p.SSH[i].ACLSSH
	}
	return rules
}

// checkSSHSourceOfTruth refuses to encode a Policy whose SSH rules live only in
// the embedded ACL.SSH mirror. Policy.SSH shadows that field, so such a Policy
// marshals with no "ssh" key at all — the one way this package can silently drop
// policy data. Nothing builds that state today, so this guards a future caller
// who copies Load's mirror assignment in reverse; it is not a runtime path.
//
// It fires only on the unambiguous data-loss case. Any other divergence between
// the two still encodes Policy.SSH, which is the documented source of truth.
func (p *Policy) checkSSHSourceOfTruth() error {
	if len(p.SSH) == 0 && len(p.ACL.SSH) != 0 {
		return errors.New(
			"ssh rules are set only on the embedded ACL.SSH mirror, which Policy.SSH shadows; " +
				"set Policy.SSH instead",
		)
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values")
}

// Write atomically writes policy as indented standard JSON. Existing file
// permissions are retained; new files are created with mode 0644.
func Write(path string, policy *Policy) error {
	if err := policy.checkSSHSourceOfTruth(); err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	b, err := json.MarshalIndent(policy, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	b = append(b, '\n')
	return WriteRaw(path, b)
}

// WritePatch atomically applies comment-preserving RFC 6902 operations to a
// JSON or HuJSON policy, then authors any comments those operations carry.
// Callers must Load the policy first so unknown fields are rejected before an
// edit can be written.
//
// Operations apply in order, then every comment, then the document is
// reformatted. Comments come last because a comment names its node as that node
// exists after the edit — see PatchComment.
func WritePatch(path string, operations ...PatchOperation) error {
	value, err := parseFile(path)
	if err != nil {
		return err
	}
	// json.RawMessage rather than any: omitempty must track hasValue exactly.
	// On an any field omitempty omits only a nil interface, so PatchAdd(nil)
	// would encode an add with no "value" member, which RFC 6902 forbids. A
	// RawMessage is empty only when nothing was marshaled into it.
	type encodedOperation struct {
		Op    string          `json:"op"`
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value,omitempty"`
	}
	// A comment-only operation has no RFC 6902 counterpart. It must be skipped
	// rather than encoded: a zero-valued entry reaches hujson as {"op":"","path":""}
	// and fails the whole patch. The slice stays non-nil so an all-comment call
	// still marshals as [], which hujson accepts as an empty operation list.
	patch := make([]encodedOperation, 0, len(operations))
	for _, operation := range operations {
		if operation.op == "" {
			continue
		}
		segments := slices.Clone(operation.segments)
		if len(segments) > 0 {
			segments[0] = resolveTopLevelKey(value, segments[0])
		}
		encoded := encodedOperation{Op: operation.op, Path: JSONPointer(segments...)}
		if operation.hasValue {
			raw, valueErr := json.Marshal(operation.value)
			if valueErr != nil {
				return fmt.Errorf("encoding patch value for %s: %w", path, valueErr)
			}
			encoded.Value = raw
		}
		patch = append(patch, encoded)
	}
	// Indent inserted composite values so a policy previously emitted by Write
	// keeps that canonical layout. HuJSON's formatter will still retain compact
	// layout where the surrounding edited region is compact.
	rawPatch, err := json.MarshalIndent(patch, "", "\t")
	if err != nil {
		return fmt.Errorf("encoding patch for %s: %w", path, err)
	}
	if err = value.Patch(rawPatch); err != nil {
		return fmt.Errorf("patching %s: %w", path, err)
	}
	if err = applyComments(&value, path, operations); err != nil {
		return err
	}
	value.Format()
	return WriteRaw(path, value.Pack())
}

// applyComments authors each operation's comment onto the already-patched
// document.
//
// The top-level key is resolved against the post-patch document so a legacy
// capitalized key still resolves and a key the patch just created resolves to
// its own spelling. A target that does not resolve is an error rather than a
// silent skip, so the edit fails closed: hujson leaves a partially patched value
// behind on error, but nothing is written.
func applyComments(value *hujson.Value, path string, operations []PatchOperation) error {
	for _, operation := range operations {
		if operation.comment == "" {
			continue
		}
		segments := slices.Clone(operation.commentSegments)
		if len(segments) > 0 {
			segments[0] = resolveTopLevelKey(*value, segments[0])
		}
		extra, found, err := leadingExtra(value, segments)
		if err != nil {
			return fmt.Errorf("commenting %s: %w", path, err)
		}
		if !found {
			return fmt.Errorf("commenting %s: no node at %s", path, JSONPointer(segments...))
		}
		switch {
		case operation.commentOverwrite:
			replaceCommentLines(extra, operation.comment)
		case !slices.Contains(ownCommentLines(*extra), operation.comment):
			appendCommentLine(extra, operation.comment)
		}
	}
	return nil
}

// WriteRaw atomically writes data to path. Existing file permissions are
// retained; new files are created with mode 0644.
func WriteRaw(path string, data []byte) error {
	mode := defaultFileMode
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("creating temporary policy file: %w", err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()

	if err = temp.Chmod(mode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err = temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replacing %s: %w", path, err)
	}
	return nil
}
