// Package aclpolicy provides shared policy-file I/O using Tailscale's public
// ACL schema types.
package aclpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
// pinned Tailscale client nor the local extensions model.
func Load(path string) (*Policy, error) {
	raw, err := ReadRaw(path)
	if err != nil {
		return nil, err
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
