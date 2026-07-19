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

// Load reads a JSON or HuJSON policy into Tailscale's ACL type. Unknown fields
// are rejected so an edit cannot silently discard policy data that the current
// Tailscale client does not model.
func Load(path string) (*tailscale.ACL, error) {
	raw, err := ReadRaw(path)
	if err != nil {
		return nil, err
	}
	standard, err := hujson.Standardize(raw)
	if err != nil {
		return nil, fmt.Errorf("standardizing %s: %w", path, err)
	}

	var policy tailscale.ACL
	decoder := json.NewDecoder(bytes.NewReader(standard))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&policy); err != nil {
		return nil, fmt.Errorf("decoding %s as a Tailscale policy: %w", path, err)
	}
	if err = ensureEOF(decoder); err != nil {
		return nil, fmt.Errorf("decoding %s as a Tailscale policy: %w", path, err)
	}
	return &policy, nil
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
func Write(path string, policy *tailscale.ACL) error {
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
