// Package observedstate persists control-plane versions observed by tsacl.
// The state is observation only: policy parsing and classification never read it.
package observedstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	// FileName is deliberately policy-adjacent and gitignored. One file can
	// safely serve every tailnet addressed from the policy directory because
	// entries are keyed by tailnet.
	FileName      = ".tsacl-state.json"
	schemaVersion = "1"
	stateFileMode = 0o600
)

type state struct {
	SchemaVersion string            `json:"schema_version"`
	ETags         map[string]string `json:"etags"`
}

// Path returns the state file beside policyPath.
func Path(policyPath string) string {
	return filepath.Join(filepath.Dir(policyPath), FileName)
}

// Read returns the last ETag observed for tailnet.
func Read(policyPath, tailnet string) (string, error) {
	path := Path(policyPath)
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading observation state %s: %w", path, err)
	}
	stored, err := decode(contents)
	if err != nil {
		return "", fmt.Errorf("reading observation state %s: %w", path, err)
	}
	etag := stored.ETags[tailnet]
	if etag == "" {
		return "", fmt.Errorf("observation state %s has no ETag for tailnet %q", path, tailnet)
	}
	return etag, nil
}

// Record atomically records etag for tailnet without disturbing other
// tailnets in the same working copy.
func Record(policyPath, tailnet, etag string) error {
	if tailnet == "" {
		return errors.New("tailnet is empty")
	}
	if etag == "" {
		return errors.New("control plane returned an empty ETag")
	}

	path := Path(policyPath)
	stored := state{SchemaVersion: schemaVersion, ETags: make(map[string]string)}
	contents, err := os.ReadFile(path)
	switch {
	case err == nil:
		stored, err = decode(contents)
		if err != nil {
			return fmt.Errorf("reading observation state %s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return fmt.Errorf("reading observation state %s: %w", path, err)
	}
	stored.ETags[tailnet] = etag

	contents, err = json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding observation state: %w", err)
	}
	contents = append(contents, '\n')
	if err = writeAtomic(path, contents); err != nil {
		return fmt.Errorf("writing observation state %s: %w", path, err)
	}
	return nil
}

func decode(contents []byte) (state, error) {
	var stored state
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return state{}, fmt.Errorf("decoding JSON: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return state{}, errors.New("decoding JSON: multiple values")
		}
		return state{}, fmt.Errorf("decoding JSON: %w", err)
	}
	if stored.SchemaVersion != schemaVersion {
		return state{}, fmt.Errorf("unsupported schema_version %q", stored.SchemaVersion)
	}
	if stored.ETags == nil {
		return state{}, errors.New("missing etags object")
	}
	for tailnet, etag := range stored.ETags {
		if tailnet == "" || etag == "" {
			return state{}, errors.New("etags contains an empty tailnet or ETag")
		}
	}
	return stored, nil
}

func writeAtomic(path string, contents []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".tsacl-state-*")
	if err != nil {
		return fmt.Errorf("creating temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()

	if err = temp.Chmod(stateFileMode); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err = temp.Write(contents); err != nil {
		_ = temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replacing state file: %w", err)
	}
	return nil
}
