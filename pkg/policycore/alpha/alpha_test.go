package alpha_test

import (
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rshade/tail-acl/pkg/policycore/alpha"
)

func TestRegistryRegisterAndLookup(t *testing.T) {
	t.Parallel()

	registry := alpha.NewRegistry()
	feature := alpha.Feature{
		Name:        "declarative-node-sharing",
		DocURL:      "https://tailscale.com/kb/example",
		ModeledDate: time.Date(2026, time.August, 28, 0, 0, 0, 0, time.UTC),
		Stage:       alpha.StageAlpha,
	}
	if err := registry.Register(feature); err != nil {
		t.Fatalf("Register(%+v) = %v, want nil", feature, err)
	}

	got, ok := registry.Lookup(feature.Name)
	if !ok {
		t.Fatalf("Lookup(%q) = (_, false), want (_, true)", feature.Name)
	}
	if got != feature {
		t.Errorf("Lookup(%q) = %+v, want %+v", feature.Name, got, feature)
	}

	if _, found := registry.Lookup("does-not-exist"); found {
		t.Errorf("Lookup(%q) = (_, true), want (_, false)", "does-not-exist")
	}
}

func TestRegistryRegisterValidation(t *testing.T) {
	t.Parallel()

	valid := alpha.Feature{
		Name:        "declarative-node-sharing",
		DocURL:      "https://tailscale.com/kb/example",
		ModeledDate: time.Date(2026, time.August, 28, 0, 0, 0, 0, time.UTC),
		Stage:       alpha.StageAlpha,
	}

	tests := []struct {
		name    string
		mutate  func(alpha.Feature) alpha.Feature
		wantErr string
	}{
		{
			name:    "missing name",
			mutate:  func(f alpha.Feature) alpha.Feature { f.Name = ""; return f },
			wantErr: "feature name is required",
		},
		{
			name:    "missing doc URL",
			mutate:  func(f alpha.Feature) alpha.Feature { f.DocURL = ""; return f },
			wantErr: "doc URL is required",
		},
		{
			name:    "zero modeled date",
			mutate:  func(f alpha.Feature) alpha.Feature { f.ModeledDate = time.Time{}; return f },
			wantErr: "modeled date is required",
		},
		{
			name:    "unknown stage",
			mutate:  func(f alpha.Feature) alpha.Feature { f.Stage = alpha.Stage("released"); return f },
			wantErr: `unknown stage "released"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			registry := alpha.NewRegistry()
			err := registry.Register(test.mutate(valid))
			if err == nil {
				t.Fatalf("Register() = nil, want error containing %q", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("Register() error = %q, want it to contain %q", err.Error(), test.wantErr)
			}
		})
	}
}

func TestRegistryRegisterDuplicate(t *testing.T) {
	t.Parallel()

	feature := alpha.Feature{
		Name:        "declarative-node-sharing",
		DocURL:      "https://tailscale.com/kb/example",
		ModeledDate: time.Date(2026, time.August, 28, 0, 0, 0, 0, time.UTC),
		Stage:       alpha.StageAlpha,
	}

	registry := alpha.NewRegistry()
	if err := registry.Register(feature); err != nil {
		t.Fatalf("first Register(%+v) = %v, want nil", feature, err)
	}
	err := registry.Register(feature)
	if err == nil {
		t.Fatal("second Register() = nil, want error")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Errorf("second Register() error = %q, want it to contain %q", err.Error(), "already registered")
	}
}

func TestRegistryList(t *testing.T) {
	t.Parallel()

	registry := alpha.NewRegistry()
	modeled := time.Date(2026, time.August, 28, 0, 0, 0, 0, time.UTC)
	names := []string{"node-sharing", "auto-approver-v2", "config-sync"}
	for _, name := range names {
		feature := alpha.Feature{
			Name:        name,
			DocURL:      "https://tailscale.com/kb/" + name,
			ModeledDate: modeled,
			Stage:       alpha.StageAlpha,
		}
		if err := registry.Register(feature); err != nil {
			t.Fatalf("Register(%q) = %v, want nil", name, err)
		}
	}

	list := registry.List()
	if len(list) != len(names) {
		t.Fatalf("List() has %d entries, want %d", len(list), len(names))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].Name >= list[i].Name {
			t.Errorf("List() not sorted by Name: %q >= %q at index %d", list[i-1].Name, list[i].Name, i)
		}
	}
}

func TestRepositoryFeaturesFormValidInventory(t *testing.T) {
	t.Parallel()

	registry := alpha.NewRegistry()
	for _, feature := range alpha.RepositoryFeatures() {
		if err := registry.Register(feature); err != nil {
			t.Errorf("RepositoryFeatures entry %q is invalid: %v", feature.Name, err)
		}
	}
}

// TestPackageDocNamesRegistryFields guards the convention doc comment against
// silent drift: it must keep naming the canonical inventory, every Feature
// field, and the AlphaHint tier a contributor adding an alpha feature needs,
// not just describe the package in the abstract.
func TestPackageDocNamesRegistryFields(t *testing.T) {
	t.Parallel()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed to resolve the test file's path")
	}
	sourceFile := filepath.Join(filepath.Dir(thisFile), "alpha.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, sourceFile, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parser.ParseFile(%s): %v", sourceFile, err)
	}
	docPkg, err := doc.NewFromFiles(fset, []*ast.File{file}, "github.com/rshade/tail-acl/pkg/policycore/alpha")
	if err != nil {
		t.Fatalf("doc.NewFromFiles(%s): %v", sourceFile, err)
	}

	required := []string{"RepositoryFeatures", "Name", "DocURL", "ModeledDate", "Stage", alpha.AlphaHint}
	for _, want := range required {
		if !strings.Contains(docPkg.Doc, want) {
			t.Errorf("package doc comment does not mention %q; doc:\n%s", want, docPkg.Doc)
		}
	}
}
