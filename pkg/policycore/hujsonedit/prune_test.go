package hujsonedit_test

import (
	"strings"
	"testing"

	"github.com/rshade/tsacl/pkg/policycore/hujsonedit"
)

func TestPatchPruneEmpty(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		input     string
		operation []hujsonedit.PatchOperation
		want      []string
		absent    []string
	}{
		{
			name:  "empty array is removed",
			input: `{"keep": 1, "grants": [{"a": 1}]}`,
			operation: []hujsonedit.PatchOperation{
				hujsonedit.PatchRemove("grants", "0"), hujsonedit.PatchPruneEmpty("grants"),
			},
			want:   []string{`"keep"`},
			absent: []string{"grants"},
		},
		{
			name:  "non-empty container is kept",
			input: `{"grants": [{"a": 1}, {"b": 2}]}`,
			operation: []hujsonedit.PatchOperation{
				hujsonedit.PatchRemove("grants", "0"), hujsonedit.PatchPruneEmpty("grants"),
			},
			want: []string{`"grants"`, `"b"`},
		},
		{
			name:  "comment on the key keeps the empty container",
			input: "{\n\t// why\n\t\"grants\": [{\"a\": 1}],\n}\n",
			operation: []hujsonedit.PatchOperation{
				hujsonedit.PatchRemove("grants", "0"), hujsonedit.PatchPruneEmpty("grants"),
			},
			want: []string{"// why", `"grants"`},
		},
		{
			name:  "comment inside the container keeps it",
			input: "{\"groups\": {\"group:a\": [\"x\"],\n\t// tail note\n\t}}",
			operation: []hujsonedit.PatchOperation{
				hujsonedit.PatchRemove("groups", "group:a"), hujsonedit.PatchPruneEmpty("groups"),
			},
			want: []string{`"groups"`, "// tail note"},
		},
		{
			name:  "nested prunes inner then outer",
			input: `{"autoApprovers": {"routes": {"10.0.0.0/8": ["g"]}}, "x": 1}`,
			operation: []hujsonedit.PatchOperation{
				hujsonedit.PatchRemove("autoApprovers", "routes", "10.0.0.0/8"),
				hujsonedit.PatchPruneEmpty("autoApprovers", "routes"),
				hujsonedit.PatchPruneEmpty("autoApprovers"),
			},
			want:   []string{`"x"`},
			absent: []string{"autoApprovers"},
		},
		{
			name:  "absent target is a no-op",
			input: `{"x": 1}`,
			operation: []hujsonedit.PatchOperation{
				hujsonedit.PatchPruneEmpty("nothing"),
			},
			want: []string{`"x"`},
		},
		{
			name:  "scalar target is never pruned",
			input: `{"x": 1}`,
			operation: []hujsonedit.PatchOperation{
				hujsonedit.PatchPruneEmpty("x"),
			},
			want: []string{`"x"`},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			out, err := hujsonedit.PatchBytes([]byte(testCase.input), nil, testCase.operation...)
			if err != nil {
				t.Fatal(err)
			}
			got := string(out)
			for _, want := range testCase.want {
				if !strings.Contains(got, want) {
					t.Errorf("missing %q in:\n%s", want, got)
				}
			}
			for _, absent := range testCase.absent {
				if strings.Contains(got, absent) {
					t.Errorf("unexpected %q in:\n%s", absent, got)
				}
			}
		})
	}
}
