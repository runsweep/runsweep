package workflow

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/runsweep/runsweep/internal/pep"
)

func FuzzWorkflowParse(f *testing.F) {
	f.Add([]byte("jobs:\n  build:\n    name: Build ${{ matrix.os }}\n    runs-on: x\n    steps:\n      - run: npm ci\n"), "Build (ubuntu, 20)")
	f.Add([]byte("jobs:\n  a:\n    uses: ./.github/workflows/b.yml\n    secrets: inherit\n  b: {name: a}\n"), "a / c")
	f.Add([]byte("x: &a [*a]\n"), "")
	f.Fuzz(func(t *testing.T, b []byte, apiName string) {
		wf, err := Parse(b)
		if err != nil {
			return
		}
		j, ok := wf.FindJob(apiName)
		if !ok {
			return
		}
		if wf.Jobs[j.ID] != j {
			t.Fatalf("FindJob(%q) returned job %q not in wf.Jobs", apiName, j.ID)
		}
		_ = wf.Exposure(j)
	})
}

func FuzzParseCall(f *testing.F) {
	f.Add("./.github/workflows/x.yml")
	f.Add("o/r/.github/workflows/x.yml@0123456789abcdef0123456789abcdef01234567")
	f.Add("o/r/.github/workflows/x.yml@main")
	f.Fuzz(func(t *testing.T, uses string) {
		c, ok := ParseCall(uses)
		if ok && !workflowPath(c.Path) {
			t.Fatalf("ParseCall(%q) ok with path %q", uses, c.Path)
		}
	})
}

func FuzzParseTokenPerms(f *testing.F) {
	b, err := os.ReadFile("../match/actions/testdata/job.log")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(b))
	f.Add("2026-01-01T00:00:00.0000000Z ##[group]GITHUB_TOKEN Permissions\nContents: read\n##[endgroup]\n")
	f.Add("Z \n")
	f.Fuzz(func(t *testing.T, log string) {
		for k, v := range ParseTokenPerms(log) {
			if k != strings.TrimSpace(k) || k != strings.ToLower(k) || v != strings.TrimSpace(v) {
				t.Fatalf("untrimmed or mixed-case permission %q: %q", k, v)
			}
		}
	})
}

func FuzzPyInstalls(f *testing.F) {
	for _, s := range []string{"pip install x==1", "sudo -H python3 -m pip install -r r.txt", "uv run tox", "echo pip install x", "pip install $X `y`",
		`bash -c "pip install litellm && rm -rf /tmp/pipcache"`, "uv run --env-file .env sh -c 'pip install x'", "# pip\nfoo \"/a b/pip\" x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// every tool word is read as part of a command, or skipped as a comment or echo-like argument
		text := continuation.Replace(s)
		_, spans, skipped := pyScan(text)
		for _, w := range pyWords(text) {
			if !slices.Contains(skipped, w[0]) && !slices.ContainsFunc(spans, func(sp [2]int) bool { return sp[0] <= w[0] && w[0] < max(sp[1], sp[0]+1) }) {
				t.Fatalf("tool word at %d left uncovered in %q (spans %v)", w[0], text, spans)
			}
		}
		for _, in := range PyInstalls(s) {
			for _, p := range in.Pkgs {
				if p != pep.Name(p) {
					t.Fatalf("not normalized: %q", p)
				}
			}
		}
	})
}
