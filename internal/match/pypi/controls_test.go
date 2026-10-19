package pypi

import (
	"os"
	"strings"
	"testing"
)

// Excerpts of job logs from public Python repos (the archive of the mrmustard 0.7.4 sweep: none
// of them installs the package). Under an incident that names a package absent from them, a job
// may be CLEAN only if every Python section is complete and none is opaque (design §6 rule 6).
// The expectations are derived from the design (§3 completeness, §4 opaque commands) by reading
// each excerpt, not from what ParseLog printed.
func TestParseLogControls(t *testing.T) {
	type sec struct {
		cmd      string // prefix of Section.Cmd
		complete bool
		opaque   string
	}
	const none = ""
	cases := map[string][]sec{
		// uv prints "Installed 15 packages" and 15 "+" lines; tox is opaque
		"pipx-uv-tool-tox.log": {{"uv tool install", true, none}, {"tox run", false, "tox"}},
		// pipx install lists no dependencies; poetry announces 75 installs but one line
		// ("poetry-core (2.4.1 5de2411)", a VCS version) cannot be read: 74 of 75
		"poetry-install-vcs-dep.log": {{"pipx install", false, "pipx install"}, {"poetry install", false, none}, {"poetry env info", true, none}},
		// the argument starts with a variable: the packages are named at run time
		"pytest-uv-pip-sync-var.log": {{"unset UV_SYSTEM_PYTHON", false, none}},
		"uv-uvx.log":                 {{"uvx", false, "uvx"}},
		"flask-uv-run-tox.log":       {{"uv run", false, "tox"}},
		// if/else with one install command per branch: one list is enough
		"pytest-uv-tool-ifelse.log": {{"if [ -n", true, none}, {"tox run", false, "tox"}},
		"poetry-pipx-check.log":     {{"pipx install", false, "pipx install"}, {"poetry config", true, none}, {"poetry check", true, none}},
	}
	for name, want := range cases {
		b, err := os.ReadFile("testdata/controls/" + name) //nolint:gosec // G304: test fixture path
		if err != nil {
			t.Fatal(err)
		}
		l := ParseLog(string(b))
		for _, in := range append(l.Installs, l.Unparsed...) {
			if in.Name == "mrmustard" || in.Name == "made-up-pkg" {
				t.Errorf("%s: unexpected install %+v", name, in)
			}
		}
		var got []Section
		for _, s := range l.Sections {
			if s.Python {
				got = append(got, s)
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s: %d Python sections, want %d: %+v", name, len(got), len(want), got)
			continue
		}
		for i, w := range want {
			g := got[i]
			if !strings.HasPrefix(g.Cmd, w.cmd) || g.Complete != w.complete || g.Opaque != w.opaque {
				t.Errorf("%s[%d]: cmd %.30q complete=%v opaque=%q, want %q complete=%v opaque=%q",
					name, i, g.Cmd, g.Complete, g.Opaque, w.cmd, w.complete, w.opaque)
			}
		}
	}
}
