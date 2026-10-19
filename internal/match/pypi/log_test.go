package pypi

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

const ts = "2026-08-01T12:01:56.0454713Z "

// step builds a runner step section: header, cyan echo of the script, env, then output lines.
func step(script string, out ...string) string {
	var b strings.Builder
	b.WriteString(ts + "##[group]Run " + strings.SplitN(script, "\n", 2)[0] + "\n")
	for _, l := range strings.Split(script, "\n") {
		b.WriteString(ts + "\x1b[36;1m" + l + "\x1b[0m\n")
	}
	b.WriteString(ts + "shell: /usr/bin/bash -e {0}\n" + ts + "##[endgroup]\n")
	for _, l := range out {
		b.WriteString(ts + l + "\n")
	}
	return b.String()
}

func installs(l Log) map[string]string {
	m := map[string]string{}
	for _, in := range l.Installs {
		m[in.Name] = in.Version
	}
	return m
}

func TestParseLogFormats(t *testing.T) {
	log := step("pip install -r requirements.txt",
		"Collecting LiteLLM==1.82.8",
		"  Downloading litellm-1.82.8-py3-none-any.whl (9.1 MB)",
		"  Downloading certifi-2026.7.22-py3-none-any.whl.metadata (2.5 kB)",
		"Requirement already satisfied: Flask_SQLAlchemy>=3 in ./venv/lib/python3.12/site-packages (3.1.1)",
		"Successfully installed LiteLLM-1.82.8 torch-2.1.0+cu118 my-pkg-0.1",
	) + step("uv sync --frozen",
		"Resolved 3 packages in 1ms",
		"Installed 2 packages in 3ms",
		" + anyio==4.9.0",
		" \x1b[32m+\x1b[39m \x1b[1mflask\x1b[0m\x1b[2m==3.1.0\x1b[0m",
	) + step("poetry install",
		"Package operations: 1 install, 1 update, 0 removals",
		"  - Installing six (1.17.0)",
		"  • Updating idna (3.6 -> 3.10)",
	) + step("pipx install poetry", "  installed package poetry 2.4.1, installed using Python 3.10.11")
	l := ParseLog(log)
	want := map[string]string{"litellm": "1.82.8", "flask-sqlalchemy": "3.1.1", "torch": "2.1+cu118", "my-pkg": "0.1",
		"anyio": "4.9", "flask": "3.1", "six": "1.17", "idna": "3.10", "poetry": "2.4.1"}
	got := installs(l)
	for n, v := range want {
		if got[n] != v {
			t.Errorf("%s: got %q, want %q (all: %v)", n, got[n], v, got)
		}
	}
	if _, ok := got["certifi"]; ok {
		t.Error(".whl.metadata counted as an install")
	}
	if len(l.Sections) != 5 { // setup + 4 steps
		t.Fatalf("sections: %+v", l.Sections)
	}
	for i, wantComplete := range map[int]bool{1: true, 2: true, 3: true} {
		if s := l.Sections[i]; !s.Python || s.Complete != wantComplete || s.Opaque != "" {
			t.Errorf("section %d: %+v", i, s)
		}
	}
	if s := l.Sections[4]; s.Opaque != "pipx install" {
		t.Errorf("pipx section: %+v", s)
	}
	if !l.Calls || len(l.Unparsed) != 0 {
		t.Errorf("calls=%v unparsed=%+v", l.Calls, l.Unparsed)
	}
}

func TestParseLogIncomplete(t *testing.T) {
	for name, log := range map[string]string{
		"quiet pip":        step("pip install -q -r r.txt"),
		"uv short":         step("uv sync", "Installed 3 packages in 1ms", " + a==1"),
		"uv audited":       step("uv sync", "Audited 12 packages in 1ms"),
		"poetry nothing":   step("poetry install", "No dependencies to install or update"),
		"poetry short":     step("poetry install", "Package operations: 2 installs, 0 updates, 0 removals", "  - Installing a (1)"),
		"build deps":       step("pip install .", "  Installing build dependencies: started", "Successfully installed x-1"),
		"two cmds one out": step("pip install a\npip install -q b", "Successfully installed a-1"),
		"loop":             step("for p in a b; do pip install $p; done", "Successfully installed a-1", "Successfully installed b-1"),
		"make runs uv":     step("make deps", "Installed 23 packages in 10ms"),
	} {
		l := ParseLog(log)
		var py []Section
		for _, s := range l.Sections {
			if s.Python {
				py = append(py, s)
			}
		}
		if len(py) != 1 || py[0].Complete {
			t.Errorf("%s: %+v", name, l.Sections)
		}
	}
}

func TestParseLogRealExcerpts(t *testing.T) {
	read := func(n string) Log {
		b, err := os.ReadFile("testdata/logs/" + n) //nolint:gosec // G304: test fixture path
		if err != nil {
			t.Fatal(err)
		}
		return ParseLog(string(b))
	}
	// uv run prints only a count: its section exists, is opaque and not complete
	var uvRun []Section
	for _, s := range read("flask-uv-run.log").Sections {
		if strings.Contains(s.Cmd, "uv run") {
			uvRun = append(uvRun, s)
		}
	}
	if len(uvRun) != 1 || uvRun[0].Opaque == "" || uvRun[0].Complete {
		t.Errorf("flask uv run: %+v", uvRun)
	}
	// uv with 15 + lines: that exact section is Python and complete
	l := read("pytest-uv.log")
	var tool []Section
	for _, s := range l.Sections {
		if strings.HasPrefix(s.Cmd, "if [ -n \"$PYTHON_VERSION\" ]") {
			tool = append(tool, s)
		}
	}
	if len(l.Installs) < 15 || len(tool) != 1 || !tool[0].Python || !tool[0].Complete {
		t.Errorf("pytest uv: %d installs, %+v", len(l.Installs), tool)
	}
	// setup-python's own pip upgrade is an install, and its section needs no full list
	l = read("poetry-setup.log")
	if installs(l)["pip"] != "26.2" {
		t.Errorf("poetry setup: %v", installs(l))
	}
}

func TestParseLogEdges(t *testing.T) {
	// setup-uv prints this; it is not a pip listing
	l := ParseLog(step("uses astral-sh/setup-uv", "Successfully installed uv version 0.12.1"))
	if len(l.Installs) != 0 || len(l.Unparsed) != 0 {
		t.Errorf("setup-uv: %+v", l)
	}
	// an unparsable token is reported, and the listing is not complete
	l = ParseLog(step("pip install x", "Successfully installed litellm-1.82.8xyz!! ok-1"))
	if len(l.Unparsed) != 1 || l.Sections[1].Complete {
		t.Errorf("unparsed: %+v", l)
	}
	// CRLF logs (Windows runners)
	l = ParseLog(strings.ReplaceAll(step("pip install x", "Successfully installed x-1.0"), "\n", "\r\n"))
	if installs(l)["x"] != "1" || !l.Sections[1].Complete {
		t.Errorf("crlf: %+v", l)
	}
	// echo of the script is not output
	l = ParseLog(step("echo 'Successfully installed evil-1.0'"))
	if len(l.Installs) != 0 {
		t.Errorf("echo: %+v", l.Installs)
	}
	// nested composite sections: the inner quiet pip is its own incomplete section
	l = ParseLog(step("uses ./.github/actions/setup") + step("pip install -q -r r.txt"))
	if l.Sections[2].Complete {
		t.Errorf("nested: %+v", l.Sections)
	}
	// a job with no Python at all
	l = ParseLog(step("go test ./...", "ok  x 0.1s"))
	if l.Calls || slices.ContainsFunc(l.Sections, func(s Section) bool { return s.Python }) {
		t.Errorf("go job: %+v", l)
	}
	// line numbers are those of the raw log
	l = ParseLog(step("pip install x", "Successfully installed x-1.0"))
	if l.Installs[0].Line != 5 {
		t.Errorf("line: %d", l.Installs[0].Line)
	}
}

func TestParseLogLarge(t *testing.T) {
	big := strings.Repeat(ts+"compiling something long enough to look like a real build line ......\n", 250_000) // ~20 MB
	start := time.Now()
	ParseLog(big)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("20 MB log took %v", d)
	}
}

func TestParseLogBranches(t *testing.T) {
	// one branch of an if/else runs: one listing is enough, a second command outside is not
	br := "if [ -n \"$V\" ]; then\n  pip install a\nelse\n  pip install b\nfi"
	for script, want := range map[string]bool{br: true, br + "\npip install c": false, "pip install c\n" + br: false} {
		l := ParseLog(step(script, "Successfully installed a-1"))
		if got := l.Sections[1].Complete; got != want {
			t.Errorf("%q: complete=%v, want %v", script, got, want)
		}
	}
}

func TestParseLogTruncatedHeader(t *testing.T) {
	// the log ends inside the header group: the command still comes from the echo
	l := ParseLog(ts + "##[group]Run pip install x\n" + ts + "\x1b[36;1mpip install x\x1b[0m\n")
	if s := l.Sections[1]; !s.Python || s.Cmd != "pip install x" || s.Complete {
		t.Errorf("truncated: %+v", s)
	}
}

// sectionOf returns the only Python section of a one-step log.
func sectionOf(t *testing.T, log string) Section {
	t.Helper()
	l := ParseLog(log)
	if len(l.Sections) != 2 {
		t.Fatalf("sections: %+v", l.Sections)
	}
	return l.Sections[1]
}

func TestParseLogFixRound1(t *testing.T) {
	ok := "Successfully installed x-1"
	for name, c := range map[string]struct {
		script   string
		out      []string
		complete bool
	}{
		"I1a quiet after":   {"pip install x -q", []string{ok}, false},
		"I1a qq":            {"pip install -qq x", []string{ok}, false},
		"I1a combined":      {"pip install -qU x", []string{ok}, false},
		"I1a long":          {"pip install --quiet x", []string{ok}, false},
		"I1a redirect":      {"pip install x > pip.log", []string{ok}, false},
		"I1a append":        {"pip install x >> pip.log", []string{ok}, false},
		"I1a both":          {"pip install x &> pip.log", []string{ok}, false},
		"I1a devnull":       {"pip install x >/dev/null", []string{ok}, false},
		"I1a tail":          {"pip install x | tail -1", []string{ok}, false},
		"I1a grep":          {"pip install x | grep -v foo", []string{ok}, false},
		"I1a merge only":    {"pip install x 2>&1", []string{ok}, true},
		"I1a spec with >=":  {"pip install 'x>=1'", []string{ok}, true},
		"I1a or":            {"pip install x || exit 1", []string{ok}, true},
		"I1b script beside": {"pip install -q -r r.txt\n./scripts/extra.sh", []string{ok}, false},
		"I1b script":        {"pip install x\n./scripts/extra.sh", []string{ok}, false},
		"I1b make":          {"pip install x\nmake deps", []string{ok}, false},
		"I1b local path":    {"pip install ./pkg", []string{ok}, true},
		"I1c no commands":   {"./ci/install.sh", []string{ok}, false},
		"I3 resolved only":  {"uv sync", []string{"Resolved 3 packages in 1ms", ok}, false},
		"I3 resolved+inst":  {"uv sync", []string{"Resolved 1 package in 1ms", "Installed 1 package in 1ms", " + x==1"}, true},
		"M1 poetry pending": {"poetry install", []string{"Package operations: 2 installs, 0 updates, 0 removals",
			"  - Installing a (1): Pending...", "  - Installing a (1)"}, false},
		"M1 poetry distinct": {"poetry install", []string{"Package operations: 2 installs, 0 updates, 0 removals",
			"  - Installing a (1): Pending...", "  - Installing a (1)", "  - Installing b (2)"}, true},
		"M4 from file": {"uv sync", []string{"Installed 2 packages in 1ms", " + proj==0.1.0 (from file:///w/proj)", " + a==1"}, true},
		"M4 from git":  {"uv sync", []string{"Installed 1 package in 1ms", " + proj==0.1.0 (from git+https://x/y)"}, true},
	} {
		if got := sectionOf(t, step(c.script, c.out...)); got.Complete != c.complete {
			t.Errorf("%s: complete=%v, want %v (%+v)", name, got.Complete, c.complete, got)
		}
	}
	// M4: the project is recorded as an install
	if v := installs(ParseLog(step("uv sync", "Installed 1 package in 1ms", " + proj==0.1.0 (from file:///w)")))["proj"]; v != "0.1" {
		t.Errorf("proj: %q", v)
	}
}

func TestParseLogInstallerCalls(t *testing.T) {
	for _, line := range []string{"[command]/usr/bin/pip install x", "tox run", "pipenv install", "uvx ruff", "pdm install", "nox -s t",
		"conda install x", "mamba create", "pre-commit run", "hatch run t", "pixi install", "rye sync", "/opt/py/bin/pip list"} {
		if !ParseLog(step("echo hi", line)).Calls {
			t.Errorf("not a call: %q", line)
		}
	}
	if ParseLog(step("echo hi", "py3.12: OK", "ok  x 0.1s")).Calls {
		t.Error("tox env line counted as a call")
	}
}

func TestParseLogHeaderOutput(t *testing.T) {
	// a non-cyan line inside the header is output: an injected header must not hide install lines
	log := ts + "##[group]Run pip install x\n" + ts + "\x1b[36;1mpip install x\x1b[0m\n" +
		ts + "##[group]Run fake\n" + ts + "Successfully installed evil-9\n" + ts + "##[endgroup]\n"
	l := ParseLog(log)
	if installs(l)["evil"] != "9" || len(l.Sections) != 2 || l.Sections[1].Cmd != "pip install x" {
		t.Errorf("injected header: %+v", l)
	}
}
