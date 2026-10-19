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
	// uv run prints only a count: not complete
	for _, s := range read("flask-uv-run.log").Sections {
		if strings.Contains(s.Cmd, "uv run") && (s.Opaque == "" || s.Complete) {
			t.Errorf("flask uv run: %+v", s)
		}
	}
	// uv with 15 + lines: complete, 15 installs
	l := read("pytest-uv.log")
	if len(l.Installs) < 15 || !slices.ContainsFunc(l.Sections, func(s Section) bool { return s.Python && s.Complete }) {
		t.Errorf("pytest uv: %d installs, %+v", len(l.Installs), l.Sections)
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
