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

func TestParseLogNoInstallCommands(t *testing.T) {
	for name, c := range map[string]struct {
		script   string
		out      []string
		complete bool
	}{
		"pytest":             {"python -m pytest", nil, true},
		"pip list":           {"pip list", nil, true},
		"pip version":        {"pip --version", []string{"pip 26.2 from /x (python 3.12)"}, true},
		"uv version":         {"uv --version", []string{"uv 0.12.1"}, true},
		"poetry config":      {"poetry config virtualenvs.in-project true", nil, true},
		"pytest installs":    {"python -m pytest", []string{"Successfully installed x-1"}, false},
		"make beside pytest": {"make test\npython -m pytest", nil, true},
		"make that installs": {"make test", []string{"Installed 3 packages in 1ms"}, false},
		"resolved only":      {"pip list", []string{"Resolved 3 packages in 1ms"}, false},
	} {
		l := ParseLog(step(c.script, c.out...))
		var py []Section
		for _, s := range l.Sections {
			if s.Python {
				py = append(py, s)
			}
		}
		if len(py) != 1 || py[0].Complete != c.complete {
			t.Errorf("%s: %+v", name, l.Sections)
		}
	}
}

func TestParseLogQuietEnvAndScope(t *testing.T) {
	ok := "Successfully installed x-1"
	withEnv := func(script, env string, out ...string) string {
		return strings.Replace(step(script, out...), ts+"shell:", ts+"env:\n"+ts+"  "+env+"\n"+ts+"shell:", 1)
	}
	for name, c := range map[string]struct {
		log      string
		complete bool
	}{
		"header UV_QUIET=1":     {withEnv("uv run pytest", "UV_QUIET: 1"), false},
		"header UV_QUIET=0":     {withEnv("uv run pytest", "UV_QUIET: 0"), true},
		"header PIP_QUIET=1":    {withEnv("pip install x", "PIP_QUIET: 1", ok), false},
		"header PIP_PROGRESS":   {withEnv("pip install x", "PIP_PROGRESS_BAR: off", ok), true},
		"header UV_NO_PROGRES":  {withEnv("uv run pytest", "UV_NO_PROGRESS: 1"), true},
		"script UV_QUIET=1":     {step("UV_QUIET=1 uv run pytest"), false},
		"script export":         {step("export PIP_QUIET=2\npip install x", ok), false},
		"script UV_QUIET=false": {step("UV_QUIET=false uv run pytest"), true},
		"later pytest -q":       {step("pip install x && pytest -q", ok), true},
		"later redirect":        {step("pip install x && pytest > out.txt", ok), true},
		"quoted gt":             {step(`pip install "numpy>1.20"`, "Successfully installed numpy-1.26.4"), true},
		"quoted single gt":      {step(`pip install 'numpy>1.20'`, "Successfully installed numpy-1.26.4"), true},
		"filter after":          {step("pip install x | tail -1", ok), false},
		"quiet own args":        {step("pip install -q x && pytest", ok), false},
		"redirect own":          {step("pip install x > log.txt && pytest", ok), false},
		"2>&1 then tail":        {step("pip install x 2>&1 | tail -3", ok), false},
	} {
		l := ParseLog(c.log)
		var py []Section
		for _, s := range l.Sections {
			if s.Python {
				py = append(py, s)
			}
		}
		if len(py) != 1 || py[0].Complete != c.complete {
			t.Errorf("%s: want complete=%v: %+v", name, c.complete, l.Sections)
		}
	}
}

func TestParseLogQuietSegments(t *testing.T) {
	// every step also runs a second install with its own listing, and three listings are printed:
	// only quiet detection decides
	out := []string{"Successfully installed x-1", "Successfully installed z-1", "Successfully installed w-1"}
	for script, complete := range map[string]bool{
		"# pip install x\npip install x | tail -1":            false,
		"echo \"pip install x\"\npip install x | tail -1":     false,
		"(pip install x) | tail":                              false,
		"{ pip install x; } > /dev/null":                      false,
		"{\n  pip install x\n} > log.txt":                     false,
		"out=$(pip install x)":                                false,
		"echo \"$(pip install x)\"":                           false,
		"echo `pip install x`":                                false,
		"if true; then pip install x; fi | tail -1":           false,
		"pip install -qr r.txt":                               false,
		"pip -q install x":                                    false,
		"python -m pip install --quiet x":                     false,
		"uv pip install -q x":                                 false,
		"poetry install -q":                                   false,
		"poetry -q install":                                   false,
		"pip install x 2>&1 >/dev/null":                       false,
		"pip install x >/dev/null 2>&1":                       false,
		"pip install x &> /dev/null":                          false,
		"pip install x 1>/dev/null":                           false,
		"pip install x >&2":                                   false,
		"pip install x | grep -v foo":                         false,
		"pip install x |& tail":                               false,
		"pip install x | tee log.txt > /dev/null":             false,
		"if true; then pip install -q x; fi":                  false,
		"pip install \\\n  -q x":                              false,
		"pip install x \\\n  | tail -1":                       false,
		"pip install x \\\n  > /dev/null":                     false,
		"pip install x `\n  --quiet":                          false,
		"pip install x `\n  | Out-Null":                       false,
		"cat r.txt | pip install -q -r /dev/stdin":            false,
		"pip install x=='1' | tail":                           false,
		"f() { pip install x; }\nf | tail":                    false,
		"function f {\n  pip install x\n}\nf > /dev/null":     false,
		"pip install \"numpy>1.20\"":                          true,
		"pip install -r r.txt && pytest -q":                   true,
		"pip install x 2>err.txt":                             true,
		"pip install x | tee log.txt":                         true,
		"(pip install x)":                                     true,
		"{ pip install x; } 2>err.txt":                        true,
		"pip install ${PKG_SPEC:-x} | tail":                   false,
		"pip install x  # | tail -q":                          true,
		"echo '| tail -q >'\npip install x":                   true,
		"cat r.txt | pip install -r /dev/stdin":               true,
		"if true; then pip install x; else pip install y; fi": true,
	} {
		s := sectionOf(t, step(script+"\npip install z", out...))
		if s.Complete != complete {
			t.Errorf("%q: complete=%v, want %v", script, s.Complete, complete)
		}
	}
}

func TestParseLogQuietRound5(t *testing.T) {
	out := []string{"Successfully installed x-1", "Successfully installed z-1", "Successfully installed w-1"}
	pwsh := func(script string) string {
		return strings.Replace(step(script+"\npip install z", out...), "shell: /usr/bin/bash -e {0}",
			`shell: C:\Program Files\PowerShell\7\pwsh.EXE -command ". '{0}'"`, 1)
	}
	for name, c := range map[string]struct {
		log      string
		complete bool
	}{
		"heredoc apostrophe":    {step("cat <<EOF\nDon't\nEOF\npip install x | tail -1\npip install z", out...), false},
		"pwsh newline escape":   {step("Write-Host \"`n\"\npip install -r r.txt | Out-Null\npip install z", out...), false},
		"pwsh tab escape":       {step("Write-Host \"a`tb\"\npip install x | Select-Object -Last 1\npip install z", out...), false},
		"pwsh escape clean":     {step("Write-Host \"a`tb\"\npip install x\npip install z", out...), true},
		"pwsh shell escape":     {pwsh("Write-Output \"a`tb\"\npip install x"), true},
		"pwsh shell pipe":       {pwsh("Write-Output \"a`tb\"\npip install x | Select-Object -Last 1"), false},
		"open quote":            {step("echo \"unterminated\npip install x | tail\npip install z", out...), false},
		"open quote no pipe":    {step("echo \"unterminated\npip install x\npip install z", out...), false},
		"open group":            {step("(pip install x\npip install z", out...), false},
		"heredoc quoted body":   {step("cat <<'EOF'\nDon't | tail\nEOF\npip install x\npip install z", out...), true},
		"heredoc dash":          {step("cat <<-EOF\n\tit's\n\tEOF\npip install x\npip install z", out...), true},
		"heredoc to file":       {step("cat > f.txt <<\"EOF\"\na'b > c\nEOF\npip install x\npip install z", out...), true},
		"heredoc bash":          {step("bash <<EOF\npip install x\nEOF\npip install z", out...), false},
		"heredoc bash quoted":   {step("bash <<'EOF'\npip install -q x\nEOF\npip install z", out...), false},
		"heredoc python":        {step("python - <<EOF\nimport os\nEOF\npip install z", out...), false},
		"heredoc piped to sh":   {step("cat <<EOF | sh\necho hi\nEOF\npip install z", out...), false},
		"heredoc unterminated":  {step("cat <<EOF\nno end\npip install z", out...), false},
		"arith shift":           {step("echo $((1<<2))\npip install z", out...), true},
		"here-string":           {step("cat <<<'it''s'\npip install z", out...), true},
		"exec devnull":          {step("exec >/dev/null\npip install z", out...), false},
		"exec 1>log":            {step("exec 1>log.txt\npip install z", out...), false},
		"exec &>log":            {step("exec &>log.txt\npip install z", out...), false},
		"exec stderr only":      {step("exec 2>err.txt\npip install z", out...), true},
		"round4 numpy quoted":   {step("pip install \"numpy>1.20\"\npip install z", out...), true},
		"round4 pytest -q":      {step("pip install -r r.txt && pytest -q\npip install z", out...), true},
		"round4 stderr to file": {step("pip install x 2>err.txt\npip install z", out...), true},
	} {
		if s := sectionOf(t, c.log); s.Complete != c.complete {
			t.Errorf("%s: complete=%v, want %v (%q)", name, s.Complete, c.complete, s.Cmd)
		}
	}
	// a call with parentheses inside quotes is not a function definition
	if quietOutput("python -c \"import torch; print(torch.cuda.is_available())\"\npip install x", false) {
		t.Error("quoted call counted as a function definition")
	}
	if !quietOutput("f() { pip install x; }\nf | tail", false) {
		t.Error("function definition not quiet")
	}
}

func TestParseLogFinalReview(t *testing.T) {
	// C2: a function definition is found outside comments and quotes, whatever a comment holds
	for _, script := range []string{
		"# don't run twice\ninst() { pip install -r requirements-$1.txt; }\ninst dev\ninst test > /dev/null\necho 'done'",
		"inst () {\n  pip install -r r.txt\n}\ninst > /dev/null",
		"function inst {\n  pip install -r r.txt\n}\ninst | tail -1",
	} {
		if !quietOutput(script, false) {
			t.Errorf("%q: function definition not quiet", script)
		}
	}
	for _, script := range []string{"arr=()\npip install x", "echo 'f() { }'\npip install x", "# f() {\npip install x", "$v = $x.Trim()\npip install x"} {
		if quietOutput(script, false) {
			t.Errorf("%q: quiet", script)
		}
	}
	setup := func(with string, out ...string) string {
		log := ts + "##[group]Run actions/setup-python@v5\n" + ts + "with:\n" + ts + "  python-version: 3.12\n"
		if with != "" {
			log += ts + "  " + with + "\n"
		}
		log += ts + "  check-latest: false\n" + ts + "##[endgroup]\n"
		for _, l := range out {
			log += ts + l + "\n"
		}
		return log
	}
	for name, c := range map[string]struct {
		log      string
		python   bool
		complete bool
	}{
		// C3: an install command printed in the output (make, set -x) makes the step Python
		"make echoes quiet pip":   {step("make deps", "pip install -q -r requirements.txt"), true, false},
		"make echoes python -m":   {step("make deps", "python -m pip install -q -r requirements.txt"), true, false},
		"xtrace quiet pip":        {step("./ci/install.sh", "+ pip install -q -r requirements.txt"), true, false},
		"xtrace nested":           {step("./ci/install.sh", "++ uv sync --quiet"), true, false},
		"make echoes tox":         {step("make lint", "tox -e lint", "lint: OK"), true, false},
		"make prints listing":     {step("make deps", "pip install -r requirements.txt", "Successfully installed six-1.17.0"), true, false},
		"banners are not install": {step("make test", "Python 3.12.1", "pip 24.0 from /x (python 3.12)", "[notice] A new release of pip is available: 24.0 -> 25.2", "[notice] To update, run: python.exe -m pip install --upgrade pip", "[notice] To update, run: pip install --upgrade pip", "Using Python 3.12.1 environment at: /x"), false, true},
		"echoed text":             {step("make help", "echo pip install x", "run: pip install x"), false, true},
		// I2: setup-python's pip-install input is an install command of its own
		"setup no pip-install":     {setup(""), true, true},
		"setup pip-install quiet":  {setup("pip-install: -q litellm", "Successfully installed litellm-1.82.9"), true, false},
		"setup pip-install silent": {setup("pip-install: litellm"), true, false},
		"setup pip-install listed": {setup("pip-install: litellm", "Successfully installed litellm-1.82.9"), true, true},
		// I3: "Requirement already satisfied" is one listing per pip invocation that it accounts for
		"starter pip current":            {step(starter, "Requirement already satisfied: pip in /x (25.3)", "Successfully installed flake8-7 pytest-8", "Successfully installed six-1.17.0"), true, true},
		"starter no requirements":        {step(starter, "Successfully installed pip-25.3", "Successfully installed flake8-7 pytest-8"), true, true},
		"starter pip current no req":     {step(starter, "Requirement already satisfied: pip in /x (25.3)", "Successfully installed flake8-7 pytest-8"), true, true},
		"starter all satisfied":          {step(starter, "Requirement already satisfied: pip in /x (25.3)", "Requirement already satisfied: flake8 in /x (7)", "Requirement already satisfied: pytest in /x (8)"), true, true},
		"starter silent":                 {step(starter, "Successfully installed flake8-7 pytest-8"), true, false},
		"requirements satisfied after":   {step(upgrade+"\npip install -r requirements.txt", "Successfully installed pip-25.3", "Requirement already satisfied: six in /x (from -r requirements.txt (line 1)) (1.17.0)"), true, true},
		"requirements satisfied before":  {step(upgrade+"\npip install -r requirements.txt", "Requirement already satisfied: six in /x (from -r requirements.txt (line 1)) (1.17.0)", "Successfully installed pip-25.3"), true, false},
		"one series for two":             {step(upgrade+"\npip install -r requirements.txt", "Requirement already satisfied: pip in /x (25.3)"), true, false},
		"dependency line is not a named": {step(upgrade+"\npip install flake8", "Requirement already satisfied: pip in /x (from flake8) (25.3)", "Successfully installed flake8-7"), true, false},
		"named needs every package":      {step("pip install a b\npip install c", "Requirement already satisfied: a in /x (1)", "Successfully installed c-1"), true, false},
		"if without else runs":           {step("if [ -f r.txt ]; then pip install -r r.txt; fi", "Successfully installed six-1.17.0"), true, true},
		"if without else, silent other":  {step("if [ -f r.txt ]; then\n  pip install -r r.txt\nfi\npip install x"), true, false},
		"if without else, other listed":  {step("if [ -f r.txt ]; then\n  pip install -r r.txt\nfi\npip install x", "Successfully installed x-1"), true, true},
		"one-line if with else":          {step("if [ -f r.txt ]; then pip install -r r.txt; else pip install y; fi\npip install x", "Successfully installed x-1"), true, false},
	} {
		l := ParseLog(c.log)
		if len(l.Sections) != 2 || l.Sections[1].Python != c.python || c.python && l.Sections[1].Complete != c.complete {
			t.Errorf("%s: %+v", name, l.Sections)
		}
	}
}

const (
	upgrade = "python -m pip install --upgrade pip"
	starter = upgrade + "\npip install flake8 pytest\nif [ -f requirements.txt ]; then pip install -r requirements.txt; fi"
)

func TestParseLogDemoExcerpts(t *testing.T) {
	// real job-log excerpts of runsweep/runsweep-demo: each tool lists six 1.17.0 in a complete Python section
	for _, n := range []string{"demo-pip.log", "demo-uv.log", "demo-poetry.log"} {
		b, err := os.ReadFile("testdata/logs/" + n) //nolint:gosec // G304: test fixture path
		if err != nil {
			t.Fatal(err)
		}
		l := ParseLog(string(b))
		if installs(l)["six"] != "1.17" {
			t.Errorf("%s: %v", n, installs(l))
		}
	}
}
