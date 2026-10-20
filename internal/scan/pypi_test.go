package scan

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
	"github.com/runsweep/runsweep/internal/source"
	"github.com/runsweep/runsweep/internal/source/sourcetest"
)

var pypiOnly = &incident.Incident{ID: "p", Window: npmOnly.Window,
	PyPI: []incident.PyPIPackage{{Name: "litellm", Versions: []string{"1.82.8"}}}}

const lts = "2026-03-31T01:00:00Z "

func pyStep(script string, out ...string) string {
	s := lts + "##[group]Run " + strings.SplitN(script, "\n", 2)[0] + "\n"
	for _, l := range strings.Split(script, "\n") {
		s += lts + "\x1b[36;1m" + l + "\x1b[0m\n"
	}
	s += lts + "##[endgroup]\n"
	for _, l := range out {
		s += lts + l + "\n"
	}
	return s
}

// pyFx: one run, one job "t", workflow steps as given, the job log as given.
func pyFx(steps, log string, files ...string) *sourcetest.Fake {
	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
	f.Jobs[1] = []source.Job{{ID: 10, Name: "t"}}
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("on: push\njobs:\n  t:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n"+steps))
	for i := 0; i+1 < len(files); i += 2 {
		f.AddFile("o/a", "s1", files[i], []byte(files[i+1]))
	}
	f.Logs[10] = log
	return f
}

func TestScanPyPI(t *testing.T) {
	pip := "      - run: pip install -r requirements.txt\n"
	pinned := []string{"requirements.txt", "litellm==1.82.8\n"}
	for name, c := range map[string]struct {
		f      *sourcetest.Fake
		status model.Status
		note   string
	}{
		"rule 0 no python":          {pyFx("      - run: go test ./...\n", pyStep("go test ./..."), pinned...), model.Clean, ""},
		"rule 1 log shows bad":      {pyFx(pip, pyStep("pip install -r requirements.txt", "Successfully installed litellm-1.82.8")), model.Affected, ""},
		"rule 1 uv coloured":        {pyFx("      - run: uv sync\n", pyStep("uv sync", "Installed 1 package in 1ms", " \x1b[32m+\x1b[39m litellm==1.82.8")), model.Affected, ""},
		"rule 2 unparsed":           {pyFx(pip, pyStep("pip install -r requirements.txt", "Successfully installed litellm-1.82.8!!x")), model.Unchecked, "unparsed install line for"},
		"rule 3 named":              {pyFx("      - run: pip install -q litellm\n", pyStep("pip install -q litellm")), model.Possible, "runs `pip install -q litellm` at run time"},
		"rule 3 other version seen": {pyFx("      - run: pip install litellm\n", pyStep("pip install litellm", "Successfully installed litellm-1.82.9")), model.Clean, ""},
		"rule 3 extra script":       {pyFx("      - run: |\n          pip install litellm && ./extra.sh\n", pyStep("pip install litellm && ./extra.sh", "Successfully installed litellm-1.82.9")), model.Possible, "runs `pip install litellm"},
		"rule 4 dynamic":            {pyFx("      - run: pip install $PKG\n", pyStep("pip install $PKG", "Successfully installed x-1")), model.Unchecked, "package named at run time"},
		"rule 5 quiet job":          {pyFx("      - run: make test\n", pyStep("make test", "ok"), pinned...), model.Clean, ""},
		"rule 6 complete":           {pyFx(pip, pyStep("pip install -r requirements.txt", "Successfully installed requests-2.32.0"), pinned...), model.Clean, ""},
		"rule 7 quiet pinned":       {pyFx("      - run: pip install -q -r requirements.txt\n", pyStep("pip install -q -r requirements.txt"), pinned...), model.Possible, "lockfile pins litellm==1.82.8: requirements.txt"},
		"rule 7 tox pinned":         {pyFx("      - run: tox\n", pyStep("tox", "py: install_deps> python -I -m pip install"), pinned...), model.Possible, "Python install output not visible: tox"},
		"rule 8 quiet":              {pyFx("      - run: pip install -q -r requirements.txt\n", pyStep("pip install -q -r requirements.txt")), model.Unchecked, "Python install output incomplete in step: pip install -q -r requirements.txt"},
		"rule 8 uv run":             {pyFx("      - run: uv run pytest\n", pyStep("uv run pytest", "Installed 23 packages in 10ms")), model.Unchecked, "Python install output incomplete in step: uv run pytest"},
		"rule 8 third-party action": {pyFx("      - uses: snok/install-poetry@v1\n      - run: poetry install\n", pyStep("snok/install-poetry@v1")+pyStep("poetry install", "Package operations: 1 install, 0 updates, 0 removals", "  - Installing six (1.17.0)")), model.Unchecked, "action snok/install-poetry@v1 may install Python packages"},
		"rule 8 pdm":                {pyFx("      - run: pip install -q .\n", pyStep("pip install -q ."), "pdm.lock", "x"), model.Unchecked, "Python install output incomplete in step"},
		"composite nested quiet":    {pyFx("      - uses: ./.github/actions/setup\n", pyStep("./.github/actions/setup")+pyStep("pip install -q -r r.txt")), model.Unchecked, ""},
	} {
		fd := scanAny(t, c.f, pypiOnly)
		if fd.Status != c.status || c.note != "" && !hasNote(fd, c.note) && !hasEvidence(fd, c.note) {
			t.Errorf("%s: %+v", name, fd)
		}
	}
	// log unavailable
	gone := pyFx(pip, "")
	gone.GoneLogs[10] = true
	if fd := scanOne(t, gone, pypiOnly); fd.Status != model.Unchecked || !hasNote(fd, "job log unavailable: Python installs not verified") {
		t.Errorf("gone log: %+v", fd)
	}
	// unidentified job: never CLEAN by rule 6
	unk := pyFx(pip, pyStep("pip install -r requirements.txt", "Successfully installed requests-2.32.0"))
	unk.Jobs[1][0].Name = "unknown"
	if fd := scanOne(t, unk, pypiOnly); fd.Status != model.Unchecked || !hasNote(fd, "job not identified in workflow file") {
		t.Errorf("unidentified: %+v", fd)
	}
	// pull_request_target: a log line stays AFFECTED, a clean job is at least UNCHECKED
	base := pyFx(pip, pyStep("pip install -r requirements.txt", "Successfully installed litellm-1.82.8"))
	base.Runs["o/a"][0].Event = "pull_request_target"
	if fd := scanOne(t, base, pypiOnly); fd.Status != model.Affected {
		t.Errorf("base event log: %+v", fd)
	}
	// mixed incident: the worse of npm and PyPI
	mixed := *pypiOnly
	mixed.NPM = npmOnly.NPM
	if fd := scanOne(t, pyFx(pip, pyStep("pip install -r requirements.txt", "Successfully installed litellm-1.82.8")), &mixed); fd.Status != model.Affected {
		t.Errorf("mixed: %+v", fd)
	}
}

func TestScanPyPIGates(t *testing.T) {
	// workflow file unavailable: UNCHECKED for a PyPI-only incident too
	f := pyFx("", "")
	delete(f.Blobs, f.Trees["o/a@s1"][0].SHA)
	f.Trees["o/a@s1"] = nil
	if fd := scanOne(t, f, pypiOnly); fd.Status != model.Unchecked {
		t.Errorf("no workflow: %+v", fd)
	}
	// an unpinned called workflow may install anything
	g := sourcetest.New()
	g.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
	g.Jobs[1] = []source.Job{{ID: 10, Name: "call / t"}}
	g.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("on: push\njobs:\n  call:\n    uses: other/repo/.github/workflows/x.yml@main\n"))
	g.Logs[10] = pyStep("go test")
	if fd := scanOne(t, g, pypiOnly); fd.Status != model.Unchecked {
		t.Errorf("unpinned call: %+v", fd)
	}
}

// scanAny is scanOne that reports a job with no finding as CLEAN.
func scanAny(t *testing.T, f *sourcetest.Fake, i *incident.Incident) model.Finding {
	t.Helper()
	res, err := Run(context.Background(), f, i, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 {
		return model.Finding{Status: model.Clean}
	}
	return scanOne(t, f, i)
}

func TestScanPyPIEvents(t *testing.T) {
	pip := "      - run: pip install -r requirements.txt\n"
	clean := pyFx(pip, pyStep("pip install -r requirements.txt", "Successfully installed requests-2.32.0"))
	clean.Runs["o/a"][0].Event = "pull_request_target"
	if fd := scanAny(t, clean, pypiOnly); fd.Status != model.Unchecked {
		t.Errorf("base event clean: %+v", fd)
	}
	// npm POSSIBLE survives a CLEAN PyPI verdict
	mixed := *pypiOnly
	mixed.NPM = npmOnly.NPM
	f := pyFx("      - run: npm install "+npmOnly.NPM[0].Name+"\n", pyStep("npm install "+npmOnly.NPM[0].Name))
	if fd := scanAny(t, f, &mixed); fd.Status < model.Possible || !hasEvidence(fd, "run time") {
		t.Errorf("mixed npm: %+v", fd)
	}
}

func TestScanPyPIFinalReview(t *testing.T) {
	run := func(script string) string {
		return "      - run: |\n          " + strings.ReplaceAll(script, "\n", "\n          ") + "\n"
	}
	sp := "      - uses: actions/setup-python@v5\n"
	setupLog := pyStep("actions/setup-python@v5")
	f3 := "# don't run twice\ninst() { pip install -r requirements-$1.txt; }\ninst dev\ninst test > /dev/null\necho 'done'"
	starter := "python -m pip install --upgrade pip\npip install flake8 pytest\nif [ -f requirements.txt ]; then pip install -r requirements.txt; fi"
	for name, c := range map[string]struct {
		f      *sourcetest.Fake
		status model.Status
	}{
		// C1: a closed substitution before the command word
		"assign subst":      {pyFx(run("X=$(cat f) pip install -q -r requirements.txt"), pyStep("X=$(cat f) pip install -q -r requirements.txt")), model.Unchecked},
		"assign subst pkgs": {pyFx(run("PYTHONPATH=$(dirname .) pip install -q litellm"), pyStep("PYTHONPATH=$(dirname .) pip install -q litellm")), model.Possible},
		"which python":      {pyFx(sp+run("$(which python) -m pip install -q -r requirements.txt"), setupLog+pyStep("$(which python) -m pip install -q -r requirements.txt")), model.Unchecked},
		"which quoted":      {pyFx(run(`"$(which python)" -m pip install -q -r requirements.txt`), pyStep(`"$(which python)" -m pip install -q -r requirements.txt`)), model.Unchecked},
		"command -v":        {pyFx(run("$(command -v python3) -m pip install -q -r requirements.txt"), pyStep("$(command -v python3) -m pip install -q -r requirements.txt")), model.Unchecked},
		"sudo which pip":    {pyFx(run("sudo $(which pip) install -q x"), pyStep("sudo $(which pip) install -q x")), model.Unchecked},
		// C2: an apostrophe in a comment does not hide a function definition
		"function F3": {pyFx(run(f3), pyStep(f3, "Successfully installed six-1.17.0")), model.Unchecked},
		// C3: an install command printed by make or set -x
		"make echoes":       {pyFx(run("make deps"), pyStep("make deps", "pip install -q -r requirements.txt")), model.Unchecked},
		"make echoes setup": {pyFx(sp+run("make deps"), setupLog+pyStep("make deps", "python -m pip install -q -r requirements.txt")), model.Unchecked},
		"xtrace":            {pyFx(sp+run("./ci/install.sh"), setupLog+pyStep("./ci/install.sh", "+ pip install -q -r requirements.txt")), model.Unchecked},
		// I2: setup-python pip-install
		"setup pip-install": {pyFx("      - uses: actions/setup-python@v5\n        with:\n          pip-install: -q litellm\n"+run("pytest"),
			lts+"##[group]Run actions/setup-python@v5\n"+lts+"with:\n"+lts+"  pip-install: -q litellm\n"+lts+"##[endgroup]\n"+pyStep("pytest")), model.Unchecked},
		// I3: the GitHub "Python application" starter
		"starter pip current": {pyFx(sp+run(starter), setupLog+pyStep(starter, "Requirement already satisfied: pip in /x (25.3)",
			"Successfully installed flake8-7.1.0 pytest-8.3.0", "Successfully installed six-1.17.0")), model.Clean},
		"starter no requirements": {pyFx(sp+run(starter), setupLog+pyStep(starter, "Successfully installed pip-25.3",
			"Successfully installed flake8-7.1.0 pytest-8.3.0")), model.Clean},
		// M2: a default value names the installer
		"default installer": {pyFx(run(`"${PIP_CMD:-pip}" install -q -r r.txt`), pyStep(`"${PIP_CMD:-pip}" install -q -r r.txt`)), model.Unchecked},
	} {
		if fd := scanAny(t, c.f, pypiOnly); fd.Status != c.status {
			t.Errorf("%s: %v, want %v (%+v)", name, fd.Status, c.status, fd)
		}
	}
}

// TestScanPyPINoPackages: a pip install that names no package is never credited with a listing.
func TestScanPyPINoPackages(t *testing.T) {
	run := func(script string) string {
		return "      - run: |\n          " + strings.ReplaceAll(script, "\n", "\n          ") + "\n"
	}
	sp := "      - uses: actions/setup-python@v5\n"
	setupLog := pyStep("actions/setup-python@v5")
	ras := "Requirement already satisfied: pip in /x (25.3)"
	for name, c := range map[string]struct{ script, listing string }{
		"group no output":           {"pip install --group test", ""},
		"quiet config":              {"pip config set global.quiet true\npip install --group test", ""},
		"upgrade pip first":         {"python -m pip install --upgrade pip\npip install --group test", ras},
		"group and -r, one listing": {"pip install --group test\npip install -r requirements.txt", "Successfully installed six-1.17.0"},
		"constraints only":          {"pip install -c c.txt", ""},
	} {
		var out []string
		if c.listing != "" {
			out = []string{c.listing}
		}
		f := pyFx(sp+run(c.script), setupLog+pyStep(c.script, out...))
		if fd := scanAny(t, f, pypiOnly); fd.Status == model.Clean {
			t.Errorf("%s: CLEAN (%+v)", name, fd)
		}
	}
}

// TestScanPyPITox: tox is read from its listings.
func TestScanPyPITox(t *testing.T) {
	steps := "      - uses: actions/setup-python@v5\n      - run: pip install tox\n      - run: tox -e py\n"
	head := pyStep("actions/setup-python@v5") + pyStep("pip install tox", "Successfully installed tox-4.66.0 virtualenv-21.14.8")
	toxLog := func(listing string, more ...string) string {
		return head + pyStep("tox -e py", slices.Concat([]string{"py: install_deps> python -I -m pip install litellm pytest",
			"py: freeze> python -m pip freeze --all", "py: " + listing, "py: commands[0]> pytest"}, more, []string{"  py: OK (1.00 seconds)"})...)
	}
	for name, c := range map[string]struct {
		log    string
		status model.Status
		note   string
	}{
		"listed clean":          {toxLog("litellm==1.82.9,pytest==8.0.0"), model.Clean, ""},
		"listed bad":            {toxLog("litellm==1.82.8,pytest==8.0.0"), model.Affected, "litellm==1.82.8 in job log"},
		"bad entry shape":       {toxLog("litellm @ https://example.com/litellm-1.82.8.whl"), model.Unchecked, "unparsed install line for litellm"},
		"no listing":            {head + pyStep("tox -e py", "py: install_deps> python -I -m pip install litellm", "  py: OK"), model.Unchecked, "Python install output not visible: tox"},
		"quiet pip in commands": {toxLog("litellm==1.82.9", "py: commands[1]> pip install -q -r extra.txt"), model.Unchecked, "Python install output incomplete in step: tox -e py"},
	} {
		if fd := scanAny(t, pyFx(steps, c.log), pypiOnly); fd.Status != c.status || c.note != "" && !hasNote(fd, c.note) && !hasEvidence(fd, c.note) {
			t.Errorf("%s: %+v", name, fd)
		}
	}
	quiet := pyFx(strings.Replace(steps, "tox -e py", "tox -q -e py", 1), strings.Replace(toxLog("litellm==1.82.9"), "tox -e py", "tox -q -e py", 2))
	if fd := scanAny(t, quiet, pypiOnly); fd.Status != model.Unchecked {
		t.Errorf("tox -q: %+v", fd)
	}
}
