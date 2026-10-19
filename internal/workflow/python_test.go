package workflow

import (
	"slices"
	"testing"
)

func TestPyInstalls(t *testing.T) {
	type want struct {
		tool    string
		opaque  bool
		dynamic bool
		pkgs    []string
	}
	for script, w := range map[string][]want{
		"pip install -r requirements.txt":                         {{tool: "pip install"}},
		"python3.12 -m pip install --upgrade pip LiteLLM==1.82.8": {{tool: "pip install", pkgs: []string{"pip", "litellm"}}},
		".venv/bin/python -m pip install 'litellm[proxy]>=1.82'":  {{tool: "pip install", pkgs: []string{"litellm"}}},
		"sudo -H pip3.12 install -q requests":                     {{tool: "pip install", pkgs: []string{"requests"}}},
		"py -m pip install -e . -c constraints.txt":               {{tool: "pip install"}},
		"pip install $PKG":           {{tool: "pip install", dynamic: true}},
		"uv sync --frozen":           {{tool: "uv sync"}},
		"uv --directory app sync":    {{tool: "uv sync"}},
		"uv pip install ruff==0.1":   {{tool: "uv pip install", pkgs: []string{"ruff"}}},
		"uv add flask":               {{tool: "uv add", pkgs: []string{"flask"}}},
		"poetry install --no-root":   {{tool: "poetry install"}},
		"poetry -q install":          {{tool: "poetry install"}},
		"uv tool install tox":        {{tool: "uv tool install", pkgs: []string{"tox"}}},
		"uv run pytest":              nil,
		"uv run --with rich pytest":  {{tool: "uv run", opaque: true}},
		"uv run -q pytest":           {{tool: "uv run", opaque: true}},
		"uv run --no-project x.py":   {{tool: "uv run", opaque: true}},
		"uv run pip install x":       {{tool: "pip install", pkgs: []string{"x"}}},
		"uv run --frozen tox":        {{tool: "tox", opaque: true}},
		"poetry run pytest":          nil,
		"uvx ruff check":             {{tool: "uvx", opaque: true, pkgs: []string{"ruff", "check"}}},
		"tox -e py312":               {{tool: "tox", opaque: true}},
		"pre-commit run --all-files": {{tool: "pre-commit", opaque: true}},
		"python -m build":            {{tool: "python -m build", opaque: true}},
		"pip wheel .":                {{tool: "pip wheel", opaque: true}},
		"pip download x==1":          {{tool: "pip download", opaque: true}},
		"poetry lock":                {{tool: "poetry lock", opaque: true}},
		"pipx install poetry":        {{tool: "pipx install", opaque: true, pkgs: []string{"poetry"}}},
		"pip mystery-sub":            {{tool: "pip mystery-sub", opaque: true}},
		// F1: real commands behind wrappers and keywords
		"if pip install x; then echo ok; fi":              {{tool: "pip install", pkgs: []string{"x"}}},
		"! pip install x":                                 {{tool: "pip install", pkgs: []string{"x"}}},
		"PIP_INDEX_URL=https://i.example/s pip install x": {{tool: "pip install", pkgs: []string{"x"}}},
		"timeout 600 pip install x":                       {{tool: "pip install", pkgs: []string{"x"}}},
		"command pip install x":                           {{tool: "pip install", pkgs: []string{"x"}}},
		"sudo -u ci pip install x":                        {{tool: "pip install", pkgs: []string{"x"}}},
		"bash -c 'pip install x'":                         {{tool: "pip install", pkgs: []string{"x"}}},
		"poetry run pip install x":                        {{tool: "pip install", pkgs: []string{"x"}}},
		"conda run -n e pip install x":                    {{tool: "conda run", opaque: true}},
		"micromamba run -n e pip install x":               {{tool: "micromamba run", opaque: true}},
		"pdm run pytest":                                  {{tool: "pdm run", opaque: true}},
		"foo pip install x":                               {{tool: "pip (unrecognised position)", opaque: true}},
		"# pip install x\nwhich pip\ncommand -v python":   nil,
		"echo \"# c\"; pip install x":                     {{tool: "pip install", pkgs: []string{"x"}}},
		// F2: interpreter flags and modules
		"py -3.12 -m pip install x":      {{tool: "pip install", pkgs: []string{"x"}}},
		"python -I -m pip install x":     {{tool: "pip install", pkgs: []string{"x"}}},
		"python3 -mpip install x":        {{tool: "pip install", pkgs: []string{"x"}}},
		"python -X dev -m pip install x": {{tool: "pip install", pkgs: []string{"x"}}},
		"pypy3 -m pip install x":         {{tool: "pip install", pkgs: []string{"x"}}},
		"python -m tox":                  {{tool: "python -m tox", opaque: true}},
		"python -m nox":                  {{tool: "python -m nox", opaque: true}},
		"python -m pre_commit run":       {{tool: "python -m pre_commit", opaque: true}},
		"python -m piptools sync":        {{tool: "python -m piptools", opaque: true}},
		"python -m uv sync":              {{tool: "uv sync"}},
		"python -m poetry install":       {{tool: "poetry install"}},
		"python -m pipx install poetry":  {{tool: "pipx install", opaque: true, pkgs: []string{"poetry"}}},
		"python -m hatch build":          {{tool: "python -m hatch", opaque: true}},
		"python -m pdm install":          {{tool: "python -m pdm", opaque: true}},
		"python setup.py install":        {{tool: "python setup.py install", opaque: true}},
		"python setup.py bdist_wheel":    {{tool: "python setup.py bdist_wheel", opaque: true}},
		"python setup.py --version":      nil,
		// F3: quoted command words
		`"$VENV/bin/python" -m pip install x`:                    {{tool: "pip install", pkgs: []string{"x"}}},
		`"${{ steps.py.outputs.python-path }}" -m pip install x`: {{tool: "pip install", pkgs: []string{"x"}}},
		`"/my dir/python" -m pip install x`:                      {{tool: "pip install", pkgs: []string{"x"}}},
		// F4c: case-insensitive
		"PIP.EXE install x": {{tool: "pip install", pkgs: []string{"x"}}},
		// R2-2: substitutions inside echo arguments run
		"echo `pip install -q x`":              {{tool: "pip install", pkgs: []string{"x"}}},
		"echo \"$(pip install -q x)\"":         {{tool: "pip install", pkgs: []string{"x"}}},
		"echo `pip install a` `pip install b`": {{tool: "pip install", pkgs: []string{"a"}}, {tool: "pip install", pkgs: []string{"b"}}},
		"python -c 'import pip'":               {{tool: "python -c", opaque: true}},
		// C1: a tool word at the start of the next line is not consumed by the previous one
		"pip install pre-commit\npre-commit run --all-files":     {{tool: "pip install", pkgs: []string{"pre-commit"}}, {tool: "pre-commit", opaque: true}},
		"python -m pip install --upgrade pip\nuv run --with x t": {{tool: "pip install", pkgs: []string{"pip"}}, {tool: "uv run", opaque: true}},
		"pip install tox\ntox":                                   {{tool: "pip install", pkgs: []string{"tox"}}, {tool: "tox", opaque: true}},
		"pip install -U pip;pip install x":                       {{tool: "pip install", pkgs: []string{"pip"}}, {tool: "pip install", pkgs: []string{"x"}}},
		"pip install a\npip install b\npip install c":            {{tool: "pip install", pkgs: []string{"a"}}, {tool: "pip install", pkgs: []string{"b"}}, {tool: "pip install", pkgs: []string{"c"}}},
		"pip install a;pip install b;pip install c":              {{tool: "pip install", pkgs: []string{"a"}}, {tool: "pip install", pkgs: []string{"b"}}, {tool: "pip install", pkgs: []string{"c"}}},
		"tox\ntox\ntox": {{tool: "tox", opaque: true}, {tool: "tox", opaque: true}, {tool: "tox", opaque: true}},
		// F5
		"echo x | xargs pip install": {{tool: "pip install", dynamic: true}},
		"pip install x < reqs.txt":   {{tool: "pip install", pkgs: []string{"x"}}},
		"pip install < reqs.txt":     {{tool: "pip install"}},
		"pip list\npip --version\npython x.py\nuv --version\npoetry config virtualenvs.create false": nil,
		"echo pip install x": nil, // quoted-free echo argument is not a command word
	} {
		got := PyInstalls(script)
		if len(got) != len(w) {
			t.Errorf("%q: got %+v", script, got)
			continue
		}
		for i := range w {
			g := got[i]
			if g.Tool != w[i].tool || g.Opaque != w[i].opaque || g.Dynamic != w[i].dynamic || !slices.Equal(g.Pkgs, w[i].pkgs) {
				t.Errorf("%q[%d]: got %+v, want %+v", script, i, g, w[i])
			}
		}
	}
}

func TestHasPythonAndActions(t *testing.T) {
	job := func(uses []string, runs ...string) *Job { return &Job{Uses: uses, Runs: runs} }
	co := []string{"actions/checkout@v4"}
	for name, c := range map[string]struct {
		j          *Job
		has, actOK bool
	}{
		"no python":      {job(co, "make test"), true, true}, // opaque runner may run pip
		"plain":          {job(co, "go test ./..."), false, true},
		"setup-node":     {job(append(co, "actions/setup-node@v4"), "go test"), false, true},
		"setup-python":   {job(append(co, "actions/setup-python@v5"), "go test"), true, true},
		"setup-uv":       {job(append(co, "astral-sh/setup-uv@v6"), "uv sync"), true, true},
		"install-poetry": {job(append(co, "snok/install-poetry@v1"), "poetry install"), true, false},
		"third party":    {job(append(co, "some/action@v1")), true, false},
		"local":          {job(append(co, "./.github/actions/x")), true, false},
		"pip":            {job(co, "pip install x"), true, true},
		"cargo":          {job(co, "cargo build"), true, true}, // buildRe: maturin/pip hooks
	} {
		if c.j.HasPython() != c.has || c.j.PyActionsOK() != c.actOK {
			t.Errorf("%s: HasPython=%v PyActionsOK=%v", name, c.j.HasPython(), c.j.PyActionsOK())
		}
	}
}

func TestHasPythonF4(t *testing.T) {
	for name, j := range map[string]*Job{
		"sudo path":      {Runs: []string{"sudo tools/setup"}},
		"assign path":    {Runs: []string{"FOO=1 scripts/x"}},
		"timeout path":   {Runs: []string{"timeout 5 scripts/x"}},
		"time path":      {Runs: []string{"time scripts/x"}},
		"script path":    {Runs: []string{"script/bootstrap"}},
		"after cd":       {Runs: []string{"cd x && scripts/setup"}},
		"backslash path": {Runs: []string{`tools\setup.cmd`}},
		"shell python":   {Runs: []string{"print(1)"}, Shells: []string{"python {0}"}},
		"shell template": {Runs: []string{"x"}, Shells: []string{"${{ matrix.shell }}"}},
		"upper pip":      {Runs: []string{"PIP.EXE install x"}},
		"pypy":           {Runs: []string{"pypy3 -m pip install x"}},
	} {
		if !j.HasPython() {
			t.Errorf("%s: HasPython=false", name)
		}
	}
	for name, j := range map[string]*Job{
		"cd path arg": {Runs: []string{"cd a/b\nmkdir -p c/d\necho x/y"}},
		"bash shell":  {Runs: []string{"go test"}, Shells: []string{"bash", "pwsh", "bash --noprofile -e {0}"}},
	} {
		if j.HasPython() {
			t.Errorf("%s: HasPython=true", name)
		}
	}
}

func TestParseShells(t *testing.T) {
	w, err := Parse([]byte("defaults:\n  run:\n    shell: bash\njobs:\n  a:\n    defaults:\n      run:\n        shell: pwsh\n    steps:\n      - run: x\n        shell: python {0}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := w.Jobs["a"].Shells; !slices.Equal(got, []string{"bash", "pwsh", "python {0}"}) {
		t.Errorf("Shells = %q", got)
	}
}
