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
		"uv run pytest":              {{tool: "uv run", opaque: true}},
		"uvx ruff check":             {{tool: "uvx", opaque: true, pkgs: []string{"ruff", "check"}}},
		"tox -e py312":               {{tool: "tox", opaque: true}},
		"pre-commit run --all-files": {{tool: "pre-commit", opaque: true}},
		"python -m build":            {{tool: "python -m build", opaque: true}},
		"pip wheel .":                {{tool: "pip wheel", opaque: true}},
		"pip download x==1":          {{tool: "pip download", opaque: true}},
		"poetry lock":                {{tool: "poetry lock", opaque: true}},
		"pipx install poetry":        {{tool: "pipx install", opaque: true, pkgs: []string{"poetry"}}},
		"pip mystery-sub":            {{tool: "pip mystery-sub", opaque: true}},
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
