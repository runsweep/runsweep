package pypi

import (
	"os"
	"slices"
	"testing"

	"github.com/runsweep/runsweep/internal/incident"
)

func readFix(t *testing.T, n string) []byte {
	b, err := os.ReadFile("testdata/" + n) //nolint:gosec // fixed fixtures
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRequirements(t *testing.T) {
	got := ParseRequirements(readFix(t, "requirements.txt"))
	want := []Pkg{{"flask-sqlalchemy", "3.1.1"}, {"litellm", "1.82.8"}, {"numpy", "2"}}
	if !slices.Equal(got, want) {
		t.Errorf("got %+v", got)
	}
}

func TestParseLocks(t *testing.T) {
	for file, want := range map[string][]Pkg{
		"uv.lock":     {{"litellm", "1.82.8"}, {"myproj", "0.1"}},
		"poetry.lock": {{"litellm", "1.82.7"}},
		"pylock.toml": {{"litellm", "1.82.8"}},
	} {
		got, err := ParseTOMLLock(file, readFix(t, file))
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%s: %+v %v", file, got, err)
		}
	}
	got, err := ParsePipfileLock(readFix(t, "Pipfile.lock"))
	if err != nil || !slices.Equal(got, []Pkg{{"litellm", "1.82.8"}, {"pytest", "8"}}) {
		t.Errorf("Pipfile.lock: %+v %v", got, err)
	}
	for file, b := range map[string]string{"uv.lock": "[[package]\n", "Pipfile.lock": "{"} {
		var err error
		if file == "Pipfile.lock" {
			_, err = ParsePipfileLock([]byte(b))
		} else {
			_, err = ParseTOMLLock(file, []byte(b))
		}
		if err == nil {
			t.Errorf("%s: corrupt file accepted", file)
		}
	}
}

func TestIsManifest(t *testing.T) {
	for p, want := range map[string]string{
		"requirements.txt": "requirements", "requirements-dev.txt": "requirements", "ci/dev-requirements.txt": "requirements",
		"requirements/base.txt": "requirements", "constraints.txt": "requirements", "uv.lock": "toml", "app/poetry.lock": "toml",
		"pylock.toml": "toml", "pylock.dev.toml": "toml", "Pipfile.lock": "pipfile", "pdm.lock": "pdm",
		".venv/lib/requirements.txt": "", "x/node_modules/a/requirements.txt": "", "notes.txt": "", ".tox/py/uv.lock": "",
	} {
		k, ok := IsManifest(p)
		if k != want || ok != (want != "") {
			t.Errorf("%s: %q %v", p, k, ok)
		}
	}
}

func TestBad(t *testing.T) {
	b := NewBad([]incident.PyPIPackage{{Name: "LiteLLM", Versions: []string{"1.82.8"}}, {Name: "evil_pkg", Versions: []string{"*"}}})
	for _, c := range []struct {
		n, v string
		want bool
	}{{"litellm", "1.82.8", true}, {"lite_llm", "1.82.8", false}, {"LITELLM", "1.82.8.0", true}, {"litellm", "1.82.8+cu1", true},
		{"litellm", "1.82.9", false}, {"Evil.Pkg", "0.0.1", true}, {"evil-pkg", "garbage", true}, {"litellm", "garbage", false}} {
		if b.Is(c.n, c.v) != c.want {
			t.Errorf("Is(%s, %s) != %v", c.n, c.v, c.want)
		}
	}
	if !b.Has("LiteLLM") || !b.Has("lite.llm") == b.Has("lite-llm") || b.Has("lite-llm") {
		t.Error("Has") // lite.llm and lite-llm both normalize to lite-llm, which is not litellm
	}
	if !b.Mentions("litellm-1.82.8xyz") || b.Mentions("litellmx-1") {
		t.Error("Mentions")
	}
}
