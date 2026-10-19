package workflow

import "testing"

func TestRunsScript(t *testing.T) {
	for script, want := range map[string]bool{
		"pip install -r r.txt\n./scripts/extra.sh": true,
		"./ci/install.sh":                          true,
		"pip install x\nmake deps":                 true,
		"pip install x\nnode build.js":             true,
		"pip install x\n$INSTALL":                  true,
		"pip install ./pkg":                        false,
		"pip install -r r.txt":                     false,
		"python --version\npip install x":          false,
		"uv sync --frozen":                         false,
	} {
		if got := RunsScript(script); got != want {
			t.Errorf("%q: got %v, want %v", script, got, want)
		}
	}
}
