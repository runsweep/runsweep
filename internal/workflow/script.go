package workflow

import (
	"regexp"
	"strings"
)

// scriptRe is opaqueRe without the Python interpreter: PyInstalls already classifies python commands.
var scriptRe = regexp.MustCompile(strings.Replace(opaqueRe.String(), "python3?|", "", 1))

// RunsScript reports whether a shell script runs something other than a Python tool: a make or task
// runner, a script file, node, docker, eval, a command named by a variable. Commands PyInstalls
// recognises are left out, so `pip install ./pkg` is not a script.
func RunsScript(text string) bool {
	for _, in := range PyInstalls(text) {
		if in.Cmd != "" {
			text = strings.Replace(text, in.Cmd, "", 1)
		}
	}
	return scriptRe.MatchString(text)
}
