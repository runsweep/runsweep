package workflow

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/runsweep/runsweep/internal/pep"
)

// pyWordRe is a Python tool word, case-insensitively, with its version and .exe suffix. pyWords
// checks its neighbours in code: the regexp never consumes them, so quotes, paths and adjacent
// words never hide an occurrence.
var pyWordRe = regexp.MustCompile(`(?i)(?:pip-sync|pip-compile|pre-commit|cibuildwheel|micromamba|pipenv|python(?:\d+(?:\.\d+)*)?|pypy(?:\d+(?:\.\d+)*)?|pipx|pip(?:\d+(?:\.\d+)*)?|poetry|pixi|py|uvx|uv|pdm|hatch|tox|nox|conda|mamba|rye|flit|maturin)(?:\.exe)?`)

func pyWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

// pyWords returns the [start, end) of every Python tool word in text: not preceded by a word
// character or '.', not followed by a word character, a path separator (python/ is a directory)
// or a file extension (uv.lock, tox.ini). A '/' or '\' before the word is a path to it.
func pyWords(text string) [][]int {
	var out [][]int
	for _, m := range pyWordRe.FindAllStringIndex(text, -1) {
		s, e := m[0], m[1]
		if s > 0 && (pyWordByte(text[s-1]) || text[s-1] == '.') {
			continue
		}
		if e < len(text) && (pyWordByte(text[e]) || text[e] == '/' || text[e] == '\\' ||
			text[e] == '.' && e+1 < len(text) && pyWordByte(text[e+1]) && text[e+1] != '-' && text[e+1] != '_') {
			continue
		}
		out = append(out, m)
	}
	return out
}

const (
	pyAssign = `[A-Za-z_]\w*=(?:"[^"]*"|'[^']*'|\S*)`
	// wrappers that run the next word as a command
	pyWrap = `(?:` + pyAssign + `\s+|!\s+` +
		`|sudo\b(?:\s+(?:-[ugCDhpRrt]\s+\S+|-\S+|` + pyAssign + `))*\s+` +
		`|timeout\b(?:\s+-\S+)*\s+[\d.]+[smhd]?\s+` +
		`|nice\b(?:\s+(?:-n\s+-?\d+|-\S+))*\s+` +
		`|(?:env|time|exec|nohup|command|xargs)\b(?:\s+(?:-\S+|` + pyAssign + `))*\s+` +
		`|(?:ba|z|da)?sh\s+(?:-\S+\s+)*-\w*c\s+)*`
)

// pyStartRe: what may precede a command word on its line.
var pyStartRe = regexp.MustCompile(`(?:^|[;&|({` + "`" + `]|\$\(|\b(?:then|do|else|if|elif|while|until)\b)\s*` + pyWrap + `$`)

// pyInterpRe: an interpreter given as a quoted string or variable, then flags and -m: the tool word
// is the module ("${{ steps.py.outputs.python-path }}" -m pip install x).
var pyInterpRe = regexp.MustCompile(`(?:"[^"]*"|'[^']*'|\$\S+)\s+(?:-\S+\s+)*-m\s+$`)

// pyNoCmd: words whose arguments are text, not commands.
var pyNoCmd = map[string]bool{"echo": true, "printf": true, "print": true, "cat": true, "grep": true, "which": true,
	"type": true, "hash": true}

var pyLeadWord = map[string]bool{"if": true, "elif": true, "while": true, "until": true, "then": true, "do": true, "else": true, "!": true}

// HasPyTool reports whether text mentions a Python tool as a word, anywhere: quoted, in a path,
// in an argument. A step whose script has one has its log read.
func HasPyTool(text string) bool { return len(pyWords(text)) > 0 }

// PyInstall is a Python command that installs packages, or an opaque one that installs or runs
// sdist code without listing versions.
type PyInstall struct {
	Cmd     string   // the command as written, up to its end
	Tool    string   // "pip install", "uv sync", "tox", …
	Pkgs    []string // PEP 503 names given as arguments
	Dynamic bool     // a package named by a variable or substitution
	Opaque  bool
}

var (
	pipNoInstall = map[string]bool{"list": true, "freeze": true, "show": true, "check": true, "config": true, "cache": true,
		"help": true, "hash": true, "inspect": true, "debug": true, "completion": true, "uninstall": true, "index": true}
	uvNoInstall = map[string]bool{"version": true, "self": true, "cache": true, "python": true, "venv": true, "tree": true,
		"export": true, "init": true, "publish": true, "help": true, "auth": true, "format": true}
	poetryNoInstall = map[string]bool{"config": true, "show": true, "check": true, "env": true, "version": true,
		"export": true, "publish": true, "help": true, "about": true, "list": true, "search": true, "new": true, "init": true, "self": true, "source": true, "remove": true}
	alwaysOpaque = map[string]bool{"uvx": true, "tox": true, "nox": true, "pre-commit": true, "hatch": true, "pdm": true,
		"pipenv": true, "pixi": true, "rye": true, "cibuildwheel": true, "pip-sync": true, "pip-compile": true}
	// value flags of pip, uv and poetry: the next argument is not a package or subcommand
	pyValueFlags = map[string]bool{"-r": true, "--requirement": true, "-c": true, "--constraint": true, "-e": true, "--editable": true,
		"-i": true, "--index-url": true, "--extra-index-url": true, "-f": true, "--find-links": true, "-t": true, "--target": true,
		"--prefix": true, "--root": true, "--python": true, "-p": true, "--platform": true, "--src": true, "--config-settings": true,
		"-C": true, "--python-version": true, "--implementation": true, "--abi": true, "--only-binary": true, "--no-binary": true,
		"--progress-bar": true, "--log": true, "--cache-dir": true, "--trusted-host": true, "--proxy": true, "--timeout": true,
		"--retries": true, "--exists-action": true, "--report": true, "--group": true, "--directory": true, "--project": true,
		"--with": true, "--from": true, "-w": true, "--extra": true, "-E": true, "--extras": true, "--only": true, "--without": true,
		"--index": true, "--default-index": true, "--upgrade-package": true, "-P": true}
	redirectRe = regexp.MustCompile(`^\d*[<>]`)
	redirectOp = regexp.MustCompile(`^\d*(?:<|>>?)$`)
	pep508Re   = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:$|[\[<>=!~;@ (])`)
)

// PyInstalls returns the Python install and opaque commands in a shell script. Every tool word is
// accounted for: an argument of a Python command already read, a comment or echo-like argument, a
// command at a recognised start (classified), or else Opaque "<tool> (unrecognised position)".
func PyInstalls(text string) []PyInstall {
	out, _, _ := pyScan(continuation.Replace(text))
	return out
}

// pyScan is PyInstalls on joined lines. spans are the [start, end) ranges whose tool words were
// read as part of a command (an accepted command, an unrecognised word, the own flags of uv run);
// skipped are the word starts left out as comment or echo-like text.
func pyScan(text string) (out []PyInstall, spans [][2]int, skipped []int) {
	inside := 0 // end of the last Python command: its inner words are not commands of their own
	runAt := -1 // start of the command run by the last uv run / poetry run: a command start
	words := pyWords(text)
	if len(words) > maxMatches {
		return []PyInstall{{Cmd: text, Tool: "more than " + strconv.Itoa(maxMatches) + " Python tool words", Opaque: true}}, [][2]int{{0, len(text)}}, nil
	}
	for _, m := range words {
		wordStart, wordEnd := m[0], m[1]
		if wordStart < inside {
			continue
		}
		lineStart := strings.LastIndexByte(text[:wordStart], '\n') + 1
		cmdStart := pyCmdStart(text, lineStart, wordStart)
		linePrefix := text[lineStart:cmdStart]
		prefix := linePrefix
		if runAt >= lineStart && runAt <= cmdStart {
			prefix = text[runAt:cmdStart] // uv run sh -c '…': the inner command is a command line of its own
		}
		if pyComment(linePrefix) {
			skipped = append(skipped, wordStart)
			continue
		}
		seg := prefix
		if i := strings.LastIndexAny(seg, ";&|({`"); i >= 0 {
			seg = seg[i+1:]
		}
		lead := strings.Fields(seg)
		for len(lead) > 0 && pyLeadWord[lead[0]] {
			lead = lead[1:]
		}
		if len(lead) > 0 && (pyNoCmd[lead[0]] || lead[0] == "command" && len(lead) > 1 && (lead[1] == "-v" || lead[1] == "-V")) {
			skipped = append(skipped, wordStart)
			continue // echo pip install x: an argument, not a command
		}
		tool := strings.TrimSuffix(strings.ToLower(text[wordStart:wordEnd]), ".exe")
		rest := text[wordEnd:]
		if rest != "" && (rest[0] == '"' || rest[0] == '\'') {
			rest = rest[1:] // the closing quote of a quoted command word
		}
		restStart := len(text) - len(rest)
		if i := strings.IndexByte(rest, '`'); i >= 0 && strings.Count(linePrefix, "`")%2 == 1 {
			rest = rest[:i] // inside a backtick substitution: it ends at the closing backtick
		}
		args, offs, capped := pyArgs(rest)
		end := restStart + len(rest)
		if i := strings.IndexAny(rest, "\n;&|)"); i >= 0 {
			end = restStart + i
		}
		cmd := strings.TrimSpace(text[cmdStart:end])
		if i := strings.LastIndexAny(prefix, ";&|`"); i >= 0 {
			prefix = prefix[i:] // both regexps read the last command only: a long line stays linear
		}
		if !pyStartRe.MatchString(prefix) && !pyInterpRe.MatchString(prefix) {
			inside = end
			spans = append(spans, [2]int{cmdStart, end})
			out = append(out, PyInstall{Cmd: cmd, Tool: tool + " (unrecognised position)", Opaque: true})
			continue
		}
		inside = end
		if k := runInner(tool, args); k >= 0 {
			// uv run / poetry run: only their own flags are inside; the command they run is read on its own
			inside, runAt = restStart+offs[k], restStart+offs[k]
		}
		spans = append(spans, [2]int{cmdStart, inside})
		if in, ok := classify(tool, args); ok {
			in.Cmd = cmd
			in.Dynamic = in.Dynamic || capped || slices.Contains(lead, "xargs") // xargs: packages come from stdin
			out = append(out, in)
		}
	}
	return out, spans, skipped
}

// pyCmdStart returns where the command word holding the tool word at wordStart begins: its path
// ($VENV/bin/, "/my dir/) and an opening quote.
func pyCmdStart(text string, lineStart, wordStart int) int {
	start := wordStart
	if start > lineStart && (text[start-1] == '/' || text[start-1] == '\\') {
		for start > lineStart && !strings.ContainsRune(" \t;&|()'\"`", rune(text[start-1])) {
			start--
		}
		if start > lineStart && text[start-1] == ' ' {
			// a quoted path with spaces: an opening quote before it with no command separator between
			line := text[lineStart:start]
			if q := strings.LastIndexAny(line, `"'`); q >= 0 && strings.Count(line[:q], line[q:q+1])%2 == 0 &&
				!strings.ContainsAny(line[q:], ";&|()`") {
				return lineStart + q
			}
		}
	}
	if start > lineStart && (text[start-1] == '"' || text[start-1] == '\'') {
		start--
	}
	return start
}

// pyArgs is commandArgs that also returns where each argument starts in s (its quote included).
func pyArgs(s string) (args []string, offs []int, capped bool) {
	for i, n := 0, 0; i < len(s); {
		switch c := s[i]; {
		case c == '\n' || c == ';' || c == '&' || c == '|' || c == ')':
			return args, offs, false
		case argSep[c]:
			i++
		default:
			if n++; n > maxArgs {
				return args, offs, true
			}
			j := i
			for j < len(s) && !argSep[s[j]] {
				j++
			}
			// a leading backtick stays: it marks a command substitution
			if f := strings.TrimRight(strings.TrimLeft(s[i:j], `'",`), "'\"`,"); f != "" {
				args, offs = append(args, f), append(offs, i)
			}
			i = j
		}
	}
	return args, offs, false
}

// pyComment reports whether prefix (the line before a word) is inside a shell comment: a # at a
// word start with no open quote before it.
func pyComment(prefix string) bool {
	var q rune
	for i, c := range prefix {
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#' && (i == 0 || prefix[i-1] == ' ' || prefix[i-1] == '\t'):
			return true
		}
	}
	return false
}

// positional returns the arguments that are neither flags nor flag values.
func positional(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if redirectRe.MatchString(a) {
			if redirectOp.MatchString(a) {
				i++ // the operator's target is the next argument
			}
			continue
		}
		if strings.HasPrefix(a, "-") {
			if pyValueFlags[a] && !strings.Contains(a, "=") {
				i++
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// classify turns a tool word and its arguments into a PyInstall; ok is false for commands that
// neither install nor run sdist code (pip list, python script.py).
func classify(tool string, args []string) (PyInstall, bool) {
	base := strings.TrimRight(tool, "0123456789.")
	pos := positional(args)
	sub := func(i int) string {
		if i < len(pos) {
			return pos[i]
		}
		return ""
	}
	switch {
	case base == "python" || base == "py" || base == "pypy":
		return classifyInterpreter(args)
	case base == "pip":
		s := sub(0)
		switch {
		case s == "" || pipNoInstall[s]:
			return PyInstall{}, false
		case s == "install":
			in := PyInstall{Tool: "pip install"}
			in.Pkgs, in.Dynamic = pyPkgs(pos[1:])
			return in, true
		default: // wheel, download and anything unknown may build an sdist
			return PyInstall{Tool: "pip " + s, Opaque: true}, true
		}
	case tool == "uv":
		switch s := sub(0); {
		case s == "" || uvNoInstall[s]:
			return PyInstall{}, false
		case s == "pip" && (sub(1) == "install" || sub(1) == "sync"):
			in := PyInstall{Tool: "uv pip " + sub(1)}
			in.Pkgs, in.Dynamic = pyPkgs(pos[2:])
			return in, true
		case s == "pip" && (sub(1) == "list" || sub(1) == "freeze" || sub(1) == "show" || sub(1) == "check" || sub(1) == "tree"):
			return PyInstall{}, false
		case s == "sync":
			return PyInstall{Tool: "uv sync"}, true
		case s == "add":
			in := PyInstall{Tool: "uv add"}
			in.Pkgs, in.Dynamic = pyPkgs(pos[1:])
			return in, true
		case s == "tool" && sub(1) == "install": // prints a + line per package (pytest log)
			in := PyInstall{Tool: "uv tool install"}
			in.Pkgs, in.Dynamic = pyPkgs(pos[2:])
			return in, true
		case s == "pip" || s == "tool":
			return PyInstall{Tool: "uv " + s + " " + sub(1), Opaque: true}, true
		case s == "run": // uv's own output shows what it syncs; PyInstalls reads the command it runs
			own, script := args, ""
			if k := runInner("uv", args); k >= 0 {
				own, script = args[:k], args[k]
			}
			for _, a := range own {
				name, _, _ := strings.Cut(a, "=")
				if slices.Contains([]string{"--with", "--with-requirements", "--with-editable", "--isolated", "-q", "--quiet", "--script"}, name) ||
					name == "--no-project" && strings.HasSuffix(script, ".py") {
					return PyInstall{Tool: "uv run", Opaque: true}, true
				}
			}
			return PyInstall{}, false
		default: // lock, build and anything unknown
			return PyInstall{Tool: "uv " + s, Opaque: true}, true
		}
	case tool == "poetry":
		switch s := sub(0); {
		case s == "" || poetryNoInstall[s]:
			return PyInstall{}, false
		case s == "install" || s == "sync" || s == "update":
			return PyInstall{Tool: "poetry " + s}, true
		case s == "run": // installs nothing; PyInstalls reads the command it runs
			return PyInstall{}, false
		case s == "add":
			in := PyInstall{Tool: "poetry add"}
			in.Pkgs, in.Dynamic = pyPkgs(pos[1:])
			return in, true
		default: // lock, build and anything unknown
			return PyInstall{Tool: "poetry " + s, Opaque: true}, true
		}
	case tool == "pipx":
		s := sub(0)
		if s != "install" && s != "run" && s != "inject" && s != "upgrade" && s != "reinstall" {
			return PyInstall{}, false
		}
		in := PyInstall{Tool: "pipx " + s, Opaque: true}
		in.Pkgs, in.Dynamic = pyPkgs(pos[1:])
		return in, true
	case tool == "uvx":
		in := PyInstall{Tool: "uvx", Opaque: true}
		in.Pkgs, in.Dynamic = pyPkgs(pos)
		return in, true
	case alwaysOpaque[tool]:
		if sub(0) == "run" && (tool == "pdm" || tool == "hatch" || tool == "pipenv" || tool == "rye" || tool == "pixi") {
			return PyInstall{Tool: tool + " run", Opaque: true}, true
		}
		return PyInstall{Tool: tool, Opaque: true}, true
	case tool == "conda" || tool == "mamba" || tool == "micromamba":
		if s := sub(0); s == "install" || s == "create" || s == "update" || s == "env" || s == "run" {
			return PyInstall{Tool: tool + " " + s, Opaque: true}, true
		}
	case tool == "flit" && sub(0) == "install", tool == "maturin" && sub(0) == "develop":
		return PyInstall{Tool: tool + " " + sub(0), Opaque: true}, true
	}
	return PyInstall{}, false
}

// pyInterpOpaque are the python -m modules that install or build without a pip line of their own.
var pyInterpOpaque = map[string]bool{"tox": true, "nox": true, "pre_commit": true, "piptools": true, "hatch": true, "pdm": true}

// setupPyCmds are the setup.py commands that build or install.
var setupPyCmds = map[string]bool{"install": true, "develop": true, "bdist_wheel": true, "build": true, "sdist": true,
	"egg_info": true, "bdist_egg": true, "easy_install": true}

// runValueFlags are the flags of uv and poetry, before and after run, whose value is the next argument.
var runValueFlags = map[string]bool{"--directory": true, "--project": true, "-C": true, "-P": true, "--config-file": true,
	"--cache-dir": true, "--color": true, "--python": true, "-p": true, "--with": true, "--with-editable": true,
	"--with-requirements": true, "--env-file": true, "--package": true, "--extra": true, "--no-extra": true, "--group": true,
	"--no-group": true, "--only-group": true, "--index": true, "--default-index": true, "--index-url": true, "-i": true,
	"--extra-index-url": true, "--find-links": true, "-f": true, "--index-strategy": true, "--keyring-provider": true,
	"--resolution": true, "--prerelease": true, "--exclude-newer": true, "--link-mode": true, "--refresh-package": true,
	"--reinstall-package": true, "--upgrade-package": true, "--no-build-package": true, "--no-binary-package": true,
	"--config-setting": true, "--python-platform": true, "--allow-insecure-host": true, "--fork-strategy": true}

// runInner returns the index in args (the arguments after the tool word) of the command that
// `uv run` or `poetry run` runs, python -m uv|poetry included, or -1. Flags are skipped, known value
// flags with their value; any other word is taken as the command, so a tool word after an unknown
// flag's value is not at a command start.
func runInner(tool string, args []string) int {
	if base := strings.TrimRight(tool, "0123456789."); base == "python" || base == "py" || base == "pypy" {
		mod, i := pyModule(args)
		if mod != "uv" && mod != "poetry" {
			return -1
		}
		if k := runInner(mod, args[i:]); k >= 0 {
			return i + k
		}
		return -1
	}
	if tool != "uv" && tool != "poetry" {
		return -1
	}
	run := false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case strings.HasPrefix(a, "-"):
			if runValueFlags[a] {
				i++
			}
		case run:
			return i
		case a == "run":
			run = true
		default:
			return -1
		}
	}
	return -1
}

// pyModule reads `python [flags] -m MODULE`: the module and the index of its first argument, or ""
// and the index of the first argument that is not an interpreter flag.
func pyModule(args []string) (string, int) {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "-m" && i+1 < len(args):
			return args[i+1], i + 2
		case strings.HasPrefix(a, "-m") && len(a) > 2:
			return a[2:], i + 1
		case a == "-X" || a == "-W":
			i++
		case a == "-c" || !strings.HasPrefix(a, "-"):
			return "", i
		}
	}
	return "", len(args)
}

// classifyInterpreter reads `python [flags] -m MODULE args`, `python -c` and `python setup.py CMD`.
func classifyInterpreter(args []string) (PyInstall, bool) {
	mod, i := pyModule(args)
	switch {
	case mod != "":
		return classifyModule(mod, args[i:])
	case i < len(args) && args[i] == "-c": // inline code may run pip
		return PyInstall{Tool: "python -c", Opaque: true}, true
	case i+1 < len(args) && strings.HasSuffix(args[i], "setup.py") && setupPyCmds[args[i+1]]:
		return PyInstall{Tool: "python setup.py " + args[i+1], Opaque: true}, true
	}
	return PyInstall{}, false
}

func classifyModule(mod string, args []string) (PyInstall, bool) {
	switch {
	case mod == "pip" || mod == "uv" || mod == "poetry" || mod == "pipx":
		return classify(mod, args)
	case mod == "build" || pyInterpOpaque[mod]:
		return PyInstall{Tool: "python -m " + mod, Opaque: true}, true
	}
	return PyInstall{}, false
}

// pyPkgs reads PEP 508 names from install arguments; paths, URLs and archives are not names.
func pyPkgs(args []string) (pkgs []string, dynamic bool) {
	for _, a := range args {
		switch {
		case strings.ContainsAny(a, "$`"):
			dynamic = true
		case strings.ContainsAny(a, "/\\") || strings.HasPrefix(a, ".") || strings.Contains(a, "://") ||
			strings.HasSuffix(a, ".whl") || strings.HasSuffix(a, ".tar.gz") || strings.HasSuffix(a, ".zip"):
		default:
			if m := pep508Re.FindStringSubmatch(a); m != nil && pep.ValidName(m[1]) {
				pkgs = append(pkgs, pep.Name(m[1]))
			}
		}
	}
	return pkgs, dynamic
}

// PyInstalls returns the Python install and opaque commands of the job's run: steps and github-scripts.
func (j *Job) PyInstalls() []PyInstall {
	var out []PyInstall
	for _, s := range slices.Concat(j.Runs, j.Scripts) {
		out = append(out, PyInstalls(s)...)
	}
	return out
}

// baseActions never install Python packages: checkout, cache, artifacts, github-script and the
// non-Python setup actions.
func baseAction(u string) bool {
	name, _, _ := strings.Cut(strings.ToLower(u), "@")
	return name != "actions/setup-python" && strings.HasPrefix(name, "actions/setup-") ||
		slices.Contains([]string{"actions/checkout", "actions/cache", "actions/upload-artifact",
			"actions/download-artifact", "actions/github-script"}, name)
}

// HasPython is false only when nothing in the job can install a Python package: no Python tool or
// build tool word, no opaque script, and only base actions. Such a job is CLEAN for PyPI without its log.
func (j *Job) HasPython() bool {
	if slices.ContainsFunc(slices.Concat(j.Runs, j.Scripts), func(s string) bool { return HasPyTool(s) || buildRe.MatchString(s) }) {
		return true
	}
	return j.RunsOpaque() || slices.ContainsFunc(j.Runs, pathCmdRe.MatchString) ||
		slices.ContainsFunc(j.Shells, func(sh string) bool {
			f := strings.Fields(strings.ToLower(sh))
			return len(f) == 0 || !plainShell[f[0]]
		}) ||
		slices.ContainsFunc(j.Uses, func(u string) bool { return !baseAction(u) })
}

// pathCmdRe: a command word with a path (script/bootstrap, tools\setup.cmd) runs a repository script.
var pathCmdRe = regexp.MustCompile(`(?m)(?:^|[;&|({]|\b(?:then|do|else|if|elif|while|until)\b)[ \t]*` + pyWrap + `["']?[^\s;&|()'"]*[/\\]`)

// plainShell are the shells whose commands the scan reads; any other `shell:` (python, a template)
// runs code it does not see.
var plainShell = map[string]bool{"bash": true, "sh": true, "pwsh": true, "powershell": true, "cmd": true}

// PyActionsOK reports whether every action of the job is a base action or a Python setup action
// whose own installs the log shows (actions/setup-python, astral-sh/setup-uv). Other actions may
// install packages without listing versions (D-011: no allowlist of third-party actions).
func (j *Job) PyActionsOK() bool {
	return !slices.ContainsFunc(j.Uses, func(u string) bool {
		name, _, _ := strings.Cut(strings.ToLower(u), "@")
		return !baseAction(u) && name != "actions/setup-python" && name != "astral-sh/setup-uv"
	})
}
