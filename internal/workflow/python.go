package workflow

import (
	"regexp"
	"slices"
	"strings"

	"github.com/runsweep/runsweep/internal/pep"
)

// pyToolRe finds a Python tool word, case-insensitively. Group 1 is what precedes the word in the
// same command word: a quote and/or a path (.venv/bin/, "$VENV/bin/, "/my dir/); group 2 is the tool.
var pyToolRe = regexp.MustCompile(`(?i)(?:^|[^\w./-])("[^"\n]*/|'[^'\n]*/|["']?(?:[^\s;&|()'"` + "`" + `]*/)?)(pip-sync|pip-compile|pre-commit|cibuildwheel|micromamba|pipenv|python(?:\d+(?:\.\d+)*)?|pypy(?:\d+(?:\.\d+)*)?|pipx|pip(?:\d+(?:\.\d+)*)?|poetry|pixi|py|uvx|uv|pdm|hatch|tox|nox|conda|mamba|rye|flit|maturin)(?:\.exe)?["']?`)

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

// HasPyTool reports whether text mentions a Python tool as a word.
func HasPyTool(text string) bool { return len(pyToolMatches(text, 1)) > 0 }

// pyToolMatches finds the tool words that end a word (the regexp does not consume what follows, so
// the next line's first word is not skipped). n caps the matches read.
func pyToolMatches(text string, n int) [][]int {
	var out [][]int
	for _, m := range pyToolRe.FindAllStringSubmatchIndex(text, maxMatches) {
		if m[1] == len(text) || strings.IndexByte(" \t;&|)\n", text[m[1]]) >= 0 {
			if out = append(out, m); len(out) == n {
				break
			}
		}
	}
	return out
}

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

// PyInstalls returns the Python install and opaque commands in a shell script. A tool word at an
// unrecognised position (not a command start, not inside another Python command) is Opaque.
func PyInstalls(text string) []PyInstall {
	text = continuation.Replace(text)
	var out []PyInstall
	inside := 0 // end of the last Python command: its inner words are not commands of their own
	for _, m := range pyToolMatches(text, maxMatches) {
		toolStart, toolEnd := m[4], m[5]
		if toolStart < inside {
			continue
		}
		cmdStart := m[2] // the command word starts with its quote and path
		lineStart := strings.LastIndexByte(text[:cmdStart], '\n') + 1
		prefix := text[lineStart:cmdStart]
		if pyComment(prefix) {
			continue
		}
		seg := prefix
		if i := strings.LastIndexAny(seg, ";&|({`"); i >= 0 {
			seg = seg[i+1:]
		}
		words := strings.Fields(seg)
		for len(words) > 0 && pyLeadWord[words[0]] {
			words = words[1:]
		}
		if len(words) > 0 && (pyNoCmd[words[0]] || words[0] == "command" && len(words) > 1 && (words[1] == "-v" || words[1] == "-V")) {
			continue // echo pip install x: an argument, not a command
		}
		tool := strings.ToLower(text[toolStart:toolEnd])
		rest := text[toolEnd:]
		if len(rest) >= 4 && strings.EqualFold(rest[:4], ".exe") {
			rest = rest[4:]
		}
		if rest != "" && (rest[0] == '"' || rest[0] == '\'') {
			rest = rest[1:] // the closing quote of a quoted command word
		}
		restStart := len(text) - len(rest)
		if i := strings.IndexByte(rest, '`'); i >= 0 && strings.Count(prefix, "`")%2 == 1 {
			rest = rest[:i] // inside a backtick substitution: it ends at the closing backtick
		}
		args, capped := commandArgs(rest)
		end := restStart + len(rest)
		if i := strings.IndexAny(rest, "\n;&|)"); i >= 0 {
			end = restStart + i
		}
		inside = end
		cmd := strings.TrimSpace(text[cmdStart:end])
		if !pyStartRe.MatchString(prefix) && !pyInterpRe.MatchString(prefix) {
			out = append(out, PyInstall{Cmd: cmd, Tool: tool + " (unrecognised position)", Opaque: true})
			continue
		}
		if in, ok := classify(tool, args); ok {
			in.Cmd = cmd
			in.Dynamic = in.Dynamic || capped || slices.Contains(words, "xargs") // xargs: packages come from stdin
			out = append(out, in)
		}
	}
	return out
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
		case s == "run":
			rest := runCommand(afterFirstPositional(args))
			for _, a := range args {
				name, _, _ := strings.Cut(a, "=")
				if slices.Contains([]string{"--with", "--with-requirements", "--with-editable", "--isolated", "-q", "--quiet", "--script"}, name) ||
					name == "--no-project" && len(rest) > 0 && strings.HasSuffix(rest[0], ".py") {
					return PyInstall{Tool: "uv run", Opaque: true}, true
				}
			}
			return classifyInner(rest) // uv's own output shows what it syncs
		default: // lock, build and anything unknown
			return PyInstall{Tool: "uv " + s, Opaque: true}, true
		}
	case tool == "poetry":
		switch s := sub(0); {
		case s == "" || poetryNoInstall[s]:
			return PyInstall{}, false
		case s == "install" || s == "sync" || s == "update":
			return PyInstall{Tool: "poetry " + s}, true
		case s == "run":
			return classifyInner(runCommand(afterFirstPositional(args)))
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

// afterFirstPositional returns the arguments after the first one that is neither a flag nor a flag
// value, and runCommand the arguments from that first one on: for `uv run [flags] cmd args` the
// command and its arguments.
func afterFirstPositional(args []string) []string {
	if c := runCommand(args); len(c) > 0 {
		return c[1:]
	}
	return nil
}

func runCommand(args []string) []string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case redirectRe.MatchString(a):
			if redirectOp.MatchString(a) {
				i++
			}
		case strings.HasPrefix(a, "-"):
			if pyValueFlags[a] && !strings.Contains(a, "=") {
				i++
			}
		default:
			return args[i:]
		}
	}
	return nil
}

// classifyInner classifies the command run by `poetry run` and `uv run`, which install nothing themselves.
func classifyInner(cmd []string) (PyInstall, bool) {
	if len(cmd) == 0 {
		return PyInstall{}, false
	}
	tool := strings.ToLower(cmd[0])
	if i := strings.LastIndexAny(tool, `/\`); i >= 0 {
		tool = tool[i+1:]
	}
	return classify(strings.TrimSuffix(tool, ".exe"), cmd[1:])
}

// classifyInterpreter reads `python [flags] -m MODULE args` and `python setup.py CMD`.
func classifyInterpreter(args []string) (PyInstall, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-m" && i+1 < len(args):
			return classifyModule(args[i+1], args[i+2:])
		case strings.HasPrefix(a, "-m") && len(a) > 2:
			return classifyModule(a[2:], args[i+1:])
		case a == "-c": // inline code may run pip
			return PyInstall{Tool: "python -c", Opaque: true}, true
		case a == "-X" || a == "-W":
			i++
		case strings.HasPrefix(a, "-"):
		default:
			if strings.HasSuffix(a, "setup.py") && i+1 < len(args) && setupPyCmds[args[i+1]] {
				return PyInstall{Tool: "python setup.py " + args[i+1], Opaque: true}, true
			}
			return PyInstall{}, false
		}
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
