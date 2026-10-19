package workflow

import (
	"regexp"
	"slices"
	"strings"

	"github.com/runsweep/runsweep/internal/pep"
)

// pyToolRe finds a Python tool word, a path before it allowed (.venv/bin/python, /usr/bin/pip3).
var pyToolRe = regexp.MustCompile(`(?:^|[^\w./-])(?:[^\s;&|()'"` + "`" + `]*/)?(pip-sync|pip-compile|pre-commit|python[\d.]*|pip[\d.]*|pipx|pipenv|py|uvx|uv|poetry|pdm|hatch|tox|nox|conda|mamba|micromamba|pixi|rye|flit|maturin|cibuildwheel)(?:\.exe)?(?:$|[ \t;&|)\n])`)

// pyStartRe: what may precede a command word on its line.
var pyStartRe = regexp.MustCompile(`(?:^|[;&|({]|\$\(|\b(?:then|do|else)\b)\s*(?:(?:sudo|env|time|exec|nohup|xargs)\b(?:\s+(?:-\S+|[A-Za-z_]\w*=\S*))*\s+)*$`)

// HasPyTool reports whether text mentions a Python tool as a word.
func HasPyTool(text string) bool { return pyToolRe.MatchString(text) }

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
		"export": true, "publish": true, "run": true, "help": true, "about": true, "list": true, "search": true, "new": true, "init": true, "self": true, "source": true, "remove": true}
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
	pep508Re = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:$|[\[<>=!~;@ (])`)
)

// PyInstalls returns the Python install and opaque commands in a shell script.
func PyInstalls(text string) []PyInstall {
	text = continuation.Replace(text)
	var out []PyInstall
	for _, m := range pyToolRe.FindAllStringSubmatchIndex(text, maxMatches) {
		wordStart := m[2] // the tool name; a path before it is part of the command word
		cmdStart := wordStart
		for cmdStart > 0 && !strings.ContainsRune(" \t\n;&|(", rune(text[cmdStart-1])) {
			cmdStart--
		}
		lineStart := strings.LastIndexByte(text[:cmdStart], '\n') + 1
		if !pyStartRe.MatchString(text[lineStart:cmdStart]) {
			continue // an argument (echo pip install x), not a command
		}
		tool := text[m[2]:m[3]]
		args, capped := commandArgs(strings.TrimPrefix(text[m[3]:], ".exe"))
		end := len(text)
		if i := strings.IndexAny(text[m[3]:], "\n;&|)"); i >= 0 {
			end = m[3] + i
		}
		cmd := strings.TrimSpace(text[cmdStart:end])
		if in, ok := classify(tool, args); ok {
			in.Cmd = cmd
			in.Dynamic = in.Dynamic || capped
			out = append(out, in)
		}
	}
	return out
}

// positional returns the arguments that are neither flags nor flag values.
func positional(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
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
	case base == "python" || base == "py":
		if len(args) >= 2 && args[0] == "-m" {
			switch args[1] {
			case "pip":
				return classify("pip", args[2:])
			case "build":
				return PyInstall{Tool: "python -m build", Opaque: true}, true
			}
		}
		return PyInstall{}, false
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
		default: // run, lock, build and anything unknown
			return PyInstall{Tool: "uv " + s, Opaque: true}, true
		}
	case tool == "poetry":
		switch s := sub(0); {
		case s == "" || poetryNoInstall[s]:
			return PyInstall{}, false
		case s == "install" || s == "sync" || s == "update":
			return PyInstall{Tool: "poetry " + s}, true
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
		return PyInstall{Tool: tool, Opaque: true}, true
	case tool == "conda" || tool == "mamba" || tool == "micromamba":
		if s := sub(0); s == "install" || s == "create" || s == "update" || s == "env" {
			return PyInstall{Tool: tool + " " + s, Opaque: true}, true
		}
	case tool == "flit" && sub(0) == "install", tool == "maturin" && sub(0) == "develop":
		return PyInstall{Tool: tool + " " + sub(0), Opaque: true}, true
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
	if slices.ContainsFunc(slices.Concat(j.Runs, j.Scripts), func(s string) bool { return pyToolRe.MatchString(s) || buildRe.MatchString(s) }) {
		return true
	}
	return j.RunsOpaque() || slices.ContainsFunc(j.Uses, func(u string) bool { return !baseAction(u) })
}

// PyActionsOK reports whether every action of the job is a base action or a Python setup action
// whose own installs the log shows (actions/setup-python, astral-sh/setup-uv). Other actions may
// install packages without listing versions (D-011: no allowlist of third-party actions).
func (j *Job) PyActionsOK() bool {
	return !slices.ContainsFunc(j.Uses, func(u string) bool {
		name, _, _ := strings.Cut(strings.ToLower(u), "@")
		return !baseAction(u) && name != "actions/setup-python" && name != "astral-sh/setup-uv"
	})
}
