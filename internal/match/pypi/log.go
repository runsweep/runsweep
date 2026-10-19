// Package pypi finds PyPI packages a job installed: install lines in its log (the proof) and
// lockfiles in the repository (the fallback when the log does not list every version).
package pypi

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/runsweep/runsweep/internal/pep"
	"github.com/runsweep/runsweep/internal/workflow"
)

// Log is what a job log shows about Python installs.
type Log struct {
	Sections []Section // [0] is the runner's set-up part before the first step
	Installs []Install // versions installed or already present, anywhere in the output
	Unparsed []Install // install lines whose name or version could not be read
	Calls    bool      // the output shows a Python installer or an install line
}

// Section is one step of the log, from its "##[group]Run" line to the next.
type Section struct {
	Line     int    // 1-based line of "##[group]Run"
	Cmd      string // the step header and its script echo
	Python   bool   // runs a Python tool, is a Python setup action, or prints install output
	Opaque   string // the first opaque Python command of the step (tox, uv run, …)
	Complete bool   // every install command printed a full list of versions
}

// Install is a package version an install line shows.
type Install struct {
	Name, Version string // PEP 503 name and canonical version; raw text in Unparsed
	Line          int
	Text          string
}

var (
	tsRe  = regexp.MustCompile(`^\d{4}-\d\d-\d\dT[\d:.]+Z `)
	sgrRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

	pipDoneRe    = regexp.MustCompile(`^\s*Successfully installed (.+?)\s*$`)
	setupUVRe    = regexp.MustCompile(`^\s*Successfully installed uv version \S+\s*$`)
	pipHaveRe    = regexp.MustCompile(`^\s*Requirement already satisfied: ([A-Za-z0-9][A-Za-z0-9._-]*)\S* in .* \(([^()]+)\)\s*$`)
	pipFileRe    = regexp.MustCompile(`^\s*(?:Downloading|Using cached) (?:\S*/)?([^\s/]+?\.(?:whl|tar\.gz|zip))(?:\s|$)`)
	uvLineRe     = regexp.MustCompile(`^\s*[+~] ([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)\s*$`)
	uvDoneRe     = regexp.MustCompile(`^\s*Installed (\d+) packages? in `)
	poetryOpsRe  = regexp.MustCompile(`^\s*Package operations: (\d+) installs?, (\d+) updates?, \d+ removals?`)
	poetryLineRe = regexp.MustCompile(`^\s*[-•] (?:Installing|Updating|Downgrading) ([A-Za-z0-9][A-Za-z0-9._-]*) \(([^)]*)\)`)
	pipxRe       = regexp.MustCompile(`^\s*installed package (\S+) (\S+?),`)
	// output that shows an install without a full list of versions
	partialRe = regexp.MustCompile(`^\s*(?:Audited \d+ packages?|No dependencies to install or update|Installing build dependencies|Building \S+ @ )`)
	// an installer the output names (a runner [command] line, a version banner)
	callRe = regexp.MustCompile(`^\s*(?:\[command\])?(?:\S*/)?(?:pip[\d.]*|uv|poetry|pipx|python[\d.]*)(?:\s|$)`)
	loopRe = regexp.MustCompile(`\b(?:for|while|xargs)\b`)
)

// literals every line worth a regexp contains; the rest of a big log is skipped cheaply
var lineLiterals = []string{"installed", "Installed", "Requirement already", "Downloading", "Using cached",
	"==", "Package operations", "Installing", "Updating", "Downgrading", "Audited", "No dependencies", "Building", "pip", "uv", "poetry", "python"}

// section accumulates one step while the log is read.
type section struct {
	Section
	echo     bool // inside the header (until ##[endgroup])
	blocks   int  // full version lists seen
	partial  bool
	have     bool // Requirement already satisfied lines seen
	pipDone  bool
	uvWant   int // lines still expected after "Installed N packages"
	uvOpen   bool
	poWant   int
	poOpen   bool
	setup    bool // a Python setup action: needs no full list
	hdr      string
	echoText []string
}

func (s *section) closeBlocks() {
	if s.uvOpen {
		if s.uvWant == 0 {
			s.blocks++
		} else {
			s.partial = true
		}
		s.uvOpen = false
	}
	if s.poOpen {
		if s.poWant == 0 {
			s.blocks++
		} else {
			s.partial = true
		}
		s.poOpen = false
	}
}

// setCmd takes the command from the script echo, or from the header of a uses: step.
func (s *section) setCmd() {
	s.echo = false
	s.Cmd = s.hdr
	if len(s.echoText) > 0 {
		s.Cmd = strings.Join(s.echoText, "\n")
	}
	s.Python = s.Python || workflow.HasPyTool(s.Cmd)
}

func (s *section) finish() Section {
	if s.echo { // the log ended inside the header
		s.setCmd()
	}
	s.closeBlocks()
	if s.have && !s.pipDone {
		s.blocks++ // everything was already there; versions listed
	}
	out := s.Section
	if !out.Python {
		return out
	}
	cmds, dynamic := 0, false
	for _, in := range workflow.PyInstalls(out.Cmd) {
		if in.Opaque && out.Opaque == "" {
			out.Opaque = in.Tool
		}
		if !in.Opaque {
			cmds++
		}
		dynamic = dynamic || in.Dynamic
	}
	loop := cmds > 0 && loopRe.MatchString(out.Cmd)
	cmds -= alternatives(out.Cmd)
	out.Complete = out.Opaque == "" && (s.setup || !s.partial && !dynamic && !loop && s.blocks >= cmds)
	return out
}

// alternatives counts install commands that never run together: a script with a single
// if/else/fi runs one branch, so only the larger one needs a listing. Any other shape counts 0.
func alternatives(script string) int {
	lines := strings.Split(script, "\n")
	ifAt, elseAt, fiAt := -1, -1, -1
	for i, l := range lines {
		switch w := strings.TrimSpace(l); {
		case strings.HasPrefix(w, "if "):
			if ifAt >= 0 {
				return 0
			}
			ifAt = i
		case w == "else":
			if elseAt >= 0 {
				return 0
			}
			elseAt = i
		case w == "fi":
			if fiAt >= 0 {
				return 0
			}
			fiAt = i
		case strings.HasPrefix(w, "elif "):
			return 0
		}
	}
	if ifAt < 0 || elseAt < ifAt || fiAt < elseAt {
		return 0
	}
	count := func(ls []string) int {
		n := 0
		for _, in := range workflow.PyInstalls(strings.Join(ls, "\n")) {
			if !in.Opaque {
				n++
			}
		}
		return n
	}
	return min(count(lines[ifAt+1:elseAt]), count(lines[elseAt+1:fiAt]))
}

// ParseLog reads a job log. Line numbers are those of the raw log.
func ParseLog(log string) Log {
	var l Log
	cur := &section{}
	n := 0
	for log != "" {
		var raw string
		raw, log, _ = strings.Cut(log, "\n")
		n++
		raw = strings.TrimSuffix(raw, "\r")
		if strings.Contains(raw, "##[group]Run ") {
			l.Sections = append(l.Sections, cur.finish())
			_, hdr, _ := strings.Cut(raw, "##[group]Run ")
			cur = &section{Section: Section{Line: n}, echo: true, hdr: hdr}
			low := strings.ToLower(hdr)
			cur.setup = strings.HasPrefix(low, "actions/setup-python@") || strings.HasPrefix(low, "astral-sh/setup-uv@")
			cur.Python = cur.setup
			continue
		}
		if cur.echo {
			if strings.Contains(raw, "##[endgroup]") {
				cur.setCmd()
			} else if strings.Contains(raw, "\x1b[36;1m") {
				cur.echoText = append(cur.echoText, sgrRe.ReplaceAllString(tsRe.ReplaceAllString(raw, ""), ""))
			}
			continue
		}
		if !containsAny(raw, lineLiterals) {
			continue
		}
		line := sgrRe.ReplaceAllString(tsRe.ReplaceAllString(raw, ""), "")
		l.parseLine(cur, line, n)
	}
	l.Sections = append(l.Sections, cur.finish())
	return l
}

func containsAny(s string, subs []string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func (l *Log) add(name, ver string, n int, text string) bool {
	v, ok := pep.ParseVersion(ver)
	if !ok || !pep.ValidName(name) {
		l.Unparsed = append(l.Unparsed, Install{Name: name, Version: ver, Line: n, Text: text})
		return false
	}
	l.Installs = append(l.Installs, Install{Name: pep.Name(name), Version: versionText(v), Line: n, Text: text})
	return true
}

// versionText shows a canonical version with its local label.
func versionText(v pep.Version) string {
	if v.Local != "" {
		return v.Public + "+" + v.Local
	}
	return v.Public
}

func (l *Log) parseLine(cur *section, line string, n int) {
	install := func() { cur.Python, l.Calls = true, true }
	switch {
	case setupUVRe.MatchString(line):
	case pipDoneRe.MatchString(line):
		install()
		cur.pipDone = true
		ok := true
		for _, tok := range strings.Fields(pipDoneRe.FindStringSubmatch(line)[1]) {
			name, ver, split := splitNameVersion(tok)
			if !split {
				l.Unparsed = append(l.Unparsed, Install{Name: tok, Line: n, Text: line})
				ok = false
				continue
			}
			ok = l.add(name, ver, n, line) && ok
		}
		if ok {
			cur.blocks++
		} else {
			cur.partial = true
		}
	case pipHaveRe.MatchString(line):
		install()
		m := pipHaveRe.FindStringSubmatch(line)
		cur.have = true
		if !l.add(m[1], m[2], n, line) {
			cur.partial = true
		}
	case pipFileRe.MatchString(line):
		install()
		if name, ver, ok := splitFile(pipFileRe.FindStringSubmatch(line)[1]); ok {
			l.add(name, ver, n, line)
		}
	case uvDoneRe.MatchString(line):
		install()
		cur.closeBlocks()
		cur.uvWant, _ = strconv.Atoi(uvDoneRe.FindStringSubmatch(line)[1])
		cur.uvOpen = true
	case uvLineRe.MatchString(line):
		install()
		m := uvLineRe.FindStringSubmatch(line)
		if !l.add(m[1], m[2], n, line) {
			cur.partial = true
		}
		if cur.uvOpen {
			cur.uvWant--
		}
	case poetryOpsRe.MatchString(line):
		install()
		cur.closeBlocks()
		m := poetryOpsRe.FindStringSubmatch(line)
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		cur.poWant, cur.poOpen = a+b, true
	case poetryLineRe.MatchString(line):
		install()
		m := poetryLineRe.FindStringSubmatch(line)
		ver := m[2]
		if _, after, ok := strings.Cut(ver, "-> "); ok {
			ver = after
		}
		if !l.add(m[1], strings.TrimSpace(ver), n, line) {
			cur.partial = true
		}
		if cur.poOpen {
			cur.poWant--
		}
	case pipxRe.MatchString(line):
		install()
		m := pipxRe.FindStringSubmatch(line)
		l.add(m[1], m[2], n, line)
	case partialRe.MatchString(line):
		install()
		cur.partial = true
	case callRe.MatchString(line):
		l.Calls = true
	}
}

// splitNameVersion splits pip's "name-version" token at the last '-' followed by a valid version.
func splitNameVersion(tok string) (name, ver string, ok bool) {
	i := strings.LastIndexByte(tok, '-')
	if i <= 0 || i == len(tok)-1 {
		return "", "", false
	}
	if _, ok := pep.ParseVersion(tok[i+1:]); !ok || !pep.ValidName(tok[:i]) {
		return "", "", false
	}
	return tok[:i], tok[i+1:], true
}

// splitFile reads name and version from a wheel ({name}-{ver}-….whl) or sdist ({name}-{ver}.tar.gz) file name.
func splitFile(f string) (name, ver string, ok bool) {
	if base, isWheel := strings.CutSuffix(f, ".whl"); isWheel {
		parts := strings.Split(base, "-")
		if len(parts) < 5 {
			return "", "", false
		}
		return parts[0], parts[1], true
	}
	base := strings.TrimSuffix(strings.TrimSuffix(f, ".tar.gz"), ".zip")
	return splitNameVersion(base)
}
