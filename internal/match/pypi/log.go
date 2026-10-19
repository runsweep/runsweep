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
	uvLineRe     = regexp.MustCompile(`^\s*[+~] ([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)(?: \(from \S+\))?\s*$`)
	uvResolvedRe = regexp.MustCompile(`^\s*Resolved \d+ packages?`)
	uvDoneRe     = regexp.MustCompile(`^\s*Installed (\d+) packages? in `)
	poetryOpsRe  = regexp.MustCompile(`^\s*Package operations: (\d+) installs?, (\d+) updates?, \d+ removals?`)
	poetryLineRe = regexp.MustCompile(`^\s*[-•] (?:Installing|Updating|Downgrading) ([A-Za-z0-9][A-Za-z0-9._-]*) \(([^)]*)\)`)
	pipxRe       = regexp.MustCompile(`^\s*installed package (\S+) (\S+?),`)
	// output that shows an install without a full list of versions
	partialRe = regexp.MustCompile(`^\s*(?:Audited \d+ packages?|No dependencies to install or update|Installing build dependencies|Building \S+ @ )`)
	loopRe    = regexp.MustCompile(`\b(?:for|while|xargs)\b`)
)

// literals every line worth a regexp contains; the rest of a big log is skipped cheaply
var lineLiterals = []string{"installed", "Installed", "Requirement already", "Downloading", "Using cached",
	"==", "Package operations", "Installing", "Updating", "Downgrading", "Audited", "No dependencies", "Building", "Resolved", "pip", "uv", "poetry", "python", "Python", "Pip",
	"tox", "nox", "pdm", "hatch", "pipenv", "conda", "mamba", "pixi", "rye", "pre-commit"}

// section accumulates one step while the log is read.
type section struct {
	Section
	echo     bool // inside the header (until ##[endgroup])
	blocks   int  // full version lists seen
	partial  bool
	have     bool // Requirement already satisfied lines seen
	pipDone  bool
	uvWant   int // packages "Installed N packages" announced
	uvOpen   bool
	uvNames  map[string]bool // distinct packages listed since then
	uvSeen   bool            // an "Installed N" or "Audited" block was printed
	resolved bool            // "Resolved N packages" was printed
	envQuiet bool            // UV_QUIET or PIP_QUIET set in the step's environment
	sawOut   bool            // the output showed any install, listing or partial line
	poWant   int
	poOpen   bool
	poNames  map[string]bool
	setup    bool // a Python setup action: needs no full list
	hdr      string
	echoText []string
}

func (s *section) closeBlocks() {
	if s.uvOpen {
		if len(s.uvNames) >= s.uvWant {
			s.blocks++
		} else {
			s.partial = true
		}
		s.uvOpen = false
	}
	if s.poOpen {
		if len(s.poNames) >= s.poWant {
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
	if s.resolved && !s.uvSeen {
		s.partial = true // uv resolved but printed no list of what it installed
	}
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
	if s.setup {
		out.Complete = out.Opaque == ""
		return out
	}
	if s.envQuiet || envQuiet(out.Cmd) {
		return out // quiet by environment: versions may go unprinted
	}
	if cmds == 0 {
		// no install command: complete only if nothing in the output looks like an install
		out.Complete = out.Opaque == "" && !s.sawOut && !s.partial
		return out
	}
	// a listing is proof only for commands seen in the script: none, a script run beside them, or
	// a command that hides its output leave versions unaccounted for
	out.Complete = out.Opaque == "" && !s.partial && !dynamic && !loop && s.blocks >= cmds &&
		!workflow.RunsScript(out.Cmd) && !quietOutput(out.Cmd)
	return out
}

var (
	quotedRe   = regexp.MustCompile(`"[^"]*"|'[^']*'`)
	envQuietRe = regexp.MustCompile(`(?:^|[\s;&|(])(?:UV|PIP)_QUIET(?:=|:\s*)["']?([^\s"';&|]*)`)
)

// envQuiet reports whether text sets UV_QUIET or PIP_QUIET to something other than off.
func envQuiet(text string) bool {
	for _, m := range envQuietRe.FindAllStringSubmatch(text, -1) {
		if v := strings.ToLower(m[1]); v != "" && v != "0" && v != "false" {
			return true
		}
	}
	return false
}

// segment is one command of a script with its pipes and redirects; hidden when an enclosing
// group's output is captured, piped or redirected.
type segment struct {
	text   string
	hidden bool
}

// group is a (…), { …; }, $(…) or `…` group: segments [start, end) are inside, segment end follows it.
type group struct {
	start, end int
	captured   bool
}

// segments splits a script into commands on newlines, ;, &&, ||, groups and substitutions,
// outside quotes, and drops comments. Pipes and redirects stay in their segment.
func segments(script string) []segment {
	type frame struct {
		kind  byte // '(', '$', '`', '{'
		quote byte // the quote state to restore on close
		start int
	}
	var (
		segs   []segment
		groups []group
		stack  []frame
		cur    strings.Builder
		quote  byte
		param  int // open ${
	)
	cut := func() { segs = append(segs, segment{text: cur.String()}); cur.Reset() }
	wordStart := func() bool {
		t := cur.String()
		return t == "" || t[len(t)-1] == ' ' || t[len(t)-1] == '\t'
	}
	open := func(kind byte) {
		stack = append(stack, frame{kind, quote, len(segs) + 1})
		cut()
		quote = 0
	}
	closeTop := func() {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		cut()
		groups = append(groups, group{f.start, len(segs), f.kind == '$' || f.kind == '`'})
		quote = f.quote
	}
	top := func() byte {
		if len(stack) == 0 {
			return 0
		}
		return stack[len(stack)-1].kind
	}
	for i := 0; i < len(script); i++ {
		c := script[i]
		next := byte(0)
		if i+1 < len(script) {
			next = script[i+1]
		}
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
			cur.WriteByte(c)
		case c == '\\' && next != 0:
			cur.WriteByte(c)
			cur.WriteByte(next)
			i++
		case c == '$' && next == '(':
			i++
			open('$')
		case c == '`':
			if top() == '`' {
				closeTop()
			} else {
				open('`')
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			}
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			quote = c
			cur.WriteByte(c)
		case c == '#' && wordStart():
			for i+1 < len(script) && script[i+1] != '\n' {
				i++
			}
		case c == '\n' || c == ';':
			cut()
		case (c == '&' || c == '|') && next == c:
			i++
			cut()
		case c == '$' && next == '{':
			i++
			param++
			cur.WriteString("${")
		case c == '(':
			open('(')
		case c == ')':
			if t := top(); t == '(' || t == '$' {
				closeTop()
			} else {
				cut()
			}
		case c == '{' && wordStart() && (next == 0 || next == ' ' || next == '\t' || next == '\n'):
			open('{')
		case c == '}' && param > 0:
			param--
			cur.WriteByte(c)
		case c == '}' && top() == '{' && wordStart():
			closeTop()
		default:
			cur.WriteByte(c)
		}
	}
	cut()
	for _, g := range groups {
		if g.captured || g.end < len(segs) && hidesOutput(pipeline(segs[g.end].text)) {
			for i := g.start; i < g.end; i++ {
				segs[i].hidden = true
			}
		}
	}
	return segs
}

// pipeline splits a command on unquoted | (and |&).
func pipeline(seg string) []string {
	var (
		out   []string
		quote byte
		last  int
	)
	for i := 0; i < len(seg); i++ {
		switch c := seg[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' {
				i++
			}
		case c == '\\':
			i++
		case c == '\'' || c == '"':
			quote = c
		case c == '|':
			out = append(out, seg[last:i])
			if i+1 < len(seg) && seg[i+1] == '&' {
				i++
			}
			last = i + 1
		}
	}
	return append(out, seg[last:])
}

// hidesOutput reports whether a pipeline, from the command whose output matters on, redirects
// stdout or pipes it into anything but tee.
func hidesOutput(els []string) bool {
	for i, el := range els {
		if i > 0 && firstWord(el) != "tee" || redirectsStdout(quotedRe.ReplaceAllString(el, "")) {
			return true
		}
	}
	return false
}

// redirectsStdout reports whether unquoted text redirects fd 1: >, >>, 1>, &>, >&; 2> alone does not.
func redirectsStdout(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '>' {
			continue
		}
		j := i
		for j > 0 && s[j-1] >= '0' && s[j-1] <= '9' {
			j--
		}
		switch {
		case j < i && (j == 0 || s[j-1] == ' ' || s[j-1] == '\t'): // a file descriptor number
			if s[j:i] == "1" {
				return true
			}
		case i > 0 && s[i-1] == '>': // the second > of >>
		default:
			return true
		}
		for i+1 < len(s) && s[i+1] == '>' {
			i++
		}
	}
	return false
}

func firstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

func countInstalls(text string) int {
	n := 0
	for _, in := range workflow.PyInstalls(text) {
		if !in.Opaque {
			n++
		}
	}
	return n
}

var (
	quietRe   = regexp.MustCompile(`(?:^|\s)(?:-[a-zA-Z]*q[a-zA-Z]*|--quiet)(?:[\s=]|$)`)
	textWords = map[string]bool{"echo": true, "printf": true, "print": true, "cat": true}
	leadWords = map[string]bool{"then": true, "do": true, "else": true, "if": true, "elif": true, "while": true, "until": true, "!": true}
	endWords  = map[string]bool{"fi": true, "done": true, "esac": true}
)

// joinLines joins shell (\) and PowerShell (`) continued lines. A line ending in a backtick
// with an even count of backticks closes a substitution instead, and is kept.
func joinLines(script string) string {
	lines := strings.Split(strings.ReplaceAll(script, "\r\n", "\n"), "\n")
	var b strings.Builder
	for i, l := range lines {
		switch {
		case i == len(lines)-1:
			b.WriteString(l)
		case strings.HasSuffix(l, "\\") || strings.HasSuffix(l, "`") && strings.Count(l, "`")%2 == 1:
			b.WriteString(l[:len(l)-1] + " ")
		default:
			b.WriteString(l + "\n")
		}
	}
	return b.String()
}

// quietOutput reports whether an install command of the script asks for quiet output (a quiet
// flag) or hides it (stdout redirected, piped into anything but tee, captured by $(…), or the same
// done to its enclosing group, if-block or loop).
func quietOutput(script string) bool {
	script = joinLines(script)
	found := 0
	for _, seg := range segments(script) {
		text := strings.TrimSpace(seg.text)
		w := firstWord(text)
		for leadWords[w] {
			text = strings.TrimSpace(text[len(w):])
			w = firstWord(text)
		}
		if endWords[w] {
			if hidesOutput(pipeline(text[len(w):])) {
				return true // fi | tail: the block's output is hidden
			}
			continue
		}
		els := pipeline(text)
		for i, el := range els {
			if textWords[firstWord(el)] {
				continue
			}
			n := countInstalls(el)
			if n == 0 {
				continue
			}
			found += n
			if seg.hidden || hidesOutput(els[i:]) || quietRe.MatchString(quotedRe.ReplaceAllString(strings.Join(els[i:], " "), "")) {
				return true
			}
		}
	}
	return found < countInstalls(script) // an install no segment accounts for: assume the worst
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
		if !cur.echo && strings.Contains(raw, "##[group]Run ") {
			l.Sections = append(l.Sections, cur.finish())
			_, hdr, _ := strings.Cut(raw, "##[group]Run ")
			cur = &section{Section: Section{Line: n}, echo: true, hdr: hdr}
			low := strings.ToLower(hdr)
			cur.setup = strings.HasPrefix(low, "actions/setup-python@") || strings.HasPrefix(low, "astral-sh/setup-uv@")
			cur.Python = cur.setup
			continue
		}
		if cur.echo {
			// only cyan lines are script text; anything else in the header is output
			if strings.Contains(raw, "##[endgroup]") {
				cur.setCmd()
				continue
			}
			if strings.Contains(raw, "\x1b[36;1m") {
				cur.echoText = append(cur.echoText, sgrRe.ReplaceAllString(tsRe.ReplaceAllString(raw, ""), ""))
				continue
			}
			if m := envQuietRe.FindStringSubmatch(sgrRe.ReplaceAllString(tsRe.ReplaceAllString(raw, ""), "")); m != nil && envQuiet(m[0]) {
				cur.envQuiet = true
			}
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
	install := func() { cur.Python, l.Calls, cur.sawOut = true, true, true }
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
		cur.uvOpen, cur.uvSeen, cur.uvNames = true, true, map[string]bool{}
	case uvResolvedRe.MatchString(line):
		cur.resolved, cur.sawOut = true, true
	case uvLineRe.MatchString(line):
		install()
		m := uvLineRe.FindStringSubmatch(line)
		if !l.add(m[1], m[2], n, line) {
			cur.partial = true
		}
		if cur.uvOpen {
			cur.uvNames[pep.Name(m[1])] = true
		}
	case poetryOpsRe.MatchString(line):
		install()
		cur.closeBlocks()
		m := poetryOpsRe.FindStringSubmatch(line)
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		cur.poWant, cur.poOpen, cur.poNames = a+b, true, map[string]bool{}
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
			cur.poNames[pep.Name(m[1])] = true
		}
	case pipxRe.MatchString(line):
		install()
		m := pipxRe.FindStringSubmatch(line)
		l.add(m[1], m[2], n, line)
	case partialRe.MatchString(line):
		install()
		cur.uvSeen = cur.uvSeen || strings.Contains(line, "Audited")
		cur.partial = true
	case callsInstaller(line):
		l.Calls = true
	}
}

// callsInstaller reports whether an output line starts with a Python tool word (a runner
// "[command]/usr/bin/pip install" line, a version banner).
func callsInstaller(line string) bool {
	f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(line), "[command]"))
	return len(f) > 0 && workflow.HasPyTool(f[0])
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
