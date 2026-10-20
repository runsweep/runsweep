// Package pypi finds PyPI packages a job installed: install lines in its log (the proof) and
// lockfiles in the repository (the fallback when the log does not list every version).
package pypi

import (
	"maps"
	"path"
	"regexp"
	"slices"
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
	rasTail  bool           // "Requirement already satisfied" lines after the last "Successfully installed"
	rasTop   map[string]int // packages "Requirement already satisfied" names as requested, not as a dependency
	uvWant   int            // packages "Installed N packages" announced
	uvOpen   bool
	uvNames  map[string]bool // distinct packages listed since then
	uvSeen   bool            // an "Installed N" or "Audited" block was printed
	resolved bool            // "Resolved N packages" was printed
	envQuiet bool            // UV_QUIET or PIP_QUIET set in the step's environment
	pwsh     bool            // the step runs in PowerShell
	sawOut   bool            // the output showed any install, listing or partial line
	poWant   int
	poOpen   bool
	poNames  map[string]bool
	tox      bool            // the step's script runs tox (tox, python -m tox)
	toxEnv   map[string]bool // tox environments that ran: true once a listing of every package was read
	toxWait  map[string]bool // a tox 4 freeze> line whose listing has not been read yet
	toxBad   map[string]bool // environments no listing can complete: an sdist or editable package, a custom freeze, tox 3
	toxSetup bool            // inside a tox action that sets an environment up: the listing covers its installer output
	toxCmds  []string        // the commands tox ran (commands[N]>, run-test:): installs there need their own output
	scratch  *section        // takes the installer output of tox setup actions
	setup    bool            // a Python setup action: needs no full list
	pipArgs  string          // the pip-install input of actions/setup-python
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
	s.tox = countTox(s.Cmd) > 0
}

func (s *section) finish() Section {
	if s.echo { // the log ended inside the header
		s.setCmd()
	}
	s.closeBlocks()
	if s.resolved && !s.uvSeen {
		s.partial = true // uv resolved but printed no list of what it installed
	}
	out := s.Section
	if !out.Python {
		return out
	}
	script := out.Cmd
	if s.setup {
		if s.pipArgs == "" {
			out.Complete = true // the action's own installs need no list
			return out
		}
		script = "pip install " + s.pipArgs // setup-python installs its pip-install input like a step would
	}
	// tox is read from its listings: every environment that ran printed one, tox's output is not
	// hidden, and the commands tox ran are judged like the step's own
	toxOK := false
	if len(s.toxEnv) > 0 {
		script += "\n" + strings.Join(s.toxCmds, "\n")
		toxOK = !slices.Contains(slices.Collect(maps.Values(s.toxEnv)), false) && len(s.toxBad) == 0 && !s.envQuiet && !envQuiet(script) &&
			!quietFor(script, s.pwsh, countTox)
		if !toxOK {
			out.Opaque = "tox"
		}
	}
	cmds, dynamic, named := 0, false, 0
	for _, in := range workflow.PyInstalls(script) {
		if in.Opaque && out.Opaque == "" && (!toxOK || !toxRun(in)) {
			out.Opaque = in.Tool
		}
		if !in.Opaque {
			cmds++
		}
		dynamic = dynamic || in.Dynamic
		if in.Named && !slices.ContainsFunc(in.Pkgs, func(p string) bool { return s.rasTop[p] == 0 }) {
			// every package it names was already satisfied: its listing is those lines
			named++
			for _, p := range in.Pkgs {
				s.rasTop[p]--
			}
		}
	}
	if s.rasTail {
		named = max(named, 1) // a series after the last "Successfully installed" is a pip run of its own
	}
	// ponytail: the named and the trailing series may be one; max is the safe count, summing them needs output order
	s.blocks += named
	loop := cmds > 0 && loopRe.MatchString(script)
	need := cmds - alternatives(script)
	if s.envQuiet || envQuiet(script) {
		return out // quiet by environment: versions may go unprinted
	}
	if cmds == 0 {
		// no install command: complete only if nothing in the output looks like an install
		out.Complete = out.Opaque == "" && !s.sawOut && !s.partial
		return out
	}
	// a listing is proof only for commands seen in the script: none, a script run beside them, or
	// a command that hides its output leave versions unaccounted for
	out.Complete = out.Opaque == "" && !s.partial && !dynamic && !loop && s.blocks >= need &&
		!workflow.RunsScript(script) && !quietOutput(script, s.pwsh)
	return out
}

var (
	quotedRe   = regexp.MustCompile(`"[^"]*"|'[^']*'`)
	envQuietRe = regexp.MustCompile(`(?:^|[\s;&|(])(?:UV|PIP|TOX)_QUIET(?:=|:\s*)["']?([^\s"';&|]*)`)
)

// envQuiet reports whether text sets UV_QUIET, PIP_QUIET or TOX_QUIET to something other than off.
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
// outside quotes, and drops comments and heredoc bodies. Pipes and redirects stay in their
// segment. quiet is true when the script cannot be followed: an open quote, group or heredoc at
// the end, a heredoc fed to a command that may run it (bash <<EOF, cat <<EOF | sh), or a shell
// function definition (its output may be piped where it is called; not followed). In PowerShell
// (pwsh), a backtick inside "…" escapes the next character.
func segments(script string, pwsh bool) (segs []segment, quiet bool) {
	type heredoc struct {
		word string
		seg  int // the segment of the command that reads it
	}
	type frame struct {
		kind  byte // '(', '$', '`', '{'
		quote byte // the quote state to restore on close
		start int
	}
	var (
		groups  []group
		stack   []frame
		cur     strings.Builder
		quote   byte
		param   int // open ${
		pending []heredoc
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
		case pwsh && quote == '"' && c == '`' && next != 0:
			cur.WriteByte(c)
			cur.WriteByte(next)
			i++
		case c == '\\' && next != 0 && !pwsh:
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
		case c == '\n':
			cut()
			for _, h := range pending {
				end := skipHeredoc(script, i+1, h.word)
				if end < 0 {
					return segs, true // no terminator line
				}
				i = end - 1
				if !feedsData(segs[h.seg].text) {
					quiet = true
				}
			}
			pending = nil
		case c == ';':
			cut()
		case c == '<' && next == '<' && quote == 0:
			word, end := heredocWord(script, i)
			if end < 0 {
				return segs, true
			}
			if word != "" {
				pending = append(pending, heredoc{word, len(segs)})
			}
			cur.WriteString(script[i:end])
			i = end - 1
		case (c == '&' || c == '|') && next == c:
			i++
			cut()
		case c == '$' && next == '{':
			i++
			param++
			cur.WriteString("${")
		case c == '(':
			if f := strings.Fields(cur.String()); len(f) > 0 && funcNameRe.MatchString(f[len(f)-1]) &&
				strings.HasPrefix(strings.TrimLeft(script[i+1:], " \t"), ")") {
				quiet = true // name() { …; }: a function definition (arr=(), $(), $x.Trim() are not)
			}
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
	if quote != 0 || len(stack) > 0 || param > 0 || len(pending) > 0 ||
		slices.ContainsFunc(segs, func(s segment) bool { return funcRe.MatchString(s.text) }) {
		quiet = true
	}
	for _, g := range groups {
		if g.captured || g.end < len(segs) && hidesOutput(pipeline(segs[g.end].text)) {
			for i := g.start; i < g.end; i++ {
				segs[i].hidden = true
			}
		}
	}
	return segs, quiet
}

// heredocWord reads the heredoc operator at script[i] ("<<"): its terminator word (unquoted) and
// the end of the operator. A here-string (<<<) or a shift (1<<2) has no word; end < 0 for an
// unterminated quoted word.
func heredocWord(script string, i int) (word string, end int) {
	j := i + 2
	if j < len(script) && script[j] == '<' {
		return "", j + 1
	}
	if j < len(script) && script[j] == '-' {
		j++
	}
	for j < len(script) && (script[j] == ' ' || script[j] == '\t') {
		j++
	}
	if j == len(script) {
		return "", j
	}
	if q := script[j]; q == '\'' || q == '"' {
		k := strings.IndexByte(script[j+1:], q)
		if k < 0 {
			return "", -1
		}
		return script[j+1 : j+1+k], j + 2 + k
	}
	if c := script[j]; c != '_' && c != '\\' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return "", i + 2
	}
	k := j
	for k < len(script) && !strings.ContainsRune(" \t\n;&|<>()", rune(script[k])) {
		k++
	}
	return strings.NewReplacer("\\", "", "'", "", `"`, "").Replace(script[j:k]), k
}

// skipHeredoc returns the position after the heredoc body that starts at pos and its terminator
// line, or -1 when no line is the terminator.
func skipHeredoc(script string, pos int, word string) int {
	for pos < len(script) {
		line, _, found := strings.Cut(script[pos:], "\n")
		pos += len(line) + 1
		if strings.TrimSpace(line) == word {
			return min(pos, len(script))
		}
		if !found {
			break
		}
	}
	return -1
}

// dataWords read a heredoc as data.
var dataWords = map[string]bool{"cat": true, "tee": true, "read": true, "mapfile": true, "readarray": true,
	"grep": true, "sed": true, "awk": true, "jq": true, "envsubst": true}

// feedsData reports whether every command of a pipeline only reads its input as data.
func feedsData(seg string) bool {
	for _, el := range pipeline(seg) {
		if w := leadStripped(el); !dataWords[w] {
			return false
		}
	}
	return true
}

// leadStripped is the first word of a command after if/then/do/… keywords.
func leadStripped(text string) string {
	f := strings.Fields(text)
	for len(f) > 0 && leadWords[f[0]] {
		f = f[1:]
	}
	if len(f) == 0 {
		return ""
	}
	return f[0]
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
	quietRe     = regexp.MustCompile(`(?:^|\s)(?:-[a-zA-Z]*q[a-zA-Z]*|--quiet)(?:[\s=]|$)`)
	textWords   = map[string]bool{"echo": true, "printf": true, "print": true, "cat": true}
	leadWords   = map[string]bool{"then": true, "do": true, "else": true, "if": true, "elif": true, "while": true, "until": true, "!": true}
	endWords    = map[string]bool{"fi": true, "done": true, "esac": true}
	pipInputRe  = regexp.MustCompile(`^\s*pip-install: (.*\S)`) // the pip-install input in a setup-python header
	pwshShellRe = regexp.MustCompile(`(?i)^\s*shell: .*\b(?:pwsh|powershell)\b`)
	pwshTextRe  = regexp.MustCompile(`(?i)write-host|\$env:|\|\s*out-null|\*>\s*\$null`)
	funcRe      = regexp.MustCompile(`^\s*function\s`) // a shell function definition by keyword
	funcNameRe  = regexp.MustCompile(`^[A-Za-z_][\w.:-]*$`)
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
func quietOutput(script string, pwsh bool) bool { return quietFor(script, pwsh, countInstalls) }

// quietFor is quietOutput for the commands count counts (installs, or tox runs).
func quietFor(script string, pwsh bool, count func(string) int) bool {
	script = joinLines(script)
	segs, quiet := segments(script, pwsh || pwshTextRe.MatchString(script))
	if quiet {
		return true
	}
	found, muted := 0, false
	for _, seg := range segs {
		text := strings.TrimSpace(seg.text)
		w := firstWord(text)
		for leadWords[w] {
			text = strings.TrimSpace(text[len(w):])
			w = firstWord(text)
		}
		if w == "exec" && redirectsStdout(quotedRe.ReplaceAllString(text[len(w):], "")) {
			muted = true // exec >/dev/null: every later command's output is hidden
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
			n := count(el)
			if n == 0 {
				continue
			}
			found += n
			if muted || seg.hidden || hidesOutput(els[i:]) || quietRe.MatchString(quotedRe.ReplaceAllString(strings.Join(els[i:], " "), "")) {
				return true
			}
		}
	}
	return found < count(script) // a command no segment accounts for: assume the worst
}

// alternatives counts install commands that may not run: a script with a single if/else/fi runs
// one branch, so only the larger one needs a listing; a single if/fi without else may skip its
// branch (if [ -f requirements.txt ]; then pip install -r requirements.txt; fi). Any other shape
// counts 0.
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
	count := func(ls ...string) int {
		n := 0
		for _, in := range workflow.PyInstalls(strings.Join(ls, "\n")) {
			if !in.Opaque {
				n++
			}
		}
		return n
	}
	switch {
	case ifAt < 0:
	case elseAt < 0 && fiAt < 0:
		if m := oneLineIfRe.FindStringSubmatch(strings.TrimSpace(lines[ifAt])); m != nil && !nestedRe.MatchString(m[1]) {
			return count(m[1])
		}
	case elseAt < 0 && fiAt > ifAt:
		return count(lines[ifAt+1 : fiAt]...)
	case elseAt > ifAt && fiAt > elseAt:
		return min(count(lines[ifAt+1:elseAt]...), count(lines[elseAt+1:fiAt]...))
	}
	return 0
}

var (
	oneLineIfRe = regexp.MustCompile(`^if [^;]*;\s*then\s(.*?);?\s*fi$`) // if COND; then BODY; fi on one line
	nestedRe    = regexp.MustCompile(`\b(?:if|then|else|elif|fi)\b`)
)

// ParseLog reads a job log. Line numbers are those of the raw log.
func ParseLog(log string) Log {
	var l Log
	cur := &section{rasTop: map[string]int{}}
	n := 0
	for log != "" {
		var raw string
		raw, log, _ = strings.Cut(log, "\n")
		n++
		raw = strings.TrimSuffix(raw, "\r")
		if !cur.echo && strings.Contains(raw, "##[group]Run ") {
			l.Sections = append(l.Sections, cur.finish())
			_, hdr, _ := strings.Cut(raw, "##[group]Run ")
			cur = &section{Section: Section{Line: n}, echo: true, hdr: hdr, rasTop: map[string]int{}}
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
			hl := sgrRe.ReplaceAllString(tsRe.ReplaceAllString(raw, ""), "")
			if m := envQuietRe.FindStringSubmatch(hl); m != nil && envQuiet(m[0]) {
				cur.envQuiet = true
			}
			cur.pwsh = cur.pwsh || pwshShellRe.MatchString(hl)
			if m := pipInputRe.FindStringSubmatch(hl); m != nil && cur.setup {
				cur.pipArgs = m[1]
			}
		}
		// tox lines: env prefixes, listings (an empty one ends in ":"), summaries
		if strings.Contains(raw, ": ") || strings.Contains(raw, ":\x1b") || strings.HasSuffix(raw, ":") {
			if l.toxLine(cur, sgrRe.ReplaceAllString(tsRe.ReplaceAllString(raw, ""), ""), n) {
				continue
			}
		}
		if !containsAny(raw, lineLiterals) {
			continue
		}
		line := sgrRe.ReplaceAllString(tsRe.ReplaceAllString(raw, ""), "")
		if cur.toxSetup {
			// tox's own installer output (tox -vv): its versions are installs, its completeness is
			// the listing's; evidence of an unlisted install (build dependencies) still counts
			if cur.scratch == nil {
				cur.scratch = &section{rasTop: map[string]int{}}
			}
			l.parseLine(cur.scratch, line, n)
			cur.Python, cur.partial = true, cur.partial || cur.scratch.partial
			continue
		}
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
	case setupUVRe.MatchString(line), strings.HasPrefix(line, "Terminate orphan process: "): // the runner names a process it kills
	case pipDoneRe.MatchString(line):
		install()
		cur.rasTail = false
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
		cur.rasTail = true
		if !strings.Contains(line, "(from ") {
			cur.rasTop[pep.Name(m[1])]++
		}
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
	case echoesInstall(line):
		install() // make or set -x printed an install command: its output is the step's
	case callsInstaller(line):
		l.Calls = true
	}
}

// echoesInstall reports whether an output line holds an install command (make echoing a recipe,
// set -x, a runner "[command]" line): an install or a tool that always installs, not a bare tool
// word (a "Python 3.12" banner, "pip 24.0 from …", pip's update notice).
func echoesInstall(line string) bool {
	t := strings.TrimLeft(strings.TrimPrefix(strings.TrimSpace(line), "[command]"), "+ ")
	return slices.ContainsFunc(workflow.PyInstalls(t), func(in workflow.PyInstall) bool {
		return !in.Opaque || workflow.AlwaysInstalls(in.Tool)
	})
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

var (
	// tox 4: "<env>: <action>> <command>"; tox -vv puts "<ms> <level> " before the action and a
	// " [file:line]" source after the line
	// (an env name is anything up to the ": " separator: docs:html, non-ASCII letters)
	toxActRe = regexp.MustCompile(`^(\S+?): (\d+ [A-Z] )?([a-z_-]+(?:\[\d+\])?)(?: [^>]*)?> (.*)$`)
	toxEnvRe = regexp.MustCompile(`^(\S+?):(?: (\d+ [A-Z] )?(.*))?$`)
	toxSrcRe = regexp.MustCompile(` \[[\w/.-]+:\d+\]$`)
	// the result of an environment, tox 4 and tox 3
	toxSumRe = regexp.MustCompile(`^\s*(?:ERROR:\s+)?(\S+?): (?:OK|FAIL|commands succeeded|commands failed)\b`)
	// tox 3: "<env> <action>: <text>"
	tox3Re = regexp.MustCompile(`^(\S+?) (create|recreate|installdeps|inst|inst-nodeps|develop-inst|develop-inst-nodeps|develop-inst-noop|installed|run-test-pre|run-test|run-test-post):(?: (.*))?$`)
	// tox 4's own list_dependencies_command: pip freeze --all, or tox-uv's uv pip freeze
	toxFreezeRe = regexp.MustCompile(`^(?:(?:\S*[/\\])?python[\d.]*(?:\.exe)? (?:-I )?-m pip|(?:\S*[/\\])?pip[\d.]*(?:\.exe)?) freeze --all$|^(?:\S*[/\\])?uv(?:\.exe)? --color never pip freeze$`)
	// a listing entry for a local directory installed in editable mode
	toxEditableRe = regexp.MustCompile(`^-e (?:/|\.|file:|[A-Za-z]:[\\/])`)
	// tox 4 actions that install nothing in their environment: after the listing they leave it whole
	toxReadOnly = map[string]bool{"freeze": true, "exit": true, "_exit": true, "_optional_hooks": true,
		"get_requires_for_build_sdist": true, "get_requires_for_build_wheel": true, "get_requires_for_build_editable": true,
		"prepare_metadata_for_build_wheel": true, "prepare_metadata_for_build_editable": true,
		"build_sdist": true, "build_wheel": true, "build_editable": true}
)

// toxRun reports whether a command runs tox itself. uvx tox, uv tool run tox and pipx run tox are
// not: they install tox's own environment, and print nothing when it comes from their cache.
func toxRun(in workflow.PyInstall) bool { return in.Tool == "tox" || in.Tool == "python -m tox" }

func countTox(text string) int {
	n := 0
	for _, in := range workflow.PyInstalls(text) {
		if toxRun(in) {
			n++
		}
	}
	return n
}

// ran records a tox environment that ran; it needs a listing.
func (s *section) ran(env string) {
	if s.toxEnv == nil {
		s.toxEnv, s.toxWait, s.toxBad = map[string]bool{}, map[string]bool{}, map[string]bool{}
	}
	if _, ok := s.toxEnv[env]; !ok {
		s.toxEnv[env] = false
	}
	s.Python = true
}

// toxLine reads a tox line: an action, a listing or a result. Outside a step that runs tox, only
// known tox 4 actions start reading (any "word: x> y" line would otherwise).
func (l *Log) toxLine(s *section, line string, n int) bool {
	if m := toxActRe.FindStringSubmatch(line); m != nil {
		env, act, cmd := m[1], m[3], m[4]
		if m[2] != "" {
			cmd = toxSrcRe.ReplaceAllString(cmd, "")
		}
		cmds := strings.HasPrefix(act, "commands")
		if !s.tox && s.toxEnv == nil && !cmds && !toxReadOnly[act] && act != "venv" && !strings.HasPrefix(act, "install_") {
			return false
		}
		s.ran(env)
		l.Calls = true
		switch {
		case act == "exit": // tox -vv and failures: the end of a command, not a new one
		case act == "freeze":
			s.toxWait[env], s.toxSetup = true, true
			if !toxFreezeRe.MatchString(strings.TrimSpace(cmd)) {
				s.toxBad[env] = true // a custom list_dependencies_command may leave packages out
			}
		case cmds:
			s.toxCmds = append(s.toxCmds, cmd)
			delete(s.toxWait, env)
			s.toxSetup = false
		default:
			delete(s.toxWait, env)
			s.toxSetup = true
			if !toxReadOnly[act] {
				s.toxEnv[env] = false // installs after the listing: not in it
			}
			if act == "install_package" && !wheelOnly(cmd) {
				s.toxBad[env] = true // built from an sdist or a directory in a build env no listing shows
			}
		}
		return true
	}
	if m := toxSumRe.FindStringSubmatch(line); m != nil && (s.tox || s.toxEnv != nil) {
		s.ran(m[1])
		delete(s.toxWait, m[1])
		s.toxSetup = false
		return true
	}
	if m := tox3Re.FindStringSubmatch(line); m != nil {
		env, act, rest := m[1], m[2], m[3]
		s.ran(env)
		s.toxBad[env] = true // tox 3 lists with plain pip freeze (no pip, setuptools, wheel) and builds an sdist
		l.Calls = true
		switch act {
		case "installed":
			s.toxEnv[env] = l.toxListing(rest, n, line)
			s.toxSetup = false
		case "run-test-pre", "run-test", "run-test-post":
			if _, c, ok := strings.Cut(rest, " | "); ok {
				s.toxCmds = append(s.toxCmds, c)
			}
			s.toxSetup = false
		default:
			s.toxEnv[env] = false
			s.toxSetup = true
		}
		return true
	}
	if m := toxEnvRe.FindStringSubmatch(line); m != nil && s.toxWait[m[1]] {
		// the line after "<env>: freeze>" from the same environment is its listing
		list := m[3]
		if m[2] != "" {
			list = toxSrcRe.ReplaceAllString(list, "")
		}
		delete(s.toxWait, m[1])
		s.toxEnv[m[1]] = l.toxListing(list, n, line)
		return true
	}
	return false
}

// toxListing reads a comma-separated freeze listing: name==version entries are installs, a local
// project (name @ file://…, -e <path>) is skipped, anything else makes the listing not complete.
func (l *Log) toxListing(list string, n int, line string) bool {
	list = strings.TrimSpace(list)
	if list == "" {
		return true // an environment with nothing installed
	}
	ok := true
	for _, e := range strings.Split(list, ",") {
		e = strings.TrimSpace(e)
		if name, ver, found := strings.Cut(e, "=="); found && !strings.ContainsAny(name, " @;") && !strings.ContainsAny(ver, " =@;") {
			ok = l.add(name, ver, n, line) && ok
			continue
		}
		if name, url, found := strings.Cut(e, " @ "); found && strings.HasPrefix(url, "file://") && pep.ValidName(name) {
			// a local file or directory; a file named name-version is that version
			if fn, ver, split := splitFile(path.Base(url)); split && pep.Name(fn) == pep.Name(name) {
				l.add(name, ver, n, line)
			}
			continue
		}
		if toxEditableRe.MatchString(e) {
			continue
		}
		l.Unparsed = append(l.Unparsed, Install{Name: nameRe.FindString(e), Line: n, Text: line})
		ok = false
	}
	return ok
}

// wheelOnly reports whether a tox install_package command installs only wheel files: no sdist,
// directory or editable install, each of which builds in an environment no listing shows.
func wheelOnly(cmd string) bool {
	f := strings.Fields(cmd)
	i := slices.Index(f, "install")
	if i < 0 {
		return false
	}
	n := 0
	for _, a := range f[i+1:] {
		switch {
		case strings.HasPrefix(a, "--editable") || strings.HasPrefix(a, "--requirement"),
			!strings.HasPrefix(a, "--") && strings.HasPrefix(a, "-") && strings.ContainsAny(a, "er"): // -e/w, -rreq.txt, clusters
			return false
		case strings.HasPrefix(a, "-"):
		case strings.HasSuffix(strings.Trim(a, `'"`), ".whl"):
			n++
		default:
			return false
		}
	}
	return n > 0
}
