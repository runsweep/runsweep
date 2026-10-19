package scan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/runsweep/runsweep/internal/match/pypi"
	"github.com/runsweep/runsweep/internal/model"
	"github.com/runsweep/runsweep/internal/workflow"
)

// pypiNeedsLog: an identified job with nothing that can install a Python package is CLEAN for
// PyPI without its log (rule 0 of the spec); every other job is judged from its log.
func pypiNeedsLog(wj, rj *workflow.Job) bool { return wj == nil || rj == nil || rj.HasPython() }

// pypiJob judges one job against the incident's PyPI packages. A job log line is the only proof
// (AFFECTED); a job is CLEAN only when its log lists every version each install printed; otherwise
// a pinning lockfile makes it POSSIBLE and anything else UNCHECKED with the first reason.
func (s *scanner) pypiJob(wj, rj *workflow.Job, log string, logErr error, lock pypi.Result) (model.Status, []model.Evidence) {
	if !pypiNeedsLog(wj, rj) {
		return model.Clean, nil
	}
	read := logErr == nil
	var l pypi.Log
	if read {
		l = pypi.ParseLog(log)
		for _, in := range l.Installs {
			if s.pypiBad.Is(in.Name, in.Version) {
				return model.Affected, []model.Evidence{{Kind: "pypi", Detail: fmt.Sprintf("%s==%s in job log (line %d)", in.Name, in.Version, in.Line)}}
			}
		}
		for _, u := range l.Unparsed {
			if s.pypiBad.Mentions(u.Name) {
				return model.Unchecked, []model.Evidence{note("unparsed install line for %s (line %d)", u.Name, u.Line)}
			}
		}
	}
	var cmds []workflow.PyInstall
	if rj != nil {
		cmds = rj.PyInstalls()
	}
	for _, in := range cmds {
		for _, p := range in.Pkgs {
			if s.pypiBad.Has(p) && !slices.ContainsFunc(l.Installs, func(i pypi.Install) bool { return i.Name == p && completeAt(l, i.Line) }) {
				return model.Possible, []model.Evidence{{Kind: "pypi", Detail: fmt.Sprintf("runs `%s` at run time", in.Cmd)}}
			}
		}
	}
	for _, in := range cmds {
		if in.Dynamic {
			return model.Unchecked, []model.Evidence{note("package named at run time: `%s`", in.Cmd)}
		}
	}
	var py []pypi.Section
	for _, sec := range l.Sections {
		if sec.Python {
			py = append(py, sec)
		}
	}
	if read && !l.Calls && len(py) == 0 {
		return model.Clean, nil // quiet job, like npm's
	}
	complete := !slices.ContainsFunc(py, func(sec pypi.Section) bool { return !sec.Complete })
	if read && wj != nil && rj.PyActionsOK() && complete {
		return model.Clean, nil
	}
	why := pypiReason(read, py, wj, rj, lock)
	if len(lock.Pinned) > 0 {
		p := lock.Pinned[0]
		d := fmt.Sprintf("lockfile pins %s==%s: %s", p.Name, p.Version, p.Path)
		if n := len(lock.Pinned) - 1; n > 0 {
			d += fmt.Sprintf(" +%d more", n)
		}
		return model.Possible, []model.Evidence{{Kind: "pypi", Detail: d}, note("%s", why)}
	}
	return model.Unchecked, []model.Evidence{note("%s", why)}
}

// pypiReason is the first reason the job could not be cleared, in the spec's order.
func pypiReason(read bool, py []pypi.Section, wj, rj *workflow.Job, lock pypi.Result) string {
	if !read {
		return "job log unavailable: Python installs not verified"
	}
	for _, sec := range py {
		if sec.Opaque != "" {
			return "Python install output not visible: " + sec.Opaque
		}
	}
	for _, sec := range py {
		if !sec.Complete {
			cmd, _, _ := strings.Cut(strings.TrimSpace(sec.Cmd), "\n")
			if r := []rune(cmd); len(r) > 80 {
				cmd = string(r[:80]) + "…"
			}
			return "Python install output incomplete in step: " + cmd
		}
	}
	if rj != nil {
		for _, u := range rj.Uses {
			if (&workflow.Job{Uses: []string{u}}).PyActionsOK() {
				continue
			}
			return "action " + u + " may install Python packages"
		}
	}
	if wj == nil {
		return "job not identified in workflow file"
	}
	if len(lock.Failed) > 0 {
		f := lock.Failed[0]
		if strings.HasSuffix(f, "pdm.lock") {
			return "pdm.lock is not read"
		}
		return "lockfile not read: " + f
	}
	if lock.Truncated {
		return "too many manifests — not all read"
	}
	return "Python installs not verified"
}

// completeAt reports whether log line n lies in a Python section whose installs printed full lists.
func completeAt(l pypi.Log, n int) bool {
	for i, sec := range l.Sections {
		end := 1 << 30
		if i+1 < len(l.Sections) {
			end = l.Sections[i+1].Line
		}
		if sec.Python && sec.Complete && n >= sec.Line && n < end {
			return true
		}
	}
	return false
}
