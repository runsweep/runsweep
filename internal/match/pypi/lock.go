package pypi

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/pep"
)

// Pkg is a pinned distribution: PEP 503 name, canonical version.
type Pkg struct{ Name, Version string }

// Bad is the incident's PyPI packages, normalized for matching.
type Bad struct {
	any  map[string]bool
	vers map[string][]pep.Version
}

// NewBad normalizes the incident's packages. Versions were validated with the incident.
func NewBad(pkgs []incident.PyPIPackage) Bad {
	b := Bad{any: map[string]bool{}, vers: map[string][]pep.Version{}}
	for _, p := range pkgs {
		n := pep.Name(p.Name)
		for _, v := range p.Versions {
			if v == "*" {
				b.any[n] = true
			} else if pv, ok := pep.ParseVersion(v); ok {
				b.vers[n] = append(b.vers[n], pv)
			}
		}
	}
	return b
}

// Has reports whether the incident names the package.
func (b Bad) Has(name string) bool {
	n := pep.Name(name)
	return b.any[n] || len(b.vers[n]) > 0
}

// Is reports whether name at version is a bad release; a "*" package is bad at any version,
// even one that does not parse.
func (b Bad) Is(name, version string) bool {
	n := pep.Name(name)
	if b.any[n] {
		return true
	}
	v, ok := pep.ParseVersion(version)
	return ok && slices.ContainsFunc(b.vers[n], func(bad pep.Version) bool { return pep.Matches(bad, v) })
}

// Mentions reports whether an unparsed pip token ("name-version") may be a bad package.
func (b Bad) Mentions(token string) bool {
	t := pep.Name(token)
	hit := func(n string) bool { return t == n || strings.HasPrefix(t, n+"-") }
	for n := range b.any {
		if hit(n) {
			return true
		}
	}
	for n := range b.vers {
		if hit(n) {
			return true
		}
	}
	return false
}

var reqRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;,#]+)\s*(?:;.*)?$`)

// ParseRequirements returns the exact pins (== or ===) of a requirements or constraints file.
// Ranges, bare names, options and URLs are not pins.
func ParseRequirements(b []byte) []Pkg {
	text := strings.NewReplacer("\\\r\n", " ", "\\\n", " ").Replace(string(b))
	var out []Pkg
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, " -"); i >= 0 { // trailing --hash=… options
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := reqRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if v, ok := pep.ParseVersion(m[2]); ok && pep.ValidName(m[1]) {
			out = append(out, Pkg{pep.Name(m[1]), versionText(v)})
		}
	}
	return sortPkgs(out)
}

// ParseTOMLLock reads uv.lock and poetry.lock ([[package]]) or pylock*.toml ([[packages]]).
func ParseTOMLLock(p string, b []byte) ([]Pkg, error) {
	var doc struct {
		Package  []struct{ Name, Version string } `toml:"package"`
		Packages []struct{ Name, Version string } `toml:"packages"`
	}
	if _, err := toml.Decode(string(b), &doc); err != nil {
		return nil, err
	}
	list := doc.Package
	if strings.HasPrefix(path.Base(p), "pylock") {
		list = doc.Packages
	}
	var out []Pkg
	for _, e := range list {
		if e.Version == "" { // a source tree or VCS entry
			continue
		}
		v, ok := pep.ParseVersion(e.Version)
		if !ok || !pep.ValidName(e.Name) {
			return nil, fmt.Errorf("package %q version %q unreadable", e.Name, e.Version)
		}
		out = append(out, Pkg{pep.Name(e.Name), versionText(v)})
	}
	return sortPkgs(out), nil
}

// ParsePipfileLock reads the default and develop sections of Pipfile.lock.
func ParsePipfileLock(b []byte) ([]Pkg, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []Pkg
	for _, sec := range []string{"default", "develop"} {
		var pkgs map[string]struct {
			Version string `json:"version"`
		}
		if raw, ok := doc[sec]; ok {
			if err := json.Unmarshal(raw, &pkgs); err != nil {
				return nil, err
			}
		}
		for name, p := range pkgs {
			if p.Version == "" { // VCS or path entry
				continue
			}
			v, ok := pep.ParseVersion(strings.TrimPrefix(p.Version, "=="))
			if !ok || !pep.ValidName(name) {
				return nil, fmt.Errorf("package %q version %q unreadable", name, p.Version)
			}
			out = append(out, Pkg{pep.Name(name), versionText(v)})
		}
	}
	return sortPkgs(out), nil
}

func sortPkgs(p []Pkg) []Pkg {
	slices.SortFunc(p, func(a, b Pkg) int { return strings.Compare(a.Name+"@"+a.Version, b.Name+"@"+b.Version) })
	return slices.Compact(p)
}

var skipDirs = []string{".venv", "venv", "site-packages", "node_modules", ".tox", ".nox"}

// IsManifest classifies a tree path: "requirements", "toml", "pipfile" or "pdm" (unread).
func IsManifest(p string) (string, bool) {
	for _, seg := range strings.Split(path.Dir(p), "/") {
		if slices.Contains(skipDirs, seg) {
			return "", false
		}
	}
	base := path.Base(p)
	switch {
	case base == "uv.lock" || base == "poetry.lock" || base == "pylock.toml" || strings.HasPrefix(base, "pylock.") && strings.HasSuffix(base, ".toml"):
		return "toml", true
	case base == "Pipfile.lock":
		return "pipfile", true
	case base == "pdm.lock":
		return "pdm", true
	case strings.HasSuffix(base, ".txt") && (strings.Contains(base, "requirements") || strings.HasPrefix(base, "constraints") || path.Base(path.Dir(p)) == "requirements"):
		return "requirements", true
	}
	return "", false
}
