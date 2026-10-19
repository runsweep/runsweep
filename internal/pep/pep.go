// internal/pep/pep.go

// Package pep normalizes Python package names (PEP 503) and versions (PEP 440), so a name or
// version written in a log, a lockfile and an incident compares equal however it is spelled.
package pep

import (
	"regexp"
	"strings"
)

var (
	validNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	nameSepRe   = regexp.MustCompile(`[-_.]+`)
	// PEP 440 appendix B, lowercased input
	versionRe = regexp.MustCompile(`^v?(?:(\d+)!)?(\d+(?:\.\d+)*)` +
		`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?` +
		`(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?` +
		`(?:[-_.]?(dev)[-_.]?(\d+)?)?` +
		`(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)
)

// maxVersion caps the length of a version string read from a log or lockfile.
const maxVersion = 128

// ValidName reports whether s is a PEP 508 distribution name.
func ValidName(s string) bool { return len(s) <= 214 && validNameRe.MatchString(s) }

// Name returns the PEP 503 normalized form of a distribution name.
func Name(s string) string { return strings.ToLower(nameSepRe.ReplaceAllString(s, "-")) }

// Version is a canonical PEP 440 version: Public holds epoch, release, pre, post and dev parts;
// Local the part after "+".
type Version struct{ Public, Local string }

// ParseVersion returns the canonical form of a PEP 440 version.
func ParseVersion(s string) (Version, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > maxVersion {
		return Version{}, false
	}
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	var b strings.Builder
	if e := num(m[1]); e != "" && e != "0" {
		b.WriteString(e + "!")
	}
	rel := strings.Split(m[2], ".")
	for i := range rel {
		rel[i] = num(rel[i])
	}
	for len(rel) > 1 && rel[len(rel)-1] == "0" {
		rel = rel[:len(rel)-1]
	}
	b.WriteString(strings.Join(rel, "."))
	if m[3] != "" {
		b.WriteString(map[string]string{"a": "a", "alpha": "a", "b": "b", "beta": "b", "c": "rc", "rc": "rc", "pre": "rc", "preview": "rc"}[m[3]])
		b.WriteString(num(m[4]))
	}
	switch {
	case m[5] != "":
		b.WriteString(".post" + num(m[5]))
	case m[6] != "":
		b.WriteString(".post" + num(m[7]))
	}
	if m[8] != "" {
		b.WriteString(".dev" + num(m[9]))
	}
	local := m[10]
	if local != "" {
		parts := strings.FieldsFunc(local, func(r rune) bool { return r == '-' || r == '_' || r == '.' })
		for i, p := range parts {
			if strings.Trim(p, "0123456789") == "" {
				parts[i] = num(p)
			}
		}
		local = strings.Join(parts, ".")
	}
	return Version{Public: b.String(), Local: local}, true
}

// num strips leading zeros of a digit string; "" (an omitted number) is 0.
func num(s string) string {
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

// Matches reports whether an installed version is the bad one: equal public parts, and the
// installed local label ignored unless the bad version names one (1.82.8+cu118 is a build of 1.82.8).
func Matches(bad, installed Version) bool {
	return bad.Public == installed.Public && (bad.Local == "" || bad.Local == installed.Local)
}
