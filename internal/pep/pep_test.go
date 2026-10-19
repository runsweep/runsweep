// internal/pep/pep_test.go
package pep

import "testing"

func TestName(t *testing.T) {
	for in, want := range map[string]string{
		"Flask_SQLAlchemy": "flask-sqlalchemy", "flask.sqlalchemy": "flask-sqlalchemy",
		"Flask--SQL__Alchemy": "flask-sql-alchemy", "litellm": "litellm", "A": "a",
	} {
		if got := Name(in); got != want {
			t.Errorf("Name(%q) = %q, want %q", in, got, want)
		}
	}
	for s, want := range map[string]bool{"litellm": true, "a": true, "a.b-c_d": true, "-a": false, "a-": false, "": false, "a b": false, "a/b": false} {
		if ValidName(s) != want {
			t.Errorf("ValidName(%q) != %v", s, want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for in, want := range map[string]Version{
		"1.0":               {Public: "1"},
		"1.0.0":             {Public: "1"},
		"v1.82.8":           {Public: "1.82.8"},
		"1.82.8+cu118":      {Public: "1.82.8", Local: "cu118"},
		"1.0+Ubuntu-1":      {Public: "1", Local: "ubuntu.1"},
		"0!1.0":             {Public: "1"},
		"1!2.0":             {Public: "1!2"},
		"1.0a1":             {Public: "1a1"},
		"1.0-alpha.1":       {Public: "1a1"},
		"1.0.beta":          {Public: "1b0"},
		"1.0c2":             {Public: "1rc2"},
		"1.0pre3":           {Public: "1rc3"},
		"1.0preview":        {Public: "1rc0"},
		"1.0-1":             {Public: "1.post1"},
		"1.0.post":          {Public: "1.post0"},
		"1.0rev2":           {Public: "1.post2"},
		"1.0r":              {Public: "1.post0"},
		"1.0.dev":           {Public: "1.dev0"},
		"1.0rc1.post2.dev3": {Public: "1rc1.post2.dev3"},
		"01.002":            {Public: "1.2"},
		" 2.6.3 ":           {Public: "2.6.3"},
		"0":                 {Public: "0"},
		"0.0":               {Public: "0"},
	} {
		got, ok := ParseVersion(in)
		if !ok || got != want {
			t.Errorf("ParseVersion(%q) = %+v %v, want %+v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "x", "1..0", "1.0+", "1.0+a..b", "1.0 2", "latest", "*", "1.0-", "1.0+@"} {
		if _, ok := ParseVersion(bad); ok {
			t.Errorf("ParseVersion(%q) accepted", bad)
		}
	}
}

func TestMatches(t *testing.T) {
	v := func(s string) Version {
		x, ok := ParseVersion(s)
		if !ok {
			t.Fatalf("parse %q", s)
		}
		return x
	}
	for _, c := range []struct {
		bad, inst string
		want      bool
	}{
		{"1.82.8", "1.82.8", true},
		{"1.82.8", "1.82.8.0", true},
		{"1.82.8", "1.82.8+cu118", true},
		{"1.82.8+cu118", "1.82.8", false},
		{"1.82.8+cu118", "1.82.8+cu118", true},
		{"1.82.8", "1.82.9", false},
		{"2.6.3", "2.6.3.post1", false},
		{"1.0", "1!1.0", false},
	} {
		if got := Matches(v(c.bad), v(c.inst)); got != c.want {
			t.Errorf("Matches(%s, %s) = %v", c.bad, c.inst, got)
		}
	}
}
