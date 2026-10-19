package report

import (
	"strings"
	"testing"
	"unicode"
)

func FuzzClean(f *testing.F) {
	f.Add("plain text")
	f.Add("a\u202eb\u200bc\x1b[31m\r\nd\U000e0041")
	f.Add("\xff\xfe")
	f.Fuzz(func(t *testing.T, s string) {
		for _, r := range Clean(s) {
			if unicode.Is(unicode.Cf, r) || r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x2028 || r == 0x2029 {
				t.Fatalf("Clean(%q) kept %U", s, r)
			}
		}
	})
}

func FuzzMarkdown(f *testing.F) {
	for _, s := range evilStrings {
		f.Add(s, s, s, s)
	}
	f.Add("</details>\n<a href=x>", "@a/b`", "![p](https://e/p.png)", "](http://e)")
	want := markup(renderHostile(f, "x", false))
	f.Fuzz(func(t *testing.T, job, secret, note, errMsg string) {
		inc, res := hostile(note, false)
		res.Findings[0].Run.Job, res.Rotation[1].Name, res.Unverified[0].Name, res.Error = job, secret, secret, errMsg
		var b strings.Builder
		if err := Markdown(&b, inc, res); err != nil {
			t.Fatal(err)
		}
		if got := markup(b.String()); got != want {
			t.Fatalf("markup outside code spans: %q, want %q\n%s", got, want, b.String())
		}
	})
}
