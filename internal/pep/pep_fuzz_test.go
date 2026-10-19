package pep

import "testing"

func FuzzPEP440(f *testing.F) {
	for _, s := range []string{"1.0", "1!2.0rc1.post2.dev3+abc.1", "v1.82.8", "1.0-1", "", "x", "1..0"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, ok := ParseVersion(s)
		if !ok {
			return
		}
		// canonical form is stable and matches itself
		w, ok := ParseVersion(v.Public)
		if !ok || w.Public != v.Public {
			t.Fatalf("not stable: %q -> %+v -> %+v %v", s, v, w, ok)
		}
		if !Matches(v, v) {
			t.Fatalf("does not match itself: %q", s)
		}
	})
}
