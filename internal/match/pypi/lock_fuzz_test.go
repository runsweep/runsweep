package pypi

import "testing"

func FuzzParseRequirements(f *testing.F) {
	f.Add([]byte("a==1 \\\n  --hash=sha256:x\nb[c]===2 ; x\n-r y.txt\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, p := range ParseRequirements(b) {
			if p.Name == "" || p.Version == "" {
				t.Fatalf("%+v", p)
			}
		}
	})
}

func FuzzParseTomlLock(f *testing.F) {
	f.Add([]byte("[[package]]\nname = \"a\"\nversion = \"1\"\n"))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = ParseTOMLLock("uv.lock", b)
		_, _ = ParseTOMLLock("pylock.toml", b)
	})
}

func FuzzParsePipfileLock(f *testing.F) {
	f.Add([]byte(`{"default":{"a":{"version":"==1"}}}`))
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = ParsePipfileLock(b) })
}
