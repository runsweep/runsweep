package pypi

import "testing"

func FuzzParsePyLog(f *testing.F) {
	f.Add(step("pip install x", "Successfully installed x-1.0 y-2"))
	f.Add(step("uv sync", "Installed 1 package in 1ms", " + a==1"))
	f.Add(step("poetry install", "Package operations: 1 install, 0 updates, 0 removals", "  - Installing a (1)"))
	f.Add("##[group]Run \n\x1b[36;1m\n##[endgroup]\nSuccessfully installed -\n")
	f.Fuzz(func(t *testing.T, s string) {
		l := ParseLog(s)
		for _, in := range l.Installs {
			if in.Name == "" || in.Version == "" || in.Line < 1 {
				t.Fatalf("bad install %+v", in)
			}
		}
		for _, sec := range l.Sections {
			if sec.Complete && sec.Opaque != "" {
				t.Fatalf("opaque section complete: %+v", sec)
			}
		}
	})
}
