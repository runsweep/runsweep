package pypi

import (
	"context"
	"fmt"
	"testing"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/source/sourcetest"
)

func TestMatch(t *testing.T) {
	bad := NewBad([]incident.PyPIPackage{{Name: "litellm", Versions: []string{"1.82.8"}}})
	f := sourcetest.New()
	f.AddFile("o/a", "s", "requirements.txt", readFix(t, "requirements.txt"))
	f.AddFile("o/a", "s", "svc/poetry.lock", readFix(t, "poetry.lock")) // 1.82.7: not bad
	f.AddFile("o/a", "s", "pdm.lock", []byte("x"))
	f.AddFile("o/a", "s", "broken/uv.lock", []byte("[[package]\n"))
	f.AddFile("o/a", "s", ".venv/requirements.txt", []byte("litellm==1.82.8\n")) // skipped dir
	var c Cache
	r, err := c.Match(context.Background(), f, "o/a", "s", bad)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Pinned) != 1 || r.Pinned[0] != (Pin{"requirements.txt", "litellm", "1.82.8"}) {
		t.Errorf("pinned: %+v", r.Pinned)
	}
	if fmt.Sprint(r.Failed) != "[broken/uv.lock pdm.lock]" || r.Truncated {
		t.Errorf("failed: %v truncated %v", r.Failed, r.Truncated)
	}
	// over the cap
	g := sourcetest.New()
	for i := 0; i <= maxManifests; i++ {
		g.AddFile("o/a", "s", fmt.Sprintf("d%d/requirements.txt", i), []byte("x==1\n"))
	}
	if r, _ := c.Match(context.Background(), g, "o/a", "s", bad); !r.Truncated {
		t.Error("cap not reported")
	}
	// a tree GitHub truncated
	g.Truncated["o/a@s"] = true
	if r, _ := c.Match(context.Background(), g, "o/a", "s", bad); !r.Truncated {
		t.Error("truncated tree not reported")
	}
}
