package pypi

import (
	"context"
	"errors"
	"path"
	"slices"
	"sync"

	"github.com/runsweep/runsweep/internal/source"
)

// Fetcher is the part of source.Source the matcher needs.
type Fetcher interface {
	Tree(ctx context.Context, repo, sha string) ([]source.TreeEntry, bool, error)
	Blob(ctx context.Context, repo, blobSHA string, limit int) ([]byte, error)
}

// maxManifests caps the Python manifests read per commit tree.
const maxManifests = 500

// Pin is a manifest that pins a bad version.
type Pin struct{ Path, Name, Version string }

// Result is what the repository's manifests say; it is fallback evidence, never above POSSIBLE.
type Result struct {
	Pinned    []Pin
	Failed    []string // manifests not read: pdm.lock, parse errors, over the size cap
	Truncated bool     // more than maxManifests, or GitHub truncated the tree
}

// Cache keeps parsed manifests of one scan by file name and blob SHA. The zero value is ready to use.
type Cache struct{ m sync.Map }

type parsed struct {
	pkgs []Pkg
	err  error
}

// Match reads the Python manifests of repo@sha.
func (c *Cache) Match(ctx context.Context, f Fetcher, repo, sha string, bad Bad) (Result, error) {
	var r Result
	entries, truncated, err := f.Tree(ctx, repo, sha)
	if err != nil {
		return r, err
	}
	r.Truncated = truncated
	reads := 0
	for _, e := range entries {
		kind, ok := IsManifest(e.Path)
		if !ok {
			continue
		}
		if kind == "pdm" {
			r.Failed = append(r.Failed, e.Path)
			continue
		}
		if reads++; reads > maxManifests {
			r.Truncated = true
			continue
		}
		// the name is part of the key: pylock.toml and uv.lock read different tables
		key := path.Base(e.Path) + "@" + e.SHA
		v, ok := c.m.Load(key)
		if !ok {
			b, err := f.Blob(ctx, repo, e.SHA, source.MaxManifestBytes)
			var p parsed
			switch {
			case errors.Is(err, source.ErrIncomplete):
				p.err = err
			case err != nil:
				return r, err
			default:
				source.Parse(func() {
					switch kind {
					case "requirements":
						p.pkgs = ParseRequirements(b)
					case "toml":
						p.pkgs, p.err = ParseTOMLLock(e.Path, b)
					case "pipfile":
						p.pkgs, p.err = ParsePipfileLock(b)
					}
				})
			}
			c.m.Store(key, p)
			v = p
		}
		p := v.(parsed)
		if p.err != nil {
			r.Failed = append(r.Failed, e.Path)
			continue
		}
		for _, pkg := range p.pkgs {
			if bad.Is(pkg.Name, pkg.Version) {
				r.Pinned = append(r.Pinned, Pin{e.Path, pkg.Name, pkg.Version})
			}
		}
	}
	slices.Sort(r.Failed)
	return r, nil
}
