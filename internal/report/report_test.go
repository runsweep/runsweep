package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sample() (*incident.Incident, *model.Result) {
	t0 := time.Date(2026, 3, 31, 0, 21, 0, 0, time.UTC)
	inc := &incident.Incident{ID: "axios-2026-03", Title: "axios malicious release", Window: incident.Window{Start: t0, End: t0.Add(3 * time.Hour)},
		Refs: []string{"https://osv.dev/vulnerability/MAL-2026-2307"}}
	run := model.RunRef{Repo: "o/app", RunID: 42, RunNumber: 17, Workflow: ".github/workflows/ci.yml", HeadSHA: "abcdef1234567",
		RunURL: "https://github.com/o/app/actions/runs/42", CreatedAt: t0.Add(time.Hour), JobID: 7, Job: "build",
		JobURL: "https://github.com/o/app/actions/runs/42/job/7", Attempt: 2}
	res := &model.Result{IncidentID: inc.ID, Start: inc.Window.Start, End: inc.Window.End, ReposTargeted: 3, RunsScanned: 3, JobsScanned: 5,
		Findings: []model.Finding{
			{Run: run, Status: model.Affected, Evidence: []model.Evidence{{Kind: "npm", Detail: "axios@1.14.1 in package-lock.json at abcdef1"}},
				Exposure: &model.Exposure{Secrets: []string{"NPM_TOKEN"}, IDTokenWrite: true, JobMatched: true}},
			// run-level finding: jobs list unavailable, no job name
			{Run: model.RunRef{Repo: "o/old", RunID: 9, Workflow: ".github/workflows/ci.yml"}, Status: model.Unchecked,
				Evidence: []model.Evidence{{Kind: "note", Detail: "jobs unavailable: deleted by GitHub retention (HTTP 410)"}}},
		},
		Rotation: []model.RotationItem{
			{Name: "OIDC token (id-token: write)", Tier: 1, Reason: "review cloud roles", Runs: []model.RunRef{run}, Confirmed: true},
			{Name: "NPM_TOKEN", Tier: 2, Reason: "rotate", Runs: []model.RunRef{run}, Confirmed: true},
		},
		Unverified: []model.RotationItem{
			{Name: "DEPLOY_KEY", Tier: 2, Reason: "rotate", Runs: []model.RunRef{{Repo: "o/app", RunID: 43, Job: "publish"}}},
		},
		Skipped:  []model.Skip{{Repo: "o/private", Reason: "no access (HTTP 403/404)"}},
		Lookback: 7 * 24 * time.Hour,
	}
	return inc, res
}

func golden(t *testing.T, name string, got []byte) {
	path := "testdata/" + name
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: fixed testdata path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch; run `go test ./internal/report -update` and review the diff\n%s", name, got)
	}
}

func TestMarkdown(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.golden.md", b.Bytes())
}

func TestJSON(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.golden.json", b.Bytes())
}

func TestMarkdownEscapesCells(t *testing.T) {
	inc, res := sample()
	evil := "a|b\n| X | injected |\r\n`c`"
	res.Findings[0].Run.Job = evil
	res.Findings[0].Evidence[0].Detail = evil
	res.Rotation[1].Name = evil
	res.Rotation[1].Runs[0].Job = evil
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "injected") {
			if strings.Contains(line, "\r") || !strings.Contains(line, `a\|b \| X \| injected`) {
				t.Fatalf("unescaped row: %q", line)
			}
		}
	}
	if strings.Contains(out, "\r") || strings.Contains(out, "`c`") {
		t.Fatalf("CR or backtick leaked:\n%s", out)
	}
	if strings.Contains(out, "\n| X |") {
		t.Fatalf("row injected:\n%s", out)
	}
}

func TestMarkdownNoInjection(t *testing.T) {
	inc, res := sample()
	evil := "[x](http://e) <img src=x onerror=1> @user o/r#1"
	inc.Title = "t\n`x`"
	inc.Refs = []string{"a](http://e)"}
	res.Findings[0].Run.Job = evil
	res.Findings[0].Run.RunURL = "https://evil.example/x"
	res.Findings[0].Evidence[0].Detail = evil
	res.Skipped[0].Reason = evil
	res.Rotation[1].Runs[0].Job = evil
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "](") && !strings.Contains(line, "](https://github.com/") && !strings.Contains(line, "`") {
			t.Fatalf("bare link: %q", line)
		}
		for _, bad := range []string{"<img", "](http://e)", "@user"} {
			// every occurrence must be inside a code span: odd number of backticks before it
			for i := strings.Index(line, bad); i >= 0; {
				if strings.Count(line[:i], "`")%2 == 0 {
					t.Fatalf("%q outside code span: %q", bad, line)
				}
				j := strings.Index(line[i+1:], bad)
				if j < 0 {
					break
				}
				i += 1 + j
			}
		}
	}
	if strings.Contains(out, "(https://evil") {
		t.Fatal("non-github run URL linked")
	}
	// finding rows unchanged: 2 findings
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| `o/") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("finding rows = %d", n)
	}
}

func TestJSONEmptyAndUTC(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, &incident.Incident{ID: "x"}, &model.Result{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"findings": []`, `"rotation": []`, `"unverified_rotation": []`, `"skipped": []`} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %s in\n%s", want, b.String())
		}
	}
	inc, res := sample()
	z := time.FixedZone("x", 2*3600)
	inc.Window.Start = inc.Window.Start.In(z)
	res.Start = res.Start.In(z)
	res.Findings[0].Run.CreatedAt = res.Findings[0].Run.CreatedAt.In(z)
	res.Findings[1].Evidence = nil
	b.Reset()
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "+02:00") || strings.Contains(b.String(), `"evidence": null`) {
		t.Fatalf("not normalized:\n%s", b.String())
	}
	if res.Findings[1].Evidence != nil {
		t.Fatal("caller's Result mutated")
	}
}

func TestMarkdownStripsTerminalEscapes(t *testing.T) {
	inc, res := sample()
	evil := "\x1b]0;pwned\x07\x1b[2J\u0085  \x7f"
	inc.Title = evil
	inc.Refs = []string{evil}
	res.Findings[0].Run.Job = evil
	res.Skipped[0].Repo = evil
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\x1b\x07\u0085  \x7f") {
		t.Fatalf("control characters leaked: %q", b.String())
	}
}

func TestMarkdownRetentionWarning(t *testing.T) {
	inc, res := sample()
	res.RetentionWarning = true
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "**Scanned** 2 repos · 3 runs · 5 jobs\nWarning: incident window starts more than 90 days ago; GitHub may have deleted runs — absence of runs is not evidence.\n") {
		t.Fatal(b.String())
	}
}

func TestCleanDropsBidi(t *testing.T) {
	in := "a\u200eb\u200fc\u202ad\u202ee\u2066f\u2069g\u2067h\u2068i"
	if got := Clean(in); got != "abcdefghi" {
		t.Fatalf("%q", got)
	}
}

func TestCleanDropsInvisibleFillers(t *testing.T) {
	in := "a\u115fb\u1160c\u3164d\uffa0e\u2800f\ufe0fg\U000e0100h"
	if got := Clean(in); got != "abcdefgh" {
		t.Fatalf("%q", got)
	}
}

func TestJSONEscapesC1(t *testing.T) {
	inc, res := sample()
	res.Findings[0].Evidence[0].Detail = "x\u0085y\u009bz"
	var b bytes.Buffer
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\u0085\u009b") || !strings.Contains(b.String(), `x\u0085y\u009bz`) {
		t.Fatalf("C1 not escaped: %q", b.String())
	}
	var v any
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
}

func TestMarkdownAttempt(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "| [17](https://github.com/o/app/actions/runs/42/job/7) attempt 2 |") {
		t.Fatal(b.String())
	}
	res.Findings[0].Run.Attempt = 1
	for i := range res.Rotation {
		res.Rotation[i].Runs[0].Attempt = 1
	}
	b.Reset()
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "attempt") {
		t.Fatalf("first attempt must not be labelled:\n%s", b.String())
	}
}

func TestJSONEscapesBidiRoundTrip(t *testing.T) {
	inc, res := sample()
	in := "привет\u0085a\u200eb\u200fc\u202ad\u202ee\u2066f\u2069g"
	res.Findings[0].Evidence[0].Detail = in
	var b bytes.Buffer
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\u0085\u200e\u200f\u202a\u202e\u2066\u2069") || !strings.Contains(b.String(), `\u200e`) {
		t.Fatalf("not escaped: %q", b.String())
	}
	var v struct {
		Findings []struct{ Evidence []model.Evidence } `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &v); err != nil || v.Findings[0].Evidence[0].Detail != in {
		t.Fatalf("%v %q", err, v.Findings[0].Evidence[0].Detail)
	}
	b.Reset()
	res.Findings[0].Evidence[0].Detail = "привет\u0085"
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b.Bytes(), &v); err != nil || v.Findings[0].Evidence[0].Detail != "привет\u0085" {
		t.Fatalf("%v %q", err, v.Findings[0].Evidence[0].Detail)
	}
}

func TestSeenInAttempt(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "`o/app` run [17](https://github.com/o/app/actions/runs/42/job/7) › `build` attempt 2") {
		t.Fatal(b.String())
	}
}

// Every format character (zero-width, BOM, soft hyphen, ...) and the tag block U+E0000–E007F are
// dropped from terminal text and escaped in JSON, so hidden text never reaches a reader.
func TestFormatCharsAndTags(t *testing.T) {
	in := "a\u200bb\ufeffc\u00add\u2060e\U000E0041f\U000E0000g\U000E007Fh\u061ci\tj\nk"
	if got := Clean(in); got != "abcdefghij k" {
		t.Fatalf("Clean: %q", got)
	}
	inc, res := sample()
	res.Findings[0].Evidence[0].Detail = in
	var b bytes.Buffer
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\u200b\ufeff\u00ad\u2060\U000E0041\U000E0000\U000E007F\u061c") || !strings.Contains(b.String(), `e\udb40\udc41f`) {
		t.Fatalf("not escaped: %q", b.String())
	}
	var v struct {
		Findings []struct{ Evidence []model.Evidence } `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &v); err != nil || v.Findings[0].Evidence[0].Detail != in {
		t.Fatalf("%v %q", err, v.Findings[0].Evidence[0].Detail)
	}
}

func TestMarkdownOnlyUnverified(t *testing.T) {
	inc, res := sample()
	res.Rotation, res.Findings = nil, res.Findings[:1] // no job with unknown secrets
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "### Rotate first\n\nNothing confirmed to rotate; 1 secret in jobs that could not be checked.\n\n"+
		"### Not verified\n\n❔ ") || strings.Contains(b.String(), "Nothing to rotate") {
		t.Fatal(b.String())
	}
}

// An incomplete scan with findings still shows them and what could not be verified; only the
// lines that read as "all clear" are dropped.
func TestIncompleteKeepsFindings(t *testing.T) {
	inc, res := sample()
	res.Incomplete, res.Error, res.Rotation = true, "o/b: HTTP 401", nil
	for name, render := range map[string]func(*bytes.Buffer) error{
		"text": func(b *bytes.Buffer) error { return Text(b, inc, res, false) },
		"md":   func(b *bytes.Buffer) error { return Markdown(b, inc, res) },
	} {
		var b bytes.Buffer
		if err := render(&b); err != nil {
			t.Fatal(err)
		}
		s := b.String()
		head, title := "Scan incomplete: o/b: HTTP 401\n", unverifiedTitle
		if name == "md" {
			head, title = "> **Scan incomplete: o/b: HTTP 401.**", "### Not verified"
		}
		if !strings.Contains(s, head) || name == "text" && !strings.HasPrefix(s, head) || !strings.Contains(s, title) ||
			!strings.Contains(s, "DEPLOY_KEY") || !strings.Contains(s, "axios@1.14.1 in package-lock.json") || strings.Contains(s, "Nothing") {
			t.Errorf("%s:\n%s", name, s)
		}
	}
}

// Jobs whose secrets are unknown are never summed up as "Nothing to rotate.".
func TestSecretsUnknownReplacesNothingToRotate(t *testing.T) {
	inc, res := sample() // o/old#9: jobs unavailable, no exposure
	res.Rotation, res.Unverified = nil, nil
	const line = "Secrets unknown for 1 job (workflow file, job list or run not available); review them manually: "
	var txt, md, js bytes.Buffer
	if err := Text(&txt, inc, res, false); err != nil {
		t.Fatal(err)
	}
	if err := Markdown(&md, inc, res); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&js, inc, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(txt.String(), "  "+line+"o/old#9.\n") || strings.Contains(txt.String(), "Nothing to rotate") {
		t.Errorf("text:\n%s", txt.String())
	}
	if !strings.Contains(md.String(), line+"`o/old#9`.\n") || strings.Contains(md.String(), "Nothing to rotate") {
		t.Errorf("md:\n%s", md.String())
	}
	if !strings.Contains(js.String(), `"secrets_unknown_jobs": 1`) {
		t.Errorf("json:\n%s", js.String())
	}
	// an exposure whose secrets are unknown counts too; a known one does not
	res.Findings[1].Exposure = &model.Exposure{SecretsUnknown: true}
	res.Findings = append(res.Findings, model.Finding{Status: model.Unchecked, Exposure: &model.Exposure{}})
	if n := len(secretsUnknown(res)); n != 1 {
		t.Errorf("got %d", n)
	}
}

func render(t *testing.T, inc *incident.Incident, res *model.Result) string {
	t.Helper()
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestMarkdownVerdicts(t *testing.T) {
	inc, hit := sample()
	_, allClear := sample()
	allClear.Findings, allClear.Rotation, allClear.Unverified, allClear.Skipped = nil, nil, nil, nil
	_, notCleared := sample()
	notCleared.Findings, notCleared.Rotation = notCleared.Findings[1:], nil
	_, incomplete := sample()
	incomplete.Incomplete, incomplete.Error = true, "o/b: HTTP 401\x1b[2J"
	_, possible := sample()
	possible.Findings[0].Status, possible.Rotation = model.Possible, possible.Rotation[:0]
	_, skipped := sample()
	skipped.Findings, skipped.Rotation, skipped.Unverified = nil, nil, nil
	_, retention := sample()
	retention.Findings, retention.Rotation, retention.Unverified, retention.Skipped, retention.RetentionWarning = nil, nil, nil, nil, true
	for _, tc := range []struct {
		name string
		res  *model.Result
		want []string
		deny []string
	}{
		{"hit", hit, []string{"> [!CAUTION]\n> **Exposed: 1 job ran a compromised package or action.**  \n> Rotate the 2 secrets under *Rotate first* now.\n",
			"| **1** | 0 | **1** | 3 |", "#### 🛑 Affected · 1", "### Not verified"}, []string{"clean", "safe"}},
		{"clear", allClear, []string{"> [!NOTE]\n> **No exposure found. All 5 jobs were checked.**  \n> Nothing to rotate for this incident.\n",
			"| 0 | 0 | 0 | 5 |", "### Rotate first\n\nNothing. No job is affected, possible or unchecked.\n", "#### ✅ Clean · 5"}, []string{"#### 🛑", "### Not verified"}},
		{"not cleared", notCleared, []string{"> [!WARNING]\n> **Not cleared: 1 of 5 jobs could not be verified.**  \n> No job is proven to have run it. Treat the secrets under *Not verified*",
			"| 0 | 0 | **1** | 4 |", "<details>\n<summary>1 job · jobs unavailable: deleted by GitHub retention (HTTP 410)</summary>"}, []string{"No exposure"}},
		{"incomplete", incomplete, []string{"> [!WARNING]\n> **Scan incomplete: o/b: HTTP 401[2J.**  \n> The report covers only what was checked; an empty section proves nothing.\n"}, []string{"\x1b", "[!NOTE]"}},
		{"possible", possible, []string{"> [!CAUTION]\n> **Possibly exposed: 1 job may have run a compromised package or action.**  \n> Review the secrets under *Also review* now.\n"}, nil},
		{"skipped", skipped, []string{"**Not cleared: 1 repository was skipped.**"}, []string{"[!NOTE]"}},
		{"retention", retention, []string{"**Not cleared: runs older than 90 days may be gone.**"}, []string{"[!NOTE]"}},
	} {
		out := render(t, inc, tc.res)
		for _, w := range tc.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing %q in\n%s", tc.name, w, out)
			}
		}
		verdict := mdVerdict(tc.res)
		for _, d := range tc.deny {
			if strings.Contains(out, d) {
				t.Errorf("%s: unexpected %q in\n%s", tc.name, d, out)
			}
		}
		if !strings.HasPrefix(verdict, "> [!NOTE]") && (strings.Contains(verdict, "✅") || strings.Contains(strings.ToLower(verdict), "clean") || strings.Contains(strings.ToLower(verdict), "safe")) {
			t.Errorf("%s: verdict reads as all clear: %s", tc.name, verdict)
		}
		if n := strings.Count(out, "> [!"); n != 1 {
			t.Errorf("%s: %d alerts", tc.name, n)
		}
		if !strings.HasSuffix(out, "runsweep dev · [How to read this report](https://github.com/runsweep/runsweep#readme)\n") {
			t.Errorf("%s: footer:\n%s", tc.name, out)
		}
	}
}

func TestMarkdownLimitsCountAndVersion(t *testing.T) {
	defer func(v string) { Version = v }(Version)
	Version = "v1.2.3"
	inc, res := sample()
	out := render(t, inc, res)
	want := fmt.Sprintf("<summary>Limits · %d things runsweep cannot see</summary>", strings.Count(limits, "\n- ")+1)
	if !strings.Contains(out, want) || strings.Count(limits, "\n- ")+1 != strings.Count(limits, "- ") || !strings.Contains(out, "runsweep v1.2.3 · [How") {
		t.Fatal(out)
	}
}

func TestMarkdownCleanFloor(t *testing.T) {
	inc, res := sample()
	res.JobsScanned = 1 // fewer jobs than findings
	if out := render(t, inc, res); !strings.Contains(out, "| **1** | 0 | **1** | 0 |") || strings.Contains(out, "Clean ·") {
		t.Fatal(out)
	}
}

func TestMarkdownPossibleFolds(t *testing.T) {
	inc, res := sample()
	f := res.Findings[0]
	f.Status = model.Possible
	res.Findings = nil
	for range 20 {
		res.Findings = append(res.Findings, f)
	}
	if out := render(t, inc, res); strings.Contains(out, "<summary>20 jobs") {
		t.Fatal("20 possible jobs must stay open")
	}
	res.Findings = append(res.Findings, f)
	if out := render(t, inc, res); !strings.Contains(out, "#### ⚠️ Possible · 21\n\n<details>\n<summary>21 jobs</summary>") {
		t.Fatal(out)
	}
}

func TestMarkdownUncheckedGroupsAndWhy(t *testing.T) {
	inc, res := sample()
	un := func(run int64, note string) model.Finding {
		var ev []model.Evidence
		if note != "" {
			ev = []model.Evidence{{Kind: "npm", Detail: "x"}, {Kind: "note", Detail: note}, {Kind: "note", Detail: "second"}}
		}
		return model.Finding{Run: model.RunRef{Repo: "o/app", RunID: run, Job: "j"}, Status: model.Unchecked, Evidence: ev}
	}
	res.Findings = []model.Finding{un(1, "log gone"), un(2, ""), un(3, "gradle"), un(43, "gradle"), un(5, "gradle"), un(6, "log gone")}
	out := render(t, inc, res)
	i, j, k := strings.Index(out, "<summary>3 jobs · gradle"), strings.Index(out, "<summary>2 jobs · log gone"), strings.Index(out, "<summary>1 job · no reason recorded")
	if i < 0 || j < i || k < j {
		t.Fatalf("groups not ordered by size:\n%s", out)
	}
	if !strings.Contains(out, "| **`DEPLOY_KEY`** | publish/deploy | 1 | gradle |") {
		t.Fatalf("why not verified:\n%s", out)
	}
}

func TestMarkdownSummaryInjection(t *testing.T) {
	inc, res := sample()
	evil := "</summary><img src=x onerror=1>|`x`](http://e)\n<details>" + strings.Repeat("я", 200)
	res.Findings[1].Evidence = []model.Evidence{{Kind: "note", Detail: evil}}
	res.Findings[1].Run.Job = "</details>|`j`](http://e)\n<b>"
	res.Rotation[1].Name = "n</td>|`](http://e)\n<b>"
	out := render(t, inc, res)
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "<summary>1 job") {
			if !strings.HasSuffix(line, "…</summary>") || strings.Count(line, "<") != 2 || strings.Count(line, "</summary>") != 1 || strings.Contains(line, "](") {
				t.Fatalf("summary: %q", line)
			}
			if n := strings.Count(line, "я"); n == 0 || n > 120-len([]rune(cell(strings.SplitN(evil, "я", 2)[0]))) {
				t.Fatalf("reason not cut to 120 runes (%d я): %q", n, line)
			}
		}
	}
	for _, bad := range []string{"<img", "<b>", "</td>", "</details>|"} {
		if strings.Contains(strings.ReplaceAll(out, "</details>\n", ""), bad) && !strings.Contains(out, "`"+bad) && !strings.Contains(out, "\\|") {
			t.Fatalf("raw %q leaked:\n%s", bad, out)
		}
	}
	if n := strings.Count(out, "\n<details>\n"); n != 2 { // the UNCHECKED group and Limits
		t.Fatalf("%d <details>:\n%s", n, out)
	}
}

func TestMarkdownRunLinkNeverUntrusted(t *testing.T) {
	inc, res := sample()
	res.Findings[0].Run.JobURL = "https://evil.example/x"
	res.Findings[0].Run.RunURL = "https://github.com/o/a)(b"
	res.Rotation[0].Runs[0].JobURL = "https://github.com/o/app/actions/runs/42/job/7 [x](http://e)"
	out := render(t, inc, res)
	if strings.Contains(out, "evil.example") || strings.Contains(out, "](http://e") || strings.Contains(out, "](https://github.com/o/a)") {
		t.Fatal(out)
	}
	if !strings.Contains(out, "| 17 attempt 2 |") {
		t.Fatalf("an unlinkable run keeps its number as plain text:\n%s", out)
	}
}
