// Package report renders scan results.
package report

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
)

// kindNames name the secret kinds in the Markdown report, by tier.
var kindNames = map[int]string{1: "cloud", 2: "publish/deploy", 3: "third-party", 4: "GITHUB_TOKEN"}

var tierNames = map[int]string{1: "1 · cloud", 2: "2 · publish/deploy", 3: "3 · third-party", 4: "4 · GITHUB_TOKEN"}

const limits = `- GitHub deletes workflow runs, checks and logs after the repository's retention period (default 90 days). Older runs cannot be checked and show as UNCHECKED or are absent.
- Which secrets a job could read is derived from the workflow file at the run's commit; GitHub's API does not expose it directly.
- Priority by secret name is a name-based heuristic. Review the list; do not treat it as complete.
- A job whose log was unavailable is reported UNCHECKED: actions used via composite actions (and reusable workflows that are neither local nor pinned to a SHA) can only be seen in the log. Job logs over 64 MB count as unavailable.
- Lockfiles are assumed to be written by npm, pnpm or yarn; hand-edited lockfiles may be misread. bun.lock, bun.lockb, deno.lock and .pnp.cjs are not read: their directory is at least UNCHECKED, even next to a lockfile that is read (it may be stale).
- A missing, unread, unsupported or stale lockfile does not mark a job whose log shows no package install and whose workflow installs none. A lockfile that pins a bad version does not mark an identified job whose log shows no package install or package manager call (or is unavailable), whose workflow installs nothing and runs no opaque script, and whose only actions are actions/checkout, actions/setup-*, actions/cache, actions/upload-artifact, actions/download-artifact and actions/github-script; this never applies to pull_request_target or workflow_run runs. A pin is AFFECTED only for a job that installed from that lockfile (the root one or one in a directory its steps or log name); a job that may have installed it is POSSIBLE. A dependency on a package of the same repository (a workspace) is not reported as missing from the lockfile.
- An install whose output is fully suppressed inside a JS action or a called script is not seen.
- A lockfile in a directory that declares workspaces covers only its members. A package.json that no lockfile covers, below the root, is POSSIBLE only for a job whose steps or log name its directory; otherwise UNCHECKED.
- Packages named on the command line (npm i axios) are found only in the workflow's own run: steps, not in scripts it calls or in local composite actions.
- Only repositories the token can see are scanned.
- Pull request runs are checked at the pull request's head commit, not the merge commit.
- Jobs that check out another ref (e.g. actions/checkout with: ref:, issue_comment) are judged by the run's commit.
- Container images are not checked.
- Re-runs of runs created more than the lookback period (default 7 days) before the window are not scanned; use --lookback 30d for full coverage.
- Called workflows are read when local or pinned to a commit SHA, and in the scanned repository's owner or a public repository; others are judged from the caller job, at least UNCHECKED for another owner's private repository.
- Workflow files over 1 MiB, lockfiles or package.json over 32 MB, and those past the first 500 of a commit are not read; the job is at least UNCHECKED.
- Lateral movement is not traced: caches, artifacts and needs outputs, dispatch and workflow_run chains, and self-hosted runners (runs-on is not read) can carry malicious code beyond the job that ran it. node_modules restored from a cache or artifact is not seen.
- pull_request_target and workflow_run run the base-branch workflow, but files are read at head_sha: secrets and lockfile may differ from what ran, and a fork can control them. Such runs are at least UNCHECKED; lockfile and uses: evidence is capped at POSSIBLE; a bad action download in the log is still AFFECTED.
- A job name made only of an expression, or equal to another job's id, leaves the job unidentified; its exposure is taken from the whole workflow, so more jobs are POSSIBLE or UNCHECKED.
- Runs that start after the window end are not scanned.
- GitHub Enterprise is not supported; OIDC trust in nested reusable workflows is not resolved.
- npm and GitHub Actions only.
`

// spreadNote warns that a finding may not be the whole damage; "" when nothing is AFFECTED or POSSIBLE.
func spreadNote(r *model.Result) string {
	if r.Count(model.Affected)+r.Count(model.Possible) == 0 {
		return ""
	}
	return "Malicious code can spread through caches, artifacts, self-hosted runners and workflow chains; see Limits\n"
}

// unverifiedTitle heads what UNCHECKED jobs could read.
const unverifiedTitle = "Not verified — could not rule out exposure"

// nothingToRotate is the line under Rotate first besides its items: jobs whose secrets are unknown
// (runs rendered by wrap), then for an empty list "Nothing confirmed to rotate" with unverified
// items or "Nothing to rotate." without either. An incomplete scan never says "Nothing".
func nothingToRotate(r *model.Result, indent, end string, wrap func(string) string) string {
	s := ""
	if unknown := secretsUnknown(r); len(unknown) > 0 {
		s = fmt.Sprintf("%sSecrets unknown for %s (workflow file, job list or run not available); review them manually: %s.%s",
			indent, count(len(unknown), "job"), seenIn(unknown, wrap), end)
	}
	switch {
	case r.Incomplete || len(r.Rotation) > 0:
		return s
	case len(r.Unverified) > 0:
		return s + fmt.Sprintf("%sNothing confirmed to rotate; %s in jobs that could not be checked.%s", indent, count(len(r.Unverified), "secret"), end)
	case s != "":
		return s
	}
	return indent + "Nothing to rotate." + end
}

// secretsUnknown lists the non-CLEAN jobs whose secrets are unknown: no exposure (a run-level
// finding) or a workflow file that was unavailable.
func secretsUnknown(r *model.Result) []model.RunRef {
	var out []model.RunRef
	for _, f := range r.Findings {
		if f.Status != model.Clean && (f.Exposure == nil || f.Exposure.SecretsUnknown) {
			out = append(out, f.Run)
		}
	}
	return out
}

// RetentionNote explains why an old window can look clean.
const RetentionNote = "incident window starts more than 90 days ago; GitHub may have deleted runs — absence of runs is not evidence"

// Version is the release shown in the Markdown footer; main sets it to the --version string.
var Version = "dev"

// Markdown renders the scan result as a Markdown report.
func Markdown(w io.Writer, inc *incident.Incident, r *model.Result) error {
	var b strings.Builder
	full := !r.Incomplete || len(r.Findings) > 0 // an empty list would read as "all clear"
	b.WriteString("## runsweep · " + code(inc.ID) + "\n\n")
	b.WriteString(mdVerdict(r))
	if full {
		b.WriteString(mdCounts(r))
	}
	fmt.Fprintf(&b, "**Incident** %s  \n**Window** %s → %s UTC  \n**Scanned** %s · %s · %s\n",
		code(inc.Title), r.Start.UTC().Format("2006-01-02 15:04"), r.End.UTC().Format("2006-01-02 15:04"),
		count(r.ReposTargeted-len(r.Skipped), "repo"), count(r.RunsScanned, "run"), count(r.JobsScanned, "job"))
	if r.RetentionWarning {
		b.WriteString("Warning: " + RetentionNote + ".\n")
	}
	b.WriteString("\n")
	if full {
		mdFindings(&b, r)
	}
	if len(r.Skipped) > 0 {
		b.WriteString("### Skipped repositories\n\n")
		for _, s := range r.Skipped {
			fmt.Fprintf(&b, "- %s — %s\n", code(s.Repo), code(s.Reason))
		}
		b.WriteString("\nThe token needs read access to Actions, Contents and Metadata for these repositories.\n\n")
	}
	if len(inc.Refs) > 0 {
		b.WriteString("### Incident sources\n\n")
		for _, ref := range inc.Refs {
			fmt.Fprintf(&b, "- %s\n", code(ref))
		}
		b.WriteString("\n")
	}
	if n := spreadNote(r); n != "" {
		b.WriteString(n + "\n")
	}
	fmt.Fprintf(&b, "---\n\nrunsweep sees what job logs, workflow files and lockfiles show; some installs leave no trace there. "+
		"Read the limits before you close the incident.\n\n<details>\n<summary>Limits · %d things runsweep cannot see</summary>\n\n%s\n</details>\n\n",
		strings.Count(limits, "\n- ")+1, limits)
	fmt.Fprintf(&b, "runsweep %s · [How to read this report](https://github.com/runsweep/runsweep#readme)\n", Clean(Version))
	_, err := io.WriteString(w, b.String())
	return err
}

// cleanJobs is the number of scanned jobs that are neither AFFECTED, POSSIBLE nor UNCHECKED.
func cleanJobs(r *model.Result) int {
	return max(0, r.JobsScanned-r.Count(model.Affected)-r.Count(model.Possible)-r.Count(model.Unchecked))
}

// mdVerdict renders the one alert that says what the reader must do.
func mdVerdict(r *model.Result) string {
	a, p, u := r.Count(model.Affected), r.Count(model.Possible), r.Count(model.Unchecked)
	var kind, head, todo string
	switch {
	case r.Incomplete:
		kind, head = "WARNING", "Scan incomplete: "+Clean(r.Error)+"."
		todo = "The report covers only what was checked; an empty section proves nothing."
	case a > 0:
		kind, head = "CAUTION", fmt.Sprintf("Exposed: %s ran a compromised package or action.", count(a, "job"))
		k := 0
		for _, it := range r.Rotation {
			if it.Confirmed {
				k++
			}
		}
		todo = "Review the secrets under *Also review* and *Not verified*."
		if k > 0 {
			todo = fmt.Sprintf("Rotate the %s under *Rotate first* now.", count(k, "secret"))
		}
	case p > 0:
		kind, head = "CAUTION", fmt.Sprintf("Possibly exposed: %s may have run a compromised package or action.", count(p, "job"))
		todo = "Review the secrets under *Also review* now."
	case u > 0 || len(r.Skipped) > 0 || r.RetentionWarning:
		kind = "WARNING"
		switch {
		case u > 0:
			head = fmt.Sprintf("Not cleared: %d of %s could not be verified.", u, count(r.JobsScanned, "job"))
		case len(r.Skipped) > 0:
			head = fmt.Sprintf("Not cleared: %d repositories were skipped.", len(r.Skipped))
			if len(r.Skipped) == 1 {
				head = "Not cleared: 1 repository was skipped."
			}
		default:
			head = "Not cleared: runs older than 90 days may be gone."
		}
		todo = "No job is proven to have run it. Treat the secrets under *Not verified* as possibly exposed until you rotate them or recover the evidence."
	default:
		kind, head = "NOTE", fmt.Sprintf("No exposure found. All %s were checked.", count(r.JobsScanned, "job"))
		todo = "Nothing to rotate for this incident."
	}
	return fmt.Sprintf("> [!%s]\n> **%s**  \n> %s\n\n", kind, head, todo)
}

// mdCounts renders the status counters; non-zero risk counts are bold.
func mdCounts(r *model.Result) string {
	n := func(s model.Status) string {
		if c := r.Count(s); c > 0 {
			return fmt.Sprintf("**%d**", c)
		}
		return "0"
	}
	return fmt.Sprintf("| 🛑 Affected | ⚠️ Possible | ❔ Unchecked | ✅ Clean |\n| :---: | :---: | :---: | :---: |\n| %s | %s | %s | %d |\n\n",
		n(model.Affected), n(model.Possible), n(model.Unchecked), cleanJobs(r))
}

// mdFindings renders the rotation lists and the findings.
func mdFindings(b *strings.Builder, r *model.Result) {
	var confirmed, review []model.RotationItem
	for _, it := range r.Rotation {
		if it.Confirmed {
			confirmed = append(confirmed, it)
		} else {
			review = append(review, it)
		}
	}
	b.WriteString("### Rotate first\n\n")
	nothing := nothingToRotate(r, "", "\n\n", code)
	if len(confirmed) > 0 {
		mdItems(b, confirmed, "🛑")
	} else {
		switch {
		case nothing == "Nothing to rotate.\n\n":
			nothing = "Nothing. No job is affected, possible or unchecked.\n\n"
		case nothing == "" && !r.Incomplete && len(review) > 0:
			nothing = "Nothing confirmed to rotate. Review the secrets under *Also review*.\n\n"
		}
	}
	b.WriteString(nothing)
	if len(review) > 0 {
		b.WriteString("**Also review** · secrets only ⚠️ possible jobs could read:\n\n")
		mdItems(b, review, "⚠️")
	}
	if len(r.Unverified) > 0 {
		b.WriteString("### Not verified\n\n")
		b.WriteString("❔ " + count(r.Count(model.Unchecked), "job") + " could not be checked, so these secrets may have been exposed. " +
			"Rotate them, or recover the evidence and run runsweep again.\n\n")
		b.WriteString("| Secret | Kind | Unchecked jobs | Why not verified |\n| --- | --- | :---: | --- |\n")
		for _, it := range r.Unverified {
			fmt.Fprintf(b, "| **%s** | %s | %d | %s |\n", code(it.Name), kind(it.Tier), len(it.Runs), cell(whyNot(r, it)))
		}
		b.WriteString("\n")
	}

	b.WriteString("### Findings\n\n")
	var by [4][]model.Finding
	for _, f := range r.Findings {
		by[f.Status] = append(by[f.Status], f)
	}
	if fs := by[model.Affected]; len(fs) > 0 {
		fmt.Fprintf(b, "#### 🛑 Affected · %d\n\n%s\n", len(fs), mdTable(fs))
	}
	if fs := by[model.Possible]; len(fs) > 0 {
		fmt.Fprintf(b, "#### ⚠️ Possible · %d\n\n", len(fs))
		if len(fs) > 20 {
			fmt.Fprintf(b, "<details>\n<summary>%s</summary>\n\n%s\n</details>\n\n", count(len(fs), "job"), mdTable(fs))
		} else {
			b.WriteString(mdTable(fs) + "\n")
		}
	}
	if fs := by[model.Unchecked]; len(fs) > 0 {
		fmt.Fprintf(b, "#### ❔ Unchecked · %d\n\n", len(fs))
		groups := map[string][]model.Finding{}
		var order []string
		for _, f := range fs {
			k := firstNote(f)
			if _, ok := groups[k]; !ok {
				order = append(order, k)
			}
			groups[k] = append(groups[k], f)
		}
		slices.SortStableFunc(order, func(x, y string) int { return len(groups[y]) - len(groups[x]) })
		for _, k := range order {
			reason := "no reason recorded"
			if k != "" {
				reason = k
			}
			fmt.Fprintf(b, "<details>\n<summary>%s · %s</summary>\n\n%s\n</details>\n\n", count(len(groups[k]), "job"), summaryText(reason), mdTable(groups[k]))
		}
	}
	if n := cleanJobs(r); n > 0 {
		fmt.Fprintf(b, "#### ✅ Clean · %d\n\nChecked, nothing found.\n\n", n)
	}
}

// kind names what a secret of the given tier is for.
func kind(tier int) string {
	if s, ok := kindNames[tier]; ok {
		return s
	}
	return fmt.Sprint(tier)
}

// firstNote is the detail of a finding's first note evidence, cleaned; "" without one.
func firstNote(f model.Finding) string {
	for _, e := range f.Evidence {
		if e.Kind == "note" {
			return Clean(e.Detail)
		}
	}
	return ""
}

// whyNot is the most common first note among the UNCHECKED findings of the item's runs (the
// first found on a tie); "" without a note.
func whyNot(r *model.Result, it model.RotationItem) string {
	n := map[string]int{}
	best := ""
	for _, f := range r.Findings {
		k := firstNote(f)
		if f.Status != model.Unchecked || k == "" ||
			!slices.ContainsFunc(it.Runs, func(x model.RunRef) bool { return x.Repo == f.Run.Repo && x.RunID == f.Run.RunID }) {
			continue
		}
		n[k]++
		if best == "" || n[k] > n[best] {
			best = k
		}
	}
	return best
}

// summaryText makes untrusted text safe inside <summary>: one table-safe line of at most
// 120 characters with HTML and link/code-span characters escaped.
func summaryText(s string) string {
	if rs := []rune(s); len(rs) > 120 {
		s = string(rs[:119]) + "…"
	}
	return mdChars.Replace(html.EscapeString(cell(s)))
}

// mdChars turns the characters that start a link or a code span into entities.
var mdChars = strings.NewReplacer("[", "&#91;", "]", "&#93;", "`", "&#96;")

// mdItems renders rotation items as a numbered list; mark tells who saw them.
func mdItems(b *strings.Builder, list []model.RotationItem, mark string) {
	for i, it := range list {
		fmt.Fprintf(b, "%d. **%s** · %s  \n   %s  \n   Seen by %s %s\n", i+1, code(it.Name), kind(it.Tier), cell(it.Reason), mark, seenRuns(it.Runs))
	}
	b.WriteString("\n")
}

// seenRuns lists up to three runs as "`repo` run [N](job url) › `job`", then "+N more".
func seenRuns(runs []model.RunRef) string {
	var parts []string
	for i, r := range runs {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("+%d more", len(runs)-3))
			break
		}
		s := code(r.Repo)
		if r.RunID != 0 { // 0: a repository-level finding (runs cap)
			s += " run " + runLink(r)
		}
		if r.Job != "" {
			s += " › " + code(r.Job)
		}
		if r.Attempt > 1 {
			s += fmt.Sprintf(" attempt %d", r.Attempt)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}

// runLink links the run number (the run ID when unknown) to the job, or to the run without one.
func runLink(r model.RunRef) string {
	n := r.RunNumber
	if n == 0 {
		n = r.RunID
	}
	return link(fmt.Sprint(n), cmp.Or(r.JobURL, r.RunURL))
}

// mdTable renders findings as a table of repo, workflow › job, run and evidence.
func mdTable(fs []model.Finding) string {
	var b strings.Builder
	b.WriteString("| Repo | Workflow › job | Run | Evidence |\n| --- | --- | --- | --- |\n")
	for _, f := range fs {
		var ev []string
		for _, e := range f.Evidence {
			ev = append(ev, code(e.Detail))
		}
		wf := f.Run.Workflow
		if strings.HasPrefix(wf, ".github/workflows/") {
			wf = path.Base(wf)
		}
		job := code(wf)
		if f.Run.Job != "" {
			job += " › " + code(f.Run.Job)
		}
		run := ""
		if f.Run.RunID != 0 { // 0: a repository-level finding (runs cap)
			run = runLink(f.Run)
		}
		if f.Run.Attempt > 1 {
			run += fmt.Sprintf(" attempt %d", f.Run.Attempt)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", code(f.Run.Repo), job, run, strings.Join(ev, "; "))
	}
	return b.String()
}

// JSON renders the scan result as JSON.
func JSON(w io.Writer, inc *incident.Incident, r *model.Result) error {
	c := *inc
	c.Window.Start, c.Window.End = c.Window.Start.UTC(), c.Window.End.UTC()
	inc = &c
	r = normalize(r)
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		Incident *incident.Incident `json:"incident"`
		*model.Result
		SecretsUnknown int `json:"secrets_unknown_jobs"`
		CleanJobs      int `json:"clean_jobs"`
	}{inc, r, len(secretsUnknown(r)), cleanJobs(r)}); err != nil {
		return err
	}
	_, err := w.Write(escapeRe.ReplaceAllFunc(b.Bytes(), func(m []byte) []byte {
		r, _ := utf8.DecodeRune(m)
		if r1, r2 := utf16.EncodeRune(r); r1 != utf8.RuneError { // outside the BMP: a surrogate pair
			return fmt.Appendf(nil, `\u%04x\u%04x`, r1, r2)
		}
		return fmt.Appendf(nil, `\u%04x`, r)
	}))
	return err
}

// escapeRe matches C1 control characters, format characters (Cf: bidi controls, zero-width
// characters, ...) and the tag block, which encoding/json leaves unescaped.
var escapeRe = regexp.MustCompile(`[\x{80}-\x{9f}\p{Cf}\x{e0000}-\x{e007f}]`)

// seenIn lists up to three runs, each rendered by wrap, then "+N more".
func seenIn(runs []model.RunRef, wrap func(string) string) string {
	var parts []string
	for i, r := range runs {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("+%d more", len(runs)-3))
			break
		}
		s := r.Repo
		if r.RunID != 0 { // 0: a repository-level finding (runs cap)
			s += fmt.Sprintf("#%d", r.RunID)
		}
		s = strings.TrimSpace(s + " " + r.Job)
		if r.Attempt > 1 {
			s += fmt.Sprintf(" attempt %d", r.Attempt)
		}
		parts = append(parts, wrap(s))
	}
	return strings.Join(parts, ", ")
}

// link renders a Markdown link only for plain github.com URLs; anything else is plain text.
func link(text, url string) string {
	if !strings.HasPrefix(url, "https://github.com/") || strings.ContainsAny(url, " ()|<>\r\n\t`") {
		return text
	}
	return "[" + text + "](" + url + ")"
}

// seenBy tells a confirmed rotation item from one only POSSIBLE jobs could read; "" for the
// Not verified list, where every job is UNCHECKED.
func seenBy(it model.RotationItem, plan bool) string {
	switch {
	case !plan:
		return ""
	case it.Confirmed:
		return " · AFFECTED job"
	}
	return " · POSSIBLE jobs only"
}

func tier(n int) string {
	if s, ok := tierNames[n]; ok {
		return s
	}
	return fmt.Sprint(n)
}

// cell keeps text in one table cell: line breaks flattened, pipes escaped, control characters dropped.
func cell(s string) string { return strings.ReplaceAll(Clean(s), "|", `\|`) }

var newlines = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")

// Clean makes repo-derived text safe for a terminal: CR/LF become spaces; C0/C1 controls, DEL,
// Unicode line/paragraph separators, format characters (Cf: bidi controls, zero-width characters,
// ...), the tag block, the blank fillers (Hangul fillers, braille blank) and variation selectors
// are dropped (no escape sequences reach the terminal, no text reordering, no hidden text).
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r >= 0x7f && r <= 0x9f, r == 0x2028, r == 0x2029, unicode.Is(unicode.Cf, r), r >= 0xe0000 && r <= 0xe007f,
			r == 0x115f, r == 0x1160, r == 0x3164, r == 0xffa0, r == 0x2800, r >= 0xfe00 && r <= 0xfe0f, r >= 0xe0100 && r <= 0xe01ef:
			return -1
		}
		return r
	}, newlines.Replace(s))
}

// code renders untrusted text as an inline code span, which GFM does not interpret
// (no links, images, HTML, mentions or autolinks). Empty input gives an empty cell.
func code(s string) string {
	if s == "" {
		return ""
	}
	return "`" + cell(strings.ReplaceAll(s, "`", "'")) + "`"
}

// normalize returns a copy with nil slices made empty and times in UTC; the input is not modified.
func normalize(r *model.Result) *model.Result {
	c := *r
	c.Start, c.End = r.Start.UTC(), r.End.UTC()
	runs := func(in []model.RunRef) []model.RunRef {
		out := make([]model.RunRef, len(in))
		for i, x := range in {
			x.CreatedAt = x.CreatedAt.UTC()
			out[i] = x
		}
		return out
	}
	c.Findings = make([]model.Finding, len(r.Findings))
	for i, f := range r.Findings {
		f.Run.CreatedAt = f.Run.CreatedAt.UTC()
		f.Evidence = append([]model.Evidence{}, f.Evidence...)
		if f.Exposure != nil {
			e := *f.Exposure
			e.Secrets = append([]string{}, e.Secrets...)
			f.Exposure = &e
		}
		c.Findings[i] = f
	}
	items := func(in []model.RotationItem) []model.RotationItem {
		out := make([]model.RotationItem, len(in))
		for i, it := range in {
			it.Runs = runs(it.Runs)
			out[i] = it
		}
		return out
	}
	c.Rotation, c.Unverified = items(r.Rotation), items(r.Unverified)
	c.Skipped = append([]model.Skip{}, r.Skipped...)
	return &c
}
