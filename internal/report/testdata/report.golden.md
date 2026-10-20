## runsweep · `axios-2026-03`

> [!CAUTION]
> **Exposed: 1 job ran a compromised package or action.**  
> Rotate the 2 secrets under *Rotate first* now.

| 🛑 Affected | ⚠️ Possible | ❔ Unchecked | ✅ Clean |
| :---: | :---: | :---: | :---: |
| **1** | 0 | **1** | 3 |

**Incident** `axios malicious release`  
**Window** 2026-03-31 00:21 → 2026-03-31 03:21 UTC  
**Scanned** 2 repos · 3 runs · 5 jobs

### Rotate first

1. **`OIDC token (id-token: write)`** · cloud  
   review cloud roles  
   Seen by 🛑 `o/app` run [17](https://github.com/o/app/actions/runs/42/job/7) › `build` attempt 2
2. **`NPM_TOKEN`** · publish/deploy  
   rotate  
   Seen by 🛑 `o/app` run [17](https://github.com/o/app/actions/runs/42/job/7) › `build` attempt 2

Secrets unknown for 1 job (workflow file, job list or run not available); review them manually: `o/old#9`.

### Not verified

❔ 1 job could not be checked, so these secrets may have been exposed. Rotate them, or recover the evidence and run runsweep again.

| Secret | Kind | Unchecked jobs | Why not verified |
| --- | --- | :---: | --- |
| **`DEPLOY_KEY`** | publish/deploy | 1 |  |

### Findings

#### 🛑 Affected · 1

| Repo | Workflow › job | Run | Evidence |
| --- | --- | --- | --- |
| `o/app` | `ci.yml` › `build` | [17](https://github.com/o/app/actions/runs/42/job/7) attempt 2 | `axios@1.14.1 in package-lock.json at abcdef1` |

#### ❔ Unchecked · 1

<details>
<summary>1 job · <code>jobs unavailable: deleted by GitHub retention (HTTP 410)</code></summary>

| Repo | Workflow › job | Run | Evidence |
| --- | --- | --- | --- |
| `o/old` | `ci.yml` | 9 | `jobs unavailable: deleted by GitHub retention (HTTP 410)` |

</details>

#### ✅ Clean · 3

Checked, nothing found.

### Skipped repositories

- `o/private` — `no access (HTTP 403/404)`

The token needs read access to Actions, Contents and Metadata for these repositories.

### Incident sources

- `https://osv.dev/vulnerability/MAL-2026-2307`

Malicious code can spread through caches, artifacts, self-hosted runners and workflow chains; see Limits

---

runsweep sees what job logs, workflow files and lockfiles show; some installs leave no trace there. Read the limits before you close the incident.

<details>
<summary>Limits · 28 things runsweep cannot see</summary>

- GitHub deletes workflow runs, checks and logs after the repository's retention period (default 90 days). Older runs cannot be checked and show as UNCHECKED or are absent.
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
- pull_request_target and workflow_run run the base-branch workflow, but files are read at head_sha: secrets and lockfile may differ from what ran, and a fork can control them. Such runs are at least UNCHECKED; lockfile and uses: evidence is capped at POSSIBLE; a bad action download in the log is still AFFECTED. PyPI evidence other than a job log line is at most POSSIBLE.
- A job name made only of an expression, or equal to another job's id, leaves the job unidentified; its exposure is taken from the whole workflow, so more jobs are POSSIBLE or UNCHECKED.
- Runs that start after the window end are not scanned.
- GitHub Enterprise is not supported; OIDC trust in nested reusable workflows is not resolved.
- PyPI: requirements and constraints files (== pins), uv.lock, poetry.lock, pylock.toml and Pipfile.lock are read; pdm.lock is not. Files included with -r or -c are read only when their name looks like a requirements or constraints file.
- PyPI installs are proven by pip, uv, poetry and pipx lines in the job log. A step whose output does not list every installed version (quiet or redirected output, uv run that creates or syncs the environment, build dependencies, a restored venv), wrappers (nox, pre-commit, hatch, pdm, pipenv, pipx, uvx, conda, python -m build, pip wheel or download) and tool words runsweep cannot place in a command make the job UNCHECKED, or POSSIBLE when a lockfile anywhere in the repository pins a bad version; lockfiles are not linked to jobs.
- tox 4 is read from the package listing it prints for each environment after its default freeze command (pip freeze --all, or uv --color never pip freeze with tox-uv), when the environment's package was installed from a wheel. An environment whose package is built from an sdist, a directory or installed editable (its build dependencies are in no listing), a listing from any other freeze command, tox 3, an environment without a listing, quiet or redirected tox output, or an install in tox commands without its own listing leaves the job UNCHECKED; versions in any listing still make it AFFECTED. tox run through uvx, uv tool run or pipx run stays UNCHECKED: tox's own environment is not listed.
- nox hides pip output; nox jobs stay UNCHECKED unless a lock file pins the package (POSSIBLE).
- A venv or site-packages restored from a cache shows only through "Requirement already satisfied" lines; a uv or poetry environment restored from a cache lists only what changed. Installs inside docker build, containers and scripts that silence all output are not seen. Python scripts (python script.py, code fed to python on stdin) are judged by their output only: one that installs packages without printing install lines is not seen. Neither are build tools that call pip internally without a Python tool word in the job (sam build) nor scripts that install silently, with no install output.
- PyPI version ranges (>=1,<2) are not compared.
- npm, PyPI and GitHub Actions only.

</details>

runsweep dev · [How to read this report](https://github.com/runsweep/runsweep#readme)
