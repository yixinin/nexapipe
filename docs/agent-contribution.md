# Contributing as an AI agent

This page is the walkthrough for an AI coding agent working in this repository,
and for the person supervising it. It is deliberately short on rules, because
the rules already have a home: [`AGENTS.md`](../AGENTS.md) holds the mandatory
ones — plan approval, worktree placement, git safety, what may be committed —
and [`CONTRIBUTING.md`](../CONTRIBUTING.md) holds the build, test and lint
commands. Read both before starting.

What is left here is the order to apply them in, what verification each kind of
change owes, and what a finished piece of agent work has to look like before it
is handed back. When this page and `AGENTS.md` disagree, `AGENTS.md` wins. When
this page is stale, fixing it belongs in the same pull request that made it
stale.

## What the agent decides, and what it asks about

| The agent may, without asking | The agent must ask first |
| --- | --- |
| Read, search, explain code, run builds and tests | Any write outside the approved plan |
| Create the approved worktree on the approved base | A new branch when an open PR already covers the area |
| Commit on the working branch and push it to `origin` | Force-push, rewriting the branch history |
| Fix review comments on the same branch | Pushing `main`, pushing tags, publishing a release |
| Report what it did, and what it could not verify | Merging, opening a PR the owner did not ask for |
| | Deleting a branch or a worktree |
| | Anything with an effect outside the repository |

The last line is the one agents get wrong. `gh` commands that write — opening or
editing a pull request, commenting, labelling — are external effects just as much
as a merge is. They need the same explicit approval.

## The tools, and the prompts they raise

Two mechanics come up on every task. Neither is a question for the owner — they
are things worth knowing before the first command runs, because both turn an
ordinary step into a round trip.

**The file-access gate separates the project tree from everything outside it.**
A file under the repository is read and written without asking. A file outside it
is a different scope: the first call to it prompts, and a refusal can be
remembered as a standing rule that blocks the next one. That is why the
worktrees live inside the repository rather than beside it.

**The safety check on a shell command reads a relative path as relative to the
repository root, not to the current directory.** `rm -f build.log` run from
`.worktrees/feature-x/` is checked as `<repo>/build.log` — a deletion at the top
of the repository, not in the worktree. Write the path out:

```bash
rm -f "$PWD/build.log"            # resolved against the directory you are in
```

A recoverable delete is better than either, where the environment offers one.
And a command blocked for this reason is not a tool failure to route around: it
is a signal that the command was written in a form the checker cannot resolve,
and rewriting it is cheaper than arguing with it.

## The lifecycle

### 1. Find out whether the work already exists

Before writing anything, look for a pull request that already covers the area:

```bash
gh pr list --repo open-nexa/nexapipe --state open --json number,title,headRefName
```

A PR's head branch lives in `origin` (the fork); the PR itself lives in
`upstream` (`open-nexa/nexapipe`). If the branch you are about to touch has an
open PR, the work belongs on that branch and in that branch's worktree — see
step 3 — not on a fresh one.

The `--repo` flag is what lets the command reach the upstream pull requests
from a fork checkout. `gh repo set-default open-nexa/nexapipe` sets it once per
checkout, but that setting is local to the machine and does not travel with a
clone, so a command that has to work anywhere keeps the flag.

For what to work on, the issues and the "Good first issues" list in
`CONTRIBUTING.md` are the sources. An agent should not invent scope: a task that
grew past its approval goes back for approval, rather than forward into a
bigger diff.

### 2. Plan, then wait

The plan states the goal, every file that changes, what each change does, what
could break, and how it will be verified — the exact commands and the CI jobs
that confirm them. It goes to the owner as a message; nothing is written and no
worktree is created until that plan is approved.

Approval covers that plan. A new file, a wider fix, or a different approach is a
new plan.

### 3. Put the work in a worktree

Every new branch starts from the newest `upstream/main`, never from the local
`main` ref alone:

```bash
git fetch --no-tags upstream main
mkdir -p .worktrees/<owner>            # the parent of the branch's path
git worktree add .worktrees/<owner>/<name> -b <owner>/<name> upstream/main
cd .worktrees/<owner>/<name>
git merge-base --is-ancestor upstream/main HEAD
```

The directory path is the branch name verbatim (`v070/audit-fixes` →
`.worktrees/v070/audit-fixes`), so two branch names can never land on the same
directory — flattening the slashes to dashes would let `a/b-c` and `a-b/c` both
ask for `a-b-c`. The parent directory has to exist first; `git worktree add`
does not create it.

Worktrees live inside the repository and are git-ignored, so their files go
through the same file-access path as the rest of the project — a worktree
outside the repository is a separate scope, and reading it is a prompt that can
become a standing refusal.

Searches and reads have to name the worktree explicitly: a search rooted at the
repository root does not descend into `.worktrees/`, because each worktree is
both a hidden directory and a separate git repository.

The exception is a fix to an open PR: reuse that PR's branch and its existing
worktree. Run `git worktree list` to find it and `git status` to confirm it is
clean. If it holds unrelated uncommitted work, stop and report rather than
mixing the fix into it.

### 4. Implement the smallest coherent change

Match the surrounding code, keep platform code behind its feature, and change
the wire format only in `crates/nexapipe-proto/` — never by hand on one side.
New behaviour arrives with a test. Comments, log lines, commit messages and PR
descriptions are English, always.

Scratch plans, patches and notes go to `.workbuddy/` (git-ignored), never into
the repository tree.

### 5. Verify before claiming anything

Run the row that matches what was touched. "It compiles" is not verification for
a behaviour change, and a test that was not run is not a test that passed.

| What changed | Run locally | CI job that confirms it |
| --- | --- | --- |
| `crates/nexapipe/`, `crates/nexapipe-proto/` | `cargo test --workspace`; `cargo clippy --workspace --all-targets --locked -- -D warnings`; `rustfmt --edition 2024 <file>` | `test (ubuntu-latest)`, `test (macos-15)`, `test (windows-latest)`, `lint (rustfmt + clippy)` |
| `crates/nexapipe-client/`, feature-gated code | `cargo check -p nexapipe-client --features <features>` for each feature set you touched | `client features` |
| The TUN proxy or the L4 client | `cargo ndk -t arm64-v8a --platform 26 check -p nexapipe-client --features jni,local-proxy,tun-proxy`; `cargo ndk -t x86_64 --platform 26 check -p nexapipe-client --features jni,local-proxy,tun-proxy`; `cargo test -p nexapipe-client --features tun-proxy` | `android (ndk + unit tests + lint)` |
| `ui-android/` | `cd ui-android && ./gradlew :app:testDebugUnitTest :app:compileDebugKotlin` | `android (ndk + unit tests + lint)` |
| `ui-desktop/` frontend | `cd ui-desktop && npm ci && npm run build && npm run lint:i18n && npm run lint:tokens` | `desktop (linux: rust + frontend)` |
| `ui-desktop/src-tauri/` | `cd ui-desktop/src-tauri && cargo clippy --all-targets -- -D warnings && cargo test --lib` | `desktop (linux: rust + frontend)`, `desktop cargo check (macos-15 / windows-latest)` |
| `Cargo.toml`, `Cargo.lock`, npm lockfiles | `cargo audit`; `cd ui-desktop/src-tauri && cargo audit`; `cd ui-desktop && npm audit --omit=dev --audit-level=high`; `cargo +<declared MSRV> check --workspace --all-targets --locked` when `rust-version` moves | `supply chain (audit, deny, secrets)`, `msrv` |
| Docs only | No build. Every relative link resolves, the text is English, and the claims match the code | Nothing runs: the workflow does not start for a change that touches nothing but Markdown |

`rustfmt --edition 2024 <path>` on the files you touched, not `cargo fmt --all`:
the latter rewrites files nobody asked about and buries the change under
formatting noise.

Not every command in the table is available on every machine. `cargo ndk` is a
separate install (`cargo install cargo-ndk`) and needs an Android NDK that CI
installs for itself; where it is missing the NDK row cannot be run locally, and
the report has to say so instead of leaving the box ticked. Run clippy the way
CI runs it — `cargo clippy --workspace --all-targets --locked -- -D warnings` —
because `--locked` is what stops a `Cargo.lock` edit from slipping in unnoticed.

A lint that fires in a file you did not touch is not yours to fix. The local
toolchain is usually ahead of the one CI pins, so the two disagree about what a
warning even is. `cargo clippy` on a clean `upstream/main` used to fail on
`crates/nexapipe-client/src/traffic.rs`: Rust 1.99 deprecated
`Atomic::fetch_update`, CI still runs 1.98.1 and cannot see it. Report such a
failure, leave the file alone, and let the owner decide — the fix for that one
was to take the compiler's own suggestion, `try_update`, which needs 1.95, so
the declared floor moved to 1.95 and the `msrv` job now builds the workspace on
exactly that version.

The job names are the ones `.github/workflows/ci.yml` reports on a pull request.
Rename a job there and this table is stale.

A job only runs when the change touches what it covers: the `changes` job
works out which parts of the tree a pull request touches, and the jobs that
cover a part of the tree are gated on that. A pull request that changes the
server alone does not run the Android build, and one that changes nothing but
Markdown runs nothing at all. The table above names the job to look at, not
the only job that will run.

### 6. Commit one logical change

```bash
git status                 # confirm nothing unintended is staged or untracked
git add <path> <path>      # by name, never `git add -A`
git commit -m "fix(local-proxy): handle CONNECT tunnel close"
```

The subject says what changed and in which component; the body says why, and
what was verified. Two unrelated fixes are two commits — or two PRs. No secrets,
no generated artifacts, no `.workbuddy/` scratch files.

### 7. Push, then describe and open

```bash
git push origin <branch>
```

That updates the PR when one is open on the branch. Pushing the working branch
and opening the pull request for a branch the agent just pushed are ordinary
execution, not separate approvals. Editing a pull request the owner opened, or
opening one for a branch the agent did not push, still needs their ask. The PR
description follows `.github/PULL_REQUEST_TEMPLATE.md`: what changed, why, how it
was verified — the commands that were actually run, and an honest list of what
was not run and why. Screenshots or a recording are required for UI and VPN
behaviour.

The template is a file to read, not one `gh` applies. `gh pr create --body`
takes the body verbatim: nothing fills the sections in, and a body that misses
them reads as a body that skipped the template. Read
`.github/PULL_REQUEST_TEMPLATE.md`, mirror its headings, and delete the
checklist rows that do not apply — a ticked box for a command nobody ran is
worse than no box at all. `gh pr create --body-file <path>` takes the body from
a file, which is the easier way to write a long one.

Opening the pull request for the branch the agent just pushed is allowed.
Editing a pull request somebody else opened, or opening one for a branch the
agent did not push, stays with the owner unless they asked.

### 8. Review is a loop on the same branch

Review comments are fixed in the same worktree, committed on the same branch,
and pushed again. History on a pushed branch is not rewritten without an
explicit request, so review can still see what changed between rounds. A point
the agent disagrees with is answered with a reason, not silently ignored.

### 9. Merging is the owner's decision

The agent's part ends at a green branch, an opened pull request and an honest
report. Merging, closing, tagging and releasing are the owner's, and so is
deleting the worktree — least of all one that still holds unpushed commits.

## What an agent PR must be able to say

- **What changed**, in one or two sentences, in terms of behaviour.
- **Why**, with the issue it closes.
- **How it was verified**, with the commands that were run and their result. A
  claim of "tested" without a command is noise.
- **What was not verified**, and why — a platform that was not available, a CI
  job that cannot run locally. Leaving this out is the failure mode that erodes
  review trust fastest.
- **Anything the reviewer would otherwise spend ten minutes finding** — a
  trade-off, a deliberate omission, a follow-up.

## Handing back

The final report to the owner is short and checkable: the branch and its PR link
(or why no PR was opened), the files changed, the verification commands and
their outcomes, what remains unverified, and any question that blocks the next
step. When a step failed, say which one and what the error was; a partial result
reported accurately is worth more than a clean summary that skips it.
