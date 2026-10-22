#!/usr/bin/env bash
# Print, as GitHub Actions outputs, which parts of the repository a change
# touches.
#
# A CI job that only covers one part of the tree — the desktop app, the
# Android app, the container image — has nothing to say about a pull request
# that leaves that part alone. This script turns the diff into the booleans
# those jobs gate on, so a job runs exactly when it can fail.
#
# The outputs:
#   rust              the workspace, the vendored patch and the lockfile
#   client            the client crate and the wire format it shares
#   android           the client crate and the Android app
#   desktop           the client crate and the desktop app
#   image             the Dockerfiles and the docker ignore file
#   desktop_lockfile  the desktop package.json and the lockfile that pins it
#   codeql            everything CodeQL reads: the Rust, the TypeScript and
#                     the workflow files
#
# On a push there is no base to diff against, so every group is in scope: a
# push to main is the state of the world, and the jobs run against it.
#
# Usage:
#   BASE_SHA=<base> HEAD_SHA=<head> .github/scripts/changed-paths.sh
#
# BASE_SHA empty means "no base": every group is in scope.

set -euo pipefail

BASE_SHA="${BASE_SHA:-}"
HEAD_SHA="${HEAD_SHA:-HEAD}"

# The diff the groups are read out of. Empty means "no base to diff against".
changed=""
if [ -n "$BASE_SHA" ]; then
  # The merge base, not the base commit: the base branch moves, and the
  # changes it gained since the branch was opened are not this branch's
  # changes.
  merge_base="$(git merge-base "$BASE_SHA" "$HEAD_SHA")"
  changed="$(git diff --name-only "$merge_base" "$HEAD_SHA")"
fi

# Whether every group is in scope. A change to the workflows, or to the
# scripts they call, can break any of the jobs — including the ones this
# script gates — so it puts them all in scope.
all=false
if [ -z "$changed" ]; then
  all=true
fi

# matches <extended regular expression>
#
# True when a path in the diff matches. The paths are read line by line
# instead of through a pipe, so that the first match cannot close the pipe
# under the feet of the command that produced it.
matches() {
  local pattern="$1" path

  if [ "$all" = true ]; then
    return 0
  fi

  while IFS= read -r path; do
    [ -z "$path" ] && continue
    if [[ "$path" =~ $pattern ]]; then
      return 0
    fi
  done <<< "$changed"

  return 1
}

if [ "$all" = false ] && matches '^\.github/'; then
  all=true
fi

emit() {
  local name="$1" pattern="$2"
  if matches "$pattern"; then
    echo "$name=true" >> "$GITHUB_OUTPUT"
  else
    echo "$name=false" >> "$GITHUB_OUTPUT"
  fi
}

# The workspace, the vendored patch it builds against, and the files that
# decide which dependencies it pulls in.
emit rust '^(crates/|third_party/|Cargo\.toml$|Cargo\.lock$|deny\.toml$)'

# The client crate and the wire format crate it shares with the server. The
# desktop app and the Android app both link it, so a change here is a change
# for them too.
emit client '^crates/nexapipe-(client|proto)/'

emit android '^(crates/nexapipe-(client|proto)/|ui-android/)'
emit desktop '^(crates/nexapipe-(client|proto)/|ui-desktop/)'

# The container image is built from the Dockerfiles at the root.
emit image '^(Dockerfile[^/]*|\.dockerignore$)'

# The desktop frontend's dependency tree. Its lockfile records each
# platform's native optional package, so it is what decides whether the
# release can install the frontend on that platform.
emit desktop_lockfile '^ui-desktop/package(-lock)?\.json$'

# What CodeQL reads: the Rust in crates/, the TypeScript in ui-desktop/ and
# the workflow files in .github/. A change to ui-android/ alone is Kotlin,
# which CodeQL analyses in its own job.
emit codeql '^(crates/|third_party/|ui-desktop/|\.github/)'
