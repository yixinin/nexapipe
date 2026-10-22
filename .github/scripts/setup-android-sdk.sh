#!/usr/bin/env bash
# Install the Android SDK pieces the CI jobs need.
#
# Two callers, two needs: the Android job wants the platform, the build
# tools and the NDK, and CodeQL wants the platform and the build tools only
# — it compiles the Kotlin sources and never touches the native build.
#
# Not android-actions/setup-android: it installs "tools" by default, a
# package that has been pulled from the SDK repository and fails outright on
# current images.
#
# Environment:
#   ANDROID_PLATFORM  the platform to install, e.g. 37.0
#   BUILD_TOOLS       the build tools to install, e.g. 37.0.0
#   NDK_VERSION       the NDK to install when WITH_NDK is true
#   WITH_NDK          "true" to install the NDK as well

set -euo pipefail

PLATFORM="${ANDROID_PLATFORM:-37.0}"
BUILD_TOOLS="${BUILD_TOOLS:-37.0.0}"
NDK_VERSION="${NDK_VERSION:-29.0.14206865}"
WITH_NDK="${WITH_NDK:-false}"

SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/usr/local/lib/android/sdk}}"
export ANDROID_SDK_ROOT="$SDK" ANDROID_HOME="$SDK"
echo "ANDROID_SDK_ROOT=$SDK" >> "$GITHUB_ENV"
echo "ANDROID_HOME=$SDK" >> "$GITHUB_ENV"

if [ -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]; then
  SM="$SDK/cmdline-tools/latest/bin/sdkmanager"
else
  SM=$(ls -1 "$SDK"/cmdline-tools/*/bin/sdkmanager 2>/dev/null | sort -V | tail -n 1)
fi
[ -x "${SM:-}" ] || { echo "::error::sdkmanager not found under $SDK/cmdline-tools"; exit 1; }

yes | "$SM" --licenses > /dev/null 2>&1 || true

"$SM" --install "platforms;android-${PLATFORM}" "build-tools;${BUILD_TOOLS}"

if [ "$WITH_NDK" = true ]; then
  # An NDK that is already in the image is used as it is; only when there is
  # none is the pinned one installed. The pinned version is what the release
  # is built with, so a change to it is a change to this script.
  NDK_DIR=$(ls -1d "$SDK"/ndk/*/ 2>/dev/null | sort -V | tail -n 1 | sed 's:/$::' || true)
  if [ -z "${NDK_DIR:-}" ]; then
    "$SM" --install "ndk;${NDK_VERSION}" \
      || echo "::warning::pinned NDK unavailable, falling back to whatever is in the image"
    NDK_DIR=$(ls -1d "$SDK"/ndk/*/ 2>/dev/null | sort -V | tail -n 1 | sed 's:/$::' || true)
  fi
  [ -n "${NDK_DIR:-}" ] || { echo "::error::no NDK available"; exit 1; }
  echo "ANDROID_NDK_HOME=$NDK_DIR" >> "$GITHUB_ENV"
  echo "NDK: $NDK_DIR"
fi
