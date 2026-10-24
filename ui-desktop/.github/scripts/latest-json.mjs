// Generates a single-platform updater manifest, latest-<os>-<arch>.json, for the
// current platform/arch.
// Each of the 6 jobs emits one; the release job merges them into the final latest.json.
//
// See https://v2.tauri.app/plugin/updater/ for the Tauri updater manifest structure
//   { version, pub_date, platforms: { "<target>": { signature, url } } }
//
// Environment variables:
//   MATRIX_OS / MATRIX_ARCH   platform and arch
//   VERSION                   version number (without the leading v)
//   UPDATER_FILE              payload file name under release-artifact/ (skipped if empty)
//   GITHUB_REPOSITORY         owner/repo
//   GITHUB_REF_NAME           tag, e.g. v0.2.0
import fs from "node:fs";
import path from "node:path";

const os = process.env.MATRIX_OS ?? "";
const arch = process.env.MATRIX_ARCH ?? "";
const version = process.env.VERSION ?? "";
const updaterFile = process.env.UPDATER_FILE ?? "";
const repository = process.env.GITHUB_REPOSITORY ?? "";
// TAG_NAME (set by the release workflow) takes precedence over GITHUB_REF_NAME so
// a workflow_dispatch re-run of an existing tag still builds asset URLs pointing
// at the tag instead of at the branch the dispatch ran on.
const tag = process.env.TAG_NAME ?? process.env.GITHUB_REF_NAME ?? "";
const outDir = "release-artifact";

if (!updaterFile) {
  // No payload for this platform. Whether that is a defect or a
  // configuration depends on the signing key: with a key configured, every
  // platform has to publish an update payload, so a platform without one is
  // a broken release. Without a key there is no auto-update at all, which is
  // a configuration somebody chose.
  if ((process.env.TAURI_SIGNING_PRIVATE_KEY ?? "").trim()) {
    console.error(
      `::error::no updater payload was staged for ${os}-${arch}, but the updater signing key is configured: this platform would get no update.`,
    );
    process.exit(1);
  }
  console.log("No updater payload and no updater signing key configured: this release has no auto-update.");
  process.exit(0);
}

// Tauri target triple naming: x86_64 / aarch64
const cpu = arch === "arm64" ? "aarch64" : "x86_64";
const platformKey = {
  windows: `windows-${cpu}`,
  macos: `darwin-${cpu}`,
  linux: `linux-${cpu}`,
}[os];

if (!platformKey) {
  console.error(`::error::unknown platform: ${os}`);
  process.exit(1);
}

const sigPath = path.join(outDir, `${updaterFile}.sig`);
if (!fs.existsSync(sigPath)) {
  console.error(`::error::signature file ${sigPath} not found, cannot generate latest.json.`);
  process.exit(1);
}

const manifest = {
  version,
  pub_date: new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z"),
  platforms: {
    [platformKey]: {
      // The .sig file holds the complete signature: put it in verbatim, without any
      // cleanup or newline stripping.
      signature: fs.readFileSync(sigPath, "utf8").trim(),
      // The updater downloads from the Release assets; the asset name must match exactly.
      url: `https://github.com/${repository}/releases/download/${tag}/${updaterFile}`,
    },
  },
};

const outPath = path.join(outDir, `latest-${os}-${arch}.json`);
fs.writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`);

console.log(`Generated ${outPath}:`);
console.log(fs.readFileSync(outPath, "utf8"));
