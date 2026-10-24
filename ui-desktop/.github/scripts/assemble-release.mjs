// release job: gather the artifacts of the 6 matrix jobs into a single release directory.
//   - merge latest-<os>-<arch>.json -> latest.json (one entry per platform)
//   - generate a sha256sum -c compatible SHA256SUMS.txt (LF line endings, no BOM)
//
// Environment variables:
//   DIST_DIR   directory the artifacts were downloaded and extracted into (default dist)
//   OUT_DIR    aggregated output directory (default release-artifacts)
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const distDir = process.env.DIST_DIR ?? "dist";
const outDir = process.env.OUT_DIR ?? "release-artifacts";

function walkFiles(dir) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(full));
    else out.push(full);
  }
  return out;
}

const allFiles = walkFiles(distDir);
if (allFiles.length === 0) {
  console.error(`::error::no files under ${distDir}, the build jobs may all have failed.`);
  process.exit(1);
}

// ------------------------------------------------------------ copy release assets

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });

const manifests = [];
const published = [];

for (const src of allFiles) {
  const name = path.basename(src);

  // Per-job temporary manifests: only used for merging, not published as assets
  if (/^latest-.+\.json$/.test(name)) {
    manifests.push(src);
    continue;
  }
  if (name === "latest.json") continue;

  const dst = path.join(outDir, name);
  if (fs.existsSync(dst)) {
    console.log(`::warning::duplicate asset name ${name}, the later one overwrites the earlier (from ${src})`);
  }
  fs.copyFileSync(src, dst);
  published.push(name);
}

// ------------------------------------------------------------ merge latest.json

if (manifests.length > 0) {
  const combined = { version: null, pub_date: null, platforms: {} };

  for (const file of manifests.sort()) {
    const json = JSON.parse(fs.readFileSync(file, "utf8"));
    if (!combined.version) {
      combined.version = json.version;
      combined.pub_date = json.pub_date;
    }
    Object.assign(combined.platforms, json.platforms);
  }

  const latestPath = path.join(outDir, "latest.json");
  fs.writeFileSync(latestPath, `${JSON.stringify(combined, null, 2)}\n`);
  published.push("latest.json");

  const expected = [
    "windows-x86_64",
    "windows-aarch64",
    "darwin-x86_64",
    "darwin-aarch64",
    "linux-x86_64",
    "linux-aarch64",
  ];
  const missing = expected.filter((p) => !(p in combined.platforms));
  console.log(`\nlatest.json covers ${Object.keys(combined.platforms).length}/6 platforms:`);
  for (const key of expected) {
    const entry = combined.platforms[key];
    console.log(`  ${entry ? "✓" : "✗"} ${key}${entry ? `  -> ${path.basename(entry.url)}` : ""}`);
  }
  if (missing.length > 0) {
    // A partial updater manifest is not a partial release: it is a release
    // in which the missing platforms get no update at all, and nothing in
    // the published artifacts says so. Linux lost its updater in v1.0.0
    // exactly this way, and the release went out green because a missing
    // platform was only a warning.
    console.error(
      `::error::latest.json is missing platforms: ${missing.join(", ")}. The release is not published: the missing platforms would get no update, and no artifact says so.`,
    );
    process.exit(1);
  }
} else {
  // No platform published a manifest. That is what a release without an
  // updater signing key looks like, and it is a configuration rather than a
  // defect — but it means the desktop app cannot update itself, so it is
  // worth a line in the log.
  console.log(
    "::warning::no updater manifest found: this release has no latest.json, so the desktop app cannot update itself.",
  );
}

// ------------------------------------------------------------ SHA256SUMS

// Deliberately joined with '\n' and written without a BOM so that sha256sum -c works
// out of the box on macOS / Linux.
const lines = [];
for (const name of published.slice().sort()) {
  const data = fs.readFileSync(path.join(outDir, name));
  const hash = crypto.createHash("sha256").update(data).digest("hex");
  lines.push(`${hash}  ${name}`);
}
fs.writeFileSync(path.join(outDir, "SHA256SUMS.txt"), `${lines.join("\n")}\n`);

console.log(`\nFinal release contains ${published.length + 1} files:`);
for (const name of published.slice().sort()) {
  const size = fs.statSync(path.join(outDir, name)).size;
  console.log(`  ${name}  (${(size / 1024 / 1024).toFixed(2)} MiB)`);
}
console.log("  SHA256SUMS.txt");
