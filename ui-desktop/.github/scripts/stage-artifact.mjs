// Collects the Tauri bundle output into a flat, publish-ready release-artifact/
// directory and picks out this platform's updater payload (with its .sig signature) so
// latest.json can be generated afterwards.
//
// Every file is renamed to the repository-wide rule
//
//   <product>-<version>-<platform>[-setup].<ext>
//
// because Tauri's own bundle names are not consistent across formats: the deb/dmg/NSIS
// installers use `nexa_0.2.0_amd64`, the rpm uses `nexa-0.2.0-1.x86_64`, and the macOS
// updater payload carries no arch at all. The server archives follow the same rule with
// the `nexapipe` product name and the cargo target triple as the platform, so one
// Release never mixes two spellings of one artifact.
//
// Environment variables:
//   MATRIX_OS      windows | macos | linux
//   MATRIX_ARCH    amd64 | arm64
//   MATRIX_TARGET  cargo target triple
//   TARGET_DIR     cargo target directory (usually src-tauri/target)
//   VERSION        version number (without the leading v)
//
// Written to $GITHUB_OUTPUT:
//   updater_file=   updater payload file name (inside release-artifact/)
//   renamed=       true/false, whether the payload was renamed away from the name Tauri
//                  gave it
//   resign_files=  newline-separated list of artifacts (inside release-artifact/) whose
//                  .sig was made for the old name and must be regenerated
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const os = process.env.MATRIX_OS ?? "";
const arch = process.env.MATRIX_ARCH ?? "";
const target = process.env.MATRIX_TARGET ?? "";
const version = process.env.VERSION ?? "";
const targetDir = process.env.TARGET_DIR ?? "src-tauri/target";
const outDir = "release-artifact";

// The updater signing key, as the workflow hands it to this job. It decides
// what a missing payload means: without a key there is no auto-update at all
// (a configuration), with a key every platform has to have one (a defect).
const signingKeyConfigured = Boolean((process.env.TAURI_SIGNING_PRIVATE_KEY ?? "").trim());

if (!os || !arch || !version) {
  console.error("::error::missing MATRIX_OS / MATRIX_ARCH / VERSION environment variables");
  process.exit(1);
}

// ---------------------------------------------------------------- helpers

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

function setOutput(key, value) {
  console.log(`output ${key}=${value}`);
  const file = process.env.GITHUB_OUTPUT;
  if (file) fs.appendFileSync(file, `${key}=${value}\n`);
}

// ---------------------------------------------------------------- canonical file names

// Product name of the GUI (tauri.conf.json productName). The server archives are named
// by the release workflow itself and keep "nexapipe"; everything here is the client app.
const product = (() => {
  try {
    return JSON.parse(fs.readFileSync("src-tauri/tauri.conf.json", "utf8")).productName || "nexa";
  } catch {
    console.warn("::warning::could not read productName from src-tauri/tauri.conf.json, falling back to 'nexa'");
    return "nexa";
  }
})();

// amd64/arm64 from the matrix, normalized to the CPU names used everywhere else in the
// repository (the cargo triples and the updater manifest keys).
const cpu = arch === "arm64" ? "aarch64" : "x86_64";
const platformSlug = `${os}-${cpu}`;
const assetBase = `${product}-${version}-${platformSlug}`;
console.log(`Canonical asset base: ${assetBase}`);

// Tauri bundle name -> canonical release asset name. Returns null for anything this
// script does not publish, so the two lists cannot drift apart silently.
function canonicalName(name) {
  const isSig = name.endsWith(".sig");
  const stem = isSig ? name.slice(0, -".sig".length) : name;
  // Longest suffix first: ".app.tar.gz" must win over ".tar.gz", "-setup.nsis.zip"
  // over ".zip".
  let out = null;
  if (stem.endsWith(".app.tar.gz")) out = `${assetBase}.app.tar.gz`;
  else if (stem.endsWith(".AppImage.tar.gz")) out = `${assetBase}.AppImage.tar.gz`;
  else if (stem.endsWith(".nsis.zip")) out = `${assetBase}-setup.nsis.zip`;
  else if (stem.endsWith("-setup.exe")) out = `${assetBase}-setup.exe`;
  else if (stem.endsWith(".AppImage")) out = `${assetBase}.AppImage`;
  else if (stem.endsWith(".dmg")) out = `${assetBase}.dmg`;
  else if (stem.endsWith(".deb")) out = `${assetBase}.deb`;
  else if (stem.endsWith(".rpm")) out = `${assetBase}.rpm`;
  return out === null ? null : isSig ? `${out}.sig` : out;
}

// ---------------------------------------------------------------- locate bundle dirs

// With --target, cargo puts artifacts in target/<triple>/release/; without it they land
// in target/release/. Probe both and use whichever one has a bundle.
const bundleRoots = [
  path.join(targetDir, target, "release", "bundle"),
  path.join(targetDir, "release", "bundle"),
].filter((p) => fs.existsSync(p));

if (bundleRoots.length === 0) {
  console.error(`::error::no bundle directory under ${targetDir}, the build probably failed.`);
  process.exit(1);
}

console.log("bundle directories:");
for (const root of bundleRoots) console.log(`  ${root}`);

// `nexa.app` is the macOS bundle directory; files inside it belong to the .app
// internals and must not be treated as standalone release assets (the real assets are
// .dmg and .app.tar.gz).
const isInsideAppBundle = (p) => /[\\/][^\\/]+\.app[\\/]/.test(p);

let bundleFiles = [];
for (const root of bundleRoots) {
  bundleFiles.push(...walkFiles(root));
}
bundleFiles = bundleFiles.filter((p) => !isInsideAppBundle(p));

if (bundleFiles.length === 0) {
  console.error("::error::the bundle directory contains no artifacts.");
  process.exit(1);
}

// ---------------------------------------------------------------- pick updater payload

const byName = (re) => bundleFiles.filter((p) => re.test(path.basename(p)));

// Only these file types belong in a Release. Without this filter, macOS jobs leak
// the DMG bundler's helper scripts (bundle_dmg.sh, template.applescript,
// eula-resources-template.xml, icon.icns) which Tauri writes next to the .dmg.
const PUBLISHABLE = [
  /\.dmg$/,
  /\.app\.tar\.gz(\.sig)?$/,
  /\.nsis\.zip(\.sig)?$/,
  /-setup\.exe(\.sig)?$/,
  /\.deb$/,
  /\.rpm$/,
  // The AppImage and its signature: the AppImage is the updater payload on
  // Linux (see below), so the signature has to travel with it.
  /\.AppImage(\.sig)?$/,
  /\.AppImage\.tar\.gz(\.sig)?$/,
];
const isPublishable = (name) => PUBLISHABLE.some((re) => re.test(name));
const filteredOut = bundleFiles.filter((p) => !isPublishable(path.basename(p)));
if (filteredOut.length > 0) {
  console.log("Not publishing (not a release asset):");
  for (const p of filteredOut) console.log(`  ${path.basename(p)}`);
}

// Tauri v2 updater payloads per platform:
//   windows  the NSIS `*-setup.exe` is itself the update bundle (`*.nsis.zip` in
//            v1Compatible mode)
//   macos    `<productName>.app.tar.gz`
//   linux    the `*.AppImage` itself
// Note: every regex is anchored with $ so `xxx.sig` is never matched by mistake.
//
// The Linux payload is the AppImage, not an archive of it: Tauri v2 signs the
// AppImage and the updater replaces that file, and a bundle that has no
// `.AppImage.tar.gz` (the v1-era form) still has to publish an update for
// Linux. The archive is still accepted when it is there, because a builder
// that produces it knows what it is doing.
let updaterSource = null;
if (os === "windows") {
  updaterSource = byName(/\.nsis\.zip$/)[0] ?? byName(/-setup\.exe$/)[0] ?? null;
} else if (os === "macos") {
  updaterSource = byName(/\.app\.tar\.gz$/)[0] ?? null;
} else if (os === "linux") {
  updaterSource = byName(/\.AppImage\.tar\.gz$/)[0] ?? byName(/\.AppImage$/)[0] ?? null;
}

// The payload gets the canonical name too. Tauri's macOS payload has no arch at all
// (the amd64 and arm64 jobs would clash), and the Windows/Linux ones spell the arch
// differently per bundle format, so in practice every payload is renamed here — and
// therefore has to be signed again, because minisign binds the signature to the file
// name.
let updaterName = null;
let renamed = false;
if (updaterSource) {
  const original = path.basename(updaterSource);
  updaterName = canonicalName(original);
  if (!updaterName) {
    console.error(`::error::cannot map updater payload ${original} to a canonical release name`);
    process.exit(1);
  }
  renamed = updaterName !== original;
}

// ---------------------------------------------------------------- copy artifacts

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });

const copied = new Map(); // destination file name -> source path
// Artifacts whose .sig was produced for the name Tauri gave them: after a rename the
// signature has to be regenerated (the workflow does it with `tauri signer sign`).
const resign = [];

for (const src of bundleFiles) {
  const name = path.basename(src);
  if (!isPublishable(name)) continue;
  const dst = canonicalName(name);
  if (!dst) {
    console.warn(`::warning::no canonical name for publishable artifact ${name}, skipping`);
    continue;
  }
  if (copied.has(dst) && copied.get(dst) !== src) {
    console.warn(`::warning::overwriting artifact with the same name: ${dst} (${copied.get(dst)} -> ${src})`);
  }
  copied.set(dst, src);
  if (dst !== name && !dst.endsWith(".sig") && fs.existsSync(`${src}.sig`)) resign.push(dst);
}

for (const [name, src] of copied) {
  if (name !== path.basename(src)) console.log(`renamed: ${path.basename(src)} -> ${name}`);
  fs.copyFileSync(src, path.join(outDir, name));
}

// ---------------------------------------------------------------- report

const written = fs.readdirSync(outDir).sort();
console.log(`\nStaged ${written.length} files into ${outDir}/:`);
for (const f of written) {
  const size = fs.statSync(path.join(outDir, f)).size;
  console.log(`  ${f}  (${(size / 1024 / 1024).toFixed(2)} MiB)`);
}

if (updaterSource) {
  const hasSig = fs.existsSync(path.join(outDir, `${updaterName}.sig`));
  console.log(`\nupdater payload: ${updaterName} (signature ${hasSig ? "generated" : "missing"})`);
  if (!hasSig) {
    if (signingKeyConfigured) {
      // The key is configured, so the artifact was supposed to be signed. It
      // was not, and an unsigned payload is an update nobody can install:
      // the updater refuses a file whose signature does not verify.
      console.error(
        `::error::the updater payload ${updaterName} carries no signature, but the updater signing key is configured: this platform would get no update.`,
      );
      process.exit(1);
    }
    console.log(
      "::warning::no updater signature was produced and no updater signing key is configured: this release has no auto-update for this platform.",
    );
  }
  setOutput("updater_file", hasSig ? updaterName : "");
} else {
  if (signingKeyConfigured) {
    console.error(
      "::error::no updater payload was found for this platform, but the updater signing key is configured: this platform would get no update.",
    );
    process.exit(1);
  }
  console.log(
    "\nNo updater payload and no updater signing key configured: this release has no auto-update for this platform.",
  );
  setOutput("updater_file", "");
}

setOutput("renamed", renamed ? "true" : "false");

// Multiline values need the random-delimiter form of $GITHUB_OUTPUT; the workflow reads
// them back with a `while read` loop.
const resignFile = process.env.GITHUB_OUTPUT;
if (resignFile) {
  const delimiter = `resign-${crypto.randomUUID()}`;
  fs.appendFileSync(resignFile, `resign_files<<${delimiter}\n${[...new Set(resign)].join("\n")}\n${delimiter}\n`);
}
if (resign.length > 0) {
  console.log(`\nSignatures to regenerate (file name changed): ${[...new Set(resign)].join(", ")}`);
}
