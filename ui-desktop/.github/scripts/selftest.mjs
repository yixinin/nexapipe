#!/usr/bin/env node
// Self-test for the release pipeline.
//
//   node ui-desktop/.github/scripts/selftest.mjs
//
// Two halves:
//
//   1. The three release scripts (stage-artifact.mjs, latest-json.mjs,
//      assemble-release.mjs) are run over bundles built the way Tauri builds
//      them, and what they would publish is checked. This is the half that
//      catches a platform silently dropping out of the updater manifest.
//
//   2. The release workflow is read and the properties the scripts cannot
//      enforce themselves are checked: the order the assets are uploaded in,
//      the tag checks every versioned job makes, the image retag, the signing
//      of the checksum file, and the environment the publishing jobs run in.
//
// It replaces selftest.py, which is dead: it hardcodes a Windows path, it
// asserts a job graph that no longer exists, and nothing referenced it.
//
// No dependencies beyond node itself, so it runs in CI without an install
// step.
import assert from "node:assert";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const scriptDir = import.meta.dirname;
const repoRoot = path.resolve(scriptDir, "..", "..", "..");
const workflowPath = path.join(repoRoot, ".github", "workflows", "release.yml");

const VERSION = "1.0.0";
const PRODUCT = "nexa";

let failures = 0;
let checks = 0;

function check(label, ok, detail = "") {
  checks += 1;
  if (ok) {
    console.log(`PASS  ${label}${detail ? `  ${detail}` : ""}`);
  } else {
    failures += 1;
    console.log(`FAIL  ${label}${detail ? `  ${detail}` : ""}`);
  }
}

function section(title) {
  console.log(`\n=== ${title} ===`);
}

// ---------------------------------------------------------------- helpers

function run(script, cwd, env) {
  const res = spawnSync(process.execPath, [path.join(scriptDir, script)], {
    cwd,
    env: { ...process.env, ...env },
    encoding: "utf8",
  });
  return {
    code: res.status,
    out: `${res.stdout ?? ""}${res.stderr ?? ""}`,
    stdout: res.stdout ?? "",
  };
}

function writeFile(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, content);
}

// A minisign signature file is text; the content does not matter to the
// scripts, only that it exists next to the payload it belongs to.
function fakeSignature(name) {
  const body = crypto.createHash("sha256").update(name).digest("base64");
  return `untrusted comment: signature from minisign secret key\n${body}\ntrusted comment: filename: ${name}\n${body}\n`;
}

// ---------------------------------------------------------------- 1. the scripts

// The bundles Tauri produces, per platform. The names are the ones Tauri
// writes; stage-artifact.mjs renames them to the canonical release names.
//
// The Linux bundle has no `.AppImage.tar.gz`: Tauri v2 signs the AppImage
// itself and that is the file the updater replaces. The v1-era
// `.AppImage.tar.gz` is still accepted when it is there, but a release that
// only has the AppImage must still publish an updater payload for Linux.
const PLATFORMS = [
  {
    os: "windows",
    arch: "amd64",
    target: "x86_64-pc-windows-msvc",
    bundleDir: "nsis",
    files: ["nexa_0.2.0_x64-setup.exe", "nexa_0.2.0_x64-setup.exe.sig"],
    updater: `${PRODUCT}-${VERSION}-windows-x86_64-setup.exe`,
    renamed: false,
  },
  {
    os: "windows",
    arch: "arm64",
    target: "aarch64-pc-windows-msvc",
    bundleDir: "nsis",
    files: ["nexa_0.2.0_arm64-setup.exe", "nexa_0.2.0_arm64-setup.exe.sig"],
    updater: `${PRODUCT}-${VERSION}-windows-aarch64-setup.exe`,
    renamed: false,
  },
  {
    os: "macos",
    arch: "amd64",
    target: "x86_64-apple-darwin",
    bundleDir: "dmg",
    files: [
      "nexa.app.tar.gz",
      "nexa.app.tar.gz.sig",
      "nexa_0.2.0_x64.dmg",
      // The DMG bundler writes its helper scripts next to the image; they are
      // not release assets.
      "bundle_dmg.sh",
      "template.applescript",
      "eula-resources.template.xml",
      "icon.icns",
    ],
    updater: `${PRODUCT}-${VERSION}-macos-x86_64.app.tar.gz`,
    renamed: true,
  },
  {
    os: "macos",
    arch: "arm64",
    target: "aarch64-apple-darwin",
    bundleDir: "dmg",
    files: ["nexa.app.tar.gz", "nexa.app.tar.gz.sig", "nexa_0.2.0_aarch64.dmg"],
    updater: `${PRODUCT}-${VERSION}-macos-aarch64.app.tar.gz`,
    renamed: true,
  },
  {
    os: "linux",
    arch: "amd64",
    target: "x86_64-unknown-linux-gnu",
    bundleDir: "appimage",
    files: [
      "nexa_0.2.0_amd64.AppImage",
      "nexa_0.2.0_amd64.AppImage.sig",
      "nexa_0.2.0_amd64.deb",
      "nexa_0.2.0_amd64.deb.sig",
      "nexa-0.2.0-1.x86_64.rpm",
      "nexa-0.2.0-1.x86_64.rpm.sig",
    ],
    updater: `${PRODUCT}-${VERSION}-linux-x86_64.AppImage`,
    renamed: true,
  },
  {
    os: "linux",
    arch: "arm64",
    target: "aarch64-unknown-linux-gnu",
    bundleDir: "appimage",
    files: [
      "nexa_0.2.0_arm64.AppImage",
      "nexa_0.2.0_arm64.AppImage.sig",
      "nexa_0.2.0_arm64.deb",
      "nexa_0.2.0_arm64.deb.sig",
      "nexa-0.2.0-1.aarch64.rpm",
      "nexa-0.2.0-1.aarch64.rpm.sig",
    ],
    updater: `${PRODUCT}-${VERSION}-linux-aarch64.AppImage`,
    renamed: true,
  },
];

// Builds one platform's fake bundle and returns the work directory.
function makeBundle(root, platform, { extraFiles = [], skipFiles = [] } = {}) {
  const work = path.join(root, `${platform.os}-${platform.arch}`);
  fs.mkdirSync(work, { recursive: true });
  // stage-artifact.mjs reads the product name out of the Tauri config.
  const tauriConf = JSON.parse(
    fs.readFileSync(path.join(repoRoot, "ui-desktop", "src-tauri", "tauri.conf.json"), "utf8"),
  );
  writeFile(path.join(work, "src-tauri", "tauri.conf.json"), `${JSON.stringify(tauriConf, null, 2)}\n`);

  const bundle = path.join(work, "src-tauri", "target", platform.target, "release", "bundle", platform.bundleDir);
  fs.mkdirSync(bundle, { recursive: true });
  const names = [...platform.files, ...extraFiles].filter((f) => !skipFiles.includes(f));
  for (const name of names) {
    writeFile(path.join(bundle, name), `payload-${name}`);
  }
  if (platform.os === "macos") {
    // The .app directory: its contents belong to the application, not to the
    // release.
    const inner = path.join(bundle, "..", "macos", "nexa.app", "Contents", "MacOS");
    writeFile(path.join(inner, "nexa"), "binary");
  }
  const output = path.join(work, "github_output.txt");
  fs.writeFileSync(output, "");
  return { work, output, bundle };
}

// The scripts write their outputs in the two forms $GITHUB_OUTPUT accepts:
// `key=value`, and `key<<delimiter` for a value that spans several lines.
function readOutputs(outputFile) {
  const out = {};
  const lines = fs.readFileSync(outputFile, "utf8").split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const heredoc = line.match(/^([A-Za-z0-9_]+)<<(.+)$/);
    if (heredoc) {
      const body = [];
      i += 1;
      while (i < lines.length && lines[i] !== heredoc[2]) {
        body.push(lines[i]);
        i += 1;
      }
      out[heredoc[1]] = body.join("\n");
      continue;
    }
    const idx = line.indexOf("=");
    if (idx > 0) out[line.slice(0, idx)] = line.slice(idx + 1);
  }
  return out;
}

// The re-sign step of the workflow: a minisign signature is bound to the name
// of the file it was made for, so every artifact the staging renamed is
// signed again under its new name.
function resign(work, outputFile) {
  const outputs = readOutputs(outputFile);
  const list = outputs.resign_files ?? "";
  for (const name of list.split("\n").filter(Boolean)) {
    fs.rmSync(path.join(work, "release-artifact", `${name}.sig`), { force: true });
    writeFile(path.join(work, "release-artifact", `${name}.sig`), fakeSignature(name));
  }
  return outputs;
}

function stageAndGenerate(platform, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexapipe-selftest-"));
  const { work, output } = makeBundle(root, platform, options);
  const env = {
    MATRIX_OS: platform.os,
    MATRIX_ARCH: platform.arch,
    MATRIX_TARGET: platform.target,
    TARGET_DIR: "src-tauri/target",
    VERSION,
    GITHUB_OUTPUT: output,
    GITHUB_REPOSITORY: "open-nexa/nexapipe",
    GITHUB_REF_NAME: `v${VERSION}`,
  };
  const staged = run("stage-artifact.mjs", work, env);
  const outputs = staged.code === 0 ? resign(work, output) : {};
  let manifest = null;
  if (staged.code === 0) {
    const generated = run("latest-json.mjs", work, {
      ...env,
      UPDATER_FILE: outputs.updater_file ?? "",
    });
    const manifestPath = path.join(work, "release-artifact", `latest-${platform.os}-${platform.arch}.json`);
    if (generated.code === 0 && fs.existsSync(manifestPath)) {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    }
    outputs.manifestRun = generated;
  }
  return { root, work, output, env, staged, outputs, manifest };
}

// ---------------------------------------------------------------- 2. the workflow

const workflowText = fs.readFileSync(workflowPath, "utf8");
const workflowLines = workflowText.split("\n");

// The body of one job: from `  <name>:` to the next job header.
function jobBlock(name) {
  const start = workflowLines.findIndex((l) => l === `  ${name}:`);
  if (start < 0) return null;
  let end = workflowLines.length;
  for (let i = start + 1; i < workflowLines.length; i += 1) {
    if (/^ {2}[A-Za-z0-9_-]+:/.test(workflowLines[i])) {
      end = i;
      break;
    }
  }
  return workflowLines.slice(start, end).join("\n");
}

// The body of one step of a job: from `      - name: <name>` to the next step.
function stepBlock(jobName, stepName) {
  const block = jobBlock(jobName);
  if (!block) return null;
  const lines = block.split("\n");
  const start = lines.findIndex((l) => l.trim() === `- name: ${stepName}`);
  if (start < 0) return null;
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^ {6}- /.test(lines[i])) {
      end = i;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

// ---------------------------------------------------------------- the tests

section("1. stage-artifact.mjs picks an updater payload for every platform");

for (const platform of PLATFORMS) {
  const run = stageAndGenerate(platform);
  const { outputs } = run;
  check(
    `stage-artifact [${platform.os}-${platform.arch}] succeeds`,
    run.staged.code === 0,
    run.staged.code === 0 ? "" : run.staged.out.split("\n").filter(Boolean).slice(-1)[0],
  );
  check(
    `updater payload [${platform.os}-${platform.arch}]`,
    outputs.updater_file === platform.updater,
    `got=${JSON.stringify(outputs.updater_file)} want=${JSON.stringify(platform.updater)}`,
  );
  check(
    `updater payload exists [${platform.os}-${platform.arch}]`,
    fs.existsSync(path.join(run.work, "release-artifact", platform.updater)),
  );
  check(
    `updater manifest generated [${platform.os}-${platform.arch}]`,
    run.manifest !== null,
  );
  if (run.manifest) {
    const key = Object.keys(run.manifest.platforms)[0];
    const entry = run.manifest.platforms[key];
    check(
      `manifest url names the payload [${platform.os}-${platform.arch}]`,
      entry.url.endsWith(`/${platform.updater}`),
      entry.url,
    );
    check(
      `manifest signature is the one over that payload [${platform.os}-${platform.arch}]`,
      entry.signature.includes(`filename: ${platform.updater}`),
      entry.signature,
    );
  }
  // The contents of the .app directory belong to the application, not to the
  // release.
  const leaked = fs
    .readdirSync(path.join(run.work, "release-artifact"))
    .filter((n) => n === "nexa" || n.endsWith(".app"));
  check(`no .app internals leaked [${platform.os}-${platform.arch}]`, leaked.length === 0, JSON.stringify(leaked));
  fs.rmSync(run.root, { recursive: true, force: true });
}

section("2. the Linux updater payload");

{
  // The v1-era archive, when it is there, is still preferred.
  const withArchive = stageAndGenerate(PLATFORMS[4], {
    extraFiles: ["nexa_0.2.0_amd64.AppImage.tar.gz", "nexa_0.2.0_amd64.AppImage.tar.gz.sig"],
  });
  check(
    "a .AppImage.tar.gz is preferred when the bundle has one",
    withArchive.outputs.updater_file === `${PRODUCT}-${VERSION}-linux-x86_64.AppImage.tar.gz`,
    `got=${JSON.stringify(withArchive.outputs.updater_file)}`,
  );
  fs.rmSync(withArchive.root, { recursive: true, force: true });

  // And the plain AppImage is the payload when it is not: Tauri v2 signs the
  // AppImage itself, and the updater replaces that file.
  const appImageOnly = stageAndGenerate(PLATFORMS[4]);
  check(
    "a .AppImage alone is the Linux updater payload",
    appImageOnly.outputs.updater_file === `${PRODUCT}-${VERSION}-linux-x86_64.AppImage`,
    `got=${JSON.stringify(appImageOnly.outputs.updater_file)}`,
  );
  check(
    "the Linux updater payload has a signature",
    fs.existsSync(path.join(appImageOnly.work, "release-artifact", `${PRODUCT}-${VERSION}-linux-x86_64.AppImage.sig`)),
  );
  fs.rmSync(appImageOnly.root, { recursive: true, force: true });
}

section("3. the updater manifest refuses to be silently skipped");

{
  // The signing key is configured, so every platform has to publish a payload.
  // A platform that does not is a defect, not a configuration.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexapipe-selftest-"));
  const work = root;
  writeFile(path.join(work, "release-artifact", "nexa-1.0.0-linux-x86_64.AppImage"), "payload");
  const res = run("latest-json.mjs", work, {
    MATRIX_OS: "linux",
    MATRIX_ARCH: "amd64",
    VERSION,
    UPDATER_FILE: "",
    TAURI_SIGNING_PRIVATE_KEY: "a-private-key",
    GITHUB_REPOSITORY: "open-nexa/nexapipe",
    GITHUB_REF_NAME: `v${VERSION}`,
  });
  check(
    "a missing payload with a configured signing key fails",
    res.code !== 0,
    `exit=${res.code}`,
  );
  fs.rmSync(root, { recursive: true, force: true });

  // Without a key there is no auto-update at all, which is a configuration
  // and not a defect.
  const root2 = fs.mkdtempSync(path.join(os.tmpdir(), "nexapipe-selftest-"));
  const res2 = run("latest-json.mjs", root2, {
    MATRIX_OS: "linux",
    MATRIX_ARCH: "amd64",
    VERSION,
    UPDATER_FILE: "",
    TAURI_SIGNING_PRIVATE_KEY: "",
    GITHUB_REPOSITORY: "open-nexa/nexapipe",
    GITHUB_REF_NAME: `v${VERSION}`,
  });
  check(
    "a missing payload without a signing key is a configuration, not a failure",
    res2.code === 0,
    `exit=${res2.code}`,
  );
  fs.rmSync(root2, { recursive: true, force: true });
}

section("4. assemble-release.mjs refuses to publish a partial updater manifest");

function assemble(platforms) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "nexapipe-selftest-"));
  const dist = path.join(root, "dist");
  fs.mkdirSync(dist, { recursive: true });
  for (const platform of platforms) {
    const staged = stageAndGenerate(platform);
    const stagedDir = path.join(staged.work, "release-artifact");
    for (const name of fs.readdirSync(stagedDir)) {
      fs.copyFileSync(path.join(stagedDir, name), path.join(dist, name));
    }
    fs.rmSync(staged.root, { recursive: true, force: true });
  }
  const res = run("assemble-release.mjs", root, { DIST_DIR: "dist", OUT_DIR: "release-artifacts" });
  const outDir = path.join(root, "release-artifacts");
  let latest = null;
  const latestPath = path.join(outDir, "latest.json");
  if (fs.existsSync(latestPath)) {
    latest = JSON.parse(fs.readFileSync(latestPath, "utf8"));
  }
  return { root, res, outDir, latest };
}

{
  const complete = assemble(PLATFORMS);
  check("assemble-release succeeds with all six platforms", complete.res.code === 0, complete.res.out.slice(-400));
  const keys = complete.latest ? Object.keys(complete.latest.platforms).sort() : [];
  check(
    "latest.json carries all six platforms",
    JSON.stringify(keys) ===
      JSON.stringify([
        "darwin-aarch64",
        "darwin-x86_64",
        "linux-aarch64",
        "linux-x86_64",
        "windows-aarch64",
        "windows-x86_64",
      ]),
    JSON.stringify(keys),
  );
  if (complete.latest) {
    const names = new Set(fs.readdirSync(complete.outDir));
    const dangling = Object.values(complete.latest.platforms)
      .map((p) => p.url.split("/").pop())
      .filter((n) => !names.has(n));
    check("every manifest url names an asset that is published", dangling.length === 0, JSON.stringify(dangling));
  }
  fs.rmSync(complete.root, { recursive: true, force: true });

  // One platform short: the release must not go out. A partial manifest is
  // how Linux lost its updater in v1.0.0.
  const partial = assemble(PLATFORMS.slice(0, 5));
  check(
    "assemble-release fails when a platform is missing",
    partial.res.code !== 0,
    `exit=${partial.res.code}`,
  );
  fs.rmSync(partial.root, { recursive: true, force: true });
}

section("5. the release workflow");

{
  // -- the assets are uploaded in an order that never points at a missing file
  const publish = stepBlock("release", "Publish release");
  check("the release job has a publish step", publish !== null);
  if (publish) {
    check(
      "the publish step does not upload a glob",
      !/gh release (create|upload)[^\n]*dist\/\*/.test(publish),
    );
    check(
      "the publish step separates the index files from the payloads",
      /latest\.json/.test(publish) && /SHA256SUMS\.txt/.test(publish),
    );
    // The upload commands themselves, not the prose around them: the index
    // files have to be uploaded after the payloads they name.
    const uploadLines = publish
      .split("\n")
      .map((line, i) => [i, line])
      .filter(([, line]) => /gh release upload/.test(line));
    const payloadUploads = uploadLines.filter(([, line]) => /PAYLOAD_FILES/.test(line));
    const indexUploads = uploadLines.filter(([, line]) => /INDEX_FILES/.test(line));
    check(
      "the index files are uploaded after the payloads",
      payloadUploads.length > 0 &&
        indexUploads.length > 0 &&
        indexUploads[0][0] > payloadUploads[0][0],
      `payload=${payloadUploads[0]?.[0]} index=${indexUploads[0]?.[0]}`,
    );
    const createAt = publish.split("\n").findIndex((l) => /gh release create/.test(l));
    const createLine = publish.split("\n")[createAt] ?? "";
    check(
      "the release is created with the payloads, not with the index files",
      /PAYLOAD_FILES/.test(createLine) && !/INDEX_FILES/.test(createLine),
      createLine.trim(),
    );
    const clobberUploads = uploadLines.filter(([, line]) => /--clobber/.test(line));
    check(
      "the re-run path uploads in the same order",
      clobberUploads.length >= 2 &&
        /PAYLOAD_FILES/.test(clobberUploads[0][1]) &&
        /INDEX_FILES/.test(clobberUploads[1][1]) &&
        clobberUploads[1][0] > clobberUploads[0][0],
      clobberUploads.map(([, line]) => line.trim()).join(" | "),
    );
  }

  // -- every versioned job refuses a tag that is not the version
  for (const job of ["build", "build-desktop", "build-apk"]) {
    const block = jobBlock(job);
    check(`the ${job} job exists`, block !== null);
    const step = stepBlock(job, "Verify the release tag");
    check(`the ${job} job verifies the release tag`, step !== null);
    if (step) {
      check(`the ${job} tag check fails the job`, /exit 1/.test(step));
      check(`the ${job} tag check compares the tag with the workspace version`, /version/.test(step));
      check(`the ${job} tag check requires an annotated tag`, /cat-file/.test(step));
    }
  }

  // -- the image is not tagged "latest" before the release exists
  const publishImage = jobBlock("publish-image");
  check("the publish-image job exists", publishImage !== null);
  if (publishImage) {
    check(
      "publish-image does not move the latest tag",
      !/nexapipe:latest/.test(publishImage),
    );
  }
  const releaseBlock = jobBlock("release");
  check("the release job exists", releaseBlock !== null);
  if (releaseBlock && publishImage) {
    const retagAt = releaseBlock.search(/nexapipe:latest/);
    const createAt = releaseBlock.search(/gh release create/);
    check(
      "the latest tag is moved after the release is created",
      retagAt > 0 && createAt > 0 && retagAt > createAt,
      `create=${createAt} retag=${retagAt}`,
    );
  }

  // -- the checksum file is signed
  if (releaseBlock) {
    check(
      "the release job signs SHA256SUMS.txt",
      /SHA256SUMS\.txt/.test(releaseBlock) && /signer sign/.test(releaseBlock),
    );
    check(
      "the signed checksum file is published",
      /SHA256SUMS\.txt\.sig/.test(releaseBlock),
    );
  }

  // -- the publishing jobs run in an environment a repository can gate
  for (const job of ["build-desktop", "build-apk", "build-image", "publish-image", "release"]) {
    const block = jobBlock(job);
    check(`the ${job} job runs in the release environment`, block !== null && /environment: release/.test(block));
  }

  // -- the image digest is visible to a user
  if (releaseBlock) {
    check(
      "the release notes carry the image digest",
      /needs\.publish-image\.outputs\.digest/.test(releaseBlock),
    );
  }
}

// ---------------------------------------------------------------- summary

console.log(`\n${"=".repeat(60)}`);
console.log(failures === 0 ? `all ${checks} checks passed` : `${failures} of ${checks} checks FAILED`);
process.exit(failures === 0 ? 0 : 1);
