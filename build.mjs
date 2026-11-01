#!/usr/bin/env node

// Builds, tests and checks simple-ca.
// Usage: ./build.mjs [build|trust|test|check|clean|assets] [<goos>/<goarch>]
//
// The build action writes simple-ca, request-cert, the Go client of the signing API in
// cmd/request-cert, and on Linux simple-ca-trust of cmd/simple-ca-trust. The platform defaults
// to the host's. Naming one builds for it instead, writing simple-ca-<goos>-<goarch> and
// request-cert-<goos>-<goarch>, and for linux simple-ca-trust-linux-<goarch>. Releases are made by
// release.mjs.
//
// The trust action writes simple-ca-trust for the host, or simple-ca-trust-<goos>-<goarch> for
// the platform named: cmd/simple-ca-trust with go for linux, on any host; trust/macos with swift
// for darwin and trust/windows with dotnet for windows, each on a host of its platform only, and
// skipped elsewhere.
//
// The assets action downloads the browser files of serve-markdown's page, for the version of
// serve-markdown in go.mod, from its GitHub release into assets/markdown, which serve embeds
// for its /help/ and /docs/ pages. build, test and check download them first when assets/markdown holds
// another version, and go on without them, warning, when the download fails.

import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const usage = "usage: ./build.mjs [build|trust|test|check|clean|assets] [<goos>/<goarch>]";
const root = dirname(fileURLToPath(import.meta.url));
const [action = "build", platform = ""] = process.argv.slice(2);
const markdownAssets = join(root, "assets", "markdown");
const versionFile = join(markdownAssets, ".version");
const requiredTag = readFileSync(join(root, "go.mod"), "utf8")
  .match(/^\s*github\.com\/skoszewski\/serve-markdown\/v3 (v\S+)/m)?.[1] ?? "";

/**
 * Runs a command in the repository and returns what it wrote to stdout; the command's failure
 * ends the build with its exit status.
 */
function run(command, args, { env = process.env, capture = false } = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    env,
    stdio: capture ? ["inherit", "pipe", "inherit"] : "inherit",
    encoding: "utf8",
  });
  if (result.error) {
    console.error(`${command}: ${result.error.message}`);
    process.exit(1);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
  return result.stdout ?? "";
}

/**
 * Downloads the serve-markdown-assets archive of the serve-markdown version go.mod requires and
 * unpacks it into assets/markdown, replacing what it held but .gitkeep; throws when that fails.
 */
async function fetchMarkdownAssets() {
  if (requiredTag === "") {
    throw new Error("go.mod requires no github.com/skoszewski/serve-markdown/v3");
  }
  const tag = requiredTag;
  const url = `https://github.com/skoszewski/serve-markdown/releases/download/${tag}/` +
    `serve-markdown-assets-${tag.slice(1)}.tar.gz`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url}: ${response.status} ${response.statusText}`);
  }
  const scratch = mkdtempSync(join(tmpdir(), "simple-ca-assets-"));
  try {
    const archive = join(scratch, "assets.tar.gz");
    writeFileSync(archive, Buffer.from(await response.arrayBuffer()));
    for (const name of readdirSync(markdownAssets)) {
      if (name !== ".gitkeep") {
        rmSync(join(markdownAssets, name), { recursive: true, force: true });
      }
    }
    run("tar", ["-xzf", archive, "-C", markdownAssets]);
    writeFileSync(versionFile, `${tag}\n`);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  console.log(`assets/markdown: serve-markdown ${tag}`);
}

const env = { ...process.env, CGO_ENABLED: "0" };

if (!["build", "trust", "test", "check", "clean", "assets"].includes(action)) {
  console.error(usage);
  process.exit(2);
}

// The executables are named after their program, with -<goos>-<goarch> for a platform named, and
// the suffix Go gives executables of the target, .exe on Windows.
let nameSuffix = "";
if (action === "build" && platform === "") {
  nameSuffix = run("go", ["env", "GOEXE"], { env, capture: true }).trim();
}

if (platform !== "") {
  const [goos, goarch, ...rest] = platform.split("/");
  if (!goos || !goarch || rest.length > 0) {
    console.error("platform must be given as <goos>/<goarch>, e.g. linux/amd64");
    process.exit(2);
  }
  env.GOOS = goos;
  env.GOARCH = goarch;
  nameSuffix = `-${goos}-${goarch}${goos === "windows" ? ".exe" : ""}`;
}

// The page's browser files are fetched again once go.mod requires another serve-markdown.
if (["build", "test", "check"].includes(action)) {
  let held = "";
  try {
    held = readFileSync(versionFile, "utf8").trim();
  } catch {}
  if (requiredTag !== held) {
    try {
      await fetchMarkdownAssets();
    } catch (error) {
      console.error(`warning: ${error.message}; simple-ca is built without the /help/ and /docs/ pages`);
    }
  }
}

switch (action) {
  case "assets":
    try {
      await fetchMarkdownAssets();
    } catch (error) {
      console.error(error.message);
      process.exit(1);
    }
    break;
  case "build":
    run("go", ["build", "-o", `simple-ca${nameSuffix}`, "."], { env });
    run("go", ["build", "-o", `request-cert${nameSuffix}`, "./cmd/request-cert"], { env });
    if (platform !== "" ? env.GOOS === "linux" : process.platform === "linux") {
      run("go", ["build", "-o", `simple-ca-trust${nameSuffix}`, "./cmd/simple-ca-trust"], { env });
    }
    break;
  case "trust": {
    // The target is the platform named, else the host; the Swift and .NET versions are built only
    // on a host of their own platform, the Go version on any host.
    const host = { darwin: "darwin", linux: "linux", win32: "windows" }[process.platform] ?? process.platform;
    const goos = env.GOOS ?? host;
    const goarch = env.GOARCH ?? { x64: "amd64", arm64: "arm64" }[process.arch] ?? process.arch;
    const name = platform === "" ? "simple-ca-trust" : `simple-ca-trust-${goos}-${goarch}`;
    if (goos === "linux") {
      run("go", ["build", "-o", name, "./cmd/simple-ca-trust"], { env });
    } else if (goos === "darwin" && host === "darwin") {
      const macos = join(root, "trust", "macos");
      const arch = ["--arch", { amd64: "x86_64", arm64: "arm64" }[goarch] ?? goarch];
      run("swift", ["build", "-c", "release", "--package-path", macos, ...arch]);
      const bin = run("swift", ["build", "-c", "release", "--package-path", macos, ...arch, "--show-bin-path"],
        { capture: true }).trim();
      copyFileSync(join(bin, "simple-ca-trust"), join(root, name));
    } else if (goos === "windows" && host === "windows") {
      const out = join(root, "build", `trust-windows-${goarch}`);
      run("dotnet", ["publish", join(root, "trust", "windows"), "-c", "Release",
        "-r", `win-${{ amd64: "x64", arm64: "arm64" }[goarch] ?? goarch}`, "-o", out]);
      copyFileSync(join(out, "simple-ca-trust.exe"), join(root, `${name}.exe`));
    } else if (goos === "darwin" || goos === "windows") {
      console.error(`note: simple-ca-trust for ${goos} is built on ${goos} only; skipped`);
    } else {
      console.error(`note: simple-ca-trust has no version for ${goos}; skipped`);
    }
    break;
  }
  case "test":
    run("go", ["test", "./..."], { env });
    break;
  case "check": {
    const unformatted = run("gofmt", ["-l", "."], { capture: true }).trim();
    if (unformatted !== "") {
      console.error(`these files are not gofmt clean:\n${unformatted}`);
      process.exit(1);
    }
    run("go", ["vet", "./..."], { env });
    run("go", ["test", "./..."], { env });
    break;
  }
  case "clean":
    for (const name of readdirSync(root)) {
      if (["simple-ca", "request-cert"].some((program) =>
        name === program || name === `${program}.exe` || name.startsWith(`${program}-`))) {
        rmSync(`${root}/${name}`, { force: true });
      }
    }
    rmSync(`${root}/build`, { recursive: true, force: true });
    rmSync(`${root}/dist`, { recursive: true, force: true });
    for (const dir of ["trust/macos/.build", "trust/windows/bin", "trust/windows/obj"]) {
      rmSync(join(root, dir), { recursive: true, force: true });
    }
    break;
}
