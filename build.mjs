#!/usr/bin/env node

// Builds, tests and checks simple-ca.
// Usage: ./build.mjs [build|trust|test|check|clean|assets] [--self-contained] [<goos>/<goarch>]
//        ./build.mjs docker [--registry REGISTRY] [--push] [<goos>/<goarch>]
//        ./build.mjs deb
//        ./build.mjs dist [--dpkg]
//
// The executables are written to bin/, which clean removes. The build action writes simple-ca,
// request-cert, the Go client of the signing API in cmd/request-cert, token-setup, which exchanges
// a setup code, in cmd/token-setup, request-token, the client of /api/federation-token and of the
// clouds, in cmd/request-token, simple-ca-wif of cmd/simple-ca-wif, and on Linux simple-ca-trust of
// cmd/simple-ca-trust. The platform defaults to the host's. Naming one builds for it instead,
// writing simple-ca-<goos>-<goarch>, request-cert-<goos>-<goarch>, token-setup-<goos>-<goarch>,
// request-token-<goos>-<goarch> and simple-ca-wif-<goos>-<goarch>, and for linux
// simple-ca-trust-linux-<goarch>. While the newest CHANGELOG.md entry is not tagged, the Go
// programs report its release candidate, vX.Y.Z-rc, as their version. Releases are made by
// release.mjs.
//
// The trust action writes simple-ca-trust for the host, or simple-ca-trust-<goos>-<goarch> for
// the platform named: cmd/simple-ca-trust with go for linux and trust/windows with dotnet for
// windows, on any host; trust/macos with swift for darwin, on macOS only, and skipped elsewhere.
// For windows it writes the project file trust/windows/simple-ca-trust.csproj, for a single
// simple-ca-trust.exe running on the installed .NET runtime, or carrying the runtime with
// --self-contained; its version is dev, or the InformationalVersion environment variable.
//
// The docker action builds the image of the Dockerfile with docker buildx, for the platform named
// or the host's, as simple-ca:<version>, the version of the newest CHANGELOG.md entry, and
// simple-ca:latest, below the registry --registry names, else SIMPLE_CA_REGISTRY when it is set,
// and pushes it with --push.
//
// The deb action builds the Debian package of debian-package/ with docker buildx, for the platform
// of the Docker host, compiling the programs in the image of debian-package/Dockerfile, and writes
// simple-ca_<version>_<arch>.deb to dist/. Its version is X.Y.Z-1 for the newest CHANGELOG.md
// entry X.Y.Z, or X.Y.Z-N for an entry X.Y.Z-N, with the programs of vX.Y.Z, and X.Y.Z~rc-N
// while vX.Y.Z is not tagged; debian-package/debian/changelog is written from the entry. It downloads the browser files of serve-markdown's page first when assets/markdown
// holds another version, and fails when that fails.
//
// The dist action makes the files of an internal release in dist/: the archives the GitHub
// workflow builds, simple-ca-X.Y.Z-<goos>-<goarch>.tar.gz, .zip for windows, of linux, darwin and
// windows for amd64 and arm64, with the programs versioned vX.Y.Z of the newest CHANGELOG.md
// entry. It refuses uncommitted changes and an entry that no commit has the summary line of, so
// release.mjs --no-tag releases the entry first. A platform whose simple-ca-trust the host cannot
// build is skipped: darwin needs macOS with swift, windows dotnet. With --dpkg it also builds the
// Debian package X.Y.Z-1 for the platform of the container engine, with the container CLI on
// macOS when it is installed, else with docker buildx.
//
// The assets action downloads the browser files of serve-markdown's page, for the version of
// serve-markdown in go.mod, from its GitHub release into assets/markdown, which serve embeds
// for its /help/ and /docs/ pages. build, test and check download them first when assets/markdown holds
// another version, and go on without them, warning, when the download fails.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const usage = "usage: ./build.mjs [build|trust|test|check|clean|assets] [--self-contained] [<goos>/<goarch>]\n" +
  "       ./build.mjs docker [--registry REGISTRY] [--push] [<goos>/<goarch>]\n" +
  "       ./build.mjs deb\n" +
  "       ./build.mjs dist [--dpkg]";
const root = dirname(fileURLToPath(import.meta.url));
let selfContained = false;
let push = false;
let dpkg = false;
let registry = null;
const positional = [];
for (let i = 2; i < process.argv.length; i++) {
  const arg = process.argv[i];
  if (arg === "--self-contained") {
    selfContained = true;
  } else if (arg === "--push") {
    push = true;
  } else if (arg === "--dpkg") {
    dpkg = true;
  } else if (arg === "--registry") {
    registry = process.argv[++i] ?? "";
  } else if (arg.startsWith("--registry=")) {
    registry = arg.slice("--registry=".length);
  } else {
    positional.push(arg);
  }
}
const [action = "build", platform = ""] = positional;
// The registry of the docker action is SIMPLE_CA_REGISTRY without --registry.
if (registry === null && action === "docker" && process.env.SIMPLE_CA_REGISTRY) {
  registry = process.env.SIMPLE_CA_REGISTRY;
}
const markdownAssets = join(root, "assets", "markdown");
const versionFile = join(markdownAssets, ".version");
const checksumFile = join(root, "assets", "markdown.sha256");
const requiredTag = readFileSync(join(root, "go.mod"), "utf8")
  .match(/^\s*github\.com\/skoszewski\/serve-markdown\/v3 (v\S+)/m)?.[1] ?? "";

/**
 * Runs a command in the repository, or in the directory cwd, and returns what it wrote to stdout;
 * the command's failure ends the build with its exit status.
 */
function run(command, args, { env = process.env, capture = false, cwd = root } = {}) {
  const result = spawnSync(command, args, {
    cwd,
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
 * Downloads the serve-markdown-assets archive of the serve-markdown version go.mod requires,
 * checks it against the SHA-256 assets/markdown.sha256 has for that version, and unpacks it into
 * assets/markdown, replacing what it held but .gitkeep; throws when that fails.
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
  const bytes = Buffer.from(await response.arrayBuffer());
  const pinned = readFileSync(checksumFile, "utf8").split("\n").map((line) => line.trim().split(/\s+/))
    .find(([version]) => version === tag)?.[1];
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (pinned !== actual) {
    throw new Error(`${url}: SHA-256 ${actual} is not the one assets/markdown.sha256 has for ${tag}, ${pinned ?? "none"}`);
  }
  const scratch = mkdtempSync(join(tmpdir(), "simple-ca-assets-"));
  try {
    const archive = join(scratch, "assets.tar.gz");
    writeFileSync(archive, bytes);
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

// The version of the newest CHANGELOG.md entry, "## x.y.z", the one a release takes, or "" without
// one.
const changelogVersion = readFileSync(join(root, "CHANGELOG.md"), "utf8").match(/^## (\S+)/m)?.[1] ?? "";

// The Go programs of an entry not tagged yet are built as its release candidate, vX.Y.Z-rc; those
// of a tagged entry, and without git, keep the version Go derives from the module.
const tagged = spawnSync("git", ["tag", "--list", `v${changelogVersion}`], { cwd: root, encoding: "utf8" });
const candidate = changelogVersion !== "" && tagged.status === 0 && tagged.stdout.trim() === "" ?
  `v${changelogVersion}-rc` : "";
const binDir = join(root, "bin");
const goBuild = (output, pkg) => {
  mkdirSync(binDir, { recursive: true });
  run("go", ["build", ...(candidate ? ["-ldflags", `-X main.buildVersion=${candidate}`] : []), "-o",
    join(binDir, output), pkg], { env });
};

const host = { darwin: "darwin", linux: "linux", win32: "windows" }[process.platform] ?? process.platform;

// Reports whether command runs with args, which tells whether a tool is installed.
const works = (command, args) => spawnSync(command, args, { cwd: root, stdio: "ignore" }).status === 0;

/**
 * Builds simple-ca-trust for goos/goarch to the file out and reports whether it did: the Go
 * program for linux, the Swift one for darwin on macOS alone, the .NET one for windows. With a
 * version, the program reports it and the Go build is -trimpath; without one, the Go program
 * reports the release candidate, and the others dev or InformationalVersion.
 */
function buildTrust(goos, goarch, out, version = "") {
  mkdirSync(dirname(out), { recursive: true });
  if (goos === "linux") {
    const flags = version ? ["-trimpath", "-ldflags", `-X main.buildVersion=${version}`] :
      candidate ? ["-ldflags", `-X main.buildVersion=${candidate}`] : [];
    run("go", ["build", ...flags, "-o", out, "./cmd/simple-ca-trust"], { env: { ...env, GOOS: goos, GOARCH: goarch } });
    return true;
  }
  if (goos === "darwin" && host === "darwin") {
    const macos = join(root, "trust", "macos");
    const arch = ["--arch", { amd64: "x86_64", arm64: "arm64" }[goarch] ?? goarch];
    // A version is built into Version.swift, which is given back its content afterwards.
    const swiftVersion = join(macos, "Sources", "simple-ca-trust", "Version.swift");
    const original = readFileSync(swiftVersion, "utf8");
    if (version) {
      writeFileSync(swiftVersion, "/// The version simple-ca-trust prints; a release build replaces this file.\n" +
        `let version = "${version}"\n`);
    }
    try {
      run("swift", ["build", "-c", "release", "--package-path", macos, ...arch]);
      const bin = run("swift", ["build", "-c", "release", "--package-path", macos, ...arch, "--show-bin-path"],
        { capture: true }).trim();
      copyFileSync(join(bin, "simple-ca-trust"), out);
    } finally {
      writeFileSync(swiftVersion, original);
    }
    return true;
  }
  if (goos === "windows") {
    // The project file is written for each build, self-contained or running on the installed
    // .NET runtime.
    const project = join(root, "trust", "windows", "simple-ca-trust.csproj");
    writeFileSync(project, `<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <AssemblyName>simple-ca-trust</AssemblyName>
    <RootNamespace>SimpleCaTrust</RootNamespace>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <PublishSingleFile>true</PublishSingleFile>
    <SelfContained>${selfContained}</SelfContained>
    <InvariantGlobalization>true</InvariantGlobalization>
    <InformationalVersion Condition="'$(InformationalVersion)' == ''">dev</InformationalVersion>
    <IncludeSourceRevisionInInformationalVersion>false</IncludeSourceRevisionInInformationalVersion>
  </PropertyGroup>

</Project>
`);
    const publish = join(binDir, `trust-windows-${goarch}`);
    run("dotnet", ["publish", project, "-c", "Release",
      "-r", `win-${{ amd64: "x64", arm64: "arm64" }[goarch] ?? goarch}`, "-o", publish],
      { env: version ? { ...process.env, InformationalVersion: version } : process.env });
    copyFileSync(join(publish, "simple-ca-trust.exe"), out);
    return true;
  }
  return false;
}

/**
 * Builds the Debian package of the newest CHANGELOG.md entry to dist/ with the container engine
 * engine, docker or container, after writing debian-package/debian/changelog from the entry. The
 * version is X.Y.Z-N, with the programs of vX.Y.Z, and X.Y.Z~rc-N with those of vX.Y.Z-rc while
 * vX.Y.Z is not tagged, unless internal, the package of an internal release.
 */
function buildDeb(engine, internal = false) {
  if (!changelogVersion) {
    console.error("CHANGELOG.md has no \"## x.y.z\" entry");
    process.exit(1);
  }
  // debian/changelog holds the newest CHANGELOG.md entry: its summary line, then its items.
  const lines = readFileSync(join(root, "CHANGELOG.md"), "utf8").split(/^## /m)[1].split("\n").slice(1);
  const summary = lines.find((line) => line.trim() !== "");
  const items = lines.filter((line) => /^(- |  \S)/.test(line))
    .map((line) => line.startsWith("- ") ? `  * ${line.slice(2)}` : `    ${line.trim()}`);
  // An entry x.y.z-N is the code of vx.y.z, packaged again as the Debian revision N.
  const [, upstream, revision = "1"] = changelogVersion.match(/^(.*?)(?:-([0-9]+))?$/);
  const upstreamTag = spawnSync("git", ["tag", "--list", `v${upstream}`], { cwd: root, encoding: "utf8" });
  const prerelease = !internal && upstreamTag.status === 0 && upstreamTag.stdout.trim() === "";
  const debVersion = prerelease ? `${upstream}~rc-${revision}` : `${upstream}-${revision}`;
  const date = new Date().toUTCString().replace(/GMT$/, "+0000");
  writeFileSync(join(root, "debian-package", "debian", "changelog"),
    `simple-ca (${debVersion}) unstable; urgency=medium\n\n  ${summary}\n\n${items.join("\n")}\n\n` +
    ` -- Slawomir Koszewski <slawek@koszewscy.waw.pl>  ${date}\n`);
  const args = ["-f", "debian-package/Dockerfile", "--build-arg", `VERSION=v${upstream}${prerelease ? "-rc" : ""}`];
  if (engine === "container") {
    run("container", ["build", ...args, "--output", "type=local,dest=dist", "."]);
  } else {
    run("docker", ["buildx", "build", ...args, "--output", "type=local,dest=dist", "."]);
  }
}

if (!["build", "trust", "test", "check", "clean", "assets", "docker", "deb", "dist"].includes(action) ||
  (selfContained && action !== "trust") || (push && action !== "docker") || (dpkg && action !== "dist") ||
  (registry !== null && (action !== "docker" || registry === "")) ||
  (["deb", "dist"].includes(action) && platform !== "")) {
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

// The page's browser files are fetched again once go.mod requires another serve-markdown; the
// package is not built without them.
if (["build", "test", "check", "deb", "dist"].includes(action)) {
  let held = "";
  try {
    held = readFileSync(versionFile, "utf8").trim();
  } catch {}
  if (requiredTag !== held) {
    try {
      await fetchMarkdownAssets();
    } catch (error) {
      if (action === "deb" || action === "dist") {
        console.error(error.message);
        process.exit(1);
      }
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
    goBuild(`simple-ca${nameSuffix}`, ".");
    goBuild(`request-cert${nameSuffix}`, "./cmd/request-cert");
    goBuild(`token-setup${nameSuffix}`, "./cmd/token-setup");
    goBuild(`request-token${nameSuffix}`, "./cmd/request-token");
    goBuild(`simple-ca-wif${nameSuffix}`, "./cmd/simple-ca-wif");
    if (platform !== "" ? env.GOOS === "linux" : process.platform === "linux") {
      goBuild(`simple-ca-trust${nameSuffix}`, "./cmd/simple-ca-trust");
    }
    break;
  case "trust": {
    // The target is the platform named, else the host; the Swift version is built only on macOS,
    // the Go and .NET versions on any host.
    const goos = env.GOOS ?? host;
    const goarch = env.GOARCH ?? { x64: "amd64", arm64: "arm64" }[process.arch] ?? process.arch;
    const name = platform === "" ? "simple-ca-trust" : `simple-ca-trust-${goos}-${goarch}`;
    if (!buildTrust(goos, goarch, join(binDir, goos === "windows" ? `${name}.exe` : name))) {
      console.error(goos === "darwin" ? "note: simple-ca-trust for darwin is built on darwin only; skipped" :
        `note: simple-ca-trust has no version for ${goos}; skipped`);
    }
    break;
  }
  case "docker": {
    // The image is tagged with the version of the newest CHANGELOG.md entry, the one a release
    // takes, and as latest, below the registry when one is named.
    const version = changelogVersion;
    if (!version) {
      console.error("CHANGELOG.md has no \"## x.y.z\" entry");
      process.exit(1);
    }
    const image = registry === null ? "simple-ca" : `${registry.replace(/\/+$/, "")}/simple-ca`;
    run("docker", ["buildx", "build", ...(push ? ["--push"] : []), "--build-arg", `VERSION=v${version}`,
      ...(platform === "" ? [] : ["--platform", platform]),
      "-t", `${image}:${version}`, "-t", `${image}:latest`, "."]);
    break;
  }
  case "deb":
    buildDeb("docker");
    break;
  case "dist": {
    if (!changelogVersion) {
      console.error("CHANGELOG.md has no \"## x.y.z\" entry");
      process.exit(1);
    }
    // The entry is released once a commit has its summary line, the line between blank lines
    // right after its heading, and the files are those of that commit or a later one.
    const entry = readFileSync(join(root, "CHANGELOG.md"), "utf8").split(/^## /m)[1].split("\n");
    const summary = entry[1]?.trim() === "" && entry[3]?.trim() === "" ? entry[2]?.trim() : "";
    if (run("git", ["status", "--porcelain"], { capture: true }).trim() !== "") {
      console.error("dist: commit the changes first, with ./release.mjs --no-tag");
      process.exit(1);
    }
    if (!summary || !run("git", ["log", "--format=%s"], { capture: true }).split("\n").includes(summary)) {
      console.error(`dist: ${changelogVersion} is not released; release it first with ./release.mjs --no-tag`);
      process.exit(1);
    }
    const version = `v${changelogVersion}`;
    const distDir = join(root, "dist");
    mkdirSync(distDir, { recursive: true });
    const programs = [["simple-ca", "."], ["request-cert", "./cmd/request-cert"], ["token-setup", "./cmd/token-setup"],
      ["request-token", "./cmd/request-token"], ["simple-ca-wif", "./cmd/simple-ca-wif"]];
    for (const [goos, goarch] of ["linux", "darwin", "windows"].flatMap((goos) => [[goos, "amd64"], [goos, "arm64"]])) {
      if ((goos === "darwin" && (host !== "darwin" || !works("swift", ["--version"]))) ||
        (goos === "windows" && !works("dotnet", ["--version"]))) {
        console.error(`note: ${goos}/${goarch} skipped; simple-ca-trust for ${goos} needs ` +
          (goos === "darwin" ? "macOS with swift" : "dotnet"));
        continue;
      }
      // The programs of a platform are packed from bin/pack-<goos>-<goarch>, made anew.
      const exe = goos === "windows" ? ".exe" : "";
      const pack = join(binDir, `pack-${goos}-${goarch}`);
      rmSync(pack, { recursive: true, force: true });
      mkdirSync(pack, { recursive: true });
      for (const [name, pkg] of programs) {
        run("go", ["build", "-trimpath", "-ldflags", `-X main.buildVersion=${version}`, "-o",
          join(pack, `${name}${exe}`), pkg], { env: { ...env, GOOS: goos, GOARCH: goarch } });
      }
      buildTrust(goos, goarch, join(pack, `simple-ca-trust${exe}`), version);
      const archive = join(distDir, `simple-ca-${changelogVersion}-${goos}-${goarch}${goos === "windows" ? ".zip" : ".tar.gz"}`);
      rmSync(archive, { force: true });
      const files = readdirSync(pack);
      // A windows archive is a zip, made by the tar of Windows on a Windows host.
      if (goos !== "windows") {
        run("tar", ["-czf", archive, ...files], { cwd: pack });
      } else if (host === "windows") {
        run("tar", ["-a", "-cf", archive, ...files], { cwd: pack });
      } else {
        run("zip", ["-q", "-9", archive, ...files], { cwd: pack });
      }
      console.log(`dist/${archive.slice(distDir.length + 1)}`);
    }
    if (dpkg) {
      buildDeb(host === "darwin" && works("container", ["--version"]) ? "container" : "docker", true);
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
    rmSync(binDir, { recursive: true, force: true });
    rmSync(`${root}/dist`, { recursive: true, force: true });
    for (const dir of ["trust/macos/.build", "trust/windows/bin", "trust/windows/obj", "trust/windows/simple-ca-trust.csproj"]) {
      rmSync(join(root, dir), { recursive: true, force: true });
    }
    break;
}
