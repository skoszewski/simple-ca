#!/usr/bin/env node

// Builds, tests, checks and packages simple-ca.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, matchesGlob, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const usage = `usage: ./build.mjs setup
       ./build.mjs [build|trust|test|check|clean|assets] [--self-contained] [<goos>/<goarch>]
       ./build.mjs docker|container [--registry REGISTRY] [--push] [--full [DL [APT]]] [<os>/<arch>[,...]]
       ./build.mjs deb
       ./build.mjs dist [--all] [--dpkg]
       ./build.mjs apt --key FILE [--passphrase-file FILE] [SOURCE [DEST]]
       ./build.mjs sums DIR [GLOB]`;
const root = dirname(fileURLToPath(import.meta.url));
let selfContained = false;
let push = false;
let dpkg = false;
let allPlatforms = false;
let registry = null;
let keyFile = null;
let passphraseFile = null;
let fullDirs = null;
const positional = [];
for (let i = 2; i < process.argv.length; i++) {
  const arg = process.argv[i];
  if (arg === "--self-contained") {
    selfContained = true;
  } else if (arg === "--push") {
    push = true;
  } else if (arg === "--dpkg") {
    dpkg = true;
  } else if (arg === "--all") {
    allPlatforms = true;
  } else if (arg === "--registry") {
    registry = process.argv[++i] ?? "";
  } else if (arg.startsWith("--registry=")) {
    registry = arg.slice("--registry=".length);
  } else if (arg === "--key") {
    keyFile = process.argv[++i] ?? "";
  } else if (arg.startsWith("--key=")) {
    keyFile = arg.slice("--key=".length);
  } else if (arg === "--passphrase-file") {
    passphraseFile = process.argv[++i] ?? "";
  } else if (arg.startsWith("--passphrase-file=")) {
    passphraseFile = arg.slice("--passphrase-file=".length);
  } else if (arg === "--full") {
    // Up to two following arguments that are directories: the release archives and the repository.
    fullDirs = [];
    while (fullDirs.length < 2 && i + 1 < process.argv.length && !process.argv[i + 1].startsWith("--") &&
      existsSync(process.argv[i + 1]) && statSync(process.argv[i + 1]).isDirectory()) {
      fullDirs.push(resolve(process.argv[++i]));
    }
  } else {
    positional.push(arg);
  }
}
const [action = "build", platform = ""] = positional;
const imageBuild = action === "docker" || action === "container";
if (registry === null && imageBuild && process.env.SIMPLE_CA_REGISTRY) {
  registry = process.env.SIMPLE_CA_REGISTRY;
}
// The Go module, the build context of the images and Debian packages.
const src = join(root, "src");
const markdownAssets = join(src, "assets", "markdown");
const versionFile = join(markdownAssets, ".version");
const checksumFile = join(src, "assets", "markdown.sha256");
const requiredTag = readFileSync(join(src, "go.mod"), "utf8")
  .match(/^\s*github\.com\/skoszewski\/serve-markdown\/v3 (v\S+)/m)?.[1] ?? "";

/** Runs a command, in src/ by default, and returns its stdout; a failure ends the build. */
function run(command, args, { env = process.env, capture = false, cwd = src } = {}) {
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

/** Downloads, checks and unpacks the serve-markdown assets of go.mod into assets/markdown. */
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
  const scratch = scratchDir("assets");
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

// The version of the newest CHANGELOG.md entry.
const changelogVersion = readFileSync(join(root, "CHANGELOG.md"), "utf8").match(/^## (\S+)/m)?.[1] ?? "";

// The release candidate version of an untagged entry.
const tagged = spawnSync("git", ["tag", "--list", `v${changelogVersion}`], { cwd: root, encoding: "utf8" });
const candidate = changelogVersion !== "" && tagged.status === 0 && tagged.stdout.trim() === "" ?
  `v${changelogVersion}-rc` : "";
const binDir = join(root, "bin");

const buildDir = join(root, ".build");

/** Returns an empty directory name in .build/. */
function scratchDir(name) {
  const dir = join(buildDir, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

/**
 * Writes NAME.sha256, the line of sha256sum, for each file of dir matching glob, skipping dot
 * files, sum files and those whose sum file already holds the line, and prints the names written.
 */
function writeSums(dir, glob) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const name = entry.name;
    if (!entry.isFile() || name.startsWith(".") || name.endsWith(".sha256") || !matchesGlob(name, glob)) {
      continue;
    }
    const line = `${createHash("sha256").update(readFileSync(join(dir, name))).digest("hex")}  ${name}\n`;
    const sumFile = join(dir, `${name}.sha256`);
    if (!existsSync(sumFile) || readFileSync(sumFile, "utf8") !== line) {
      writeFileSync(sumFile, line);
      console.log(`${name}.sha256`);
    }
  }
}

const goBuild = (output, pkg) => {
  mkdirSync(binDir, { recursive: true });
  run("go", ["build", ...(candidate ? ["-ldflags", `-X main.buildVersion=${candidate}`] : []), "-o",
    join(binDir, output), pkg], { env });
};

const host = { darwin: "darwin", linux: "linux", win32: "windows" }[process.platform] ?? process.platform;
const hostArch = { x64: "amd64", arm64: "arm64" }[process.arch] ?? process.arch;

// Reports whether a command runs.
const works = (command, args) => spawnSync(command, args, { cwd: root, stdio: "ignore" }).status === 0;

/** Builds simple-ca-trust for goos/goarch to out, and reports whether it could. */
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
    // Version.swift holds the version during the build.
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
    const publish = scratchDir(`trust-windows-${goarch}`);
    try {
      run("dotnet", ["publish", project, "-c", "Release",
        "-r", `win-${{ amd64: "x64", arm64: "arm64" }[goarch] ?? goarch}`, "-o", publish],
        { env: version ? { ...process.env, InformationalVersion: version } : process.env });
      copyFileSync(join(publish, "simple-ca-trust.exe"), out);
    } finally {
      rmSync(publish, { recursive: true, force: true });
    }
    return true;
  }
  return false;
}

/**
 * Builds the Debian package of dir, the source package source, to dist/ with engine: for the
 * architecture of the engine with docker, and for amd64 and arm64 with the container CLI.
 */
function buildDeb(engine, dir, source, internal = false) {
  if (!changelogVersion) {
    console.error("CHANGELOG.md has no \"## x.y.z\" entry");
    process.exit(1);
  }
  // debian/changelog from the newest CHANGELOG.md entry.
  const lines = readFileSync(join(root, "CHANGELOG.md"), "utf8").split(/^## /m)[1].split("\n").slice(1);
  const summary = lines.find((line) => line.trim() !== "");
  const items = lines.filter((line) => /^(- |  \S)/.test(line))
    .map((line) => line.startsWith("- ") ? `  * ${line.slice(2)}` : `    ${line.trim()}`);
  // An entry x.y.z-N is the Debian revision N of vx.y.z.
  const [, upstream, revision = "1"] = changelogVersion.match(/^(.*?)(?:-([0-9]+))?$/);
  const upstreamTag = spawnSync("git", ["tag", "--list", `v${upstream}`], { cwd: root, encoding: "utf8" });
  const prerelease = !internal && upstreamTag.status === 0 && upstreamTag.stdout.trim() === "";
  const debVersion = prerelease ? `${upstream}~rc-${revision}` : `${upstream}-${revision}`;
  const date = new Date().toUTCString().replace(/GMT$/, "+0000");
  writeFileSync(join(src, dir, "debian", "changelog"),
    `${source} (${debVersion}) unstable; urgency=medium\n\n  ${summary}\n\n${items.join("\n")}\n\n` +
    ` -- Slawomir Koszewski <slawek@koszewscy.waw.pl>  ${date}\n`);
  const out = scratchDir(`deb-${source}`);
  try {
    const args = ["-f", join(src, dir, "Dockerfile"), "--build-arg", `VERSION=v${upstream}${prerelease ? "-rc" : ""}`,
      "--output", `type=local,dest=${out}`, src];
    if (engine === "container") {
      // The container CLI writes each architecture to out.tar/<os>_<arch>/ below dest.
      run("container", ["build", "--platform", "linux/amd64", "--platform", "linux/arm64", ...args]);
    } else {
      run("docker", ["buildx", "build", ...args]);
    }
    mkdirSync(join(root, "dist"), { recursive: true });
    for (const file of readdirSync(out, { recursive: true }).filter((file) => file.endsWith(".deb"))) {
      copyFileSync(join(out, file), join(root, "dist", basename(file)));
      console.log(`dist/${basename(file)}`);
    }
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}

// The Debian package directories of src/ and source package names.
const debPackages = [["debian-package", "simple-ca"], ["debian-package-lite", "simple-ca-lite"]];

// The Linux toolset image of setup, built from its directory.
const builderImage = "simple-ca-builder";

if (!["build", "trust", "test", "check", "clean", "assets", "docker", "container", "deb", "dist", "apt", "sums",
  "setup"].includes(action) ||
  (action === "sums" && (platform === "" || positional.length > 3)) ||
  (action === "apt" && positional.length > 3) ||
  ((keyFile !== null) !== (action === "apt")) || keyFile === "" ||
  (passphraseFile !== null && (action !== "apt" || passphraseFile === "")) ||
  (fullDirs !== null && !imageBuild) ||
  (selfContained && action !== "trust") || (push && !imageBuild) || (dpkg && action !== "dist") ||
  (allPlatforms && action !== "dist") ||
  (registry !== null && (!imageBuild || registry === "")) ||
  (["deb", "dist", "setup"].includes(action) && platform !== "")) {
  console.error(usage);
  process.exit(2);
}

// The suffix of the executables: -<goos>-<goarch> for a platform named, and .exe on Windows.
let nameSuffix = "";
if (action === "build" && platform === "") {
  nameSuffix = run("go", ["env", "GOEXE"], { env, capture: true }).trim();
}

// The image builds take a comma-separated list of platforms.
const platforms = platform === "" ? [] : platform.split(",");
if (imageBuild && platforms.some((p) => !/^[a-z0-9]+\/[a-z0-9]+(\/[a-z0-9]+)?$/.test(p))) {
  console.error("platforms must be given as <os>/<arch>[,<os>/<arch>...], e.g. linux/amd64,linux/arm64");
  process.exit(2);
}

if (platform !== "" && !imageBuild && !["apt", "sums"].includes(action)) {
  const [goos, goarch, ...rest] = platform.split("/");
  if (!goos || !goarch || rest.length > 0) {
    console.error("platform must be given as <goos>/<goarch>, e.g. linux/amd64");
    process.exit(2);
  }
  env.GOOS = goos;
  env.GOARCH = goarch;
  nameSuffix = `-${goos}-${goarch}${goos === "windows" ? ".exe" : ""}`;
}

// The serve-markdown assets are fetched when go.mod requires another version.
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
    goBuild(`simple-ca-lite${nameSuffix}`, "./cmd/simple-ca-lite");
    if (platform !== "" ? env.GOOS === "linux" : process.platform === "linux") {
      goBuild(`simple-ca-trust${nameSuffix}`, "./cmd/simple-ca-trust");
    }
    break;
  case "trust": {
    const goos = env.GOOS ?? host;
    const goarch = env.GOARCH ?? { x64: "amd64", arm64: "arm64" }[process.arch] ?? process.arch;
    const name = platform === "" ? "simple-ca-trust" : `simple-ca-trust-${goos}-${goarch}`;
    if (!buildTrust(goos, goarch, join(binDir, goos === "windows" ? `${name}.exe` : name))) {
      console.error(goos === "darwin" ? "note: simple-ca-trust for darwin is built on darwin only; skipped" :
        `note: simple-ca-trust has no version for ${goos}; skipped`);
    }
    break;
  }
  case "docker":
  case "container": {
    const version = changelogVersion;
    if (!version) {
      console.error("CHANGELOG.md has no \"## x.y.z\" entry");
      process.exit(1);
    }
    const prefix = registry === null ? "" : `${registry.replace(/\/+$/, "")}/`;
    const tagsOf = (name) => [`${prefix}${name}:${version}`, `${prefix}${name}:latest`];

    // With --full, the release archives and the apt repository are checked before any build.
    const [downloadsDir = join(root, "dist"), repoDir = join(root, "apt")] = fullDirs ?? [];
    const archives = fullDirs !== null && existsSync(downloadsDir) ?
      readdirSync(downloadsDir).filter((name) => name.startsWith(`simple-ca-${version}-`) ||
        name.startsWith(`simple-ca-lite-${version}-`)).filter((name) => /\.(tar\.gz|zip)$/.test(name)) : [];
    if (fullDirs !== null && archives.length === 0) {
      console.error(`--full: ${downloadsDir} holds no release archives of ${version}; see ./build.mjs dist`);
      process.exit(1);
    }
    const missing = fullDirs === null ? [] :
      ["Release", "InRelease", "key.asc"].filter((name) => !existsSync(join(repoDir, name)));
    if (missing.length > 0) {
      console.error(`--full: ${repoDir} has no ${missing.join(", ")}; see ./build.mjs apt`);
      process.exit(1);
    }
    if (action === "container" && !works("container", ["--version"])) {
      console.error("container: Apple's container CLI is not installed");
      process.exit(1);
    }

    // Builds the image of dockerfile in context with tags, and pushes it with --push.
    const buildImage = (dockerfile, context, tags, buildArgs) => {
      const args = [...buildArgs.flatMap((arg) => ["--build-arg", arg]), ...tags.flatMap((tag) => ["-t", tag])];
      if (action === "docker") {
        run("docker", ["buildx", "build", ...(push ? ["--push"] : []),
          ...(platform === "" ? [] : ["--platform", platform]), "-f", dockerfile, ...args, context]);
        return;
      }
      run("container", ["build", "-f", dockerfile, ...args, ...platforms.flatMap((p) => ["--platform", p]), context]);
      for (const tag of push ? tags : []) {
        run("container", ["image", "push", tag]);
      }
    };

    const tags = tagsOf("simple-ca");
    buildImage(join(src, "Dockerfile"), src, tags, [`VERSION=v${version}`]);
    if (fullDirs === null) {
      break;
    }

    // simple-ca-full: the image above with the archives, their sum files and the repository.
    const stage = scratchDir("image-full");
    try {
      for (const name of archives) {
        cpSync(join(downloadsDir, name), join(stage, "downloads", name));
      }
      writeSums(join(stage, "downloads"), "*");
      cpSync(repoDir, join(stage, "apt"), { recursive: true });
      cpSync(join(root, "Dockerfile.full"), join(stage, "Dockerfile.full"));
      buildImage(join(stage, "Dockerfile.full"), stage, tagsOf("simple-ca-full"), [`BASE=${tags[0]}`]);
    } finally {
      rmSync(stage, { recursive: true, force: true });
    }
    break;
  }
  case "deb":
    for (const [dir, source] of debPackages) {
      buildDeb("docker", dir, source);
    }
    break;
  case "dist": {
    if (!changelogVersion) {
      console.error("CHANGELOG.md has no \"## x.y.z\" entry");
      process.exit(1);
    }
    // The newest entry must be committed, with a clean tree.
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
    // The platform of the host, or with --all every platform of the release workflow.
    const targets = allPlatforms ? ["linux", "darwin", "windows"].flatMap((goos) =>
      ["amd64", "arm64"].map((goarch) => [goos, goarch])) : [[host, hostArch]];
    if (!allPlatforms && (!["linux", "darwin", "windows"].includes(host) || !["amd64", "arm64"].includes(hostArch))) {
      console.error(`dist: the release workflow builds no archive for ${host}/${hostArch}`);
      process.exit(1);
    }
    const archiveFile = (archiveName, goos, goarch) =>
      `${archiveName}-${changelogVersion}-${goos}-${goarch}${goos === "windows" ? ".zip" : ".tar.gz"}`;

    // A tagged entry is released on GitHub: --all and --dpkg download its files instead of building.
    const released = tagged.status === 0 && tagged.stdout.trim() !== "";
    const downloads = !released ? [] : [
      ...(allPlatforms ? targets.flatMap(([goos, goarch]) =>
        ["simple-ca", "simple-ca-lite"].map((archiveName) => archiveFile(archiveName, goos, goarch))) : []),
      ...(dpkg ? ["amd64", "arm64"].flatMap((arch) =>
        [`simple-ca_${changelogVersion}-1_${arch}.deb`, `simple-ca-lite_${changelogVersion}-1_${arch}.deb`]) : []),
    ];
    // The repository of the module src/.
    const repository = dirname(readFileSync(join(src, "go.mod"), "utf8").match(/^module (\S+)/m)[1]);
    for (const name of downloads) {
      const url = `https://${repository}/releases/download/${version}/${name}`;
      const response = await fetch(url);
      if (!response.ok) {
        console.error(`dist: ${url}: ${response.status} ${response.statusText}`);
        process.exit(1);
      }
      writeFileSync(join(distDir, name), Buffer.from(await response.arrayBuffer()));
      console.log(`dist/${name}`);
    }

    // A simple-ca-trust the host cannot build is skipped on a partial build; that of the host,
    // and on macOS every one of --all, must be built.
    const dotnet = works("dotnet", ["--version"]);
    const trustSkipped = (goos) => (goos === "darwin" && host !== "darwin") || (goos === "windows" && !dotnet);
    const required = new Set(targets.map(([goos]) => goos).filter((goos) => goos === host || host === "darwin"));
    for (const goos of released && allPlatforms ? [] : required) {
      const toolchain = { darwin: "swift", windows: "dotnet" }[goos];
      if (toolchain && !works(toolchain, ["--version"])) {
        console.error(`dist: simple-ca-trust for ${goos} needs ${toolchain}`);
        process.exit(1);
      }
    }
    const archives = [["simple-ca", programs], ["simple-ca-lite", [["simple-ca-lite", "./cmd/simple-ca-lite"]]]];
    for (const [goos, goarch] of released && allPlatforms ? [] : targets) for (const [archiveName, packPrograms] of archives) {
      const exe = goos === "windows" ? ".exe" : "";
      const pack = scratchDir(`pack-${archiveName}`);
      try {
        for (const [name, pkg] of packPrograms) {
          run("go", ["build", "-trimpath", "-ldflags", `-X main.buildVersion=${version}`, "-o",
            join(pack, `${name}${exe}`), pkg], { env: { ...env, GOOS: goos, GOARCH: goarch } });
        }
        if (archiveName === "simple-ca" && trustSkipped(goos)) {
          console.error(`note: simple-ca-trust for ${goos} is built ${goos === "darwin" ? "on macOS only" : "with dotnet"}; ` +
            `${archiveFile(archiveName, goos, goarch)} is packed without it`);
        } else if (archiveName === "simple-ca") {
          buildTrust(goos, goarch, join(pack, `simple-ca-trust${exe}`), version);
        }
        const archive = join(distDir, archiveFile(archiveName, goos, goarch));
        rmSync(archive, { force: true });
        const files = readdirSync(pack);
        if (goos === "windows") {
          run("tar", ["-a", "-cf", archive, ...files], { cwd: pack });
        } else {
          run("tar", ["-czf", archive, ...files], { cwd: pack });
        }
        console.log(`dist/${archive.slice(distDir.length + 1)}`);
      } finally {
        rmSync(pack, { recursive: true, force: true });
      }
    }
    if (dpkg && !released) {
      const engine = host === "darwin" && works("container", ["--version"]) ? "container" : "docker";
      for (const [dir, source] of debPackages) {
        buildDeb(engine, dir, source, true);
      }
    }
    break;
  }
  case "apt": {
    const debDir = platform === "" ? join(root, "dist") : resolve(platform);
    const aptDir = positional[2] === undefined ? join(root, "apt") : resolve(positional[2]);
    // The destination is replaced, so it must be empty or hold a repository.
    if (aptDir === debDir ||
      (existsSync(aptDir) && readdirSync(aptDir).length > 0 && !existsSync(join(aptDir, "Release")))) {
      console.error(`apt: ${aptDir} is not empty and holds no repository, or is the source directory`);
      process.exit(1);
    }
    keyFile = resolve(keyFile);
    passphraseFile = passphraseFile === null ? null : resolve(passphraseFile);
    // The packages of the newest entry: X.Y.Z-N, or X.Y.Z~rc-N before the tag, as buildDeb names them.
    const [, upstream, revision = "1"] = changelogVersion.match(/^(.*?)(?:-([0-9]+))?$/);
    const debs = existsSync(debDir) ? readdirSync(debDir).filter((name) =>
      new RegExp(`^simple-ca(-lite)?_${upstream.replaceAll(".", "\\.")}(~rc)?-${revision}_[a-z0-9]+\\.deb$`).test(name)) : [];
    if (debs.length === 0) {
      console.error(`apt: ${debDir} holds no Debian packages of ${changelogVersion}; see ./build.mjs deb`);
      process.exit(1);
    }
    for (const file of [keyFile, passphraseFile].filter((file) => file !== null && !existsSync(file))) {
      console.error(`apt: ${file} does not exist`);
      process.exit(1);
    }
    const engine = host === "darwin" && works("container", ["--version"]) ? "container" : "docker";
    if (!works(engine, ["image", "inspect", builderImage])) {
      console.error(`apt: ${engine} has no image ${builderImage}; see ./build.mjs setup`);
      process.exit(1);
    }
    const scratch = scratchDir("apt");
    const repo = join(scratch, "repo");
    const secrets = join(scratch, "secrets");
    try {
      for (const name of debs) {
        cpSync(join(debDir, name), join(repo, name));
      }
      cpSync(keyFile, join(secrets, "gpg_key"));
      if (passphraseFile !== null) {
        cpSync(passphraseFile, join(secrets, "gpg_passphrase"));
      }
      const user = process.getuid === undefined ? [] : ["--user", `${process.getuid()}:${process.getgid()}`];
      run(engine, ["run", "--rm", ...user, "--tmpfs", "/tmp", "-w", "/repo",
        "--mount", `type=bind,source=${repo},target=/repo`,
        "--mount", `type=bind,source=${secrets},target=/run/secrets,readonly`,
        builderImage, "sh", "/usr/local/bin/build-repo.sh"]);
      rmSync(aptDir, { recursive: true, force: true });
      cpSync(repo, aptDir, { recursive: true });
      console.log(aptDir);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
    break;
  }
  case "setup": {
    const engine = host === "darwin" && works("container", ["--version"]) ? "container" : "docker";
    const dir = join(root, builderImage);
    const args = ["-t", builderImage, "-f", join(dir, "Dockerfile"), dir];
    run(engine, engine === "container" ? ["build", ...args] : ["buildx", "build", "--load", ...args]);
    break;
  }
  case "sums": {
    const dir = resolve(platform);
    const glob = positional[2] ?? "*";
    if (!existsSync(dir)) {
      console.error(`sums: ${dir} does not exist`);
      process.exit(1);
    }
    writeSums(dir, glob);
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
    rmSync(buildDir, { recursive: true, force: true });
    rmSync(`${root}/dist`, { recursive: true, force: true });
    rmSync(`${root}/apt`, { recursive: true, force: true });
    for (const dir of ["trust/macos/.build", "trust/windows/bin", "trust/windows/obj", "trust/windows/simple-ca-trust.csproj"]) {
      rmSync(join(root, dir), { recursive: true, force: true });
    }
    break;
}
