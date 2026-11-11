#!/usr/bin/env node

// Builds, tests, checks and packages simple-ca; docs/development.md describes the actions.
// Usage: ./build.mjs [build|trust|test|check|clean|assets] [--self-contained] [<goos>/<goarch>]
//        ./build.mjs docker|container [--registry REGISTRY] [--push] [<os>/<arch>[,...]]
//        ./build.mjs deb
//        ./build.mjs dist [--dpkg]

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const usage = "usage: ./build.mjs [build|trust|test|check|clean|assets] [--self-contained] [<goos>/<goarch>]\n" +
  "       ./build.mjs docker|container [--registry REGISTRY] [--push] [<os>/<arch>[,...]]\n" +
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
const imageBuild = action === "docker" || action === "container";
if (registry === null && imageBuild && process.env.SIMPLE_CA_REGISTRY) {
  registry = process.env.SIMPLE_CA_REGISTRY;
}
const markdownAssets = join(root, "assets", "markdown");
const versionFile = join(markdownAssets, ".version");
const checksumFile = join(root, "assets", "markdown.sha256");
const requiredTag = readFileSync(join(root, "go.mod"), "utf8")
  .match(/^\s*github\.com\/skoszewski\/serve-markdown\/v3 (v\S+)/m)?.[1] ?? "";

/** Runs a command and returns its stdout; a failure ends the build with its exit status. */
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
 * Copies the files the ignore file re-includes, and the Dockerfile, to the directory context.
 * The container CLI fails on an ignore file with re-includes ("changes out of order"), so it
 * builds from this context.
 */
function stageContext(ignoreFile, dockerfile, context) {
  const ignore = readFileSync(join(root, ignoreFile), "utf8");
  for (const pattern of ignore.split("\n").filter((line) => line.startsWith("!")).map((line) => line.slice(1).trim())) {
    const parent = dirname(pattern);
    const base = basename(pattern);
    const match = new RegExp(`^${base.split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join("[^/]*")}$`);
    const names = !base.includes("*") ? [base] : existsSync(join(root, parent)) ?
      readdirSync(join(root, parent)).filter((name) => match.test(name)) : [];
    for (const name of names.filter((name) => existsSync(join(root, parent, name)))) {
      cpSync(join(root, parent, name), join(context, parent, name), { recursive: true });
    }
  }
  cpSync(join(root, dockerfile), join(context, dockerfile));
}

/** Builds the Debian package of dir, the source package source, to dist/ with engine. */
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
  writeFileSync(join(root, dir, "debian", "changelog"),
    `${source} (${debVersion}) unstable; urgency=medium\n\n  ${summary}\n\n${items.join("\n")}\n\n` +
    ` -- Slawomir Koszewski <slawek@koszewscy.waw.pl>  ${date}\n`);
  const args = ["--build-arg", `VERSION=v${upstream}${prerelease ? "-rc" : ""}`];
  if (engine !== "container") {
    run("docker", ["buildx", "build", "-f", `${dir}/Dockerfile`, ...args,
      "--output", `type=local,dest=${join(root, "dist")}`, "."]);
    return;
  }
  const scratch = scratchDir(`deb-${source}`);
  const context = join(scratch, "context");
  try {
    stageContext(join(dir, "Dockerfile.dockerignore"), join(dir, "Dockerfile"), context);
    // The container CLI writes a local output to out.tar/<os>_<arch>/ below dest.
    const out = join(scratch, "out");
    run("container", ["build", "-f", join(context, dir, "Dockerfile"), ...args,
      "--output", `type=local,dest=${out}`, context]);
    mkdirSync(join(root, "dist"), { recursive: true });
    for (const file of readdirSync(out, { recursive: true }).filter((file) => file.endsWith(".deb"))) {
      copyFileSync(join(out, file), join(root, "dist", basename(file)));
      console.log(`dist/${basename(file)}`);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

// The Debian package directories and source package names.
const debPackages = [["debian-package", "simple-ca"], ["debian-package-lite", "simple-ca-lite"]];

if (!["build", "trust", "test", "check", "clean", "assets", "docker", "container", "deb", "dist"].includes(action) ||
  (selfContained && action !== "trust") || (push && !imageBuild) || (dpkg && action !== "dist") ||
  (registry !== null && (!imageBuild || registry === "")) ||
  (["deb", "dist"].includes(action) && platform !== "")) {
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

if (platform !== "" && !imageBuild) {
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
    const image = registry === null ? "simple-ca" : `${registry.replace(/\/+$/, "")}/simple-ca`;
    const tags = [`${image}:${version}`, `${image}:latest`];
    const args = ["--build-arg", `VERSION=v${version}`, ...tags.flatMap((tag) => ["-t", tag])];
    if (action === "docker") {
      run("docker", ["buildx", "build", ...(push ? ["--push"] : []),
        ...(platform === "" ? [] : ["--platform", platform]), ...args, "."]);
      break;
    }
    args.push(...platforms.flatMap((p) => ["--platform", p]));
    if (!works("container", ["--version"])) {
      console.error("container: Apple's container CLI is not installed");
      process.exit(1);
    }
    const context = scratchDir("image");
    try {
      stageContext(".dockerignore", "Dockerfile", context);
      run("container", ["build", "-f", join(context, "Dockerfile"), ...args, context]);
    } finally {
      rmSync(context, { recursive: true, force: true });
    }
    for (const tag of push ? tags : []) {
      run("container", ["image", "push", tag]);
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
    const [goos, goarch] = [host, hostArch];
    if (!["linux", "darwin", "windows"].includes(goos) || !["amd64", "arm64"].includes(goarch)) {
      console.error(`dist: the release workflow builds no archive for ${goos}/${goarch}`);
      process.exit(1);
    }
    const toolchain = { darwin: "swift", windows: "dotnet" }[goos];
    if (toolchain && !works(toolchain, ["--version"])) {
      console.error(`dist: simple-ca-trust for ${goos} needs ${toolchain}`);
      process.exit(1);
    }
    const exe = goos === "windows" ? ".exe" : "";
    const archives = [["simple-ca", programs], ["simple-ca-lite", [["simple-ca-lite", "./cmd/simple-ca-lite"]]]];
    for (const [archiveName, packPrograms] of archives) {
      const pack = scratchDir(`pack-${archiveName}`);
      try {
        for (const [name, pkg] of packPrograms) {
          run("go", ["build", "-trimpath", "-ldflags", `-X main.buildVersion=${version}`, "-o",
            join(pack, `${name}${exe}`), pkg], { env: { ...env, GOOS: goos, GOARCH: goarch } });
        }
        if (archiveName === "simple-ca") {
          buildTrust(goos, goarch, join(pack, `simple-ca-trust${exe}`), version);
        }
        const archive = join(distDir,
          `${archiveName}-${changelogVersion}-${goos}-${goarch}${goos === "windows" ? ".zip" : ".tar.gz"}`);
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
    if (dpkg) {
      const engine = host === "darwin" && works("container", ["--version"]) ? "container" : "docker";
      for (const [dir, source] of debPackages) {
        buildDeb(engine, dir, source, true);
      }
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
    rmSync(buildDir, { recursive: true, force: true });
    rmSync(`${root}/dist`, { recursive: true, force: true });
    for (const dir of ["trust/macos/.build", "trust/windows/bin", "trust/windows/obj", "trust/windows/simple-ca-trust.csproj"]) {
      rmSync(join(root, dir), { recursive: true, force: true });
    }
    break;
}
