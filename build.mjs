#!/usr/bin/env node

// Builds, tests and checks simple-ca.
// Usage: ./build.mjs [build|trust|test|check|clean|assets] [--self-contained] [<goos>/<goarch>]
//
// The executables are written to bin/, which clean removes. The build action writes simple-ca,
// request-cert, the Go client of the signing API in cmd/request-cert, token-setup, which exchanges
// a setup code, in cmd/token-setup, request-jwt, the client of /api/federation-token, in
// cmd/request-jwt, and on Linux simple-ca-trust of cmd/simple-ca-trust. The platform defaults to
// the host's. Naming one builds for it instead, writing simple-ca-<goos>-<goarch>,
// request-cert-<goos>-<goarch>, token-setup-<goos>-<goarch> and request-jwt-<goos>-<goarch>, and
// for linux simple-ca-trust-linux-<goarch>. While the newest CHANGELOG.md entry is not tagged, the Go
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
  "       ./build.mjs deb";
const root = dirname(fileURLToPath(import.meta.url));
let selfContained = false;
let push = false;
let registry = null;
const positional = [];
for (let i = 2; i < process.argv.length; i++) {
  const arg = process.argv[i];
  if (arg === "--self-contained") {
    selfContained = true;
  } else if (arg === "--push") {
    push = true;
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

if (!["build", "trust", "test", "check", "clean", "assets", "docker", "deb"].includes(action) ||
  (selfContained && action !== "trust") || (push && action !== "docker") ||
  (registry !== null && (action !== "docker" || registry === "")) || (action === "deb" && platform !== "")) {
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
if (["build", "test", "check", "deb"].includes(action)) {
  let held = "";
  try {
    held = readFileSync(versionFile, "utf8").trim();
  } catch {}
  if (requiredTag !== held) {
    try {
      await fetchMarkdownAssets();
    } catch (error) {
      if (action === "deb") {
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
    goBuild(`request-jwt${nameSuffix}`, "./cmd/request-jwt");
    if (platform !== "" ? env.GOOS === "linux" : process.platform === "linux") {
      goBuild(`simple-ca-trust${nameSuffix}`, "./cmd/simple-ca-trust");
    }
    break;
  case "trust": {
    // The target is the platform named, else the host; the Swift version is built only on macOS,
    // the Go and .NET versions on any host.
    const host = { darwin: "darwin", linux: "linux", win32: "windows" }[process.platform] ?? process.platform;
    const goos = env.GOOS ?? host;
    const goarch = env.GOARCH ?? { x64: "amd64", arm64: "arm64" }[process.arch] ?? process.arch;
    const name = platform === "" ? "simple-ca-trust" : `simple-ca-trust-${goos}-${goarch}`;
    if (goos === "linux") {
      goBuild(name, "./cmd/simple-ca-trust");
    } else if (goos === "darwin" && host === "darwin") {
      const macos = join(root, "trust", "macos");
      const arch = ["--arch", { amd64: "x86_64", arm64: "arm64" }[goarch] ?? goarch];
      run("swift", ["build", "-c", "release", "--package-path", macos, ...arch]);
      const bin = run("swift", ["build", "-c", "release", "--package-path", macos, ...arch, "--show-bin-path"],
        { capture: true }).trim();
      mkdirSync(binDir, { recursive: true });
      copyFileSync(join(bin, "simple-ca-trust"), join(binDir, name));
    } else if (goos === "windows") {
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
      const out = join(binDir, `trust-windows-${goarch}`);
      run("dotnet", ["publish", project, "-c", "Release",
        "-r", `win-${{ amd64: "x64", arm64: "arm64" }[goarch] ?? goarch}`, "-o", out]);
      copyFileSync(join(out, "simple-ca-trust.exe"), join(binDir, `${name}.exe`));
    } else if (goos === "darwin") {
      console.error("note: simple-ca-trust for darwin is built on darwin only; skipped");
    } else {
      console.error(`note: simple-ca-trust has no version for ${goos}; skipped`);
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
  case "deb": {
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
    const prerelease = upstreamTag.status === 0 && upstreamTag.stdout.trim() === "";
    const debVersion = prerelease ? `${upstream}~rc-${revision}` : `${upstream}-${revision}`;
    const date = new Date().toUTCString().replace(/GMT$/, "+0000");
    writeFileSync(join(root, "debian-package", "debian", "changelog"),
      `simple-ca (${debVersion}) unstable; urgency=medium\n\n  ${summary}\n\n${items.join("\n")}\n\n` +
      ` -- Slawomir Koszewski <slawek@koszewscy.waw.pl>  ${date}\n`);
    run("docker", ["buildx", "build", "-f", "debian-package/Dockerfile",
      "--build-arg", `VERSION=v${upstream}${prerelease ? "-rc" : ""}`,
      "--output", "type=local,dest=dist", "."]);
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
