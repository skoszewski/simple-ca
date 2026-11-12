import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import {
  changelogVersion, env, host, hostArch, options, root, run, scratchDir, src, tagged, works,
} from "./context.mjs";
import { buildDeb, debPackages } from "./deb.mjs";
import { buildTrust } from "./trust.mjs";

export async function dist() {
  const { allPlatforms, dpkg } = options;
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
}
