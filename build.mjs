#!/usr/bin/env node

// Builds, tests, checks and packages simple-ca.
// Usage: ./build.mjs [build|test|check|clean] [<goos>/<goarch>]
//        ./build.mjs package [<debian-arch>]
//
// The platform defaults to the host's. Naming one builds for it instead, writing
// simple-ca-<goos>-<goarch>; it applies to the build action alone. Releases are made by
// release.mjs.
//
// The package action builds the Debian package of the newest CHANGELOG.md entry from
// debian-package, for the host's Debian architecture or the one named, on a Debian or Ubuntu host
// with dpkg-dev and debhelper. It writes simple-ca_<version>_<arch>.deb to the repository root.

import { spawnSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const usage = "usage: ./build.mjs [build|test|check|clean] [<goos>/<goarch>]\n" +
  "       ./build.mjs package [<debian-arch>]";
const root = dirname(fileURLToPath(import.meta.url));
const [action = "build", platform = ""] = process.argv.slice(2);

/**
 * Runs a command in the repository, or in cwd, and returns what it wrote to stdout; the
 * command's failure ends the build with its exit status.
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
  return result.stdout;
}

let binary = "simple-ca";
const env = { ...process.env, CGO_ENABLED: "0" };

if (!["build", "test", "check", "clean", "package"].includes(action)) {
  console.error(usage);
  process.exit(2);
}

if (platform !== "" && action !== "package") {
  const [goos, goarch, ...rest] = platform.split("/");
  if (!goos || !goarch || rest.length > 0) {
    console.error("platform must be given as <goos>/<goarch>, e.g. linux/amd64");
    process.exit(2);
  }
  env.GOOS = goos;
  env.GOARCH = goarch;
  binary = `simple-ca-${goos}-${goarch}${goos === "windows" ? ".exe" : ""}`;
}

switch (action) {
  case "build":
    run("go", ["build", "-o", binary, "."], { env });
    break;
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
  case "package": {
    // The Go architectures of the Debian architectures.
    const goArchs = { amd64: "amd64", arm64: "arm64", armhf: "arm", i386: "386" };
    const arch = platform || run("dpkg", ["--print-architecture"], { capture: true }).trim();
    if (!(arch in goArchs)) {
      console.error(`unsupported Debian architecture '${arch}': must be one of ${Object.keys(goArchs).join(", ")}`);
      process.exit(2);
    }

    // The Debian changelog, written from the entries of CHANGELOG.md, each dated by its tag, the
    // newest by now when it is not tagged yet.
    const control = readFileSync(`${root}/debian-package/debian/control`, "utf8");
    const maintainer = control.match(/^Maintainer: (.+)$/m)[1];
    const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const pad = (n) => String(n).padStart(2, "0");
    let debianChangelog = "";
    let version = "";
    for (const entry of readFileSync(`${root}/CHANGELOG.md`, "utf8").split(/^## /m).slice(1)) {
      const [heading, ...lines] = entry.trimEnd().split("\n");
      const entryVersion = heading.trim();
      const m = entryVersion.match(/^(\d+\.\d+\.\d+)(?:-(.+))?$/);
      if (!m) {
        console.error(`CHANGELOG.md: '${entryVersion}' is not a version x.y.z or x.y.z-suffix`);
        process.exit(1);
      }
      let debianVersion = `${m[1]}-1`;
      if (m[2] !== undefined) {
        debianVersion = /^\d+$/.test(m[2]) ? `${m[1]}-${m[2]}` : `${m[1]}~${m[2]}-1`;
      }
      version ||= entryVersion;
      const tagged = spawnSync("git", ["log", "-1", "--format=%ct", `refs/tags/v${entryVersion}`],
        { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
      const seconds = tagged.status === 0 && tagged.stdout.trim() !== "" ? Number(tagged.stdout.trim()) : Date.now() / 1000;
      const d = new Date(seconds * 1000);
      const date = `${days[d.getUTCDay()]}, ${pad(d.getUTCDate())} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()} ` +
        `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000`;
      const body = lines.filter((line) => line.trim() !== "").map((line) => {
        if (line.startsWith("- ")) {
          return `  * ${line.slice(2)}`;
        }
        return line.startsWith("  ") ? `    ${line.trim()}` : `  ${line.trim()}`;
      });
      const [summary, ...items] = body;
      debianChangelog += `simple-ca (${debianVersion}) unstable; urgency=medium\n\n${summary}\n` +
        (items.length > 0 ? `\n${items.join("\n")}\n` : "") + `\n -- ${maintainer}  ${date}\n\n`;
    }
    if (version === "") {
      console.error("CHANGELOG.md has no entry");
      process.exit(1);
    }

    env.GOOS = "linux";
    env.GOARCH = goArchs[arch];
    if (arch === "armhf") {
      env.GOARM = "7";
    }
    run("go", ["build", "-trimpath", "-ldflags", `-X main.buildVersion=v${version}`, "-o", "debian-package/simple-ca", "."], { env });
    mkdirSync(`${root}/debian-package/systemd`, { recursive: true });
    for (const unit of ["simple-ca.service", "simple-ca-crl.service", "simple-ca-crl.timer"]) {
      const text = readFileSync(`${root}/systemd/${unit}`, "utf8").replaceAll("/usr/local/bin/simple-ca", "/usr/bin/simple-ca");
      writeFileSync(`${root}/debian-package/systemd/${unit}`, text);
    }
    writeFileSync(`${root}/debian-package/debian/changelog`, debianChangelog.trimEnd() + "\n");
    run("dpkg-buildpackage", ["-us", "-uc", "-b", `--host-arch=${arch}`], { cwd: `${root}/debian-package` });
    break;
  }
  case "clean":
    for (const name of readdirSync(root)) {
      if (name === "simple-ca" || name === "simple-ca.exe" || name.startsWith("simple-ca-") ||
        (name.startsWith("simple-ca_") && /\.(deb|buildinfo|changes)$/.test(name))) {
        rmSync(`${root}/${name}`, { force: true });
      }
    }
    rmSync(`${root}/build`, { recursive: true, force: true });
    rmSync(`${root}/dist`, { recursive: true, force: true });
    for (const name of ["simple-ca", "systemd", "debian/changelog", "debian/.debhelper", "debian/simple-ca",
      "debian/debhelper-build-stamp", "debian/files", "debian/simple-ca.substvars"]) {
      rmSync(`${root}/debian-package/${name}`, { recursive: true, force: true });
    }
    break;
}
