import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// The root of the repository, and the options of the command line that parseArguments sets.
export const root = dirname(dirname(fileURLToPath(import.meta.url)));
export const options = {
  action: "build",
  platform: "",
  positional: [],
  platforms: [],
  selfContained: false,
  push: false,
  dpkg: false,
  allPlatforms: false,
  registry: null,
  keyFile: null,
  passphraseFile: null,
  glob: null,
  fullDirs: null,
};

// The Go module, the build context of the images and Debian packages.
export const src = join(root, "src");

/** Runs a command, in src/ by default, and returns its stdout; a failure ends the build. */
export function run(command, args, { env = process.env, capture = false, cwd = src } = {}) {
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
    console.error(`build.mjs: ${[command, args[0]].filter(Boolean).join(" ")} failed with ${result.status === null ?
      `the signal ${result.signal}` : `the exit status ${result.status}`}`);
    process.exit(result.status ?? 1);
  }
  return result.stdout ?? "";
}

/** Prints what the build does next, on stderr, so that stdout keeps the files it writes. */
export function step(message) {
  console.error(message);
}

export const env = { ...process.env, CGO_ENABLED: "0" };

// The version of the newest CHANGELOG.md entry.
export const changelogVersion = readFileSync(join(root, "CHANGELOG.md"), "utf8").match(/^## (\S+)/m)?.[1] ?? "";

// The summary of the newest CHANGELOG.md entry, as release.mjs reads it: the paragraph after its
// heading and a blank line, neither a "-" item nor holding a heading, its lines joined with single
// spaces; empty without one.
const newest = readFileSync(join(root, "CHANGELOG.md"), "utf8").split(/^## /m)[1]?.split("\n") ?? [];
const summaryEnd = newest.findIndex((line, index) => index > 1 && line.trim() === "");
const summaryLines = summaryEnd === -1 ? [] : newest.slice(2, summaryEnd);
export const changelogSummary = newest[1]?.trim() === "" && summaryLines.length > 0 && !summaryLines[0].startsWith("-") &&
  !summaryLines.some((line) => line.startsWith("#")) ? summaryLines.map((line) => line.trim()).join(" ") : "";

// The release candidate version of an untagged entry.
export const tagged = spawnSync("git", ["tag", "--list", `v${changelogVersion}`], { cwd: root, encoding: "utf8" });
export const candidate = changelogVersion !== "" && tagged.status === 0 && tagged.stdout.trim() === "" ?
  `v${changelogVersion}-rc` : "";
export const binDir = join(root, "bin");

export const buildDir = join(root, ".build");

/** Returns an empty directory name in .build/. */
export function scratchDir(name) {
  const dir = join(buildDir, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

export const host = { darwin: "darwin", linux: "linux", win32: "windows" }[process.platform] ?? process.platform;
export const hostArch = { x64: "amd64", arm64: "arm64" }[process.arch] ?? process.arch;

// Reports whether a command runs.
export const works = (command, args) => spawnSync(command, args, { cwd: root, stdio: "ignore" }).status === 0;
