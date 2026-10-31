#!/usr/bin/env node

// Builds, tests and checks simple-ca.
// Usage: ./build.mjs [build|test|check|clean] [<goos>/<goarch>]
//
// The platform defaults to the host's. Naming one builds for it instead, writing
// simple-ca-<goos>-<goarch>; it applies to the build action alone. Releases are made by
// release.mjs.

import { spawnSync } from "node:child_process";
import { readdirSync, rmSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const usage = "usage: ./build.mjs [build|test|check|clean] [<goos>/<goarch>]";
const root = dirname(fileURLToPath(import.meta.url));
const [action = "build", platform = ""] = process.argv.slice(2);

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
  return result.stdout;
}

let binary = "simple-ca";
const env = { ...process.env, CGO_ENABLED: "0" };

if (!["build", "test", "check", "clean"].includes(action)) {
  console.error(usage);
  process.exit(2);
}

if (platform !== "") {
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
  case "clean":
    for (const name of readdirSync(root)) {
      if (name === "simple-ca" || name === "simple-ca.exe" || name.startsWith("simple-ca-")) {
        rmSync(`${root}/${name}`, { force: true });
      }
    }
    rmSync(`${root}/build`, { recursive: true, force: true });
    rmSync(`${root}/dist`, { recursive: true, force: true });
    break;
}
