import { existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { env, options } from "./context.mjs";

const usage = `usage: ./build.mjs setup
       ./build.mjs [build|trust|test|check|clean|assets] [--self-contained] [<goos>/<goarch>]
       ./build.mjs docker|container [--registry REGISTRY] [--push] [--full [DL [APT]]] [<os>/<arch>[,...]]
       ./build.mjs deb
       ./build.mjs dist [--all] [--dpkg]
       ./build.mjs install
       ./build.mjs apt --key FILE [--passphrase-file FILE] [SOURCE [DEST]]
       ./build.mjs sums DIR [GLOB]`;

// Parses the command line into options, or prints the usage and exits.
export function parseArguments() {
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

  if (!["build", "trust", "test", "check", "clean", "assets", "docker", "container", "deb", "dist", "install", "apt",
    "sums", "setup"].includes(action) ||
    (action === "sums" && (platform === "" || positional.length > 3)) ||
    (action === "apt" && positional.length > 3) ||
    ((keyFile !== null) !== (action === "apt")) || keyFile === "" ||
    (passphraseFile !== null && (action !== "apt" || passphraseFile === "")) ||
    (fullDirs !== null && !imageBuild) ||
    (selfContained && action !== "trust") || (push && !imageBuild) || (dpkg && action !== "dist") ||
    (allPlatforms && action !== "dist") ||
    (registry !== null && (!imageBuild || registry === "")) ||
    (["deb", "dist", "install", "setup"].includes(action) && platform !== "")) {
    console.error(usage);
    process.exit(2);
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
  }

  Object.assign(options, { action, platform, positional, platforms, selfContained, push, dpkg,
    allPlatforms, registry, keyFile, passphraseFile, fullDirs });
}
