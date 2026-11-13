import { existsSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { env, options } from "./context.mjs";

const usage = `usage: ./build.mjs setup
       ./build.mjs [build|trust|test|check|clean|assets] [--self-contained] [<goos>/<goarch>]
       ./build.mjs docker|container [--registry REGISTRY] [--push] [--full [DL [APT]]] [<os>/<arch>[,...]]
       ./build.mjs deb
       ./build.mjs dist [--all] [--dpkg]
       ./build.mjs install
       ./build.mjs apt [--key FILE] [--passphrase-file FILE] [SOURCE [DEST]]
       ./build.mjs sums DIR [GLOB]`;

// Parses the command line into options, or prints the usage and exits.
export function parseArguments() {
  let parsed;
  try {
    parsed = parseArgs({
      options: {
        "self-contained": { type: "boolean", default: false },
        push: { type: "boolean", default: false },
        dpkg: { type: "boolean", default: false },
        all: { type: "boolean", default: false },
        full: { type: "boolean" },
        registry: { type: "string" },
        key: { type: "string" },
        "passphrase-file": { type: "string" },
      },
      allowPositionals: true,
      tokens: true,
    });
  } catch (error) {
    console.error(`build.mjs: ${error.message}\n\n${usage}`);
    process.exit(2);
  }
  const { values, tokens } = parsed;
  const selfContained = values["self-contained"];
  const { push, dpkg } = values;
  const allPlatforms = values.all;
  let registry = values.registry ?? null;
  let keyFile = values.key ?? null;
  let passphraseFile = values["passphrase-file"] ?? null;

  // --full takes up to two directories right after it: the release archives and the repository.
  let fullDirs = null;
  const taken = new Set();
  for (const [i, token] of tokens.entries()) {
    if (token.kind !== "option" || token.name !== "full") {
      continue;
    }
    fullDirs = [];
    for (let j = i + 1; fullDirs.length < 2 && j < tokens.length; j++) {
      const next = tokens[j];
      if (next.kind !== "positional" || next.index !== tokens[j - 1].index + 1 || !existsSync(next.value) ||
        !statSync(next.value).isDirectory()) {
        break;
      }
      fullDirs.push(resolve(next.value));
      taken.add(j);
    }
  }
  const positional = tokens.filter((token, i) => token.kind === "positional" && !taken.has(i)).map((token) => token.value);
  const [action = "build", platform = ""] = positional;
  const imageBuild = action === "docker" || action === "container";
  if (registry === null && imageBuild && process.env.SIMPLE_CA_REGISTRY) {
    registry = process.env.SIMPLE_CA_REGISTRY;
  }
  if (keyFile === null && action === "apt" && process.env.SIMPLE_CA_GPG_KEY_FILE) {
    keyFile = process.env.SIMPLE_CA_GPG_KEY_FILE;
  }
  if (passphraseFile === null && action === "apt" && process.env.SIMPLE_CA_GPG_PASSPHRASE_FILE) {
    passphraseFile = process.env.SIMPLE_CA_GPG_PASSPHRASE_FILE;
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
