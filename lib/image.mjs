import { cpSync, existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { changelogVersion, options, root, run, scratchDir, src, works } from "./context.mjs";
import { writeSums } from "./sums.mjs";

export async function image() {
  const { action, platform, platforms, push, registry, fullDirs } = options;
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
    return;
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
}
