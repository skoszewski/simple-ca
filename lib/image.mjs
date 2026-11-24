import { cpSync, existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { changelogVersion, options, root, run, scratchDir, src, step, works } from "./context.mjs";
import { writeSums } from "./sums.mjs";

export async function image() {
  buildImages(options.action);
}

/** Builds the images with engine, docker or container, as the options of the command line say. */
export function buildImages(engine) {
  const { platform, platforms, push, registry, fullDirs } = options;
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
  if (engine === "container" && !works("container", ["--version"])) {
    console.error("container: Apple's container CLI is not installed");
    process.exit(1);
  }

  // Builds the image of dockerfile in context with tags, and pushes it with --push.
  const buildImage = (dockerfile, context, tags, buildArgs) => {
    const args = [...buildArgs.flatMap((arg) => ["--build-arg", arg]), ...tags.flatMap((tag) => ["-t", tag])];
    step(`Building the image ${tags[0]} with ${engine}${push ? ", and pushing it" : ""}...`);
    if (engine === "docker") {
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

  // simple-ca-full: the image above with the archives, their sum files and the repository.
  if (fullDirs !== null) {
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

  // With --prune, the older versions of both images are removed from the local image store.
  if (options.prune) {
    // The tags of the local images as [repository, tag, id]; container names an image without a
    // registry docker.io/library/NAME.
    const images = engine === "docker" ?
      run("docker", ["image", "ls", "--format", "{{.Repository}} {{.Tag}} {{.ID}}"], { capture: true })
        .split("\n").filter(Boolean).map((line) => line.split(" ")) :
      JSON.parse(run("container", ["image", "list", "--format", "json"], { capture: true })).map(({ name, id }) => {
        const at = name.lastIndexOf(":");
        return [name.slice(0, at).replace(/^docker\.io\/library\//, ""), name.slice(at + 1), id];
      });
    for (const repo of [`${prefix}simple-ca`, `${prefix}simple-ca-full`]) {
      const own = images.filter(([repository]) => repository === repo);
      const latest = own.find(([, tag]) => tag === "latest");
      if (!latest) {
        step(`Pruning ${repo}: no ${repo}:latest, nothing removed`);
        continue;
      }
      const old = own.filter(([, tag, id]) => id !== latest[2] && tag !== "<none>").map(([, tag]) => `${repo}:${tag}`);
      step(`Pruning ${repo}: ${old.length === 0 ? "no older versions" : `removing ${old.join(", ")}`}`);
      if (old.length > 0) {
        run(engine, engine === "docker" ? ["image", "rm", ...old] : ["image", "delete", ...old]);
      }
    }
  }
}

