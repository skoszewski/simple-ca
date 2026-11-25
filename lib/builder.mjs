import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { changelogVersion, options, root, run, scratchDir, step, works } from "./context.mjs";

// The image of setup that apt runs, built from its directory.
const builderImage = "simple-ca-builder";

export async function apt() {
  const { platform, positional } = options;
  buildRepository(platform === "" ? join(root, "dist") : resolve(platform),
    positional[2] === undefined ? join(root, "apt") : resolve(positional[2]));
}

/** Builds the signed apt repository aptDir of the Debian packages of the newest entry in debDir. */
export function buildRepository(debDir, aptDir) {
  // The destination is replaced, so it must be empty or hold a repository.
  if (aptDir === debDir ||
    (existsSync(aptDir) && readdirSync(aptDir).length > 0 && !existsSync(join(aptDir, "Release")))) {
    console.error(`apt: ${aptDir} is not empty and holds no repository, or is the source directory`);
    process.exit(1);
  }
  const keyFile = resolve(options.keyFile);
  const passphraseFile = options.passphraseFile === null ? null : resolve(options.passphraseFile);
  // The packages of the newest entry: X.Y.Z-N, or X.Y.Z~rc-N before the tag, as buildDeb names them.
  const [, upstream, revision = "1"] = changelogVersion.match(/^(.*?)(?:-([0-9]+))?$/);
  const debs = existsSync(debDir) ? readdirSync(debDir).filter((name) =>
    new RegExp(`^simple-ca(-lite)?_${upstream.replaceAll(".", "\\.")}(~rc)?-${revision}_[a-z0-9]+\\.deb$`).test(name)) : [];
  if (debs.length === 0) {
    console.error(`apt: ${debDir} holds no Debian packages of ${changelogVersion}; see ./build.mjs deb`);
    process.exit(1);
  }
  for (const file of [keyFile, passphraseFile].filter((file) => file !== null && !existsSync(file))) {
    console.error(`apt: ${file} does not exist`);
    process.exit(1);
  }
  if (!works("docker", ["image", "inspect", builderImage])) {
    console.error(`apt: docker has no image ${builderImage}; see ./build.mjs setup`);
    process.exit(1);
  }
  const scratch = scratchDir("apt");
  const repo = join(scratch, "repo");
  const secrets = join(scratch, "secrets");
  const out = join(scratch, "out");
  // The copy of the key and the container are removed on every exit, also when a failed docker
  // command ends the build.
  let container = "";
  const cleanup = () => {
    if (container !== "") {
      spawnSync("docker", ["rm", "-f", container], { stdio: "ignore" });
    }
    rmSync(scratch, { recursive: true, force: true });
  };
  process.on("exit", cleanup);
  try {
    for (const name of debs) {
      cpSync(join(debDir, name), join(repo, name));
    }
    mkdirSync(secrets, { mode: 0o700 });
    for (const [file, name] of [[keyFile, "gpg_key"], [passphraseFile, "gpg_passphrase"]]) {
      if (file !== null) {
        copyFileSync(file, join(secrets, name));
        chmodSync(join(secrets, name), 0o600);
      }
    }
    // The files are copied into a container and out of it, as no bind mount reaches a remote engine.
    step(`Signing the apt repository of ${debs.length} packages with docker...`);
    container = run("docker", ["create", "--tmpfs", "/tmp", builderImage,
      "sh", "-c", "cd /repo && exec sh /usr/local/bin/build-repo.sh"], { capture: true }).trim();
    run("docker", ["cp", repo, `${container}:/repo`]);
    run("docker", ["cp", secrets, `${container}:/run/secrets`]);
    run("docker", ["start", "-a", container]);
    run("docker", ["cp", `${container}:/repo`, out]);
    rmSync(aptDir, { recursive: true, force: true });
    cpSync(out, aptDir, { recursive: true });
    console.log(aptDir);
  } finally {
    cleanup();
    process.off("exit", cleanup);
  }
}

export async function setup() {
  const dir = join(root, builderImage);
  step(`Building the image ${builderImage} with docker...`);
  run("docker", ["buildx", "build", "--load", "-t", builderImage, "-f", join(dir, "Dockerfile"), dir]);
}
