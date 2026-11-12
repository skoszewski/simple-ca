import { cpSync, existsSync, readdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { changelogVersion, host, options, root, run, scratchDir, works } from "./context.mjs";

// The image of setup that apt runs, built from its directory.
const builderImage = "simple-ca-builder";

export async function apt() {
  const { platform, positional } = options;
  const debDir = platform === "" ? join(root, "dist") : resolve(platform);
  const aptDir = positional[2] === undefined ? join(root, "apt") : resolve(positional[2]);
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
  const engine = host === "darwin" && works("container", ["--version"]) ? "container" : "docker";
  if (!works(engine, ["image", "inspect", builderImage])) {
    console.error(`apt: ${engine} has no image ${builderImage}; see ./build.mjs setup`);
    process.exit(1);
  }
  const scratch = scratchDir("apt");
  const repo = join(scratch, "repo");
  const secrets = join(scratch, "secrets");
  try {
    for (const name of debs) {
      cpSync(join(debDir, name), join(repo, name));
    }
    cpSync(keyFile, join(secrets, "gpg_key"));
    if (passphraseFile !== null) {
      cpSync(passphraseFile, join(secrets, "gpg_passphrase"));
    }
    const user = process.getuid === undefined ? [] : ["--user", `${process.getuid()}:${process.getgid()}`];
    run(engine, ["run", "--rm", ...user, "--tmpfs", "/tmp", "-w", "/repo",
      "--mount", `type=bind,source=${repo},target=/repo`,
      "--mount", `type=bind,source=${secrets},target=/run/secrets,readonly`,
      builderImage, "sh", "/usr/local/bin/build-repo.sh"]);
    rmSync(aptDir, { recursive: true, force: true });
    cpSync(repo, aptDir, { recursive: true });
    console.log(aptDir);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

export async function setup() {
  const engine = host === "darwin" && works("container", ["--version"]) ? "container" : "docker";
  const dir = join(root, builderImage);
  const args = ["-t", builderImage, "-f", join(dir, "Dockerfile"), dir];
  run(engine, engine === "container" ? ["build", ...args] : ["buildx", "build", "--load", ...args]);
}
