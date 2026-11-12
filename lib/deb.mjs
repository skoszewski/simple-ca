import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { changelogVersion, root, run, scratchDir, src } from "./context.mjs";

/**
 * Builds the Debian package of dir, the source package source, to dist/ with engine: for the
 * architecture of the engine with docker, and for amd64 and arm64 with the container CLI.
 */
export function buildDeb(engine, dir, source, internal = false) {
  if (!changelogVersion) {
    console.error("CHANGELOG.md has no \"## x.y.z\" entry");
    process.exit(1);
  }
  // debian/changelog from the newest CHANGELOG.md entry.
  const lines = readFileSync(join(root, "CHANGELOG.md"), "utf8").split(/^## /m)[1].split("\n").slice(1);
  const summary = lines.find((line) => line.trim() !== "");
  const items = lines.filter((line) => /^(- |  \S)/.test(line))
    .map((line) => line.startsWith("- ") ? `  * ${line.slice(2)}` : `    ${line.trim()}`);
  // An entry x.y.z-N is the Debian revision N of vx.y.z.
  const [, upstream, revision = "1"] = changelogVersion.match(/^(.*?)(?:-([0-9]+))?$/);
  const upstreamTag = spawnSync("git", ["tag", "--list", `v${upstream}`], { cwd: root, encoding: "utf8" });
  const prerelease = !internal && upstreamTag.status === 0 && upstreamTag.stdout.trim() === "";
  const debVersion = prerelease ? `${upstream}~rc-${revision}` : `${upstream}-${revision}`;
  const date = new Date().toUTCString().replace(/GMT$/, "+0000");
  writeFileSync(join(src, dir, "debian", "changelog"),
    `${source} (${debVersion}) unstable; urgency=medium\n\n  ${summary}\n\n${items.join("\n")}\n\n` +
    ` -- Slawomir Koszewski <slawek@koszewscy.waw.pl>  ${date}\n`);
  const out = scratchDir(`deb-${source}`);
  try {
    const args = ["-f", join(src, dir, "Dockerfile"), "--build-arg", `VERSION=v${upstream}${prerelease ? "-rc" : ""}`,
      "--output", `type=local,dest=${out}`, src];
    if (engine === "container") {
      // The container CLI writes each architecture to out.tar/<os>_<arch>/ below dest.
      run("container", ["build", "--platform", "linux/amd64", "--platform", "linux/arm64", ...args]);
    } else {
      run("docker", ["buildx", "build", ...args]);
    }
    mkdirSync(join(root, "dist"), { recursive: true });
    for (const file of readdirSync(out, { recursive: true }).filter((file) => file.endsWith(".deb"))) {
      copyFileSync(join(out, file), join(root, "dist", basename(file)));
      console.log(`dist/${basename(file)}`);
    }
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}

// The Debian package directories of src/ and source package names.
export const debPackages = [["debian-package", "simple-ca"], ["debian-package-lite", "simple-ca-lite"]];

export async function deb() {
  for (const [dir, source] of debPackages) {
    buildDeb("docker", dir, source);
  }
}
