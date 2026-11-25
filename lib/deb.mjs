import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { changelogSummary, changelogVersion, root, run, scratchDir, src, step } from "./context.mjs";

/**
 * Builds the Debian package of dir, the source package source, to dist/ with docker, for the
 * architecture of the Docker engine.
 */
export function buildDeb(dir, source, internal = false) {
  if (!changelogVersion) {
    console.error("CHANGELOG.md has no \"## x.y.z\" entry");
    process.exit(1);
  }
  // debian/changelog from the newest CHANGELOG.md entry.
  const lines = readFileSync(join(root, "CHANGELOG.md"), "utf8").split(/^## /m)[1].split("\n").slice(1);
  const items = lines.filter((line) => /^(- |  \S)/.test(line))
    .map((line) => line.startsWith("- ") ? `  * ${line.slice(2)}` : `    ${line.trim()}`);
  // An entry x.y.z-N is the Debian revision N of vx.y.z.
  const [, upstream, revision = "1"] = changelogVersion.match(/^(.*?)(?:-([0-9]+))?$/);
  const upstreamTag = spawnSync("git", ["tag", "--list", `v${upstream}`], { cwd: root, encoding: "utf8" });
  const prerelease = !internal && upstreamTag.status === 0 && upstreamTag.stdout.trim() === "";
  const debVersion = prerelease ? `${upstream}~rc-${revision}` : `${upstream}-${revision}`;
  const date = new Date().toUTCString().replace(/GMT$/, "+0000");
  writeFileSync(join(src, dir, "debian", "changelog"),
    `${source} (${debVersion}) unstable; urgency=medium\n\n  ${changelogSummary}\n\n${items.join("\n")}\n\n` +
    ` -- Slawomir Koszewski <slawek@koszewscy.waw.pl>  ${date}\n`);
  step(`Building the Debian package ${source} ${debVersion} with docker...`);
  const out = scratchDir(`deb-${source}`);
  try {
    const args = ["-f", join(src, dir, "Dockerfile"), "--build-arg", `VERSION=v${upstream}${prerelease ? "-rc" : ""}`,
      "--output", `type=local,dest=${out}`, src];
    run("docker", ["buildx", "build", ...args]);
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
    buildDeb(dir, source);
  }
}
