import { existsSync, mkdirSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { binDir, host, hostArch, root, run } from "./context.mjs";

/** Unpacks the newest archive of each program set of dist/ for the host over the files of bin/. */
export function install() {
  const distDir = join(root, "dist");
  const archive = new RegExp(`^(simple-ca|simple-ca-lite)-(\\d+\\.\\d+\\.\\d+(?:-\\d+)?)-${host}-${hostArch}\\.(?:tar\\.gz|zip)$`);
  const newest = new Map();
  for (const file of existsSync(distDir) ? readdirSync(distDir) : []) {
    const [, name, version] = file.match(archive) ?? [];
    if (name && (!newest.has(name) || version.localeCompare(newest.get(name).version, undefined, { numeric: true }) > 0)) {
      newest.set(name, { version, file });
    }
  }
  if (newest.size === 0) {
    console.error(`install: dist/ has no archive for ${host}/${hostArch}; build one with ./build.mjs dist`);
    process.exit(1);
  }
  mkdirSync(binDir, { recursive: true });
  for (const { file } of newest.values()) {
    run("tar", ["-xf", join(distDir, file), "-C", binDir]);
    console.log(`bin/ <- dist/${file}`);
  }
}
