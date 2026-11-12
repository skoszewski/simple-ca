import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, matchesGlob, resolve } from "node:path";
import { options } from "./context.mjs";

/**
 * Writes NAME.sha256, the line of sha256sum, for each file of dir matching glob, skipping dot
 * files, sum files and those whose sum file already holds the line, and prints the names written.
 */
export function writeSums(dir, glob) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const name = entry.name;
    if (!entry.isFile() || name.startsWith(".") || name.endsWith(".sha256") || !matchesGlob(name, glob)) {
      continue;
    }
    const line = `${createHash("sha256").update(readFileSync(join(dir, name))).digest("hex")}  ${name}\n`;
    const sumFile = join(dir, `${name}.sha256`);
    if (!existsSync(sumFile) || readFileSync(sumFile, "utf8") !== line) {
      writeFileSync(sumFile, line);
      console.log(`${name}.sha256`);
    }
  }
}

export async function sums() {
  const { platform, positional } = options;
  const dir = resolve(platform);
  const glob = positional[2] ?? "*";
  if (!existsSync(dir)) {
    console.error(`sums: ${dir} does not exist`);
    process.exit(1);
  }
  writeSums(dir, glob);
}
