import { join } from "node:path";
import { buildRepository } from "./builder.mjs";
import { options, root } from "./context.mjs";
import { dist } from "./dist.mjs";
import { buildImages } from "./image.mjs";
import { sums } from "./sums.mjs";

/**
 * Runs dist, apt, sums and docker in turn with the options of the command line: apt signs the
 * packages of dist/ into APT of --full, apt/ by default, and sums writes the sum files of DL of
 * --full, dist/ by default, with --glob.
 */
export async function publish() {
  const [downloadsDir = join(root, "dist"), repoDir = join(root, "apt")] = options.fullDirs ?? [];
  await dist();
  buildRepository(join(root, "dist"), repoDir);
  await sums(downloadsDir, options.glob ?? "*");
  buildImages("docker");
}
