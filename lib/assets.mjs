import { createHash } from "node:crypto";
import { readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { options, run, scratchDir, src } from "./context.mjs";

const markdownAssets = join(src, "assets", "markdown");
const versionFile = join(markdownAssets, ".version");
const checksumFile = join(src, "assets", "markdown.sha256");
const requiredTag = readFileSync(join(src, "go.mod"), "utf8")
  .match(/^\s*github\.com\/skoszewski\/serve-markdown\/v3 (v\S+)/m)?.[1] ?? "";

/** Downloads, checks and unpacks the serve-markdown assets of go.mod into assets/markdown. */
async function fetchMarkdownAssets() {
  if (requiredTag === "") {
    throw new Error("go.mod requires no github.com/skoszewski/serve-markdown/v3");
  }
  const tag = requiredTag;
  const url = `https://github.com/skoszewski/serve-markdown/releases/download/${tag}/` +
    `serve-markdown-assets-${tag.slice(1)}.tar.gz`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url}: ${response.status} ${response.statusText}`);
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  const pinned = readFileSync(checksumFile, "utf8").split("\n").map((line) => line.trim().split(/\s+/))
    .find(([version]) => version === tag)?.[1];
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (pinned !== actual) {
    throw new Error(`${url}: SHA-256 ${actual} is not the one assets/markdown.sha256 has for ${tag}, ${pinned ?? "none"}`);
  }
  const scratch = scratchDir("assets");
  try {
    const archive = join(scratch, "assets.tar.gz");
    writeFileSync(archive, bytes);
    for (const name of readdirSync(markdownAssets)) {
      if (name !== ".gitkeep") {
        rmSync(join(markdownAssets, name), { recursive: true, force: true });
      }
    }
    run("tar", ["-xzf", archive, "-C", markdownAssets]);
    writeFileSync(versionFile, `${tag}\n`);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
  console.log(`assets/markdown: serve-markdown ${tag}`);
}

// The serve-markdown assets are fetched when go.mod requires another version.
export async function ensureMarkdownAssets() {
  const { action } = options;
  if (["build", "test", "check", "deb", "dist"].includes(action)) {
    let held = "";
    try {
      held = readFileSync(versionFile, "utf8").trim();
    } catch {}
    if (requiredTag !== held) {
      try {
        await fetchMarkdownAssets();
      } catch (error) {
        if (action === "deb" || action === "dist") {
          console.error(error.message);
          process.exit(1);
        }
        console.error(`warning: ${error.message}; simple-ca is built without the /help/ and /docs/ pages`);
      }
    }
  }
}

export async function assets() {
  try {
    await fetchMarkdownAssets();
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
