#!/usr/bin/env node

// Releases the newest CHANGELOG.md entry: commits everything on dev with the entry's summary line,
// and with --push tags dev vX.Y.Z with the entries since the last tag as the release notes, moves
// main to it, and pushes dev, main and the tag together to a git remote, or to every remote. A
// release X.Y.Z-N of the documentation or the packaging alone is pushed without a tag.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

const CHANGELOG = `${import.meta.dirname}/CHANGELOG.md`;

const usage = `Usage: release.mjs [-h|--help] [-n|--dry-run] [--push REMOTE|all]

  -n, --dry-run  print the commands instead of running them
  --push REMOTE  also tag the release and push dev, main and the tag to the git remote REMOTE,
                 or to every remote of git remote with all

Without --push, the changes are committed with the summary line of the newest CHANGELOG.md entry,
the line between blank lines right after its "## x.y.z" heading; that commit marks the entry as
released, and the next change needs a new entry. With --push, the newest entry is committed when it
is not yet, dev is tagged v and the version of the heading, x.y.z or a semver prerelease such as
x.y.z-rc.1, main is moved to it, and dev, main and the tag are pushed in one atomic push to each
remote named; the tag builds the release there. A tag made by an earlier --push is pushed to the
remotes that do not have it yet, so --push gitea can follow --push origin. The tag's message, and
so the release notes, are the entries since the last tagged one. A version x.y.z-N, N a number, is
a release of the documentation or the packaging alone: --push moves main to dev and pushes them
without a tag, so nothing is built, and the entry goes into the notes of the next tagged release.`;

let values;
try {
  ({ values } = parseArgs({
    options: {
      'dry-run': { type: 'boolean', short: 'n', default: false },
      push: { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  }));
} catch (error) {
  console.error(`release: ${error.message}\n\n${usage}`);
  process.exit(2);
}

if (values.help) {
  console.log(usage);
  process.exit(0);
}

function fail(message) {
  console.error(`release: ${message}`);
  process.exit(1);
}

// Runs a command in the repository, or prints it on a dry run; stops with its exit status when it fails.
function run(command, ...args) {
  if (values['dry-run']) {
    console.log([command, ...args].map((arg) => (/^[\w@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replaceAll("'", "'\\''")}'`)).join(' '));
    return;
  }
  const { status } = spawnSync(command, args, { cwd: import.meta.dirname, stdio: 'inherit' });
  if (status !== 0) process.exit(status ?? 1);
}

// Runs a command that only reads, also on a dry run, and returns what it printed.
function read(command, ...args) {
  const result = spawnSync(command, args, { cwd: import.meta.dirname, encoding: 'utf8' });
  if (result.status !== 0) fail(`${command} ${args.join(' ')}: ${(result.stderr || result.error?.message || '').trim()}`);
  return result.stdout.trim();
}

// The entries, newest first: each "## " heading with its version, and its body, every line up to
// the next heading. The summary line of the newest entry follows its heading between blank lines,
// and is neither a "-" item nor a heading.
const lines = readFileSync(CHANGELOG, 'utf8').split('\n');
const headings = lines.flatMap((line, index) => (line.startsWith('## ') ? [index] : []));
if (headings.length === 0) fail(`${CHANGELOG} has no "## x.y.z" entry`);
const entries = headings.map((heading, i) => ({
  version: lines[heading].slice(3).trim(),
  body: lines.slice(heading + 1, headings[i + 1]).join('\n').trim(),
}));
const { version } = entries[0];
const number = '(0|[1-9][0-9]*)';
const identifier = '(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)';
if (!new RegExp(`^${number}\\.${number}\\.${number}(-${identifier}(\\.${identifier})*)?$`).test(version)) {
  fail(`${CHANGELOG}: "${version}" is not a version such as 3.2.0 or 3.2.0-rc.1`);
}
const tag = `v${version}`;
// A version x.y.z-N, N a number, is a later release of the same code with changes to the
// documentation or the packaging alone; it is not tagged, so nothing builds it.
const untagged = /-[0-9]+$/.test(version);
const [above, line, below] = lines.slice(headings[0] + 1, headings[0] + 4);
const summary = above?.trim() === '' && below?.trim() === '' && line?.trim() && !line.startsWith('-') && !line.startsWith('#') ? line.trim() : undefined;
if (!summary) fail(`put a summary line between blank lines right after the newest heading of ${CHANGELOG}`);

if (read('git', 'branch', '--show-current') !== 'dev') fail('a release is made from dev');
// The remotes --push names, one or all of git remote; without --push, a release counts as
// published once every remote has its tag.
const defined = read('git', 'remote').split('\n').filter(Boolean);
if (defined.length === 0) fail('the repository has no git remote');
if (values.push !== undefined && values.push !== 'all' && !defined.includes(values.push)) {
  fail(`--push ${values.push}: not a git remote; the remotes are ${defined.join(', ')}, or all`);
}
const remotes = values.push === undefined || values.push === 'all' ? defined : [values.push];
const localTags = new Set(read('git', 'tag', '--list').split('\n'));
const remoteTags = new Map(remotes.map((remote) => [remote, new Set(read('git', 'ls-remote', '--tags', remote).split('\n')
  .map((ref) => ref.split('refs/tags/')[1]?.replace(/\^\{\}$/, '')).filter(Boolean))]));
// The remotes the tag is still to be pushed to; it is published once every one has it.
const pending = remotes.filter((remote) => !remoteTags.get(remote).has(tag));
if (pending.length === 0) fail(`${tag} is published on ${remotes.join(' and ')}; add a new CHANGELOG.md entry first`);

// The release commit of an entry is a commit on dev whose message is the entry's summary line.
const hasCommits = spawnSync('git', ['rev-parse', '-q', '--verify', 'HEAD'], { cwd: import.meta.dirname }).status === 0;
const committed = hasCommits && read('git', 'log', '--format=%s', 'dev').split('\n').includes(summary);
const dirty = read('git', 'status', '--porcelain') !== '';
if (committed && dirty) fail(`${version} is released; add a new CHANGELOG.md entry for the changes`);
if (committed && values.push === undefined) fail(`${version} is released; add a new CHANGELOG.md entry, or publish it with --push`);
if (!committed && !dirty) fail(`nothing to commit for ${version}`);
if (!committed) {
  run('git', 'add', '-A');
  run('git', 'commit', '-m', summary);
}
if (values.push === undefined) process.exit(0);
if (untagged) {
  run('git', 'fetch', '.', 'dev:main');
  for (const remote of remotes) run('git', 'push', '--atomic', remote, 'dev', 'main');
  process.exit(0);
}

// The tag is made once; a tag of an earlier --push is pushed as it is to the remotes lacking it.
if (!localTags.has(tag)) {
  // The notes, the tag's message kept with its Markdown headings, are the body of the newest entry
  // followed by the entries released since the last tagged one, each under its own heading.
  const isTagged = (version) => localTags.has(`v${version}`) || remotes.some((remote) => remoteTags.get(remote).has(`v${version}`));
  const last = entries.findIndex((entry, i) => i > 0 && isTagged(entry.version));
  const notes = [entries[0].body, ...entries.slice(1, last === -1 ? undefined : last).map((entry) => `## ${entry.version}\n\n${entry.body}`)]
    .join('\n\n') + '\n';
  const notesDir = mkdtempSync(join(tmpdir(), 'release-'));
  const notesFile = join(notesDir, 'notes.md');
  writeFileSync(notesFile, notes);
  try {
    run('git', 'tag', '-a', tag, '--cleanup=whitespace', '-F', notesFile);
  } finally {
    rmSync(notesDir, { recursive: true, force: true });
  }
}
run('git', 'fetch', '.', 'dev:main');
for (const remote of pending) run('git', 'push', '--atomic', remote, 'dev', 'main', tag);
