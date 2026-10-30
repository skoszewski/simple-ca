#!/usr/bin/env node

// Releases the newest CHANGELOG.md entry: checks the sources, commits everything on dev with the
// entry's summary line, tags the commit vX.Y.Z with the entry as the release notes, moves main to
// it, and pushes dev, main and the tag together.

import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';

const CHANGELOG = `${import.meta.dirname}/CHANGELOG.md`;

const usage = `Usage: release.mjs [-h|--help] [-n|--dry-run] [--no-push] [-m|--message <message>]

  -m, --message  commit message; default: the summary line of the newest CHANGELOG.md entry,
                 the line between blank lines right after its "## x.y.z" heading
  -n, --dry-run  print the commands instead of running them
  --no-push      commit, tag and move main, but do not push

The tag is v and the version of the heading, x.y.z or a semver prerelease such as x.y.z-rc.1; its
message, and so the GitHub release notes, is the entry below the heading. The release is made from
dev: dev, main and the tag are pushed in one atomic push, and the tag builds the release.`;

const { values } = parseArgs({
  options: {
    message: { type: 'string', short: 'm' },
    'dry-run': { type: 'boolean', short: 'n', default: false },
    'no-push': { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  },
});

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

// The newest entry: its version from the first "## " heading, its summary line when the heading is
// followed by a blank line, one line that is not a "-" item, and another blank line, and its notes,
// every line up to the next "## " heading.
const lines = readFileSync(CHANGELOG, 'utf8').split('\n');
const heading = lines.findIndex((line) => line.startsWith('## '));
if (heading === -1) fail(`${CHANGELOG} has no "## x.y.z" entry`);
const version = lines[heading].slice(3).trim();
const number = '(0|[1-9][0-9]*)';
const identifier = '(0|[1-9][0-9]*|[0-9]*[a-zA-Z-][0-9a-zA-Z-]*)';
if (!new RegExp(`^${number}\\.${number}\\.${number}(-${identifier}(\\.${identifier})*)?$`).test(version)) {
  fail(`${CHANGELOG}: "${version}" is not a version such as 3.2.0 or 3.2.0-rc.1`);
}
const tag = `v${version}`;
const [above, line, below] = lines.slice(heading + 1, heading + 4);
const summary = above?.trim() === '' && below?.trim() === '' && line?.trim() && !line.startsWith('-') && !line.startsWith('#') ? line.trim() : undefined;
const next = lines.findIndex((line, index) => index > heading && line.startsWith('## '));
const notes = lines.slice(heading + 1, next === -1 ? undefined : next).join('\n').trim() + '\n';

const message = values.message ?? summary;
if (!message) {
  fail(`no commit message: pass -m, or put a summary line between blank lines right after the newest heading of ${CHANGELOG}`);
}

if (read('git', 'branch', '--show-current') !== 'dev') fail('a release is made from dev');
if (spawnSync('git', ['rev-parse', '-q', '--verify', `refs/tags/${tag}`], { cwd: import.meta.dirname }).status === 0 ||
  read('git', 'ls-remote', '--tags', 'origin', `refs/tags/${tag}`) !== '') {
  fail(`tag ${tag} exists; add a new CHANGELOG.md entry first`);
}

run('node', 'build.mjs', 'check');
if (read('git', 'status', '--porcelain') !== '') {
  run('git', 'add', '-A');
  run('git', 'commit', '-m', message);
}

// The notes are the tag's message, kept with their Markdown headings.
const notesDir = mkdtempSync(join(tmpdir(), 'release-'));
const notesFile = join(notesDir, 'notes.md');
writeFileSync(notesFile, notes);
try {
  run('git', 'tag', '-a', tag, '--cleanup=whitespace', '-F', notesFile);
} finally {
  rmSync(notesDir, { recursive: true, force: true });
}
run('git', 'fetch', '.', 'dev:main');
if (values['no-push']) process.exit(0);

run('git', 'push', '--atomic', 'origin', 'dev', 'main', tag);
