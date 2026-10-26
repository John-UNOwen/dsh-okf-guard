// End-to-end tests for template/.kb/kb.py and the git hooks in template/.githooks.
// Each case clones a scratch knowledge base built from template/ in os.tmpdir().
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const template = path.join(repo, 'template');
const isWin = process.platform === 'win32';

function works(cmd, args = ['--version']) {
  try {
    const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 20000 });
    return r.status === 0;
  } catch {
    return false;
  }
}

function findOkf() {
  if (process.env.OKF_EXE && fs.existsSync(process.env.OKF_EXE)) return process.env.OKF_EXE;
  if (works('okf')) return 'okf';
  const home = process.env.USERPROFILE || os.homedir();
  const cand = path.join(home, '.cargo', 'bin', isWin ? 'okf.exe' : 'okf');
  return fs.existsSync(cand) ? cand : null;
}

const PY = ['python', 'python3', 'py'].find((p) => works(p, ['-c', 'import sys; sys.exit(sys.version_info < (3, 8))']));
const GIT = works('git');
const OKF = findOkf();
const missing = [!PY && 'python 3.8+', !GIT && 'git', !OKF && 'okf'].filter(Boolean);
const skip = missing.length ? `kb.py tests skipped: ${missing.join(', ')} not found` : false;
if (skip) console.log('# ' + skip);

const env = {
  ...process.env,
  GIT_AUTHOR_NAME: 'kb test',
  GIT_AUTHOR_EMAIL: 'kb@example.invalid',
  GIT_COMMITTER_NAME: 'kb test',
  GIT_COMMITTER_EMAIL: 'kb@example.invalid',
};

function run(cwd, cmd, args, extraEnv) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', env: { ...env, ...extraEnv }, timeout: 60000 });
  if (r.error) throw r.error;
  return { code: r.status, out: (r.stdout || '') + (r.stderr || '') };
}
const git = (d, ...args) => run(d, 'git', ['-c', 'core.quotepath=false', ...args]);
const kb = (d, ...args) => run(d, PY, [path.join(d, '.kb', 'kb.py'), ...args]);
const file = (d, rel) => path.join(d, ...rel.split('/'));
const read = (d, rel) => fs.readFileSync(file(d, rel), 'utf8');
const write = (d, rel, text) => {
  fs.mkdirSync(path.dirname(file(d, rel)), { recursive: true });
  fs.writeFileSync(file(d, rel), text);
};
const rm = (d, ...rels) => rels.forEach((r) => fs.rmSync(file(d, r)));
const headFile = (d, rel) => {
  const r = git(d, 'show', `HEAD:${rel}`);
  return r.code === 0 ? r.out : null;
};
const headTree = (d) => git(d, 'ls-tree', '-r', '--name-only', 'HEAD').out.split('\n').filter(Boolean);
const status = (d) => git(d, 'status', '--porcelain').out.split('\n').filter(Boolean);
const gitCommit = (d, ...args) => git(d, 'commit', ...args);

let tmp;
let base;
let n = 0;

function setupBase() {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kbt-'));
  base = path.join(tmp, 'base');
  fs.cpSync(template, base, { recursive: true });
  const steps = [
    () => git(base, 'init', '-q', '-b', 'main'),
    () => git(base, 'config', 'core.hooksPath', '.githooks'),
    () => kb(base, 'log', 'Created', 'index.md', 'knowledge base'),
    () => git(base, 'add', '-A'),
    // The README step that keeps the hooks runnable on Linux and macOS clones.
    () => git(base, 'update-index', '--chmod=+x', '.githooks/pre-commit', '.githooks/commit-msg'),
    () => gitCommit(base, '-q', '-m', 'kb: start'),
  ];
  for (const s of steps) {
    const r = s();
    assert.equal(r.code, 0, r.out);
  }
}

function clone() {
  const d = path.join(tmp, `c${++n}`);
  assert.equal(git(tmp, 'clone', '-q', base, d).code, 0);
  git(d, 'config', 'core.hooksPath', '.githooks');
  git(d, 'config', 'kb.privateName', 'zeta');
  return d;
}

function newConcept(d, rel, title, desc = `${title}.`) {
  const r = kb(d, 'new', rel, '--type', 'Reference', '--title', title, '--description', desc, '--by', 'human:test');
  assert.equal(r.code, 0, r.out);
  write(d, rel, read(d, rel).replace(/^.*TODO\(kb\).*$/gm, 'Real text.'));
}

function commitNew(d, ...rels) {
  const r = kb(d, 'commit', '-m', 'kb: add ' + rels.map((x) => path.basename(x, '.md')).join(' '), ...rels);
  assert.equal(r.code, 0, r.out);
}

function dropLines(d, rel, needle) {
  write(d, rel, read(d, rel).split('\n').filter((l) => !l.includes(needle)).join('\n'));
}

describe('kb.py and hooks', { skip }, () => {
  before(setupBase);
  after(() => tmp && fs.rmSync(tmp, { recursive: true, force: true }));

  describe('#11 deletions', () => {
    test('deleting log.md is blocked', () => {
      const d = clone();
      rm(d, 'log.md');
      git(d, 'add', '-A');
      const r = gitCommit(d, '-m', 'kb: drop the log');
      assert.notEqual(r.code, 0, r.out);
      assert.match(r.out, /BLOCK log\.md: deleting log\.md is not allowed/);
      assert.ok(headTree(d).includes('log.md'));
    });

    test('deleting the root index.md is blocked', () => {
      const d = clone();
      rm(d, 'index.md');
      git(d, 'add', '-A');
      const r = gitCommit(d, '-m', 'kb: drop the root index');
      assert.notEqual(r.code, 0, r.out);
      assert.match(r.out, /BLOCK index\.md: deleting the root index\.md/);
    });

    test('deleting a folder index whose folder keeps a concept is blocked', () => {
      const d = clone();
      newConcept(d, 'projects/app-m/notes/m.md', 'M note');
      commitNew(d, 'projects/app-m/notes/m.md');
      rm(d, 'projects/app-m/notes/index.md');
      git(d, 'add', '-A');
      const r = gitCommit(d, '-m', 'kb: drop the notes index');
      assert.notEqual(r.code, 0, r.out);
      assert.match(r.out, /BLOCK projects\/app-m\/notes\/index\.md: its folder still has projects\/app-m\/notes\/m\.md/);
    });

    test('deleting a concept that an index still links to is blocked', () => {
      const d = clone();
      newConcept(d, 'projects/app-m/notes/m.md', 'M note');
      commitNew(d, 'projects/app-m/notes/m.md');
      rm(d, 'projects/app-m/notes/m.md');
      git(d, 'add', '-A');
      const r = gitCommit(d, '-m', 'kb: drop m');
      assert.notEqual(r.code, 0, r.out);
      assert.match(r.out, /BLOCK projects\/app-m\/notes\/m\.md: is deleted, but projects\/app-m\/notes\/index\.md still links to it/);
      assert.ok(headTree(d).includes('projects/app-m/notes/m.md'));
    });

    test('control: deleting a concept together with its index line commits', () => {
      const d = clone();
      newConcept(d, 'projects/app-m/notes/m1.md', 'M1 note');
      newConcept(d, 'projects/app-m/notes/m2.md', 'M2 note');
      commitNew(d, 'projects/app-m/notes/m1.md', 'projects/app-m/notes/m2.md');
      rm(d, 'projects/app-m/notes/m2.md');
      dropLines(d, 'projects/app-m/notes/index.md', '/m2.md');
      git(d, 'add', '-A');
      const r = gitCommit(d, '-m', 'kb: drop m2');
      assert.equal(r.code, 0, r.out);
      assert.ok(!headTree(d).includes('projects/app-m/notes/m2.md'));
    });
  });

  describe('#13 runnable hooks', () => {
    test('the setup records both hooks as executable', () => {
      const modes = git(base, 'ls-files', '-s', '.githooks').out;
      assert.match(modes, /^100755 \S+ 0\t\.githooks\/commit-msg$/m);
      assert.match(modes, /^100755 \S+ 0\t\.githooks\/pre-commit$/m);
    });

    test('the README setup marks the hooks executable before the first commit', () => {
      const readme = fs.readFileSync(path.join(repo, 'README.md'), 'utf8');
      const chmod = readme.indexOf('update-index --chmod=+x .githooks/pre-commit .githooks/commit-msg');
      const first = readme.indexOf('commit -m "kb: start the knowledge base"');
      assert.ok(chmod > 0 && first > chmod);
    });

    test('hook_installed() needs an executable hook outside Windows', () => {
      const d = clone();
      const code = [
        'import importlib.util, os, sys, types',
        'spec = importlib.util.spec_from_file_location("kb", sys.argv[1])',
        'kb = importlib.util.module_from_spec(spec); spec.loader.exec_module(kb)',
        'res = [kb.hook_installed()]',
        'for ok in (False, True):',
        '    kb.os = types.SimpleNamespace(name="posix", X_OK=os.X_OK, access=lambda p, m, ok=ok: ok)',
        '    res.append(kb.hook_installed())',
        'print(res)',
      ].join('\n');
      const r = run(d, PY, ['-c', code, file(d, '.kb/kb.py')]);
      assert.equal(r.out.trim(), '[True, False, True]', r.out);
    });

    test('kb.py commit runs the check itself when the hook is not executable',
      { skip: isWin && 'git for Windows runs hooks whatever their mode' }, () => {
        const d = clone();
        fs.chmodSync(file(d, '.githooks/pre-commit'), 0o644);
        newConcept(d, 'projects/app-e/notes/e.md', 'E note');
        fs.appendFileSync(file(d, 'projects/app-e/notes/e.md'), '\nTODO(kb) draft\n');
        const r = kb(d, 'commit', '-m', 'kb: add e', 'projects/app-e/notes/e.md');
        assert.notEqual(r.code, 0, r.out);
        assert.match(r.out, /pre-commit hook is not installed/);
        assert.match(r.out, /TODO\(kb\) placeholder/);
      });
  });
});
