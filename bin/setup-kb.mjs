#!/usr/bin/env node
// Create a new OKF knowledge base from template/, ready for dsh-okf-guard:
//   npx -y github:John-UNOwen/dsh-okf-guard [folder]
// The folder defaults to ~/knowledge. An existing, non-empty folder is left alone.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const template = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'template')
const isWin = process.platform === 'win32'
const home = os.homedir()
const HOOKS = ['.githooks/pre-commit', '.githooks/commit-msg']

// The long form of a path (C:\Users\ABCDEF~1 -> the real name), or the path itself.
const longPath = (p) => {
  try {
    return fs.realpathSync.native(p)
  } catch {
    return p
  }
}
const realHome = longPath(home)

// Paths are printed from the home folder on, so the account name never shows.
const shown = (p) => {
  const rel = path.relative(realHome, longPath(p))
  if (!rel) return isWin ? '%USERPROFILE%' : '~'
  if (rel.startsWith('..') || path.isAbsolute(rel)) return p
  return isWin ? `%USERPROFILE%\\${rel}` : `~/${rel}`
}
const mask = (s) => [home, realHome].reduce((t, h) => t.split(h).join(isWin ? '%USERPROFILE%' : '~'), String(s))

function fail(msg) {
  console.error(`setup: ${msg}`)
  process.exit(1)
}

function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8', timeout: 120000 })
  return { ok: !r.error && r.status === 0, out: `${r.stdout || ''}${r.stderr || ''}`.trim() }
}

function findPython() {
  const ok = 'import sys; sys.exit(sys.version_info < (3, 8))'
  for (const [cmd, pre] of isWin ? [['python', []], ['py', ['-3']], ['python3', []]] : [['python3', []], ['python', []]]) {
    if (run(cmd, [...pre, '-c', ok]).ok) return [cmd, pre]
  }
  return null
}

function findOkf() {
  if (process.env.OKF_EXE && fs.existsSync(process.env.OKF_EXE)) return process.env.OKF_EXE
  if (run('okf', ['--version']).ok) return 'okf'
  const cand = path.join(home, '.cargo', 'bin', isWin ? 'okf.exe' : 'okf')
  return fs.existsSync(cand) ? cand : null
}

const args = process.argv.slice(2)
if (args.includes('-h') || args.includes('--help')) {
  console.log('Usage: npx -y github:John-UNOwen/dsh-okf-guard [folder]\n\nCreates an OKF knowledge base (default ~/knowledge) with kb.py and the git hooks, and makes its first commit.')
  process.exit(0)
}
if (args.length > 1) fail('give at most one folder.')
const target = path.resolve(args[0] ? args[0].replace(/^~(?=$|[\\/])/, home) : path.join(home, 'knowledge'))

// Check everything before touching the disk.
if (!fs.existsSync(path.join(template, '.kb', 'kb.py'))) fail('template/ is missing from this copy of dsh-okf-guard.')
const existed = fs.existsSync(target)
if (existed && (!fs.statSync(target).isDirectory() || fs.readdirSync(target).length)) {
  fail(`${shown(target)} already exists and is not empty, so nothing was changed. dsh-okf-guard guards an existing knowledge base as it is.`)
}
if (!run('git', ['--version']).ok) fail('git was not found. Install it from https://git-scm.com/ and run this again.')
for (const [key, envs] of [['user.name', ['GIT_AUTHOR_NAME', 'GIT_COMMITTER_NAME']], ['user.email', ['GIT_AUTHOR_EMAIL', 'GIT_COMMITTER_EMAIL']]]) {
  if (!run('git', ['config', key]).out && !envs.every((e) => process.env[e])) {
    fail(`git has no ${key}, and setup makes the first commit. Set it with: git config --global ${key} "..."`)
  }
}
const py = findPython()
if (!py) fail('Python 3.8 or later was not found (tried python, py and python3).')
const okf = findOkf()
if (!okf) fail('the okf tool was not found (OKF_EXE, PATH, ~/.cargo/bin). Install it with: cargo install okf')

fs.mkdirSync(target, { recursive: true })
fs.cpSync(template, target, { recursive: true })

const env = okf === 'okf' ? null : okf
if (env) process.env.OKF_EXE = env
const steps = [
  ['git init', () => run('git', ['init', '-q', '-b', 'main'], target)],
  ['git config core.hooksPath', () => run('git', ['config', 'core.hooksPath', '.githooks'], target)],
  ['kb.py log', () => run(py[0], [...py[1], path.join(target, '.kb', 'kb.py'), 'log', 'Created', 'index.md', 'knowledge base'], target)],
  ['git add', () => run('git', ['add', '-A'], target)],
  ['mark the hooks executable', () => {
    if (!isWin) for (const h of HOOKS) fs.chmodSync(path.join(target, h), 0o755)
    return run('git', ['update-index', '--chmod=+x', ...HOOKS], target)
  }],
  ['first commit', () => run('git', ['commit', '-q', '-m', 'kb: start the knowledge base'], target)],
]
for (const [name, step] of steps) {
  const r = step()
  if (!r.ok) {
    // Undo only what this run made, so running it again starts clean.
    if (existed) for (const e of fs.readdirSync(target)) fs.rmSync(path.join(target, e), { recursive: true, force: true })
    else fs.rmSync(target, { recursive: true, force: true })
    fail(`${name} failed, so the new folder was removed again:\n${mask(r.out)}`)
  }
}

const kbPy = isWin ? `python "${shown(target).replace('%USERPROFILE%', '$env:USERPROFILE')}\\.kb\\kb.py"` : `python3 ${shown(target)}/.kb/kb.py`
console.log(`Knowledge base created at ${shown(target)}, with its first commit.`)
const same = (a, b) => (isWin ? a.toLowerCase() === b.toLowerCase() : a === b)
if (!same(longPath(target), path.join(realHome, 'knowledge'))) {
  console.log(`It is not at ~/knowledge, so set knowledgeRoot in the profile's cordis.patch.yml (see the README).`)
}
console.log(`\nTry it:\n  ${kbPy} new projects/my-app/decisions/use-sqlite.md --type Decision --title 'Use SQLite for the cache' --description 'Why SQLite beats a JSON file.' --by human:me`)
