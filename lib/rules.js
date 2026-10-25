/**
 * Decision rules for okf-guard. `decide(exec)` takes one tool call and returns
 * { kind: 'deny' | 'ask', reason } or null to leave it alone.
 *
 * The rules catch mistakes, not attacks: a command that hides what it does
 * from these checks still meets the knowledge base's own git hooks when it
 * commits.
 */

import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { homedir, userInfo } from 'node:os'
import path from 'node:path'

const WIN = process.platform === 'win32'
const P = WIN ? path.win32 : path.posix
const GENERIC_NAMES = new Set(['user', 'users', 'admin', 'administrator', 'owner', 'default', 'public', 'guest', 'root', 'home'])
const TAG = 'okf-guard: '

/** Forward slashes, no trailing slash, lower case on Windows. */
function key(p) {
  const s = String(p).replace(/\\/g, '/').replace(/\/+$/, '')
  return WIN ? s.toLowerCase() : s
}

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** Drop surrounding quotes and expand ~, %USERPROFILE%, $env:USERPROFILE and $HOME. */
export function expandHome(p, home) {
  return String(p)
    .trim()
    .replace(/^["']|["']$/g, '')
    .replace(/^~(?=$|[\\/])/, () => home)
    .replace(/\$\{env:userprofile\}|\$env:userprofile|%userprofile%|\$\{home\}|\$env:home|\$home\b/gi, () => home)
}

/**
 * Split a shell command into segments at ; && || | newlines and a background
 * `&`, outside quotes. A call operator `&` (at the start, or after = ( { ,)
 * and the `&` of redirects like 2>&1 stay in place.
 */
export function splitSegments(cmd) {
  const out = []
  let cur = ''
  let quote = null
  const cut = () => {
    out.push(cur)
    cur = ''
  }
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]
    if (quote) {
      cur += c
      if (c === quote && cmd[i - 1] !== '`') quote = null
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      cur += c
      continue
    }
    if (c === ';' || c === '\n' || c === '\r') {
      cut()
      continue
    }
    if ((c === '&' && cmd[i + 1] === '&') || (c === '|' && cmd[i + 1] === '|')) {
      cut()
      i++
      continue
    }
    if (c === '|') {
      cut()
      continue
    }
    if (c === '&') {
      const prev = cur.replace(/\s+$/, '').slice(-1)
      const callOperator = prev === '' || '=({,'.includes(prev)
      const redirect = cmd[i - 1] === '>' || cmd[i + 1] === '>'
      if (!callOperator && !redirect) {
        cut()
        continue
      }
    }
    cur += c
  }
  cut()
  return out.map((s) => s.trim()).filter(Boolean)
}

/** Split one segment into words, removing quotes. A backtick escapes the next character inside "...". */
export function words(seg) {
  const out = []
  let cur = ''
  let quote = null
  let quoted = false
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i]
    if (quote) {
      if (quote === '"' && c === '`' && i + 1 < seg.length) cur += seg[++i]
      else if (c === quote) quote = null
      else cur += c
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      quoted = true
      continue
    }
    if (/\s/.test(c)) {
      if (cur || quoted) out.push(cur)
      cur = ''
      quoted = false
      continue
    }
    cur += c
  }
  if (cur || quoted) out.push(cur)
  return out
}

/** The text inside each "..." or '...' of a segment, unescaped. */
function quotedStrings(seg) {
  return [...seg.matchAll(/"((?:[^"`]|`[\s\S])*)"|'((?:[^']|'')*)'/g)].map((m) =>
    m[1] !== undefined ? m[1].replace(/`([\s\S])/g, '$1') : m[2].replace(/''/g, "'"),
  )
}

/** A word without leading ( { $( @( & and trailing ) } , ; */
function bare(w) {
  return w
    .replace(/^.*[({]/, '')
    .replace(/^&/, '')
    .replace(/[)},;]+$/, '')
}

/** The program a word names: lower case, no folder, no .exe. */
function programName(w) {
  return bare(w)
    .split(/[\\/]/)
    .pop()
    .toLowerCase()
    .replace(/\.(exe|cmd|bat|ps1)$/, '')
}

/** The arguments after word j, up to the end of that command. */
function argsAfter(ws, j) {
  const out = []
  for (let k = j + 1; k < ws.length; k++) {
    const w = ws[k]
    if (w === '&' || w === '|' || w === ')' || w === '}') break
    // Start-Process git -ArgumentList 'add','-A'
    if (/^-(argumentlist|args)$/i.test(w) && ws[k + 1] !== undefined) {
      out.push(...ws[k + 1].split(/[\s,]+/).filter(Boolean))
      k++
      continue
    }
    const t = w.replace(/[)}]+$/, '')
    if (t) out.push(t)
    if (t !== w) break
  }
  return out
}

const CD = new Set(['cd', 'set-location', 'sl', 'chdir'])
const PUSHD = new Set(['pushd', 'push-location'])
const POPD = new Set(['popd', 'pop-location'])
const LAUNCHERS = new Set(['cmd', 'pwsh', 'powershell', 'bash', 'sh', 'zsh', 'wsl', 'iex', 'invoke-expression', 'start-process', 'invoke-command', 'start-job', 'start-threadjob'])
const PYTHON = new Set(['python', 'python3', 'py'])

const WRITE_VERBS = new Set([
  'set-content', 'add-content', 'out-file', 'new-item', 'remove-item', 'move-item', 'copy-item', 'rename-item', 'clear-content',
  'sc', 'ac', 'ni', 'ri', 'mi', 'cpi', 'rni', 'del', 'erase', 'rd', 'rmdir', 'rm', 'mv', 'cp', 'copy', 'move', 'ren',
  'tee', 'tee-object', 'truncate',
])
const COPY_VERBS = new Set(['copy-item', 'cpi', 'cp', 'copy'])
/** Verbs that move, copy or delete files but write no text from the command itself. */
const NO_CONTENT_VERBS = new Set([...COPY_VERBS, 'move-item', 'mi', 'mv', 'move', 'rename-item', 'rni', 'ren', 'remove-item', 'ri', 'rm', 'del', 'erase', 'rd', 'rmdir', 'clear-content'])
const VALUE_PARAMS = new Set(['-path', '-literalpath', '-filepath', '-destination', '-value', '-encoding', '-itemtype', '-name', '-filter', '-include', '-exclude', '-credential', '-stream', '-t', '--target-directory'])
const DOTNET_WRITE = /\[(?:system\.)?io\.(?:file|directory)\]::\s*(write|append|delete|move|copy|replace|create)/i
const REDIRECT = /(?:^|[^-=<\d&])\d?>>?\s*("[^"]*"|'[^']*'|[^\s&|;<>]+)/g
const PATH_LIKE = /[\\/]|\.[a-z][a-z0-9]{0,7}$|^\.(kb|githooks|git|gitattributes)$/i
/** A word that names a file: path-like, and either one word or starting the way paths start. */
const isPathWord = (t) => PATH_LIKE.test(t) && (!/\s/.test(t) || /^([a-z]:[\\/]|[\\/~.%]|\$env:|\$home|\$\{)/i.test(t))
const PREFIX_WORDS = new Set(['sudo', 'xargs', 'exec', 'nohup', 'time', 'command', 'env', 'try', 'finally', 'else', 'do', 'then'])

/** Whether word j is where a command starts, so a verb there runs (not just a search term). */
function atCommandStart(ws, j) {
  if (j === 0) return true
  const prev = ws[j - 1]
  return prev === '=' || prev === '&' || /[({]$/.test(prev) || /[({]/.test(ws[j].slice(0, -1)) || PREFIX_WORDS.has(prev.toLowerCase())
}

const deny = (reason) => ({ kind: 'deny', reason: TAG + reason })
const ask = (reason) => ({ kind: 'ask', reason: TAG + reason, displayReason: { en: TAG + reason } })

/** Run a program off the event loop; resolves to its stdout, or '' on any failure. */
function run(file, args, options = {}) {
  return new Promise((resolve) => {
    try {
      execFile(file, args, { encoding: 'utf8', windowsHide: true, timeout: 5000, ...options }, (error, stdout) =>
        resolve(error ? '' : String(stdout)),
      )
    } catch {
      resolve('')
    }
  })
}

/**
 * Look up the facts that need a child process: the 8.3 short form of the home
 * folder (like C:\Users\ABCDEF~1) and extra private names from
 * `git config kb.privateName` in the knowledge base. Pass the result to
 * `guard.update()`.
 */
export async function detectEnvironment(home = homedir(), root = path.join(home, 'knowledge')) {
  const [short, extra] = await Promise.all([
    WIN
      ? run('cmd.exe', ['/d', '/c', `for %I in ("${home}") do @echo %~sI`], { windowsVerbatimArguments: true })
      : Promise.resolve(''),
    run('git', ['-C', root, 'config', '--get-all', 'kb.privateName']),
  ])
  return {
    shortHome: short.trim() || null,
    extraNames: extra
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean),
  }
}

/**
 * Build the guard for one configuration. It starts no child processes; feed
 * it `detectEnvironment()` through `update()`.
 * @param {object} config - { knowledgeRoot, askBeforePush, shellTools, fileTools }
 * @param {object} [env] - { home, shortHome, extraNames, privateNames, exists }; privateNames and exists are for tests
 */
export function createGuard(config = {}, env = {}) {
  const home = env.home || homedir()
  const homeKey = key(home)
  const askBeforePush = config.askBeforePush !== false
  const shellTools = new Set(config.shellTools || ['pwsh', 'bash'])
  const fileTools = new Set(config.fileTools || ['write', 'edit', 'str_replace_editor'])
  const exists = env.exists || existsSync
  const baseNames = env.privateNames || [process.env.USERNAME, process.env.USER, (() => {
    try {
      return userInfo().username
    } catch {
      return undefined
    }
  })(), P.basename(home)]

  // Everything below depends on the short home path, which arrives later.
  let shortHome = null
  let shortKey = null
  let extraNames = []
  let root, rootKey, rootRel, shown, kbPy, commitHint
  let privateRe

  /** Rewrite a path under the short home folder to the long one. */
  function longForm(p) {
    if (!shortKey) return p
    const k = key(p)
    return k === shortKey || k.startsWith(shortKey + '/') ? home + String(p).slice(shortHome.length) : p
  }

  function configure() {
    shortKey = shortHome && key(shortHome) !== homeKey ? key(shortHome) : null
    root = longForm(P.resolve(expandHome(config.knowledgeRoot || '~/knowledge', home)))
    rootKey = key(root)
    // How to name the root in messages without writing the account name.
    rootRel = rootKey === homeKey ? '' : rootKey.startsWith(homeKey + '/') ? root.slice(home.length + 1) : null
    const sub = rootRel ? (WIN ? `\\${rootRel}` : `/${rootRel}`) : ''
    shown = rootRel === null ? root : WIN ? `%USERPROFILE%${sub}` : `~${sub}`
    kbPy =
      rootRel === null
        ? `python "${P.join(root, '.kb', 'kb.py')}"`
        : WIN
          ? `python "$env:USERPROFILE${sub}\\.kb\\kb.py"`
          : `python3 ~${sub}/.kb/kb.py`
    commitHint = `${kbPy} commit -m 'kb: <summary>' <files>`
    privateRe = undefined
  }

  /** Apply facts found later (see detectEnvironment). */
  function update(found = {}) {
    if (found.shortHome !== undefined) shortHome = found.shortHome || null
    if (Array.isArray(found.extraNames)) extraNames = found.extraNames
    configure()
  }
  update({ shortHome: env.shortHome ?? null, extraNames: env.extraNames ?? [] })

  function privateNames() {
    if (privateRe !== undefined) return privateRe
    const names = new Set()
    for (const v of [...baseNames, ...extraNames, shortKey ? P.basename(shortHome) : null]) {
      if (typeof v === 'string' && v.trim()) names.add(v.trim())
    }
    const forms = new Set()
    for (const n of names) {
      if (n.length < 3 || GENERIC_NAMES.has(n.toLowerCase())) continue
      for (const sep of [' ', '', '-', '_', '%20', '+']) forms.add(n.split(' ').join(sep))
    }
    const pats = [...forms].sort((a, b) => b.length - a.length).map(escapeRe)
    // Whole words only, so a short name does not match inside other words.
    privateRe = pats.length ? new RegExp(`(?<![a-z0-9])(?:${pats.join('|')})(?![a-z0-9])`, 'i') : null
    return privateRe
  }

  const relKb = (p) => {
    const k = key(longForm(p))
    if (k === rootKey) return ''
    return k.startsWith(rootKey + '/') ? k.slice(rootKey.length + 1) : null
  }
  const inKb = (p) => relKb(p) !== null
  const at = (cwd, p) => {
    let s = expandHome(p, home)
    if (WIN) s = s.replace(/^\/([a-zA-Z])(?=\/|$)/, '$1:') // Git Bash form /c/Users/...
    return P.resolve(cwd, s)
  }
  const isProtected = (rel) =>
    rel === 'log.md' || rel.endsWith('/log.md') || rel === '.gitattributes' || /^\.(kb|githooks|git)(\/|$)/.test(rel)
  const isIndex = (rel) => rel === 'index.md' || rel.endsWith('/index.md')

  const discard = (what) =>
    ask(`${what} throws away uncommitted edits in the knowledge base, including ones Claude left for the user to commit. Allow it?`)
  const rewrite = (what) => ask(`${what} rewrites or moves commits in the knowledge base, which only the user decides. Allow it?`)
  const shortFlags = (r, letters) => /^-[a-zA-Z]+$/.test(r) && new RegExp(`[${letters}]`).test(r.slice(1))

  /**
   * @param args - words after `git`
   * @param state - { cwd, env } of the shell command so far
   * @param prefix - GIT_DIR / GIT_WORK_TREE set in front of this command (bash)
   */
  function checkGit(args, state, prefix) {
    let cwd = state.cwd
    let gitDir = prefix.GIT_DIR ?? state.env.GIT_DIR
    let workTree = prefix.GIT_WORK_TREE ?? state.env.GIT_WORK_TREE
    const globals = []
    let i = 0
    while (i < args.length && args[i].startsWith('-')) {
      const o = args[i]
      const eq = o.startsWith('--') ? o.indexOf('=') : -1
      const name = eq > 0 ? o.slice(0, eq) : o
      const takesValue = o === '-C' || o === '-c' || ['--git-dir', '--work-tree', '--namespace', '--config-env', '--super-prefix'].includes(name)
      let value
      if (eq > 0) {
        value = o.slice(eq + 1)
        i++
      } else if (takesValue) {
        value = args[i + 1] ?? ''
        i += 2
      } else {
        i++
      }
      if (o === '-C') cwd = at(cwd, value)
      else if (name === '--git-dir') gitDir = value
      else if (name === '--work-tree') workTree = value
      else globals.push(value === undefined ? o : `${o} ${value}`)
    }
    const gd = gitDir ? at(cwd, gitDir) : null
    const repo = workTree ? at(cwd, workTree) : gd ? (P.basename(gd).toLowerCase() === '.git' ? P.dirname(gd) : gd) : cwd
    if (!inKb(repo) && !(gd && inKb(gd))) return null

    const sub = (args[i] || '').toLowerCase()
    const rest = args.slice(i + 1)
    const dashdash = rest.indexOf('--')
    const before = dashdash < 0 ? rest : rest.slice(0, dashdash)
    const positional = before.filter((r) => !r.startsWith('-'))
    const has = (...flags) => rest.some((r) => flags.includes(r))

    const hookConfig =
      sub === 'config' &&
      rest.some((r) => /hookspath/i.test(r)) &&
      (rest.filter((r) => !r.startsWith('-')).length >= 2 ||
        rest.some((r) => /^--(unset|unset-all|replace-all|add|remove-section|edit)$/.test(r) || r === '-e'))
    if (globals.some((g) => /hookspath/i.test(g)) || hookConfig) {
      return deny('the knowledge base hooks stay on. Never change core.hooksPath there.')
    }
    if (rest.includes('--no-verify') || (sub === 'commit' && rest.some((r) => shortFlags(r, 'n')))) {
      return deny(`never skip the knowledge base checks. Fix what they report, then commit with ${commitHint}`)
    }
    if (sub === 'commit') {
      return deny(`in the knowledge base, commit with kb.py so the checks run and only your files are staged: ${commitHint}`)
    }
    if (sub === 'add' || sub === 'stage') {
      return deny(`do not use git add in the knowledge base. kb.py commit stages the files you name, plus their log.md and index lines: ${commitHint}`)
    }
    if (sub === 'push') {
      if (rest.some((r) => ['--force', '--mirror', '--delete', '--prune'].includes(r) || r.startsWith('--force-with-lease') || r.startsWith('+') || /^:./.test(r) || shortFlags(r, 'fd'))) {
        return deny('never force-push the knowledge base or delete its remote branches.')
      }
      return askBeforePush ? ask('push the knowledge base to its remote? Only push when the user asked for it.') : null
    }
    if (['rebase', 'filter-branch', 'filter-repo', 'replace', 'update-ref', 'commit-tree'].includes(sub) || (sub === 'reflog' && rest[0] === 'expire')) {
      return deny(`git ${sub} rewrites history, which only the user decides. Ask the user to run it.`)
    }
    if (sub === 'reset') {
      if (has('--hard', '--keep', '--merge')) return discard('git reset --hard')
      const moves = positional.some((p) => p !== 'HEAD' && p !== '@' && !p.includes('*') && !exists(at(repo, p)))
      if (has('--soft') || moves) return rewrite('git reset to another commit')
      return null
    }
    if (sub === 'clean' && rest.some((r) => r === '--force' || shortFlags(r, 'f'))) {
      return ask('git clean deletes untracked files in the knowledge base, including new concepts not committed yet. Allow it?')
    }
    if (sub === 'checkout') {
      if (has('-B')) return rewrite('git checkout -B')
      const isPath = (p) => p === '.' || p.includes('*') || p.includes('\\') || /\.[a-z][a-z0-9]{0,7}$/i.test(p) || (p.includes('/') && exists(at(repo, p)))
      if (dashdash >= 0 || has('-f', '--force') || positional.some(isPath)) return discard(`git checkout ${dashdash >= 0 ? '--' : 'of files'}`)
      return null
    }
    if (sub === 'switch') {
      if (has('-C', '--force-create')) return rewrite('git switch -C')
      if (has('--discard-changes', '-f', '--force')) return discard('git switch --discard-changes')
      return null
    }
    if (sub === 'restore') {
      const stagedOnly = has('--staged', '-S') && !has('--worktree', '-W')
      return stagedOnly ? null : discard('git restore')
    }
    if (sub === 'stash' && ['drop', 'clear'].includes(rest[0])) {
      return ask('this deletes stashed changes in the knowledge base. Allow it?')
    }
    if (sub === 'rm') {
      return ask('delete a concept? The okf skill says to deprecate it instead (kb.py touch --verb Deprecated). Delete only when the user asked.')
    }
    if (sub === 'branch' && rest.some((r) => r === '--force' || shortFlags(r, 'fDMC'))) {
      return rewrite('git branch -f / -D')
    }
    if (sub === 'pull' && rest.some((r) => r === '-r' || r === '--rebase' || (r.startsWith('--rebase=') && r !== '--rebase=false'))) {
      return rewrite('git pull --rebase')
    }
    if (['cherry-pick', 'revert', 'am', 'merge'].includes(sub)) {
      if (has('--abort', '--quit') || (sub === 'merge' && has('--ff-only'))) return null
      return ask(`git ${sub} makes commits that skip the knowledge base check. Allow it? Afterwards run ${kbPy} check.`)
    }
    return null
  }

  const OKF_VALUE_OPTS = new Set(['--bundle', '--author', '--today', '--format', '--section', '-s', '--title', '--type', '--heading', '--link-text', '--redirect-to'])
  const OKF_LINK_CMDS = new Set(['mv', 'rename', 'rm', 'delete', 'remove', 'merge', 'merge-concepts', 'split'])

  function checkOkf(args, cwd) {
    const sub = (args[0] || '').toLowerCase()
    const rest = args.slice(1)
    const positional = []
    let bundle
    for (let i = 0; i < rest.length; i++) {
      const r = rest[i]
      if (OKF_VALUE_OPTS.has(r)) {
        if (r === '--bundle') bundle = rest[i + 1]
        i++
      } else if (r.startsWith('--bundle=')) bundle = r.slice(9)
      else if (!r.startsWith('-')) positional.push(r)
    }
    // Link-rewriting commands take concept ids and a --bundle; the rest take one path.
    const where = OKF_LINK_CMDS.has(sub) ? (bundle ?? '.') : (positional[0] ?? '.')
    if (!inKb(at(cwd, where))) return null
    if (sub === 'index') {
      return deny('okf index rewrites every index.md and deletes their hand-written text. kb.py new adds the index line for you.')
    }
    if ((sub === 'validate' || sub === 'lint') && rest.includes('--fix')) {
      return deny(`okf ${sub} --fix rewrites files across the knowledge base. Run ${kbPy} check and fix only what it reports.`)
    }
    if (sub === 'fmt' && rest.some((r) => r === '-w' || r === '--write' || /^-[a-z]*w/.test(r))) {
      if (!where.toLowerCase().endsWith('.md')) {
        return deny('okf fmt -w on a folder rewrites every file in it. Format at most one named .md file.')
      }
    }
    if (sub === 'new' || sub === 'init') {
      return deny(`create concepts with ${kbPy} new <path> --type T --title '...' --description '...' --by <producer/version>. It also writes the index and log lines.`)
    }
    if (OKF_LINK_CMDS.has(sub)) {
      if (rest.includes('--dry-run') || rest.includes('-n')) return null
      if (!rest.includes('--no-index')) {
        return deny(`okf ${sub} regenerates index.md files and deletes their hand-written text. Add --no-index (and --no-log where it exists), then fix the index and log lines with kb.py, or ask the user.`)
      }
      return ask(`okf ${sub} moves or removes concepts and rewrites links across the knowledge base. Allow it?`)
    }
    if (sub === 'studio') {
      return deny('okf studio is interactive and would hang this shell.')
    }
    return null
  }

  /** The destination of a copy command: -Destination, -t, or the last of two or more paths. */
  function copyDestination(args) {
    const positional = []
    let dest = null
    for (let i = 0; i < args.length; i++) {
      const a = args[i].toLowerCase()
      if (VALUE_PARAMS.has(a)) {
        if (a === '-destination' || a === '-t' || a === '--target-directory') dest = args[i + 1]
        i++
      } else if (!a.startsWith('-')) positional.push(args[i])
    }
    if (dest == null && positional.length >= 2) dest = positional[positional.length - 1]
    return dest == null ? [] : [dest]
  }

  const protectedMsg = () =>
    deny(`only kb.py writes log.md, and nothing should change .kb, .githooks, .git or .gitattributes. Use ${kbPy} log, touch or new.`)
  const nameMsg = () => deny('this text contains the Windows account name or the user folder path. Write %USERPROFILE% or ~ instead.')

  function checkShellWrite(seg, ws, cwd) {
    const redirects = [...seg.matchAll(REDIRECT)].map((m) => m[1]).filter((t) => !/^["']?(&\d|\$null|nul|\/dev\/null)["']?$/i.test(t))
    const vi = ws.findIndex(
      (w, j) =>
        atCommandStart(ws, j) &&
        (WRITE_VERBS.has(programName(w)) || (programName(w) === 'sed' && ws.slice(j + 1).some((a) => /^-[a-z]*i|^--in-place/.test(a)))),
    )
    const dotnet = DOTNET_WRITE.exec(seg)
    if (!redirects.length && vi < 0 && !dotnet) return null
    const verb = vi >= 0 ? programName(ws[vi]) : dotnet ? `dotnet-${dotnet[1].toLowerCase()}` : 'redirect'
    const quoted = quotedStrings(seg)

    const targets = redirects.map((t) => t.replace(/^["']|["']$/g, ''))
    if (COPY_VERBS.has(verb)) targets.push(...copyDestination(ws.slice(vi + 1)))
    else if (verb === 'dotnet-copy') targets.push(...quoted.slice(1, 2))
    else if (verb !== 'redirect') {
      for (const w of [...ws, ...quoted]) {
        const t = bare(w.replace(/^-[a-z]+:/i, ''))
        if (isPathWord(t)) targets.push(t)
      }
    }
    const inside = targets.filter((t) => inKb(at(cwd, t)))
    if (inside.some((t) => isProtected(relKb(at(cwd, t))))) return protectedMsg()

    // Text the command writes into the knowledge base must not name the account.
    // The target paths themselves are left out of that check.
    const writesText = !(NO_CONTENT_VERBS.has(verb) || ['dotnet-copy', 'dotnet-move', 'dotnet-delete'].includes(verb)) || redirects.length > 0
    if (writesText && inside.length) {
      let text = seg
      for (const t of inside) text = text.split(t).join(' ')
      const rx = privateNames()
      if (rx && rx.test(text)) return nameMsg()
    }
    return null
  }

  /** Environment set for git by this segment (PowerShell $env:, bash export/unset); true when handled. */
  function setEnv(seg, ws, state) {
    const ps = /^\$env:(git_dir|git_work_tree)\s*=\s*(.*)$/i.exec(seg)
    if (ps) {
      const value = words(ps[2])[0] ?? ''
      const name = ps[1].toUpperCase()
      if (!value || value === '$null') delete state.env[name]
      else state.env[name] = value
      return true
    }
    const first = programName(ws[0])
    if (first === 'export' || first === 'unset' || first === 'remove-item' || first === 'ri') {
      for (const w of ws.slice(1)) {
        const m = /^(?:env:)?(GIT_DIR|GIT_WORK_TREE)(?:=(.*))?$/i.exec(w)
        if (!m) continue
        const name = m[1].toUpperCase()
        if (first === 'export' && m[2]) state.env[name] = m[2]
        else delete state.env[name]
      }
      return ws.slice(1).some((w) => /^(?:env:)?GIT_(DIR|WORK_TREE)\b/i.test(w))
    }
    return false
  }

  /** GIT_DIR=... GIT_WORK_TREE=... written in front of git (bash). */
  function prefixEnv(ws, j) {
    const env = {}
    for (const w of ws.slice(0, j)) {
      const m = /^(GIT_DIR|GIT_WORK_TREE)=(.*)$/.exec(w)
      if (m) env[m[1]] = m[2]
    }
    return env
  }

  /** First deny wins at once; otherwise the first ask. */
  function pick(decisions) {
    let first = null
    for (const d of decisions) {
      if (!d) continue
      if (d.kind === 'deny') return d
      if (!first) first = d
    }
    return first
  }

  function checkSegment(seg, state, depth) {
    const ws = words(seg)
    if (!ws.length) return null
    const first = programName(ws[0])
    const target = ws.slice(1).find((a) => !a.startsWith('-'))
    if (CD.has(first)) {
      state.cwd = target ? at(state.cwd, target) : first === 'cd' ? home : state.cwd
      return null
    }
    if (PUSHD.has(first)) {
      state.stack.push(state.cwd)
      if (target) state.cwd = at(state.cwd, target)
      return null
    }
    if (POPD.has(first)) {
      if (state.stack.length) state.cwd = state.stack.pop()
      return null
    }
    if (setEnv(seg, ws, state)) return null
    // kb.py does its own checks; its arguments (commit messages) are not commands.
    if (ws.some((w) => PYTHON.has(programName(w))) && ws.some((w) => /(^|[\\/])kb\.py$/i.test(bare(w)))) return null

    const found = []
    for (let j = 0; j < ws.length; j++) {
      const name = programName(ws[j])
      if (name === 'git') found.push(checkGit(argsAfter(ws, j), state, prefixEnv(ws, j)))
      else if (name === 'okf') found.push(checkOkf(argsAfter(ws, j), state.cwd))
    }
    found.push(checkShellWrite(seg, ws, state.cwd))
    // cmd /c "...", pwsh -c "...", bash -c '...', iex "...": check the inner command too.
    if (depth < 2 && ws.some((w) => LAUNCHERS.has(programName(w)))) {
      for (const q of quotedStrings(seg)) {
        if (/\s/.test(q)) found.push(scan(q, { cwd: state.cwd, stack: [...state.stack], env: { ...state.env } }, depth + 1))
      }
    }
    return pick(found)
  }

  function scan(command, state, depth) {
    const found = []
    for (const seg of splitSegments(command)) {
      const d = checkSegment(seg, state, depth)
      if (d && d.kind === 'deny') return d
      found.push(d)
    }
    return pick(found)
  }

  function checkFile(tool, args, cwd) {
    const p = args.file_path ?? args.path ?? args.filePath
    if (typeof p !== 'string' || !p.trim()) return null
    if (tool === 'str_replace_editor' && (args.command === 'view' || args.command === undefined)) return null
    const full = at(cwd, p)
    const rel = relKb(full)
    if (rel === null) return null
    if (isProtected(rel)) {
      return deny(`only kb.py writes ${rel}. Use ${kbPy} log, touch or new.`)
    }
    const text = ['content', 'new_string', 'new_str', 'file_text', 'insert_text']
      .map((k) => args[k])
      .filter((v) => typeof v === 'string')
      .join('\n')
    const rx = privateNames()
    if (rx && rx.test(text)) return nameMsg()
    const creates = tool === 'write' || (tool === 'str_replace_editor' && args.command === 'create')
    if (creates && rel.toLowerCase().endsWith('.md') && !isIndex(rel) && !exists(full)) {
      return deny(`create concepts with ${kbPy} new <path> --type T --title '...' --description '...' --by <producer/version>, then edit the file it writes.`)
    }
    return null
  }

  /** The folder a call runs in: the shell tool's workdir argument, else the session folder. */
  function cwdOf(exec, args) {
    const header = exec && exec.agent && exec.agent.session && exec.agent.session.header
    const base = (header && typeof header.cwd === 'string' && header.cwd) || process.cwd()
    return typeof args.workdir === 'string' && args.workdir.trim() ? at(base, args.workdir) : base
  }

  /** Decide one tool call. */
  function decide(exec) {
    const name = exec && exec.name
    const args = (exec && exec.arguments) || {}
    if (typeof args !== 'object') return null
    if (shellTools.has(name) && typeof args.command === 'string') {
      return scan(args.command, { cwd: cwdOf(exec, args), stack: [], env: {} }, 0)
    }
    if (fileTools.has(name)) return checkFile(name, args, cwdOf(exec, {}))
    return null
  }

  function promptText() {
    if (!exists(P.join(root, '.kb', 'kb.py'))) return ''
    return [
      '# Knowledge base',
      '',
      `The user's knowledge base is the git repo at ${shown} (OKF markdown). It holds settled project knowledge: decisions, conventions, gotchas, verified steps, data sources and API details.`,
      '- Look things up there first: projects/<project>/index.md, then general/index.md.',
      '- Settled project knowledge goes there, including when the user says "remember this for the project" or "note this down".',
      "- The user's personal preferences belong in their instructions file (~/.dsh/AGENTS.md), not in the knowledge base. Run notes, investigations and handoffs go in plain files in the project, or are not kept. Never append them to a concept.",
      `- Change the knowledge base only with kb.py (the okf skill has the steps): ${kbPy} new, touch or commit.`,
      '- When kb.py prints BLOCK lines, fix what they say and run the same command again. Never use git add, git commit or --no-verify there.',
    ].join('\n')
  }

  return {
    decide,
    promptText,
    update,
    home,
    get root() {
      return root
    },
  }
}
