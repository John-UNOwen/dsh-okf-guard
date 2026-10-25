/**
 * Decision rules for okf-guard. `decide(exec)` takes one tool call and returns
 * { kind: 'deny' | 'ask', reason } or null to leave it alone.
 *
 * The rules catch mistakes, not attacks: a command that hides what it does
 * from these checks still meets the knowledge base's own git hooks when it
 * commits.
 */

import { execFileSync } from 'node:child_process'
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

function safe(fn) {
  try {
    return fn()
  } catch {
    return undefined
  }
}

/** Drop surrounding quotes and expand ~, %USERPROFILE%, $env:USERPROFILE and $HOME. */
export function expandHome(p, home) {
  return String(p)
    .trim()
    .replace(/^["']|["']$/g, '')
    .replace(/^~(?=$|[\\/])/, home)
    .replace(/\$\{env:userprofile\}|\$env:userprofile|%userprofile%|\$env:home|\$home\b/gi, home)
}

/** Split a shell command into segments at ; && || | and newlines, outside quotes. */
export function splitSegments(cmd) {
  const out = []
  let cur = ''
  let quote = null
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
      out.push(cur)
      cur = ''
      continue
    }
    if ((c === '&' && cmd[i + 1] === '&') || (c === '|' && cmd[i + 1] === '|')) {
      out.push(cur)
      cur = ''
      i++
      continue
    }
    if (c === '|') {
      out.push(cur)
      cur = ''
      continue
    }
    cur += c
  }
  out.push(cur)
  return out.map((s) => s.trim()).filter(Boolean)
}

/** Split one segment into words, removing quotes. */
export function words(seg) {
  const out = []
  let cur = ''
  let quote = null
  let quoted = false
  for (const c of seg) {
    if (quote) {
      if (c === quote) quote = null
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

/** The program a segment runs (lower case, no folder or .exe) and its arguments. */
function program(w) {
  let i = 0
  while (i < w.length && (w[i] === '&' || w[i] === '.')) i++
  const name = (w[i] || '').replace(/\\/g, '/').split('/').pop().toLowerCase().replace(/\.(exe|cmd|bat)$/, '')
  return { name, args: w.slice(i + 1) }
}

const deny = (reason) => ({ kind: 'deny', reason: TAG + reason })
const ask = (reason) => ({ kind: 'ask', reason: TAG + reason, displayReason: { en: TAG + reason } })

/**
 * Build the guard for one configuration.
 * @param {object} config - { knowledgeRoot, askBeforePush, shellTools, fileTools }
 * @param {object} [env] - test overrides: { home, privateNames, exists }
 */
export function createGuard(config = {}, env = {}) {
  const home = env.home || homedir()
  const root = P.resolve(expandHome(config.knowledgeRoot || '~/knowledge', home))
  const rootKey = key(root)
  const homeKey = key(home)
  const askBeforePush = config.askBeforePush !== false
  const shellTools = new Set(config.shellTools || ['pwsh', 'bash'])
  const fileTools = new Set(config.fileTools || ['write', 'edit', 'str_replace_editor'])
  const exists = env.exists || existsSync

  // How to name the root in messages without writing the account name.
  const rootRel = rootKey === homeKey ? '' : rootKey.startsWith(homeKey + '/') ? root.slice(home.length + 1) : null
  const shown = rootRel === null ? root : WIN ? `%USERPROFILE%\\${rootRel}` : `~/${rootRel}`
  const kbPy =
    rootRel === null
      ? `python "${P.join(root, '.kb', 'kb.py')}"`
      : WIN
        ? `python "$env:USERPROFILE\\${rootRel}\\.kb\\kb.py"`
        : `python3 ~/${rootRel}/.kb/kb.py`
  const commitHint = `${kbPy} commit -m 'kb: <summary>' <files>`

  // The 8.3 short form of the home folder (like C:\Users\ABCDEF~1) names the
  // same place, and its last part also gives the account name away.
  let shortHome = env.shortHome
  if (shortHome === undefined) {
    shortHome = WIN
      ? safe(() =>
          execFileSync('cmd.exe', ['/d', '/c', `for %I in ("${home}") do @echo %~sI`], {
            encoding: 'utf8',
            windowsHide: true,
            windowsVerbatimArguments: true,
            timeout: 5000,
            stdio: ['ignore', 'pipe', 'ignore'],
          }).trim(),
        )
      : null
  }
  const shortKey = shortHome && key(shortHome) !== homeKey ? key(shortHome) : null
  /** Rewrite a path under the short home folder to the long one. */
  const longForm = (p) => {
    if (!shortKey) return p
    const k = key(p)
    return k === shortKey || k.startsWith(shortKey + '/') ? home + String(p).slice(shortHome.length) : p
  }

  const msys = /^[a-z]:\//i.test(rootKey) ? `/${rootKey[0].toLowerCase()}${rootKey.slice(2)}` : null
  const relForm = rootRel === null ? null : key(rootRel)
  const rootForms = [
    rootKey,
    msys,
    shortKey && relForm ? `${shortKey}/${relForm}` : null,
    ...(relForm
      ? [`$env:userprofile/${relForm}`, `\${env:userprofile}/${relForm}`, `%userprofile%/${relForm}`, `~/${relForm}`, `$home/${relForm}`]
      : []),
  ]
    .filter(Boolean)
    .map((f) => (WIN ? f.toLowerCase() : f))

  let privateRe
  function privateNames() {
    if (privateRe !== undefined) return privateRe
    const names = new Set(env.privateNames || [])
    if (!env.privateNames) {
      for (const v of [process.env.USERNAME, process.env.USER, safe(() => userInfo().username), P.basename(home)]) {
        if (v && v.trim()) names.add(v.trim())
      }
      const extra = safe(() =>
        execFileSync('git', ['-C', root, 'config', '--get-all', 'kb.privateName'], {
          encoding: 'utf8',
          windowsHide: true,
          timeout: 5000,
          stdio: ['ignore', 'pipe', 'ignore'],
        }),
      )
      for (const v of (extra || '').split(/\r?\n/)) if (v.trim()) names.add(v.trim())
    }
    if (shortKey) names.add(P.basename(shortHome))
    const forms = new Set()
    for (const n of names) {
      if (n.length < 3 || GENERIC_NAMES.has(n.toLowerCase())) continue
      for (const sep of [' ', '', '-', '_', '%20', '+']) forms.add(n.split(' ').join(sep))
    }
    const pats = [...forms].sort((a, b) => b.length - a.length).map((f) => f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    privateRe = pats.length ? new RegExp(pats.join('|'), 'i') : null
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
  const mentionsKb = (seg, cwd) => {
    const s = key(seg)
    if (rootForms.some((f) => s.includes(f))) return true
    if (rootRel === null || key(cwd) !== homeKey) return false
    const rel = relForm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    return new RegExp(`(^|[\\s"'\`(=])(\\./)?${rel}(/|[\\s"'\`)]|$)`).test(s)
  }
  const isProtected = (rel) =>
    rel === 'log.md' || rel.endsWith('/log.md') || rel === '.gitattributes' || /^\.(kb|githooks|git)(\/|$)/.test(rel)
  const isIndex = (rel) => rel === 'index.md' || rel.endsWith('/index.md')

  function checkGit(args, cwd) {
    let i = 0
    let gitCwd = cwd
    const globals = []
    while (i < args.length && args[i].startsWith('-')) {
      const o = args[i]
      if (o === '-C') {
        gitCwd = at(gitCwd, args[i + 1] || '')
        i += 2
        continue
      }
      if (o === '-c') {
        globals.push(args[i + 1] || '')
        i += 2
        continue
      }
      globals.push(o)
      i++
    }
    if (!inKb(gitCwd)) return null
    const sub = (args[i] || '').toLowerCase()
    const rest = args.slice(i + 1)
    const positional = rest.filter((r) => !r.startsWith('-'))

    const hookGlobal = globals.some((g) => /hookspath/i.test(g))
    const hookConfig =
      sub === 'config' &&
      rest.some((r) => /hookspath/i.test(r)) &&
      (positional.length >= 2 || rest.some((r) => /^--(unset|unset-all|replace-all|add|remove-section|edit)$/.test(r) || r === '-e'))
    if (hookGlobal || hookConfig) {
      return deny('the knowledge base hooks stay on. Never change core.hooksPath there.')
    }
    if (rest.includes('--no-verify') || (sub === 'commit' && rest.some((r) => /^-[a-zA-Z]*n[a-zA-Z]*$/.test(r)))) {
      return deny(`never skip the knowledge base checks. Fix what they report, then commit with ${commitHint}`)
    }
    if (sub === 'commit') {
      return deny(`in the knowledge base, commit with kb.py so the checks run and only your files are staged: ${commitHint}`)
    }
    if (sub === 'add' || sub === 'stage') {
      return deny(`do not use git add in the knowledge base. kb.py commit stages the files you name, plus their log.md and index lines: ${commitHint}`)
    }
    if (sub === 'push') {
      if (rest.some((r) => r === '--force' || r.startsWith('--force-with-lease') || r === '--mirror' || r === '--delete' || r.startsWith('+') || /^-[a-zA-Z]*[fd]/.test(r))) {
        return deny('never force-push the knowledge base or delete its remote branches.')
      }
      return askBeforePush ? ask('push the knowledge base to its remote? Only push when the user asked for it.') : null
    }
    if (['rebase', 'filter-branch', 'filter-repo', 'replace', 'update-ref', 'commit-tree'].includes(sub) || (sub === 'reflog' && rest[0] === 'expire')) {
      return deny(`git ${sub} rewrites history, which only the user decides. Ask the user to run it.`)
    }
    if (sub === 'reset' && rest.some((r) => r === '--hard' || r === '--keep' || r === '--merge')) {
      return ask('git reset --hard throws away uncommitted edits in the knowledge base, including ones Claude left for the user to commit. Allow it?')
    }
    if (sub === 'clean' && rest.some((r) => r === '--force' || /^-[a-zA-Z]*f/.test(r))) {
      return ask('git clean deletes untracked files in the knowledge base, including new concepts not committed yet. Allow it?')
    }
    if ((sub === 'checkout' && rest.includes('--')) || (sub === 'restore' && !rest.includes('--staged') && !rest.includes('-S'))) {
      return ask(`git ${sub} throws away uncommitted edits in the knowledge base. Allow it?`)
    }
    if (sub === 'stash' && ['drop', 'clear'].includes(rest[0])) {
      return ask('this deletes stashed changes in the knowledge base. Allow it?')
    }
    if (sub === 'rm') {
      return ask('delete a concept? The okf skill says to deprecate it instead (kb.py touch --verb Deprecated). Delete only when the user asked.')
    }
    return null
  }

  function checkOkf(args, seg, cwd) {
    const sub = (args[0] || '').toLowerCase()
    const rest = args.slice(1)
    const targets = []
    for (let i = 0; i < rest.length; i++) {
      const r = rest[i]
      if (r === '--bundle' || r === '--author' || r === '--today' || r === '--format' || r === '--section' || r === '-s' || r === '--title' || r === '--type' || r === '--heading' || r === '--link-text' || r === '--redirect-to') {
        if (r === '--bundle' && rest[i + 1]) targets.push(rest[i + 1])
        i++
        continue
      }
      if (r.startsWith('--bundle=')) targets.push(r.slice(9))
      else if (!r.startsWith('-')) targets.push(r)
    }
    const concerns = inKb(cwd) || targets.some((t) => inKb(at(cwd, t))) || mentionsKb(seg, cwd)
    if (!concerns) return null
    if (sub === 'index') {
      return deny('okf index rewrites every index.md and deletes their hand-written text. kb.py new adds the index line for you.')
    }
    if ((sub === 'validate' || sub === 'lint') && rest.includes('--fix')) {
      return deny(`okf ${sub} --fix rewrites files across the knowledge base. Run ${kbPy} check and fix only what it reports.`)
    }
    if (sub === 'fmt' && rest.some((r) => r === '-w' || r === '--write' || /^-[a-z]*w/.test(r))) {
      const paths = targets.length ? targets : ['.']
      if (paths.some((t) => !t.toLowerCase().endsWith('.md'))) {
        return deny('okf fmt -w on a folder rewrites every file in it. Format at most one named .md file.')
      }
    }
    if (sub === 'new' || sub === 'init') {
      return deny(`create concepts with ${kbPy} new <path> --type T --title '...' --description '...' --by <producer/version>. It also writes the index and log lines.`)
    }
    if (['mv', 'rename', 'rm', 'delete', 'remove', 'merge', 'merge-concepts', 'split'].includes(sub)) {
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

  const WRITE_VERB =
    /(^|[\s(&])(set-content|add-content|out-file|new-item|remove-item|move-item|copy-item|rename-item|clear-content|sc|ac|ni|ri|mi|cpi|rni|del|erase|rd|rmdir|rm|mv|cp|copy|move|ren|tee|tee-object|truncate)(\s|$)|\[(system\.)?io\.(file|directory)\]::\s*(write|append|delete|move|copy|replace|create)|writealltext|writeallbytes|writealllines|appendalltext|appendalllines|sed\s+(-[a-z]*i|--in-place)/

  function checkShellWrite(seg, cwd) {
    if (!inKb(cwd) && !mentionsKb(seg, cwd)) return null
    const hits = (target) => {
      const rel = relKb(at(cwd, target))
      return rel !== null && isProtected(rel)
    }
    const msg = `only kb.py writes log.md, and nothing should change .kb, .githooks, .git or .gitattributes. Use ${kbPy} log, touch or new.`
    for (const m of seg.matchAll(/(?:^|[^-=<\d&])\d?>>?\s*("[^"]*"|'[^']*'|[^\s&|;<>]+)/g)) {
      const target = m[1]
      if (/^["']?(&\d|\$null|nul|\/dev\/null)["']?$/i.test(target)) continue
      if (hits(target)) return deny(msg)
    }
    if (!WRITE_VERB.test(key(seg))) return null
    // Plain words, plus quoted strings, which may sit inside (...) of a .NET call.
    const quoted = [...seg.matchAll(/"([^"]*)"|'([^']*)'/g)].map((m) => m[1] ?? m[2])
    for (const w of [...words(seg), ...quoted]) {
      const t = w.replace(/^-[a-z]+:/i, '').replace(/^[(,]+|[),]+$/g, '')
      if (!/[\\/]|^log\.md$|^\.(kb|githooks|gitattributes|git)\b/i.test(t)) continue
      if (hits(t)) return deny(msg)
    }
    return null
  }

  function checkShell(command, cwd) {
    let here = cwd
    for (const seg of splitSegments(command)) {
      const { name, args } = program(words(seg))
      if (['cd', 'set-location', 'sl', 'pushd', 'chdir', 'push-location'].includes(name)) {
        const target = args.find((a) => !a.startsWith('-'))
        if (target) here = at(here, target)
        continue
      }
      let d = null
      if (name === 'git') d = checkGit(args, here)
      else if (name === 'okf') d = checkOkf(args, seg, here)
      else if (['python', 'python3', 'py'].includes(name) && args.some((a) => /(^|[\\/])kb\.py$/i.test(a))) d = null
      else d = checkShellWrite(seg, here)
      if (d) return d
    }
    return null
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
    if (rx && rx.test(text)) {
      return deny('this text contains the Windows account name or the user folder path. Write %USERPROFILE% or ~ instead.')
    }
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
    if (shellTools.has(name) && typeof args.command === 'string') return checkShell(args.command, cwdOf(exec, args))
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
      '- Settled project knowledge goes there, including when the user says "remember this for the project" or "note this down". Not in mnemon documents or memory.',
      "- Mnemon memory keeps the user's personal preferences. Mnemon documents keep run notes, investigations and handoffs. Never append those to a concept.",
      `- Change the knowledge base only with kb.py (the okf skill has the steps): ${kbPy} new, touch or commit.`,
      '- When kb.py prints BLOCK lines, fix what they say and run the same command again. Never use git add, git commit or --no-verify there.',
    ].join('\n')
  }

  return { decide, promptText, root }
}
