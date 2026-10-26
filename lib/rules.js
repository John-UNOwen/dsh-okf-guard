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

/**
 * Whether a lower-case path part has the shape of the 8.3 short name of
 * another: knowle~1 for knowledge, mydocu~2.txt for "my documents.txt".
 */
function isShortOf(short, long) {
  const m = /^([^~.]{1,6})~\d{1,6}(?:\.([^.]{1,3}))?$/.exec(short)
  if (!m || long.includes('~')) return false
  const dot = long.lastIndexOf('.')
  const base = (dot > 0 ? long.slice(0, dot) : long).replace(/[\s.]/g, '').replace(/[+,;=[\]]/g, '_')
  const ext = dot > 0 ? long.slice(dot + 1).replace(/\s/g, '') : ''
  return base.length > m[1].length && base.startsWith(m[1]) && (!m[2] || ext.startsWith(m[2]))
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

/** Characters a bash backslash escapes outside quotes. Other backslashes stay, so Windows paths survive. */
const BASH_ESCAPABLE = '"\'`$\\;&|'
/** Characters a bash backslash escapes inside "...". */
const BASH_DQ_ESCAPABLE = '"`$\\'

/**
 * Lex a shell command in one pass. It is cut into segments at ; && || |
 * newlines and a background `&`, outside quotes and command substitutions; a
 * call operator `&` (at the start, or after = ( { ,) and the `&` of redirects
 * like 2>&1 stay in place. Each segment has its text, its tokens (words with
 * quotes removed and their place in the text), its quoted pieces, and the
 * bodies of its command substitutions ($( ), @( ) and bash backticks, also
 * inside "..."). Quoted and unquoted pieces that touch form one word. A quote
 * that is never closed is read as a literal character, so it cannot hide the
 * rest of the command.
 * dialect 'pwsh': a backtick escapes; '' inside '...' and "" inside "..." are
 * literal quotes. dialect 'bash': a backslash escapes quotes, $, `, \, ; & |.
 */
function lex(cmd, dialect = 'pwsh') {
  const bash = dialect === 'bash'
  const esc = bash ? '\\' : '`'
  const n = cmd.length
  const segs = []
  const literal = new Set() // places of quotes read as literal characters
  let text = ''
  let tokens = []
  let pieces = []
  let subs = []
  let word = null // { w, start }
  // Innermost open context, a linked list so a snapshot is one reference:
  // { t: 'dq' | 'sq' | 'bt' | 'sub', at, depth, q (quotes open), prev }
  let top = null
  let snap = null // the state when the outermost open quote was opened
  let last = '' // last character outside quotes that is not a space
  let paren = 0 // open ( outside quotes and substitutions; PowerShell reads on past a newline
  // A line continuation: bash \ or PowerShell ` right before a newline.
  const lineEnd = (i) => (cmd[i + 1] === '\n' ? 1 : cmd[i + 1] === '\r' && cmd[i + 2] === '\n' ? 2 : 0)

  const endWord = () => {
    if (word) tokens.push({ w: word.w, start: word.start, end: text.length })
    word = null
  }
  const add = (raw, ch = raw) => {
    if (!word) word = { w: '', start: text.length }
    text += raw
    word.w += ch
    last = ch
  }
  const cut = () => {
    endWord()
    if (tokens.length || text.trim()) segs.push({ text, tokens, pieces, subs })
    text = ''
    tokens = []
    pieces = []
    subs = []
    last = ''
  }
  const push = (t) => {
    if (t !== 'sub' && !(top && top.q)) {
      snap = { i: -1, text, tokens: tokens.length, pieces: pieces.length, subs: subs.length, word: word && { ...word }, last, top, paren, sub: false }
    }
    if ((t === 'sub' || t === 'bt') && top && top.q) snap.sub = true
    top = { t, at: text.length + (t === 'sub' ? 0 : 1), depth: 0, q: (top ? top.q : 0) + (t === 'sub' ? 0 : 1), prev: top }
  }
  const openQuote = (i, c) => {
    push(c === '"' ? 'dq' : c === "'" ? 'sq' : 'bt')
    if (top.q === 1) snap.i = i
    if (!word) word = { w: '', start: text.length }
    if (top.q === 1) snap.wlen = word.w.length
    snap.at = top.q === 1 ? text.length : snap.at
    text += c
    if (c === '`') word.w += c
  }
  const closeQuote = (c) => {
    const t = top.t
    if (t === 'bt') subs.push(text.slice(top.at))
    text += c
    if (t === 'bt') word.w += c
    top = top.prev
    last = c
    if (!(top && top.q) && t !== 'bt') pieces.push({ s: word.w.slice(snap.wlen), start: snap.at, end: text.length, sub: snap.sub })
  }
  const openSub = (raw) => {
    add(raw)
    push('sub')
    top.at = text.length
  }

  for (let i = 0; ; i++) {
    if (i >= n) {
      if (top && top.q) {
        // Never closed: read the opening quote as a character and go on from there.
        text = snap.text
        tokens.length = snap.tokens
        pieces.length = snap.pieces
        subs.length = snap.subs
        word = snap.word
        last = snap.last
        top = snap.top
        paren = snap.paren
        literal.add(snap.i)
        i = snap.i - 1
        continue
      }
      for (; top; top = top.prev) subs.push(text.slice(top.at)) // substitutions never closed
      break
    }
    const c = cmd[i]
    const next = cmd[i + 1]
    const t = top ? top.t : null
    if (t === 'sq') {
      if (c !== "'") add(c)
      else if (!bash && next === "'") add("''", "'"), i++
      else closeQuote(c)
      continue
    }
    if (t === 'bt') {
      if (c === '\\' && i + 1 < n) add(c + next), i++
      else if (c === '`') closeQuote(c)
      else add(c)
      continue
    }
    if (t === 'dq') {
      if (bash && c === '\\' && lineEnd(i)) i += lineEnd(i)
      else if (c === esc && i + 1 < n && (!bash || BASH_DQ_ESCAPABLE.includes(next))) add(c + next, next), i++
      else if (c === '$' && next === '(') openSub('$('), i++
      else if (bash && c === '`') openQuote(i, c)
      else if (c !== '"') add(c)
      else if (!bash && next === '"') add('""', '"'), i++
      else closeQuote(c)
      continue
    }
    // Outside quotes, at the top or inside a $( ) substitution.
    const inQuote = top && top.q
    if (literal.has(i)) {
      add(c)
      continue
    }
    if (c === esc && lineEnd(i)) {
      // bash joins the lines; in PowerShell the break reads as a space.
      i += lineEnd(i)
      if (!bash && !inQuote) endWord(), (text += ' ')
      continue
    }
    if (c === esc && i + 1 < n && next !== '\n' && next !== '\r' && (!bash || BASH_ESCAPABLE.includes(next))) {
      add(c + next, next)
      i++
      continue
    }
    if (c === '"' || c === "'" || (bash && c === '`')) {
      openQuote(i, c)
      continue
    }
    if ((c === '$' || (!bash && c === '@')) && next === '(') {
      openSub(c + next)
      i++
      continue
    }
    if (t === 'sub' && (c === '(' || c === ')')) {
      if (c === '(') top = { ...top, depth: top.depth + 1 }
      else if (top.depth) top = { ...top, depth: top.depth - 1 }
      else {
        subs.push(text.slice(top.at))
        top = top.prev
      }
      add(c)
      continue
    }
    if (!top && (c === '(' || c === ')')) paren = c === '(' ? paren + 1 : Math.max(0, paren - 1)
    if (!bash && !top && paren && (c === '\n' || c === '\r')) {
      endWord()
      text += ' '
      continue
    }
    const sep = c === ';' || c === '\n' || c === '\r' || c === '|' || (c === '&' && !(last === '' || '=({,'.includes(last)) && cmd[i - 1] !== '>' && next !== '>')
    if (sep && top) {
      // Inside a substitution: a word break, not a new segment.
      if (inQuote) add(c)
      else endWord(), (text += c)
      continue
    }
    if (sep) {
      cut()
      if ((c === '&' && next === '&') || (c === '|' && next === '|')) i++
      continue
    }
    if (/\s/.test(c)) {
      if (inQuote) add(c)
      else endWord(), (text += c)
      continue
    }
    add(c)
  }
  cut()
  return segs
}

/** Split a shell command into segments (see lex). */
export function splitSegments(cmd, dialect) {
  return lex(cmd, dialect).map((s) => s.text.trim())
}

/** Split one segment into words, removing quotes. */
export function words(seg, dialect) {
  return lex(seg, dialect).flatMap((s) => s.tokens.map((t) => t.w))
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

/** Whether `git <args>` writes kb.privateName (set, add, unset, edit, or drop the kb section). */
function setsPrivateName(args) {
  if ((args[0] || '').toLowerCase() !== 'config') return false
  const rest = args.slice(1)
  const names = rest.filter((r) => !r.startsWith('-'))
  const section = rest.some((r) => /^--(remove|rename)-section$/i.test(r)) || ['remove-section', 'rename-section'].includes(names[0])
  const touches = rest.some((r) => /^kb\.privatename(=|$)/i.test(r)) || (section && names.some((r) => /^kb$/i.test(r)))
  if (!touches) return false
  if (rest.some((r) => /^(--get|--get-all|--get-regexp|-l|--list|--show-origin)$/i.test(r)) || ['get', 'list'].includes(names[0])) return false
  return names.length >= 2 || section || rest.some((r) => /^(--unset|--unset-all|--add|--replace-all|--edit|-e)$/i.test(r))
}

/** A path argument the guard cannot work out, like (Get-KbPath). */
const UNRESOLVED = '\u0000(expression)'
/** A folder the guard cannot work out, after cd to an UNRESOLVED path. */
const UNKNOWN = '\u0000(unknown folder)'

/** ( minus ) outside quotes in a piece of raw command text. */
function parenBalance(raw) {
  let b = 0
  let quote = null
  for (const c of raw) {
    if (quote) {
      if (c === quote) quote = null
    } else if (c === '"' || c === "'") quote = c
    else if (c === '(') b++
    else if (c === ')') b--
  }
  return b
}

const ITEM_CMDS = new Set(['get-item', 'gi', 'resolve-path', 'rvpa', 'convert-path', 'cvpa'])

/**
 * The path a ( ) group stands for: ("x") -> x, (Join-Path a b) -> a\b,
 * (Get-Item x).FullName -> x. Anything else is UNRESOLVED.
 */
function resolveGroup(raw, dialect, depth = 0) {
  const m = /^[$@]?\(([\s\S]*)\)(?:\.(?:fullname|path|providerpath))?$/i.exec(raw.trim())
  if (!m || depth > 3) return UNRESOLVED
  const ws = words(m[1], dialect)
  const value = (w) => (/^[$@]?\(/.test(w) ? resolveGroup(w, dialect, depth + 1) : w)
  // ("x"), ($kb) and (~/x) are values; (Get-KbPath) runs a command.
  if (ws.length === 1) return /^\s*["'$(@~.\\/]|^\s*[a-z]:/i.test(m[1]) ? value(ws[0]) : UNRESOLVED
  const cmd = (ws[0] || '').toLowerCase()
  const args = ws.slice(1).filter((a) => !a.startsWith('-')).map(value)
  if (args.includes(UNRESOLVED)) return UNRESOLVED
  if (cmd === 'join-path' && args.length >= 2) return args.join(WIN ? '\\' : '/')
  if (ITEM_CMDS.has(cmd) && args.length === 1) return args[0]
  return UNRESOLVED
}

/**
 * The arguments after token j, up to the end of that command, as
 * { w, start, end, group }. A ( ) group is one argument: the path it stands
 * for, or UNRESOLVED. `end` is the index of the first token after them.
 */
function argsOf(sg, j, dialect) {
  const toks = sg.tokens
  const raw = (t) => sg.text.slice(t.start, t.end)
  const args = []
  let k = j + 1
  for (; k < toks.length; k++) {
    const tok = toks[k]
    const w = tok.w
    if (w === '&' || w === '|' || w === ')' || w === '}') break
    // Start-Process git -ArgumentList 'add','-A'
    if (/^-(argumentlist|args)$/i.test(w) && toks[k + 1]) {
      for (const a of toks[k + 1].w.split(/[\s,]+/)) if (a) args.push({ w: a, start: toks[k + 1].start, end: toks[k + 1].end })
      k++
      continue
    }
    if (/^[$@]?\(/.test(raw(tok))) {
      let bal = 0
      let m = k
      for (; m < toks.length; m++) {
        bal += parenBalance(raw(toks[m]))
        if (bal <= 0) break
      }
      if (m >= toks.length) {
        args.push({ w: UNRESOLVED, start: tok.start, end: sg.text.length, group: true })
        k = toks.length
        break
      }
      // A ) left over closes a group opened before this command.
      let text = sg.text.slice(tok.start, toks[m].end)
      if (bal < 0) text = text.slice(0, text.length + bal)
      args.push({ w: resolveGroup(text, dialect), start: tok.start, end: toks[m].end, group: true })
      k = m
      if (bal < 0) {
        k++
        break
      }
      continue
    }
    const r = raw(tok)
    const closes = (/\)$/.test(r) && parenBalance(r) < 0) || (/\}$/.test(r) && (r.match(/\}/g) || []).length > (r.match(/\{/g) || []).length)
    const t = closes ? w.replace(/[)}]+$/, '') : w
    if (t) args.push({ w: t, start: tok.start, end: tok.end })
    if (closes) {
      k++
      break
    }
  }
  return { args, end: k }
}

const CD = new Set(['cd', 'set-location', 'sl', 'chdir'])
const PUSHD = new Set(['pushd', 'push-location'])
const POPD = new Set(['popd', 'pop-location'])
const LAUNCHERS = new Set(['cmd', 'pwsh', 'powershell', 'bash', 'sh', 'zsh', 'wsl', 'iex', 'invoke-expression', 'start-process', 'invoke-command', 'start-job', 'start-threadjob'])
const BASH_LAUNCHERS = new Set(['bash', 'sh', 'zsh', 'wsl'])
/** Shell tools whose commands are read with bash rules; the rest with PowerShell rules. */
const BASH_TOOLS = /bash|zsh|wsl|^(sh|ksh|dash)$/i
const PYTHON = new Set(['python', 'python3', 'py'])
/** How deep launchers and command substitutions are followed. */
const MAX_DEPTH = 3

const WRITE_VERBS = new Set([
  'set-content', 'add-content', 'out-file', 'new-item', 'remove-item', 'move-item', 'copy-item', 'rename-item', 'clear-content',
  'sc', 'ac', 'ni', 'ri', 'mi', 'cpi', 'rni', 'del', 'erase', 'rd', 'rmdir', 'rm', 'mv', 'cp', 'copy', 'move', 'ren',
  'tee', 'tee-object', 'truncate',
])
const COPY_VERBS = new Set(['copy-item', 'cpi', 'cp', 'copy'])
/** Verbs that move, copy or delete files but write no text from the command itself. */
const NO_CONTENT_VERBS = new Set([...COPY_VERBS, 'move-item', 'mi', 'mv', 'move', 'rename-item', 'rni', 'ren', 'remove-item', 'ri', 'rm', 'del', 'erase', 'rd', 'rmdir', 'clear-content'])
const MOVE_VERBS = new Set(['move-item', 'mi', 'mv', 'move', 'rename-item', 'rni', 'ren'])
/** Verbs whose every path argument is removed or moved away. */
const MOVE_DELETE_VERBS = new Set(['move-item', 'mi', 'mv', 'move', 'rename-item', 'rni', 'ren', 'remove-item', 'ri', 'rm', 'del', 'erase', 'rd', 'rmdir', 'dotnet-delete', 'dotnet-move'])
const VALUE_PARAMS = new Set(['-path', '-literalpath', '-filepath', '-destination', '-value', '-encoding', '-itemtype', '-name', '-filter', '-include', '-exclude', '-credential', '-stream', '-t', '--target-directory'])
const PATH_PARAMS = new Set(['-path', '-literalpath', '-filepath', '-destination', '-t', '--target-directory'])
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
 * Look up the facts that need a child process: the 8.3 short forms of the
 * home folder and the knowledge base (like C:\Users\ABCDEF~1\KNOWLE~1) and
 * extra private names from `git config kb.privateName` in the knowledge base.
 * Pass the result to `guard.update()`.
 */
export async function detectEnvironment(home = homedir(), root = path.join(home, 'knowledge')) {
  const [short, extra] = await Promise.all([
    WIN
      ? run('cmd.exe', ['/d', '/c', `for %I in ("${home}" "${root}") do @echo %~sI`], { windowsVerbatimArguments: true })
      : Promise.resolve(''),
    run('git', ['-C', root, 'config', '--get-all', 'kb.privateName']),
  ])
  const [shortHome, shortRoot] = short.split(/\r?\n/).map((s) => s.trim())
  return {
    shortHome: shortHome || null,
    shortRoot: shortRoot || null,
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
 * @param {object} [env] - { home, shortHome, shortRoot, extraNames, privateNames, exists }; privateNames and exists are for tests
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
  let shortRoot = null
  let extraNames = []
  let root, rootKey, rootRel, shown, kbPy, commitHint
  // The root's path parts, each with the spellings found for it, and the first
  // part below the home folder (from there on an 8.3 name is matched by shape).
  let rootParts, rootAlts, shapeFrom
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
    rootParts = rootKey.split('/')
    rootAlts = rootParts.map((p) => new Set([p]))
    for (const alias of shortRoot ? [key(shortRoot), key(longForm(shortRoot))] : []) {
      const parts = alias.split('/')
      if (parts.length === rootParts.length) parts.forEach((p, i) => rootAlts[i].add(p))
    }
    shapeFrom = rootKey.startsWith(homeKey + '/') ? homeKey.split('/').length : 1
    privateRe = undefined
  }

  /** Apply facts found later (see detectEnvironment). */
  function update(found = {}) {
    if (found.shortHome !== undefined) shortHome = found.shortHome || null
    if (found.shortRoot !== undefined) shortRoot = found.shortRoot || null
    if (Array.isArray(found.extraNames)) extraNames = found.extraNames
    configure()
  }
  update({ shortHome: env.shortHome ?? null, shortRoot: env.shortRoot ?? null, extraNames: env.extraNames ?? [] })

  function privateNames() {
    if (privateRe !== undefined) return privateRe
    const names = new Set()
    for (const v of [...baseNames, ...extraNames, shortKey ? P.basename(shortHome) : null]) {
      if (typeof v === 'string' && v.trim()) names.add(v.trim())
    }
    const forms = new Set()
    for (const n of names) {
      // Skip names too short to match safely in any form ("a b" would match "ab").
      if (n.replace(/\s+/g, '').length < 3 || GENERIC_NAMES.has(n.toLowerCase())) continue
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
    if (k.startsWith(rootKey + '/')) return k.slice(rootKey.length + 1)
    // 8.3 names (KNOWLE~1) in the path or in the configured root.
    if (!WIN || (!k.includes('~') && !rootKey.includes('~'))) return null
    const parts = k.split('/')
    if (parts.length < rootParts.length) return null
    for (let i = 0; i < rootParts.length; i++) {
      if (rootAlts[i].has(parts[i])) continue
      if (i >= shapeFrom && (isShortOf(parts[i], rootParts[i]) || isShortOf(rootParts[i], parts[i]))) continue
      return null
    }
    return parts.slice(rootParts.length).join('/')
  }
  const inKb = (p) => relKb(p) !== null
  /** Resolve p against cwd; UNKNOWN when p is an expression, or relative to an unknown folder. */
  const at = (cwd, p) => {
    if (p === UNRESOLVED) return UNKNOWN
    let s = expandHome(p, home)
    if (WIN) s = s.replace(/^\/([a-zA-Z])(?=\/|$)/, '$1:') // Git Bash form /c/Users/...
    if (cwd === UNKNOWN && !P.isAbsolute(s)) return UNKNOWN
    return P.resolve(cwd, s)
  }
  // The root itself ('') too: deleting, moving or renaming it takes the hooks with it.
  const isProtected = (rel) =>
    rel === '' ||
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
    // kb.privateName feeds the name checks of the hooks and this guard, in any repo or globally.
    if (setsPrivateName(args.slice(i))) {
      return ask('git config kb.privateName changes which names the knowledge base checks block. Only the user changes it. Allow it?')
    }
    const gd = gitDir ? at(cwd, gitDir) : null
    const repo = workTree ? at(cwd, workTree) : gd && gd !== UNKNOWN ? (P.basename(gd).toLowerCase() === '.git' ? P.dirname(gd) : gd) : gd || cwd
    if (inKb(repo) || (gd && inKb(gd))) return gitRules(args, i, repo, globals)
    if (repo !== UNKNOWN && gd !== UNKNOWN) return null
    // The folder is an expression: fail closed when the command matters in the knowledge base.
    const d = gitRules(args, i, root, globals)
    return d && ask('this git command may run in the knowledge base (its folder is an expression the guard cannot read), where it would be refused or need approval. Allow it?')
  }

  function gitRules(args, i, repo, globals) {
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
    if (sub === 'mv') {
      const paths = [...positional, ...(dashdash >= 0 ? rest.slice(dashdash + 1) : [])]
      if (paths.some((p) => isProtected(relKb(at(repo, p)) ?? '-'))) return protectedMsg()
      return ask('git mv moves files in the knowledge base without fixing index.md, log.md or links. Allow it?')
    }
    const changesFiles =
      (sub === 'apply' && !(has('--check', '--stat', '--numstat', '--summary') && !has('--apply'))) ||
      ['read-tree', 'checkout-index', 'update-index', 'merge-file'].includes(sub) ||
      (sub === 'stash' && ['apply', 'pop', 'branch'].includes(rest[0]))
    if (changesFiles) {
      return ask(`git ${sub} changes files in the knowledge base without the kb.py checks. Allow it? Afterwards run ${kbPy} check.`)
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
    const loc = at(cwd, where)
    if (inKb(loc)) return okfRules(sub, rest, where)
    if (loc !== UNKNOWN) return null
    const d = okfRules(sub, rest, where)
    return d && ask('this okf command may run on the knowledge base (its path is an expression the guard cannot read), where it would be refused or need approval. Allow it?')
  }

  function okfRules(sub, rest, where) {
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
  const rootMsg = () =>
    deny(`never delete, move or rename the knowledge base folder itself (${shown}). Change files inside it with kb.py; ask the user for anything bigger.`)
  const nameMsg = () => deny('this text contains the Windows account name or the user folder path. Write %USERPROFILE% or ~ instead.')

  function checkShellWrite(sg, ws, cwd, dialect) {
    const seg = sg.text
    const redirects = [...seg.matchAll(REDIRECT)].map((m) => m[1]).filter((t) => !/^["']?(&\d|\$null|nul|\/dev\/null)["']?$/i.test(t))
    const vi = ws.findIndex(
      (w, j) =>
        atCommandStart(ws, j) &&
        (WRITE_VERBS.has(programName(w)) || (programName(w) === 'sed' && ws.slice(j + 1).some((a) => /^-[a-z]*i|^--in-place/.test(a)))),
    )
    const dotnet = DOTNET_WRITE.exec(seg)
    if (!redirects.length && vi < 0 && !dotnet) return null
    const verb = vi >= 0 ? programName(ws[vi]) : dotnet ? `dotnet-${dotnet[1].toLowerCase()}` : 'redirect'
    const quoted = sg.pieces.map((p) => p.s)

    const targets = redirects.map((t) => t.replace(/^["']|["']$/g, ''))
    // The verb's arguments, with each ( ) group read as the path it stands for.
    const args = vi >= 0 ? argsOf(sg, vi, dialect).args : []
    if (COPY_VERBS.has(verb)) targets.push(...copyDestination(args.map((a) => a.w)))
    else if (verb === 'dotnet-copy') targets.push(...quoted.slice(1, 2))
    else if (verb !== 'redirect') {
      for (const w of [...ws, ...quoted]) {
        const t = bare(w.replace(/^-[a-z]+:/i, ''))
        if (isPathWord(t)) targets.push(t)
      }
      args.forEach((a, k) => {
        const prev = k ? args[k - 1].w.toLowerCase() : ''
        if (a.group && !(VALUE_PARAMS.has(prev) && !PATH_PARAMS.has(prev))) targets.push(a.w)
      })
    }
    let unsure = targets.some((t) => at(cwd, t) === UNKNOWN)
    const inside = targets.filter((t) => inKb(at(cwd, t)))
    // Where a move goes: -Destination, -t, -NewName, or the last of two or more paths.
    let destIdx = -1
    if (MOVE_VERBS.has(verb)) {
      const pos = []
      args.forEach((a, k) => {
        const prev = k ? args[k - 1].w.toLowerCase() : ''
        if (['-destination', '-t', '--target-directory', '-newname'].includes(prev)) destIdx = k
        else if (!a.w.startsWith('-') && !VALUE_PARAMS.has(prev)) pos.push(k)
      })
      if (destIdx < 0 && pos.length >= 2) destIdx = pos[pos.length - 1]
    }
    const dest = destIdx >= 0 ? at(cwd, args[destIdx].w) : null
    // Deleting, moving or renaming the root folder takes the hooks with it; moving something into it is fine.
    if (MOVE_DELETE_VERBS.has(verb) && inside.some((t) => relKb(at(cwd, t)) === '' && at(cwd, t) !== dest)) return rootMsg()
    if (inside.some((t) => relKb(at(cwd, t)) !== '' && isProtected(relKb(at(cwd, t))))) return protectedMsg()

    // Deletes and moves: every argument is a path, also '.', '*' and bare folder names.
    if (MOVE_DELETE_VERBS.has(verb)) {
      const recursive = args.some((a) => /^(--recursive|-rec\w*|\/s)$/i.test(a.w) || (/^-[a-zA-Z]{1,4}$/.test(a.w) && /r/i.test(a.w) && !/^-fo/i.test(a.w)))
      let wide = 0 // 1 ask, 2 deny, 3 the root itself
      args.forEach((a, k) => {
        const prev = k ? args[k - 1].w.toLowerCase() : ''
        if (k === destIdx || a.w.startsWith('-') || (VALUE_PARAMS.has(prev) && !PATH_PARAMS.has(prev))) return
        const full = at(cwd, a.w)
        if (full === UNKNOWN) return void (unsure = true)
        const rel = relKb(full)
        if (rel === null) return
        const wild = /[*?[]/.test(P.basename(full))
        const dir = wild ? P.dirname(full) : full
        const dirRel = relKb(dir)
        let w = recursive || wild ? 1 : 0
        // A wildcard in the root, or a folder that holds a log.md, takes protected files along.
        if ((wild && dirRel !== null && isProtected(dirRel)) || isProtected(rel) || exists(P.join(dir, 'log.md'))) w = 2
        if (rel === '') w = 3
        wide = Math.max(wide, w)
      })
      if (wide === 3) return rootMsg()
      if (wide === 2) return deny(`this would delete or move log.md, .kb, .githooks or .git along with the rest. Delete single concepts only, and only when the user asked; use ${kbPy} touch --verb Deprecated instead.`)
      if (wide === 1) return ask('this deletes or moves a whole folder (or a wildcard) in the knowledge base, which may hold concepts not committed yet. Allow it?')
    }

    // Text the command writes into the knowledge base must not name the account.
    // The target paths themselves are left out of that check.
    const writesText = !(NO_CONTENT_VERBS.has(verb) || ['dotnet-copy', 'dotnet-move', 'dotnet-delete'].includes(verb)) || redirects.length > 0
    if (writesText && inside.length) {
      let text = seg
      for (const t of inside) text = text.split(t).join(' ')
      const rx = privateNames()
      if (rx && rx.test(text)) return nameMsg()
    }
    if (unsure) return ask('this command may write into the knowledge base (a path or the folder is an expression the guard cannot read). Allow it?')
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

  function checkSegment(sg, state, depth, dialect) {
    const seg = sg.text.trim()
    const ws = sg.tokens.map((t) => t.w)
    if (!ws.length) return null
    const found = []
    // Command substitutions run before the command itself: check each as a
    // command of its own. In "... $(x) ...", check the whole quoted text too.
    const inner = [...sg.subs, ...sg.pieces.filter((p) => p.sub).map((p) => p.s)]
    if (inner.length && depth >= MAX_DEPTH) return ask('this command nests command substitutions too deeply to check. Allow it?')
    for (const body of inner) {
      const d = scan(body, { cwd: state.cwd, stack: [...state.stack], env: { ...state.env } }, depth + 1, dialect)
      if (d && d.kind === 'deny') return d
      found.push(d)
    }
    const first = programName(ws[0])
    const target = CD.has(first) || PUSHD.has(first) ? argsOf(sg, 0, dialect).args.find((a) => !a.w.startsWith('-'))?.w : undefined
    if (CD.has(first)) {
      state.cwd = target ? at(state.cwd, target) : first === 'cd' ? home : state.cwd
      return pick(found)
    }
    if (PUSHD.has(first)) {
      state.stack.push(state.cwd)
      if (target) state.cwd = at(state.cwd, target)
      return pick(found)
    }
    if (POPD.has(first)) {
      if (state.stack.length) state.cwd = state.stack.pop()
      return pick(found)
    }
    if (setEnv(seg, ws, state)) return pick(found)
    // kb.py does its own checks; its arguments (commit messages) are not commands.
    if (ws.some((w) => PYTHON.has(programName(w))) && ws.some((w) => /(^|[\\/])kb\.py$/i.test(bare(w)))) return pick(found)

    for (let j = 0; j < ws.length; j++) {
      const name = programName(ws[j])
      if (name === 'git') found.push(checkGit(argsOf(sg, j, dialect).args.map((a) => a.w), state, prefixEnv(ws, j)))
      else if (name === 'okf') found.push(checkOkf(argsOf(sg, j, dialect).args.map((a) => a.w), state.cwd))
    }
    found.push(checkShellWrite(sg, ws, state.cwd, dialect))
    // cmd /c "...", pwsh -c "...", bash -c '...', iex "...": check the inner command too.
    if (depth < MAX_DEPTH && ws.some((w) => LAUNCHERS.has(programName(w)))) {
      const inner = ws.some((w) => BASH_LAUNCHERS.has(programName(w))) ? 'bash' : 'pwsh'
      for (const { s: q } of sg.pieces) {
        if (/\s/.test(q)) found.push(scan(q, { cwd: state.cwd, stack: [...state.stack], env: { ...state.env } }, depth + 1, inner))
      }
    }
    return pick(found)
  }

  function scan(command, state, depth, dialect) {
    const found = []
    for (const sg of lex(command, dialect)) {
      const d = checkSegment(sg, state, depth, dialect)
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
    if (rel === '') return rootMsg()
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
      const dialect = BASH_TOOLS.test(name) ? 'bash' : 'pwsh'
      return scan(args.command, { cwd: cwdOf(exec, args), stack: [], env: {} }, 0, dialect)
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
