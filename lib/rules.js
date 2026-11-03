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
  // The separator before and after each segment (; && || | & or a newline), so a
  // variable assignment after && or into a pipeline is not taken as certain.
  let lastSep
  const cut = (sepAfter) => {
    endWord()
    if (tokens.length || text.trim()) segs.push({ text, tokens, pieces, subs, before: lastSep, after: sepAfter })
    lastSep = sepAfter
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
    top = { t, at: text.length + (t === 'sub' ? 0 : 1), depth: 0, q: (top ? top.q : 0) + (t === 'sub' ? 0 : 1), s: (top ? top.s : 0) + (t === 'sub' || t === 'bt' ? 1 : 0), prev: top }
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
    if (t === 'bt' && top.s === 1) subs.push(text.slice(top.at))
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
      for (; top; top = top.prev) if (top.s === 1) subs.push(text.slice(top.at)) // substitutions never closed
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
        if (top.s === 1) subs.push(text.slice(top.at))
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
      const both = (c === '&' && next === '&') || (c === '|' && next === '|')
      cut(both ? c + next : c === '\r' ? '\n' : c)
      if (both) i++
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

/** The words of a piece of command text, each as { w, raw }: w without quotes, raw as written. */
function rawWords(text, dialect) {
  return lex(text, dialect).flatMap((s) => s.tokens.map((t) => ({ w: t.w, raw: s.text.slice(t.start, t.end) })))
}

/** A resolver that knows no variables: words are taken as written. */
const asWritten = (raw, w) => w

/**
 * The path a ( ) group stands for: ("x") -> x, (Join-Path a b) -> a\b,
 * (Get-Item x).FullName -> x. Anything else is UNRESOLVED. `resolve(raw, w)`
 * gives the value of one word, with its variables filled in (or UNRESOLVED).
 */
function resolveGroup(raw, dialect, depth = 0, resolve = asWritten) {
  const m = /^[$@]?\(([\s\S]*)\)(?:\.(?:fullname|path|providerpath))?$/i.exec(raw.trim())
  if (!m || depth > 3) return UNRESOLVED
  const ws = rawWords(m[1], dialect)
  const value = (t) => (/^[$@]?\(/.test(t.w) ? resolveGroup(t.w, dialect, depth + 1, resolve) : resolve(t.raw, t.w))
  // ("x"), ($kb) and (~/x) are values; (Get-KbPath) runs a command.
  if (ws.length === 1) return /^\s*["'$(@~.\\/]|^\s*[a-z]:/i.test(m[1]) ? value(ws[0]) : UNRESOLVED
  const cmd = (ws[0] ? ws[0].w : '').toLowerCase()
  const args = ws.slice(1).filter((a) => !a.w.startsWith('-')).map(value)
  if (args.includes(UNRESOLVED)) return UNRESOLVED
  if (cmd === 'join-path' && args.length >= 2) return args.join(WIN ? '\\' : '/')
  if (ITEM_CMDS.has(cmd) && args.length === 1) return args[0]
  return UNRESOLVED
}

/**
 * Command text with the inside of quotes and comments blanked out (same length),
 * so = { } there are not read as code, and where a # line comment starts (or -1).
 */
function maskQuotes(text, dialect) {
  const bash = dialect === 'bash'
  let out = ''
  let q = null
  let comment = -1
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (q) {
      if (!bash && c === '`' && q === '"') out += '  ', i++
      else if (bash && c === '\\' && q === '"') out += '  ', i++
      else if (c === q && !bash && text[i + 1] === q) out += '  ', i++
      else if (c === q) (q = null), (out += c)
      else out += ' '
      continue
    }
    if ((!bash && c === '`') || (bash && c === '\\')) {
      out += c + (text[i + 1] ?? '')
      i++
      continue
    }
    // <# block comment #> (PowerShell) and # to the end of the line, after a space or at the start.
    if (!bash && c === '<' && text[i + 1] === '#') {
      const e = text.indexOf('#>', i + 2)
      const stop = e < 0 ? text.length : e + 2
      out += ' '.repeat(stop - i)
      i = stop - 1
      continue
    }
    if (c === '#' && (i === 0 || /\s/.test(text[i - 1]))) {
      comment = i
      out += ' '.repeat(text.length - i)
      break
    }
    if (c === '"' || c === "'") q = c
    out += c
  }
  return { masked: out, comment }
}

/**
 * The arguments after token j, up to the end of that command, as
 * { w, start, end, group, vary }. A ( ) group is one argument: the path it
 * stands for, or UNRESOLVED. A word with a $variable in it has its value
 * (or UNRESOLVED) and vary: true. `end` is the index of the first token after them.
 */
function argsOf(sg, j, dialect, resolve = asWritten) {
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
      args.push({ w: resolveGroup(text, dialect, 0, resolve), start: tok.start, end: toks[m].end, group: true })
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
    if (t) {
      const vary = r.includes('$')
      args.push({ w: vary ? resolve(closes ? r.replace(/[)}]+$/, '') : r, t) : t, start: tok.start, end: tok.end, vary })
    }
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
/** The longest shell command that is checked (64 KB); longer ones ask. */
const MAX_COMMAND = 64 * 1024

const WRITE_VERBS = new Set([
  'set-content', 'add-content', 'out-file', 'new-item', 'remove-item', 'move-item', 'copy-item', 'rename-item', 'clear-content',
  'sc', 'ac', 'ni', 'ri', 'mi', 'cpi', 'rni', 'del', 'erase', 'rd', 'rmdir', 'rm', 'mv', 'cp', 'copy', 'move', 'ren',
  'tee', 'tee-object', 'truncate',
])
const COPY_VERBS = new Set(['copy-item', 'cpi', 'cp', 'copy'])
/** PowerShell verbs whose only positional path is the first; later positionals (-Value, -Encoding) are not paths. */
const CONTENT_VERBS = new Set(['set-content', 'sc', 'add-content', 'ac', 'out-file', 'tee-object', 'tee', 'new-item', 'ni'])
/** Commands that set variables in ways the table does not follow: every variable becomes unknown. */
const VAR_POISON = new Set(['set-variable', 'sv', 'new-variable', 'nv', 'clear-variable', 'clv', 'remove-variable', 'rv', '.', 'source', 'read', 'mapfile', 'readarray', 'getopts', 'eval', 'iex', 'invoke-expression'])
/** Common parameters that store into a variable, also abbreviated (-OutVar, -ov). */
const VAR_PARAMS = /(?:^|\s)-(?:outv\w*|ov|pipelinev\w*|pv|errorv\w*|ev|warningv\w*|wv|informationv\w*|iv)\b/i
/** bash words after which a command starts (while read k; if read k). */
const BASH_CTL = new Set(['while', 'until', 'if', 'elif', 'then', 'do', 'else', '!'])
/** Switches of the write verbs that take no value, so the word after them is a positional. */
const KNOWN_SWITCHES = new Set(['-force', '-nonewline', '-append', '-passthru', '-whatif', '-confirm', '-noclobber', '-asbytestream', '-verbose', '-debug', '-recurse', '-raw'])
const BASH_OPEN = new Set(['if', 'for', 'while', 'until', 'case', 'select'])
const BASH_CLOSE = new Set(['fi', 'done', 'esac'])
/** Verbs that move, copy or delete files but write no text from the command itself. */
const NO_CONTENT_VERBS = new Set([...COPY_VERBS, 'move-item', 'mi', 'mv', 'move', 'rename-item', 'rni', 'ren', 'remove-item', 'ri', 'rm', 'del', 'erase', 'rd', 'rmdir', 'clear-content'])
const MOVE_VERBS = new Set(['move-item', 'mi', 'mv', 'move', 'rename-item', 'rni', 'ren'])
/** Verbs whose every path argument is removed or moved away. */
const MOVE_DELETE_VERBS = new Set(['move-item', 'mi', 'mv', 'move', 'rename-item', 'rni', 'ren', 'remove-item', 'ri', 'rm', 'del', 'erase', 'rd', 'rmdir', 'dotnet-delete', 'dotnet-move'])
const VALUE_PARAMS = new Set(['-path', '-literalpath', '-filepath', '-destination', '-value', '-encoding', '-itemtype', '-type', '-name', '-filter', '-include', '-exclude', '-credential', '-stream', '-width', '-inputobject', '-erroraction', '-ea', '-warningaction', '-wa', '-t', '--target-directory'])
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
  let root, rootKey, rootRel, shown, rootArg, kbPy, commitHint
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
    rootArg = rootRel === null ? `"${root}"` : WIN ? `"$env:USERPROFILE${sub}"` : `~${sub}`
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

  // ---- Variables -------------------------------------------------------------
  // A command may set $repo = '...' and then write to "$repo\x". The table below
  // follows plain assignments, in order, within one command. Anything it cannot
  // follow makes that variable UNRESOLVED, and a path built from an UNRESOLVED
  // variable is treated like any other expression: fail closed, never a guess.

  /**
   * A fresh table. `assigned` (for $( ) bodies) collects every name set inside.
   * `tainted` holds names assigned inside a { } block, loop or function body:
   * that code may run later (a call, the next loop pass), so such a name stays
   * UNRESOLVED for the rest of the command, whatever plain assignment follows.
   */
  const newVars = (parent) => ({
    map: new Map(parent ? parent.map : []),
    poisoned: parent ? parent.poisoned : false,
    depth: 0,
    assigned: parent ? new Set() : null,
    tainted: new Set(parent ? parent.tainted : []),
  })
  const varKey = (name, dialect) => (dialect === 'bash' ? name : name.toLowerCase().replace(/^(script|global|local|private):/, ''))
  function lookup(name, vars, dialect) {
    const n = varKey(name, dialect)
    if (dialect === 'bash' ? n === 'HOME' || n === 'USERPROFILE' : n === 'home' || n === 'env:userprofile' || n === 'env:home') return home
    if (n.includes(':') || vars.poisoned || !vars.map.has(n)) return UNRESOLVED
    return vars.map.get(n)
  }
  function setVar(vars, name, value, dialect, taint = false) {
    const n = varKey(name, dialect)
    if (taint) vars.tainted.add(n)
    vars.map.set(n, vars.tainted.has(n) ? UNRESOLVED : value)
    if (vars.assigned) vars.assigned.add(n)
  }

  /**
   * The value of one word as the shell would expand it: '...' is literal,
   * "..." and bare text have $name, ${name}, $env:USERPROFILE and $HOME filled
   * in. UNRESOLVED when any part cannot be known: an unknown variable, $( ),
   * a property ($x.FullName), or $1 / $? and the like.
   */
  function resolveRaw(raw, w, vars, dialect) {
    const bash = dialect === 'bash'
    if (!raw.includes('$') && !(bash && raw.includes('`'))) return w
    let out = ''
    let q = null
    for (let i = 0; i < raw.length; i++) {
      const c = raw[i]
      const nx = raw[i + 1]
      if (q === "'") {
        if (c !== "'") out += c
        else if (!bash && nx === "'") (out += "'"), i++
        else q = null
        continue
      }
      if (!bash && c === '`' && i + 1 < raw.length) {
        out += nx
        i++
        continue
      }
      if (bash && c === '\\' && i + 1 < raw.length && (q === '"' ? BASH_DQ_ESCAPABLE : BASH_ESCAPABLE).includes(nx)) {
        out += nx
        i++
        continue
      }
      if (c === '"') {
        if (q !== '"') q = '"'
        else if (!bash && nx === '"') (out += '"'), i++
        else q = null
        continue
      }
      if (c === "'" && !q) {
        q = "'"
        continue
      }
      if (bash && c === '`') return UNRESOLVED
      if (c !== '$') {
        out += c
        continue
      }
      const rest = raw.slice(i + 1)
      let name
      let len
      let m
      if (rest[0] === '(') return UNRESOLVED
      if (rest[0] === '{') {
        const e = rest.indexOf('}')
        if (e < 0) return UNRESOLVED
        name = rest.slice(1, e)
        len = e + 1
      } else if ((m = (bash ? /^[A-Za-z_]\w*/ : /^[A-Za-z_]\w*(?::[A-Za-z_]\w*)?/).exec(rest))) {
        name = m[0]
        len = name.length
        // $x.Name and $x[0] outside quotes read a property or an item.
        if (!bash && !q && /^[.[]/.test(rest.slice(len))) return UNRESOLVED
      } else if (/^[0-9?#@*!$^-]/.test(rest)) return UNRESOLVED
      else {
        out += '$'
        continue
      }
      const v = lookup(name, vars, dialect)
      if (v === UNRESOLVED) return UNRESOLVED
      out += v
      i += len
    }
    return out
  }

  /** The value a plain assignment gives: a literal, a variable, "...", or Join-Path. */
  function rhsValue(rhs, resolve, dialect) {
    const r = rhs.trim()
    if (!r) return UNRESOLVED
    if (dialect === 'bash') return resolve(r, rawWords(r, 'bash')[0]?.w ?? '')
    const segs = lex(r, dialect)
    if (segs.length !== 1) return UNRESOLVED
    const s = segs[0]
    const toks = s.tokens.map((t) => ({ w: t.w, raw: s.text.slice(t.start, t.end) }))
    if (/^[$@]?\(/.test(r)) return resolveGroup(r, dialect, 0, resolve)
    if (toks.length === 1 && /^['"$]/.test(r)) return resolve(toks[0].raw, toks[0].w)
    if (toks.length >= 3 && toks[0].w.toLowerCase() === 'join-path') return resolveGroup(`(${r})`, dialect, 0, resolve)
    return UNRESOLVED
  }

  const PS_PLAIN = /^\s*\$(?:\{([^}:]+)\}|([A-Za-z_]\w*))\s*=(?!=)\s*([\s\S]*?)\s*$/
  const PS_ANY = /((?:\$\{[^}]+\}|\$[A-Za-z_][\w:]*)(?:\s*,\s*(?:\$\{[^}]+\}|\$[A-Za-z_][\w:]*))*)\s*(?:[-+*/%]|\?\?)?=(?!=)/g
  const PS_NAME = /\$(?:\{([^}]+)\}|([A-Za-z_][\w:]*))/g

  /** Update the table for one segment, before its own checks run. */
  function trackVars(sg, ws, vars, resolve, dialect) {
    const bash = dialect === 'bash'
    // Quotes and comments blanked: a { } or $x = in a string or a # comment is not code.
    const { masked, comment } = maskQuotes(sg.text, dialect)
    const code = comment >= 0 ? sg.text.slice(0, comment) : sg.text
    const braces = masked.replace(/\$\{[^}]*\}/g, '')
    const opens = (braces.match(/\{/g) || []).length
    const closes = (braces.match(/\}/g) || []).length
    const first = programName(ws[0] || '')
    const kw = bash ? (BASH_OPEN.has(first) ? 1 : BASH_CLOSE.has(first) ? -1 : 0) : 0
    const inBlock = vars.depth > 0 || opens > 0 || closes > 0 || kw !== 0 || (bash && ['then', 'do', 'else', 'elif'].includes(first))
    const chained = ['&&', '||', '|', '&'].includes(sg.before) || ['|', '&'].includes(sg.after)
    vars.depth = Math.max(0, vars.depth + opens - closes + kw)

    // Commands that set variables the table cannot follow, wherever a command starts in this segment.
    const runs = (j) => atCommandStart(ws, j) || (bash && BASH_CTL.has((ws[j - 1] || '').toLowerCase()))
    const poison = ws.some((w, j) => {
      const p = programName(w)
      if (!runs(j)) return false
      if (VAR_POISON.has(p)) return true
      if (bash && p === 'printf') return ws.slice(j + 1).some((a) => /^-v/.test(a))
      if (!bash && (p === 'tee-object' || p === 'tee')) return ws.slice(j + 1).some((a) => /^-v/i.test(a))
      return false
    })
    if (poison || (!bash && VAR_PARAMS.test(masked)) || /\[ref\]|psvariable\.set|\.sessionstate\b/i.test(masked)) {
      vars.poisoned = true
      return
    }
    const mark = (name) => setVar(vars, name, UNRESOLVED, dialect, inBlock)
    // The plain case, worked out with the table as it was before this segment.
    let plain = null
    if (!inBlock && !chained) {
      if (bash) {
        const tokRaw = sg.tokens.filter((t) => comment < 0 || t.start < comment).map((t) => sg.text.slice(t.start, t.end))
        const one = tokRaw.length === 1 ? tokRaw[0] : tokRaw.length === 2 && first === 'export' ? tokRaw[1] : null
        const m = one && /^([A-Za-z_]\w*)=([\s\S]*)$/.exec(one)
        if (m) plain = { name: m[1], value: m[2] === '' ? '' : rhsValue(m[2], resolve, dialect) }
      } else {
        const m = PS_PLAIN.exec(code)
        if (m && m[3]) plain = { name: m[1] || m[2], value: rhsValue(m[3], resolve, dialect) }
      }
    }
    // Everything else that may assign: typed, multiple, compound, loops, ++.
    if (bash) {
      for (const m of masked.matchAll(/(?:^|[\s;&|(])([A-Za-z_]\w*)\+?=/g)) mark(m[1])
      for (const m of masked.matchAll(/\bfor\s+([A-Za-z_]\w*)\s+in\b/g)) mark(m[1])
    } else {
      for (const m of masked.matchAll(PS_ANY)) for (const n of m[1].matchAll(PS_NAME)) mark(n[1] || n[2])
      for (const m of masked.matchAll(/\bforeach\s*\(\s*\$([A-Za-z_][\w:]*)/gi)) mark(m[1])
      for (const m of masked.matchAll(/\$([A-Za-z_][\w:]*)\s*(?:\+\+|--)|(?:\+\+|--)\s*\$([A-Za-z_][\w:]*)/g)) mark(m[1] || m[2])
    }
    if (plain) setVar(vars, plain.name, plain.value, dialect)
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
      return deny(`the knowledge base hooks stay on, so an agent never changes core.hooksPath there. If the hooks are missing (README setup, a new clone), ask the user to run this in a terminal themselves: git -C ${rootArg} config core.hooksPath .githooks`)
    }
    if (rest.includes('--no-verify') || (sub === 'commit' && rest.some((r) => shortFlags(r, 'n')))) {
      return deny(`never skip the knowledge base checks. Fix what they report, then commit with ${commitHint}`)
    }
    if (sub === 'commit') {
      return deny(`in the knowledge base, commit with kb.py so the checks run and only your files are staged: ${commitHint}`)
    }
    if (sub === 'add' || sub === 'stage') {
      return deny(`do not use git add in the knowledge base. kb.py commit stages the files you name, plus their log.md and index lines: ${commitHint}. The README setup lines (git add -A, the first commit) are for the user to run in a terminal, not for an agent.`)
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
    // Concepts may also be named by file path (okf rm <file>), from any folder.
    const places = [where, ...(bundle === undefined ? [] : [bundle]), ...positional].map((p) => at(cwd, p))
    if (places.some(inKb)) return okfRules(sub, rest, where)
    if (!places.includes(UNKNOWN)) return null
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

  /** Where a copy or move goes: -Destination, -t, -NewName, or the last of two or more paths. Index into args, or -1. */
  function destIndex(args) {
    const positional = []
    let dest = -1
    for (let i = 0; i < args.length; i++) {
      const a = args[i].w.toLowerCase()
      if (VALUE_PARAMS.has(a) || a === '-newname') {
        if (['-destination', '-t', '--target-directory', '-newname'].includes(a) && i + 1 < args.length) dest = i + 1
        i++
      } else if (!a.startsWith('-')) positional.push(i)
    }
    if (dest < 0 && positional.length >= 2) dest = positional[positional.length - 1]
    return dest
  }

  const protectedMsg = () =>
    deny(`only kb.py writes log.md, and nothing should change .kb, .githooks, .git or .gitattributes. Use ${kbPy} log, touch or new.`)
  const rootMsg = () =>
    deny(`never delete, move or rename the knowledge base folder itself (${shown}). Change files inside it with kb.py; ask the user for anything bigger.`)
  const nameMsg = () => deny('this text contains the Windows account name or the user folder path. Write %USERPROFILE% or ~ instead.')

  function checkShellWrite(sg, ws, cwd, dialect, resolve = asWritten) {
    const seg = sg.text
    // Each target is { t, start, end }: the path and where it is written in the segment.
    const targets = []
    let redirected = false
    for (const m of seg.matchAll(REDIRECT)) {
      if (/^["']?(&\d|\$null|nul|\/dev\/null)["']?$/i.test(m[1])) continue
      targets.push({ t: resolve(m[1], m[1].replace(/^["']|["']$/g, '')), start: m.index, end: m.index + m[0].length })
      redirected = true
    }
    let inPlace = -1 // the last sed -i flag
    ws.forEach((a, k) => {
      if (/^-[a-z]*i|^--in-place/.test(a)) inPlace = k
    })
    const vi = ws.findIndex((w, j) => atCommandStart(ws, j) && (WRITE_VERBS.has(programName(w)) || (programName(w) === 'sed' && inPlace > j)))
    const dotnet = DOTNET_WRITE.exec(seg)
    if (!redirected && vi < 0 && !dotnet) return null
    const verb = vi >= 0 ? programName(ws[vi]) : dotnet ? `dotnet-${dotnet[1].toLowerCase()}` : 'redirect'

    // The verb's arguments, with each ( ) group read as the path it stands for.
    const args = vi >= 0 ? argsOf(sg, vi, dialect, resolve).args : []
    const destIdx = COPY_VERBS.has(verb) || MOVE_VERBS.has(verb) ? destIndex(args) : -1
    const asTarget = (a) => ({ t: a.w, start: a.start, end: a.end })
    if (COPY_VERBS.has(verb)) {
      if (destIdx >= 0) targets.push(asTarget(args[destIdx]))
    } else if (verb === 'dotnet-copy') {
      if (sg.pieces[1]) targets.push({ t: sg.pieces[1].s, start: sg.pieces[1].start, end: sg.pieces[1].end })
    } else if (verb !== 'redirect') {
      for (const x of [...sg.tokens.map((tk) => ({ s: tk.w, start: tk.start, end: tk.end })), ...sg.pieces]) {
        const t = bare(x.s.replace(/^-[a-z]+:/i, ''))
        const raw = seg.slice(x.start, x.end)
        if (!raw.includes('$')) {
          if (isPathWord(t)) targets.push({ t, start: x.start, end: x.end })
          continue
        }
        // "$repo\x" and $gi: the value the variables give, or UNRESOLVED when a path-like word cannot be read.
        const v = resolve(raw.replace(/^-[a-z]+:/i, ''), x.s)
        if (v === UNRESOLVED) {
          if (isPathWord(t)) targets.push({ t: UNRESOLVED, start: x.start, end: x.end })
        } else if (isPathWord(bare(v))) targets.push({ t: bare(v), start: x.start, end: x.end })
      }
      // Set-Content $f ($lines -join ...): only the first positional is a path; the rest is the value.
      const firstOnly = CONTENT_VERBS.has(verb) && !(dialect === 'bash' && verb === 'tee')
      let pos = 0
      args.forEach((a, k) => {
        const prev = k ? args[k - 1].w.toLowerCase() : ''
        if (!a.group && a.w.startsWith('-')) return
        const named = VALUE_PARAMS.has(prev)
        // After a parameter this list does not know, the word may be its value or a positional: count
        // it as neither, and check it as a path (n = -1 is never skipped below).
        const unsure = !named && prev.startsWith('-') && !KNOWN_SWITCHES.has(prev)
        const n = named || unsure ? -1 : pos++
        if (!(a.group || a.vary)) return
        if (named && !PATH_PARAMS.has(prev)) return
        if (firstOnly && n > 0) return
        targets.push(asTarget(a))
      })
    }
    for (const x of targets) x.full = at(cwd, x.t)
    let unsure = targets.some((x) => x.full === UNKNOWN)
    const inside = targets.filter((x) => (x.rel = relKb(x.full)) !== null)
    const dest = destIdx >= 0 ? at(cwd, args[destIdx].w) : null
    // Deleting, moving or renaming the root folder takes the hooks with it; moving something into it is fine.
    if (MOVE_DELETE_VERBS.has(verb) && inside.some((x) => x.rel === '' && x.full !== dest)) return rootMsg()
    if (inside.some((x) => x.rel !== '' && isProtected(x.rel))) return protectedMsg()

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
    // The target paths themselves are left out of that check, in one pass over the text.
    const writesText = !(NO_CONTENT_VERBS.has(verb) || ['dotnet-copy', 'dotnet-move', 'dotnet-delete'].includes(verb)) || redirected
    const rx = writesText && inside.length ? privateNames() : null
    if (rx) {
      let text = ''
      let pos = 0
      for (const x of [...inside].sort((a, b) => a.start - b.start)) {
        if (x.start > pos) text += seg.slice(pos, x.start)
        text += ' '
        pos = Math.max(pos, x.end)
      }
      text += seg.slice(pos)
      if (rx.test(text)) return nameMsg()
    }
    if (unsure) return ask('this command may write into the knowledge base (a path or the folder is an expression the guard cannot read). Allow it?')
    return null
  }

  /** Environment set for git by this segment (PowerShell $env:, bash export/unset); true when handled. */
  function setEnv(sg, seg, ws, state, resolve) {
    const ps = /^\$env:(git_dir|git_work_tree)\s*=\s*(.*)$/i.exec(seg)
    if (ps) {
      const tok = rawWords(ps[2], 'pwsh')[0]
      const name = ps[1].toUpperCase()
      if (!tok || !tok.w || /^\$null$/i.test(tok.raw)) delete state.env[name]
      else state.env[name] = /^[$@]?\(/.test(tok.raw) ? resolveGroup(ps[2], 'pwsh', 0, resolve) : resolve(tok.raw, tok.w)
      return true
    }
    const first = programName(ws[0])
    if (first === 'export' || first === 'unset' || first === 'remove-item' || first === 'ri') {
      sg.tokens.slice(1).forEach((tk) => {
        const m = /^(?:env:)?(GIT_DIR|GIT_WORK_TREE)(?:=(.*))?$/i.exec(tk.w)
        if (!m) return
        const name = m[1].toUpperCase()
        const raw = sg.text.slice(tk.start, tk.end)
        if (first === 'export' && m[2]) state.env[name] = resolve(raw.slice(raw.indexOf('=') + 1), m[2])
        else delete state.env[name]
      })
      return ws.slice(1).some((w) => /^(?:env:)?GIT_(DIR|WORK_TREE)\b/i.test(w))
    }
    return false
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
      // $( ) runs in this shell: it sees the variables, and what it assigns is unknown afterwards.
      const vars = newVars(state.vars)
      const d = scan(body, { cwd: state.cwd, stack: [...state.stack], env: { ...state.env }, vars }, depth + 1, dialect)
      for (const n of vars.assigned) setVar(state.vars, n, UNRESOLVED, dialect, vars.tainted.has(n))
      if (vars.poisoned) state.vars.poisoned = true
      if (d && d.kind === 'deny') return d
      found.push(d)
    }
    const resolve = (raw, w) => resolveRaw(raw, w, state.vars, dialect)
    trackVars(sg, ws, state.vars, resolve, dialect)
    const first = programName(ws[0])
    const target = CD.has(first) || PUSHD.has(first) ? argsOf(sg, 0, dialect, resolve).args.find((a) => !a.w.startsWith('-'))?.w : undefined
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
    if (setEnv(sg, seg, ws, state, resolve)) return pick(found)
    // kb.py does its own checks; its arguments (commit messages) are not commands.
    if (ws.some((w) => PYTHON.has(programName(w))) && ws.some((w) => /(^|[\\/])kb\.py$/i.test(bare(w)))) return pick(found)

    // One pass: a git or okf word inside the arguments of an earlier one is just
    // an argument. GIT_DIR=... GIT_WORK_TREE=... in front of git (bash) apply to it.
    const prefix = {}
    for (let j = 0, skip = 0; j < ws.length; j++) {
      const name = j >= skip ? programName(ws[j]) : ''
      if (name === 'git' || name === 'okf') {
        const { args, end } = argsOf(sg, j, dialect, resolve)
        const words = args.map((a) => a.w)
        found.push(name === 'git' ? checkGit(words, state, { ...prefix }) : checkOkf(words, state.cwd))
        skip = end
      }
      const m = /^(GIT_DIR|GIT_WORK_TREE)=(.*)$/.exec(ws[j])
      if (m) {
        const raw = sg.text.slice(sg.tokens[j].start, sg.tokens[j].end)
        prefix[m[1]] = resolve(raw.slice(raw.indexOf('=') + 1), m[2])
      }
    }
    found.push(checkShellWrite(sg, ws, state.cwd, dialect, resolve))
    // cmd /c "...", pwsh -c "...", bash -c '...', iex "...": check the inner command too.
    // It runs in another shell, so none of this command's variables are known there.
    if (depth < MAX_DEPTH && ws.some((w) => LAUNCHERS.has(programName(w)))) {
      const inner = ws.some((w) => BASH_LAUNCHERS.has(programName(w))) ? 'bash' : 'pwsh'
      for (const { s: q } of sg.pieces) {
        if (/\s/.test(q)) found.push(scan(q, { cwd: state.cwd, stack: [...state.stack], env: { ...state.env }, vars: { ...newVars(), poisoned: true } }, depth + 1, inner))
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
      // Checking stays cheap: a longer command is not read at all.
      if (args.command.length > MAX_COMMAND) return ask('command too long to check; split it')
      const dialect = BASH_TOOLS.test(name) ? 'bash' : 'pwsh'
      return scan(args.command, { cwd: cwdOf(exec, args), stack: [], env: {}, vars: newVars() }, 0, dialect)
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
