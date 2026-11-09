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
    // A PowerShell here-string (@' ... '@, @" ... "@) ends only at its quote and @ at the start of a line.
    const hereEnd = top && top.here && c === (t === 'sq' ? "'" : '"') && next === '@' && (i === 0 || cmd[i - 1] === '\n')
    if (hereEnd) {
      closeQuote(c)
      add('@')
      i++
      continue
    }
    if (t === 'sq' && top.here) {
      add(c)
      continue
    }
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
      else if (c !== '"' || top.here) add(c)
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
    if (!bash && c === '@' && (next === "'" || next === '"') && /^[ \t]*\r?\n/.test(cmd.slice(i + 2))) {
      add('@')
      openQuote(i + 1, next)
      top.here = true
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

/**
 * Whether `git <args>` sets or unsets core.hooksPath for every repository (--global,
 * --system): a knowledge base clone without its own setting would lose its hooks.
 */
function setsGlobalHooksPath(args) {
  if ((args[0] || '').toLowerCase() !== 'config') return false
  const rest = args.slice(1)
  if (!rest.some((r) => /^--(global|system)$/i.test(r))) return false
  const names = rest.filter((r) => !r.startsWith('-'))
  const section = rest.some((r) => /^--(remove|rename)-section$/i.test(r)) || ['remove-section', 'rename-section'].includes(names[0])
  const touches = rest.some((r) => /^core\.hookspath(=|$)/i.test(r)) || (section && names.some((r) => /^core$/i.test(r)))
  if (!touches) return false
  if (rest.some((r) => /^(--get|--get-all|--get-regexp|-l|--list|--show-origin)$/i.test(r)) || ['get', 'list'].includes(names[0])) return false
  return names.length >= 2 || section || rest.some((r) => /^(--unset|--unset-all|--add|--replace-all|--edit|-e)$/i.test(r))
}

/** A path argument the guard cannot work out, like (Get-KbPath). */
const UNRESOLVED = '\u0000(expression)'
/** A folder the guard cannot work out, after cd to an UNRESOLVED path. */
const UNKNOWN = '\u0000(unknown folder)'
/**
 * A folder the guard cannot name but knows is outside the knowledge base and not
 * above it: one of several such folders a loop visits. Relative paths from it
 * stay outside, unless they climb with `..`.
 */
const OUTSIDE = '\u0000(outside folder)'

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
 * PowerShell strings joined with +: $bak + '\handlers' -> its value plus \handlers.
 * Each term must be a quoted string, a $variable or a ( ) group; the value is
 * UNRESOLVED when any term is. null when the text is not such a join.
 */
function joinTerms(text, dialect, depth, resolve) {
  if (dialect === 'bash' || !text.includes('+')) return null
  const terms = []
  let q = null
  let d = 0
  let from = 0
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (q) {
      if (c === '`' && q === '"') i++
      else if (c === q && text[i + 1] === q) i++
      else if (c === q) q = null
    } else if (c === '"' || c === "'") q = c
    else if (c === '(') d++
    else if (c === ')') d--
    else if (c === '+' && d === 0) {
      terms.push(text.slice(from, i).trim())
      from = i + 1
    }
  }
  if (q || d) return null
  terms.push(text.slice(from).trim())
  if (terms.length < 2) return null
  let out = ''
  for (const term of terms) {
    let v
    if (/^[$@]?\([\s\S]*\)$/.test(term)) v = resolveGroup(term, dialect, depth + 1, resolve)
    else if (/^('(?:[^']|'')*'|"(?:[^"`]|`.|"")*"|\$(?:\{[^}]+\}|[A-Za-z_][\w:]*))$/.test(term)) {
      const ws = rawWords(term, dialect)
      if (ws.length !== 1) return null
      v = resolve(ws[0].raw, ws[0].w)
    } else return null
    if (v === UNRESOLVED) return UNRESOLVED
    out += v
  }
  return out
}

/**
 * The path a ( ) group stands for: ("x") -> x, (Join-Path a b) -> a\b, ($a + '\x') -> a\x,
 * (Get-Item x).FullName -> x. Anything else is UNRESOLVED. `resolve(raw, w)`
 * gives the value of one word, with its variables filled in (or UNRESOLVED).
 */
function resolveGroup(raw, dialect, depth = 0, resolve = asWritten) {
  const m = /^[$@]?\(([\s\S]*)\)(?:\.(?:fullname|path|providerpath))?$/i.exec(raw.trim())
  if (!m || depth > 3) return UNRESOLVED
  const joined = joinTerms(m[1], dialect, depth, resolve)
  if (joined !== null) return joined
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
    // A here-string: blank everything up to its closing quote and @ at the start of a line.
    if (!bash && c === '@' && (text[i + 1] === "'" || text[i + 1] === '"') && /^[ \t]*\r?\n/.test(text.slice(i + 2))) {
      const close = text.slice(i + 2).search(new RegExp(`\\n${text[i + 1]}@`))
      const stop = close < 0 ? text.length : i + 2 + close + 3
      out += '@' + text[i + 1] + ' '.repeat(Math.max(0, stop - i - 2))
      i = stop - 1
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
/** The most values a loop variable is tried with (also the cap on combinations). */
const MAX_EACH = 64
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
    if (cwd === OUTSIDE && !P.isAbsolute(s)) return s.split(/[\\/]/).includes('..') || /^[a-z]:/i.test(s) ? UNKNOWN : OUTSIDE
    return P.resolve(cwd, s)
  }

  // ---- Variables -------------------------------------------------------------
  // A command may set $repo = '...' and then write to "$repo\x". The table below
  // follows plain assignments, in order, within one command. Anything it cannot
  // follow makes that variable UNRESOLVED, and a path built from an UNRESOLVED
  // variable is treated like any other expression: fail closed, never a guess.

  /**
   * A fresh table. `assigned` (for $( ) bodies) collects every name set inside.
   * `frames` are the blocks open at this point ({ }, and bash if/for/while), each
   * { kind, names }: 'loop', 'deferred' (a function or script block body, which
   * runs later or not at all), 'finally' or 'block'. A name set inside a block is
   * UNRESOLVED once the block closes, because the block may not have run.
   * `tainted` holds names set inside a deferred body: that code may run at any
   * later point, so such a name stays UNRESOLVED for the rest of the command.
   * `closeLater` counts the blocks the current segment closes at its end, after
   * its own checks. `head` is the text after the last brace of the previous
   * segment (foreach (...) on one line, { on the next), `prevText` its whole text
   * (the input of a pipeline), and `cwd` the folder, for $PWD.
   */
  const newVars = (parent) => ({
    map: new Map(parent ? parent.map : []),
    poisoned: parent ? parent.poisoned : false,
    frames: [],
    closeLater: 0,
    head: '',
    prevText: '',
    cwd: parent ? parent.cwd : undefined,
    assigned: parent ? new Set() : null,
    tainted: new Set(parent ? parent.tainted : []),
  })
  const varKey = (name, dialect) => (dialect === 'bash' ? name : name.toLowerCase().replace(/^(script|global|local|private):/, ''))

  // Environment variables the shell starts with; case-insensitive on Windows.
  const environ = env.environ || process.env
  let environLower = null
  function envVar(name, exact) {
    if (exact && Object.prototype.hasOwnProperty.call(environ, name)) return environ[name]
    if (exact && !WIN) return undefined
    if (!environLower) environLower = new Map(Object.entries(environ).map(([k, v]) => [k.toLowerCase(), v]))
    return environLower.get(name.toLowerCase())
  }

  let tmplDepth = 0
  function lookup(name, vars, dialect) {
    const bash = dialect === 'bash'
    const n = varKey(name, dialect)
    if (bash ? n === 'HOME' || n === 'USERPROFILE' : n === 'home' || n === 'env:userprofile' || n === 'env:home') return home
    if (vars.poisoned) return UNRESOLVED
    if (vars.map.has(n)) {
      const v = vars.map.get(n)
      // A loop variable ({ each }) has one value per pass; checkSegment tries each in turn.
      if (typeof v === 'string') return v
      // A value built from loop variables ({ tmpl }): worked out again with this view's values.
      if (v && v.tmpl !== undefined && tmplDepth < 8) {
        tmplDepth++
        try {
          const r = rhsValue(v.tmpl, (raw, w) => resolveRaw(raw, w, vars, dialect), dialect)
          return typeof r === 'string' ? r : UNRESOLVED
        } finally {
          tmplDepth--
        }
      }
      return UNRESOLVED
    }
    // Not set in this command: the shell's own values.
    const here = typeof vars.cwd === 'string' && vars.cwd !== UNKNOWN && vars.cwd !== OUTSIDE ? vars.cwd : UNRESOLVED
    if (bash) {
      if (n === 'PWD') return here
      const e = envVar(n, true)
      return typeof e === 'string' ? e : UNRESOLVED
    }
    if (n === 'pwd') return here
    // Empty outside a script file, and a script's own folder is never the knowledge base.
    if (n === 'psscriptroot') return ''
    if (n.startsWith('env:')) {
      const e = envVar(n.slice(4), false)
      return typeof e === 'string' ? e : UNRESOLVED
    }
    return UNRESOLVED
  }
  function setVar(vars, name, value, dialect, taint = false) {
    const n = varKey(name, dialect)
    if (taint || vars.frames.some((f) => f.kind === 'deferred')) vars.tainted.add(n)
    vars.map.set(n, vars.tainted.has(n) ? UNRESOLVED : value)
    if (vars.frames.length) vars.frames[vars.frames.length - 1].names.add(n)
    if (vars.assigned) vars.assigned.add(n)
  }
  /** Close the innermost block: what it set may or may not have happened. */
  function closeFrame(vars, dialect) {
    const f = vars.frames.pop()
    if (f) for (const n of f.names) setVar(vars, n, UNRESOLVED, dialect)
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
      if (rest[0] === '(') {
        // "$($repo)" reads one variable (PowerShell); anything else in $( ) runs a command.
        const sm = !bash && /^\(\s*\$([A-Za-z_]\w*(?::[A-Za-z_]\w*)?)\s*\)/.exec(rest)
        if (!sm) return UNRESOLVED
        name = sm[1]
        len = sm[0].length
      } else if (rest[0] === '{') {
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

  /**
   * The value a plain assignment gives: a literal, a variable, "...", or Join-Path.
   * A literal list ('a','b', @('a'), 1..3) gives { each: values }, like a loop variable.
   */
  function rhsValue(rhs, resolve, dialect) {
    const r = rhs.trim()
    if (!r) return UNRESOLVED
    if (dialect === 'bash') return resolve(r, rawWords(r, 'bash')[0]?.w ?? '')
    if (/^@\(|,|^-?\d+\s*\.\./.test(r)) {
      const values = literalList(r, dialect)
      if (values && (values.length > 1 || /^@\(/.test(r))) return { each: values }
    }
    // $p = $bak + '\handlers'
    const joined = joinTerms(r, dialect, 0, resolve)
    if (joined !== null) return joined
    const segs = lex(r, dialect)
    if (segs.length !== 1) return UNRESOLVED
    const s = segs[0]
    const toks = s.tokens.map((t) => ({ w: t.w, raw: s.text.slice(t.start, t.end) }))
    if (/^[$@]?\(/.test(r)) return resolveGroup(r, dialect, 0, resolve)
    if (toks.length === 1 && /^['"$]/.test(r)) return resolve(toks[0].raw, toks[0].w)
    if (toks.length >= 3 && toks[0].w.toLowerCase() === 'join-path') return resolveGroup(`(${r})`, dialect, 0, resolve)
    return UNRESOLVED
  }

  const PS_PLAIN = /^\s*\$(?:\{([^}:]+)\}|((?:env:)?[A-Za-z_]\w*))\s*=(?!=)\s*([\s\S]*?)\s*$/i
  const PS_ANY = /((?:\$\{[^}]+\}|\$[A-Za-z_][\w:]*)(?:\s*,\s*(?:\$\{[^}]+\}|\$[A-Za-z_][\w:]*))*)\s*(?:[-+*/%]|\?\?)?=(?!=)/g
  const PS_NAME = /\$(?:\{([^}]+)\}|([A-Za-z_][\w:]*))/g
  const BASH_NAME = /\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*))/g
  const loopHeads = (dialect) => (dialect === 'bash' ? /\bfor\s+([A-Za-z_]\w*)\s+in\b/g : /\bforeach\s*\(\s*\$([A-Za-z_][\w:]*)/gi)

  /**
   * A segment's text with quotes and comments blanked (`masked`), and also with
   * ${name} blanked (`blank`), where braces are blocks. Same length as the text.
   */
  function masks(sg, dialect) {
    if (!sg.mk) {
      const { masked, comment } = maskQuotes(sg.text, dialect)
      sg.mk = { masked, comment, blank: masked.replace(/\$\{[^}]*\}/g, (s) => ' '.repeat(s.length)) }
    }
    return sg.mk
  }

  /** Where braces open and close blocks. In bash only a { or } that stands as a word does. */
  function braces(b, dialect) {
    const out = []
    for (let i = 0; i < b.length; i++) {
      const c = b[i]
      if (c !== '{' && c !== '}') continue
      if (dialect === 'bash' && !((i === 0 || /[\s;&|(]/.test(b[i - 1])) && (i + 1 >= b.length || /[\s;&|)]/.test(b[i + 1])))) continue
      out.push({ pos: i, open: c === '{' })
    }
    return out
  }

  /** The bash keyword a segment starts with, past then / do / else. */
  function bashKw(b) {
    const ws = b.trim().split(/\s+/)
    let i = 0
    while (['then', 'do', 'else', '!'].includes(ws[i])) i++
    return ws[i] || ''
  }

  /** Assignments in masked text, as { name, pos }. Loop variables are not included. */
  function assignments(m, dialect) {
    const out = []
    if (dialect === 'bash') {
      for (const x of m.matchAll(/(?:^|[\s;&|(])([A-Za-z_]\w*)\+?=/g)) out.push({ name: x[1], pos: x.index })
    } else {
      for (const x of m.matchAll(PS_ANY)) for (const y of x[1].matchAll(PS_NAME)) out.push({ name: y[1] || y[2], pos: x.index })
      for (const x of m.matchAll(/\$([A-Za-z_][\w:]*)\s*(?:\+\+|--)|(?:\+\+|--)\s*\$([A-Za-z_][\w:]*)/g)) out.push({ name: x[1] || x[2], pos: x.index })
      // [ref]$name: the method it is passed to may set it.
      for (const x of m.matchAll(/\[ref\]\s*\$(?:\{([^}]+)\}|([A-Za-z_][\w:]*))/gi)) out.push({ name: x[1] || x[2], pos: x.index })
    }
    return out
  }

  /** The most names kept for one block; a loop body that assigns more makes every variable unknown. */
  const MAX_BODY_NAMES = 256

  /**
   * For every block of a command, the names assigned inside it, in one pass
   * over all segments: sg.bodies maps the place of each { in a segment (or 'kw'
   * for bash for/while/if) to { names, over }. trackVars reads it when a loop
   * opens, since what the body sets is unknown at the top of each pass.
   */
  function markBodies(segs, dialect) {
    const bash = dialect === 'bash'
    const stack = []
    const add = (b, n) => {
      if (b.over) return
      b.names.add(n)
      if (b.names.size > MAX_BODY_NAMES) b.over = true
    }
    const close = () => {
      const b = stack.pop()
      const up = stack[stack.length - 1]
      if (!b || !up) return
      if (b.over) up.over = true
      else for (const n of b.names) add(up, n)
    }
    for (const sg of segs) {
      const { masked, blank } = masks(sg, dialect)
      const items = []
      if (bash) {
        const kw = bashKw(blank)
        if (BASH_CLOSE.has(kw)) items.push({ pos: -1, t: 0 })
        // The header (for k in ...) belongs to the block around the loop: the keyword opens after it.
        if (BASH_OPEN.has(kw)) items.push({ pos: Infinity, t: 1, key: 'kw' })
      }
      for (const e of braces(blank, dialect)) items.push({ pos: e.pos, t: e.open ? 1 : 0, key: e.pos })
      for (const a of assignments(masked, dialect)) items.push({ pos: a.pos, t: 2, name: a.name })
      for (const x of masked.matchAll(loopHeads(dialect))) items.push({ pos: x.index, t: 2, name: x[1] })
      items.sort((a, b) => a.pos - b.pos || a.t - b.t)
      for (const it of items) {
        if (it.t === 0) close()
        else if (it.t === 1) {
          const b = { names: new Set(), over: false }
          ;(sg.bodies ||= new Map()).set(it.key, b)
          stack.push(b)
        } else if (stack.length) add(stack[stack.length - 1], varKey(it.name, dialect))
      }
    }
    while (stack.length) close()
  }

  /** The kind of block a { opens, from the text in front of it. */
  function braceKind(head, dialect) {
    if (dialect === 'bash') return /\(\s*\)$|^function\s/.test(head) ? 'deferred' : 'block'
    if (/@$/.test(head)) return 'block' // @{ } hashtable
    if (/(?:^|\s)(?:function|filter|workflow|configuration)\s+\S+?\s*(?:\(.*\))?$/i.test(head)) return 'deferred'
    if (/[=,]$/.test(head) || /(?:^|\s)-(?:scriptblock|action|initializationscript)$/i.test(head)) return 'deferred'
    if (/(?:^|[\s(;&|])(?:start-job|sajb|start-threadjob|invoke-command|icm|register-\w+|new-module|nmo|trap)\b/i.test(head)) return 'deferred'
    if (/(?:^|\s)finally$/i.test(head)) return 'finally'
    if (/(?:^|[\s=(])(?::\w+\s+)?(?:foreach|for|while|do|until)(?:\s*\(|$)/i.test(head) || /^(?:foreach-object|%|foreach)(?:\s|$)/i.test(head)) return 'loop'
    return 'block'
  }

  /** A literal list, or a variable holding one: its values, or null. */
  function listValues(text, vars, dialect) {
    const t = text.trim()
    const one = /^\$(?:\{([^}]+)\}|([A-Za-z_][\w:]*))$/.exec(t)
    if (one) {
      const v = vars.poisoned ? null : vars.map.get(varKey(one[1] || one[2], dialect))
      return v && v.each ? v.each : null
    }
    return literalList(t, dialect)
  }

  /**
   * The value a plain assignment stores. When the right side reads a loop
   * variable, it is kept as { tmpl } and worked out per value (see lookup).
   */
  function storedValue(name, rhs, resolve, vars, dialect) {
    const refs = [...rhs.matchAll(dialect === 'bash' ? BASH_NAME : PS_NAME)].map((m) => varKey(m[1] || m[2], dialect))
    const loopy = !vars.poisoned && refs.some((n) => typeof vars.map.get(n) === 'object')
    if (!loopy) return rhsValue(rhs, resolve, dialect)
    return refs.includes(varKey(name, dialect)) ? UNRESOLVED : { tmpl: rhs }
  }

  /**
   * Update the table for one segment, before its own checks run. markBodies
   * must have run over the command's segments first.
   */
  function trackVars(sg, ws, vars, resolve, dialect) {
    const bash = dialect === 'bash'
    // Quotes and comments blanked: a { } or $x = in a string or a # comment is not code.
    const { masked, comment, blank } = masks(sg, dialect)
    const code = comment >= 0 ? sg.text.slice(0, comment) : sg.text
    const prevText = vars.prevText
    const prevHead = vars.head
    vars.prevText = sg.text

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
    // [ref]$errs lets a method set $errs (an assignment, see assignments); [ref] on anything else
    // could reach any variable.
    const looseRef = !bash && /\[ref\](?!\s*\$(?:\{[^}]+\}|[A-Za-z_][\w:]*)(?![\w.[]))/i.test(masked)
    if (poison || (!bash && VAR_PARAMS.test(masked)) || looseRef || /psvariable\.set|\.sessionstate\b/i.test(masked)) {
      vars.poisoned = true
      return
    }

    // What happens in this segment, in text order: blocks open and close, variables are set.
    const events = []
    const kw = bash ? bashKw(blank) : ''
    if (BASH_CLOSE.has(kw)) events.push({ pos: -1, type: 'close' })
    // else / elif end one branch of an if and start the next.
    if (bash && /^(else|elif)$/.test(blank.trim().split(/\s+/)[0]) && vars.frames.length) {
      events.push({ pos: -2, type: 'close' }, { pos: -2, type: 'open', kind: 'block', body: { masked: '', blank: '' } })
    }
    if (BASH_OPEN.has(kw)) events.push({ pos: -1, type: 'open', kind: ['for', 'while', 'until', 'select'].includes(kw) ? 'loop' : 'block', body: { masked: '', blank: '' } })
    // Braces at the end close after this segment's checks: "Set-Content $p 1 }" still sees $p.
    let trail = blank.length
    while (trail > 0 && /[\s}]/.test(blank[trail - 1])) trail--
    let lastBrace = -1
    for (const e of braces(blank, dialect)) {
      if (!e.open && e.pos >= trail) vars.closeLater++
      else {
        events.push({ pos: e.pos, type: e.open ? 'open' : 'close' })
        lastBrace = e.pos
      }
    }
    for (const a of assignments(masked, dialect)) events.push({ pos: a.pos, type: 'mark', name: a.name })
    // Loop variables, with the list they run over: foreach ($k in <list>), for k in <list>.
    if (bash) {
      for (const m of masked.matchAll(/\bfor\s+([A-Za-z_]\w*)\s+in\s+([^;\n]*)/g)) {
        events.push({ pos: m.index, type: 'loop', name: m[1], list: [m.index + m[0].length - m[2].length, m.index + m[0].length] })
      }
      for (const m of masked.matchAll(/\bfor\s+([A-Za-z_]\w*)\s*(?:;|$)/g)) events.push({ pos: m.index, type: 'loop', name: m[1], list: null })
    } else {
      for (const m of masked.matchAll(/\bforeach\s*\(\s*\$([A-Za-z_][\w:]*)\s+in\s+/gi)) {
        const start = m.index + m[0].length
        let end = -1
        for (let i = start, d = 0; i < masked.length; i++) {
          if (masked[i] === '(') d++
          else if (masked[i] === ')' && !d--) {
            end = i
            break
          }
        }
        events.push({ pos: m.index, type: 'loop', name: m[1], list: end > start ? [start, end] : null })
      }
    }
    const ORDER = { close: 0, open: 1, loop: 2, mark: 3 }
    events.sort((a, b) => a.pos - b.pos || ORDER[a.type] - ORDER[b.type])

    // The last statement (after the last brace) may be a plain assignment: $x = 'C:\x'.
    // A block opened in front of it ends any && or | chain in front of the segment.
    const start = lastBrace + 1
    const chained = (start === 0 && ['&&', '||', '|', '&'].includes(sg.before)) || ['|', '&'].includes(sg.after)
    const tail = code.slice(start, Math.min(trail, code.length))
    let plain = null
    let plainDone = chained
    const findPlain = () => {
      plainDone = true
      let name
      let rhs
      if (bash) {
        const toks = sg.tokens.filter((t) => t.start >= start && t.end <= trail && (comment < 0 || t.start < comment)).map((t) => sg.text.slice(t.start, t.end))
        while (['then', 'do', 'else', '{'].includes(toks[0])) toks.shift()
        const one = toks.length === 1 ? toks[0] : toks.length === 2 && toks[0] === 'export' ? toks[1] : null
        const m = one && /^([A-Za-z_]\w*)=([\s\S]*)$/.exec(one)
        if (!m) return
        ;[name, rhs] = [m[1], m[2]]
        if (rhs === '') return void (plain = { name, value: '' })
      } else {
        const m = PS_PLAIN.exec(tail)
        if (!m || !m[3]) return
        ;[name, rhs] = [m[1] || m[2], m[3]]
      }
      plain = { name, value: storedValue(name, rhs, resolve, vars, dialect) }
    }

    let braceSeen = false
    for (const e of events) {
      if (!plainDone && e.pos >= start) findPlain()
      if (e.type === 'close') closeFrame(vars, dialect)
      else if (e.type === 'mark') setVar(vars, e.name, UNRESOLVED, dialect)
      else if (e.type === 'loop') {
        const values = e.list ? listValues(sg.text.slice(e.list[0], e.list[1]), vars, dialect) : null
        setVar(vars, e.name, values ? { each: values } : UNRESOLVED, dialect)
      } else {
        // A block opens. Its kind comes from the text in front of the brace, or from
        // the previous segment's end when the brace starts this one.
        const before = e.pos < 0 ? '' : blank.slice(0, e.pos)
        const cut = Math.max(before.lastIndexOf('{'), before.lastIndexOf('}'))
        let head = before.slice(cut + 1).trim()
        if (!head && !braceSeen && e.pos >= 0) head = prevHead
        braceSeen = true
        const kind = e.kind || braceKind(head, dialect)
        vars.frames.push({ kind, names: new Set() })
        if (kind !== 'loop') continue
        const f = vars.frames[vars.frames.length - 1]
        // The loop variable of the head stays set only inside the loop.
        for (const x of head.matchAll(loopHeads(dialect))) f.names.add(varKey(x[1], dialect))
        // ForEach-Object after a literal list: $_ takes each value.
        if (!bash && /^(?:foreach-object|%|foreach)(?:\s|$)/i.test(head)) {
          const values = sg.before === '|' && cut < 0 ? listValues(prevText, vars, dialect) : null
          for (const n of ['_', 'psitem']) {
            vars.map.set(n, values ? { each: values } : UNRESOLVED)
            f.names.add(n)
          }
        }
        // What the body assigns is unknown at the top of each pass (set by the pass before).
        const body = sg.bodies && sg.bodies.get(e.pos < 0 ? 'kw' : e.pos)
        if (!body || body.over) vars.poisoned = true
        else for (const n of body.names) setVar(vars, n, UNRESOLVED, dialect)
      }
    }
    if (!plainDone) findPlain()
    if (plain) setVar(vars, plain.name, plain.value, dialect)
    vars.head = blank.slice(lastBrace + 1, trail).trim()
  }

  /** The values of a literal list ('a', "b", 3; 1..5; bash: a 'b' "c"), or null when any item is not a literal. */
  function literalList(text, dialect) {
    const bash = dialect === 'bash'
    let t = text.trim()
    const range = !bash && /^(-?\d+)\s*\.\.\s*(-?\d+)$/.exec(t)
    if (range) {
      const [a, b] = [Number(range[1]), Number(range[2])]
      if (Math.abs(b - a) >= MAX_EACH) return null
      const out = []
      for (let i = a; ; i += a <= b ? 1 : -1) {
        out.push(String(i))
        if (i === b) return out
      }
    }
    const wrapped = !bash && /^@\(([\s\S]*)\)$/.exec(t)
    if (wrapped) t = wrapped[1].trim()
    const item = bash
      ? /\s*('[^']*'|"[^"$`\\]*"|[A-Za-z0-9_.+:\/-]+)(?=\s|$)/y
      : /\s*('(?:[^']|'')*'|"[^"$`]*"|-?\d+(?:\.\d+)*)\s*(?:,|$)/y
    const out = []
    while (item.lastIndex < t.length) {
      const at0 = item.lastIndex
      const m = item.exec(t)
      if (!m || item.lastIndex === at0) return null
      const s = m[1]
      out.push(s.startsWith("'") ? s.slice(1, -1).replace(/''/g, bash ? "''" : "'") : s.startsWith('"') ? s.slice(1, -1) : s)
      if (out.length > MAX_EACH) return null
      if (!bash && !/,\s*$/.test(m[0]) && item.lastIndex < t.length) return null
    }
    return out.length ? out : null
  }

  /**
   * Views of the table with each loop variable this segment uses set to one of
   * its values: one view per combination. [vars] when there are none, or too many.
   */
  function loopViews(text, vars, dialect) {
    if (vars.poisoned) return [vars]
    const names = new Map()
    const seen = new Set()
    // Also the loop variables a { tmpl } value is built from.
    const visit = (t, d) => {
      for (const m of t.matchAll(/\$(?:\{([^}]+)\}|([A-Za-z_][\w:]*))/g)) {
        const n = varKey(m[1] || m[2], dialect)
        if (seen.has(n)) continue
        seen.add(n)
        const v = vars.map.get(n)
        if (v && v.each) names.set(n, v.each)
        else if (v && v.tmpl !== undefined && d < 8) visit(v.tmpl, d + 1)
      }
    }
    visit(text, 0)
    let views = [new Map()]
    for (const [n, values] of names) {
      if (views.length * values.length > MAX_EACH) return [vars]
      views = views.flatMap((b) => values.map((v) => new Map([...b, [n, v]])))
    }
    if (!names.size) return [vars]
    return views.map((b) => ({ ...vars, map: new Map([...vars.map, ...b]) }))
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
    if (setsGlobalHooksPath(args.slice(i))) {
      return deny(`a global or system core.hooksPath turns off the knowledge base hooks in every clone without its own setting, so an agent never changes it. Ask the user to run it in a terminal themselves if they want it.`)
    }
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

  /** Writes in one segment: redirects, and each write command in it ({ } blocks hold several). */
  function checkShellWrite(sg, ws, cwd, dialect, resolve = asWritten) {
    const seg = sg.text
    // Each target is { t, start, end }: the path and where it is written in the segment.
    const redirects = []
    // Redirects are found with quotes blanked: a > inside a string (a bash script in
    // a here-string, "a > b") is text. The target is then read from the real text.
    for (const m of masks(sg, dialect).masked.matchAll(REDIRECT)) {
      const end = m.index + m[0].length
      const raw = seg.slice(end - m[1].length, end)
      if (/^["']?(&\d|\$null|nul|\/dev\/null)["']?$/i.test(raw)) continue
      redirects.push({ t: resolve(raw, raw.replace(/^["']|["']$/g, '')), start: m.index, end, redir: true })
    }
    let inPlace = -1 // the last sed -i flag
    ws.forEach((a, k) => {
      if (/^-[a-z]*i|^--in-place/.test(a)) inPlace = k
    })
    const vis = []
    ws.forEach((w, j) => {
      if (atCommandStart(ws, j) && (WRITE_VERBS.has(programName(w)) || (programName(w) === 'sed' && inPlace > j))) vis.push(j)
    })
    const dotnet = DOTNET_WRITE.exec(seg)
    if (!redirects.length && !vis.length && !dotnet) return null
    const found = []
    for (const vi of vis.length ? vis : [-1]) {
      const d = checkWriteAt(sg, ws, cwd, dialect, resolve, vi, redirects, dotnet)
      if (d && d.kind === 'deny') return d
      found.push(d)
    }
    return pick(found)
  }

  /** The write command at word vi (-1: only redirects or a .NET call), with the segment's redirects. */
  function checkWriteAt(sg, ws, cwd, dialect, resolve, vi, redirects, dotnet) {
    const seg = sg.text
    const targets = redirects.map((x) => ({ ...x }))
    const redirected = redirects.length > 0
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
      // Set-Content $f ($lines -join ...): only the first positional is a path; the rest is the value.
      const firstOnly = CONTENT_VERBS.has(verb) && !(dialect === 'bash' && verb === 'tee')
      // Where the verb's arguments are values, not paths (-Value $p.Id, -Encoding $e, Set-Content $f $text).
      const valueSpans = []
      // Set-Content -LiteralPath $f $text: with the path given by name, PowerShell binds the
      // positionals to -Value, so none of them is a path.
      const pathNamed = firstOnly && args.some((a, k) => k > 0 && /^-(path|literalpath|filepath)$/i.test(args[k - 1].w))
      const firstPos = pathNamed ? 0 : 1
      {
        let pos = 0
        args.forEach((a, k) => {
          const prev = k ? args[k - 1].w.toLowerCase() : ''
          if (!a.group && a.w.startsWith('-')) return
          const named = VALUE_PARAMS.has(prev)
          const unsure = !named && prev.startsWith('-') && !KNOWN_SWITCHES.has(prev)
          const n = named || unsure ? -1 : pos++
          a.n = n
          a.named = named ? prev : null
          if ((named && !PATH_PARAMS.has(prev)) || (firstOnly && n >= firstPos)) valueSpans.push([a.start, a.end])
        })
      }
      const inValue = (x) => valueSpans.some(([s, e]) => x.start >= s && x.end <= e)
      // Only the verb's own arguments are places it writes: in "Set-Content C:\x (Get-Content
      // ~/knowledge/log.md)" or "if (Test-Path ~/knowledge/log.md) { Set-Content C:\x 1 }"
      // log.md is only read.
      // A .NET call ([IO.File]::WriteAllText(...)) has no command arguments: its whole text counts.
      const from = vi < 0 ? -Infinity : args.length ? Math.min(...args.map((a) => a.start)) : Infinity
      const to = vi < 0 ? Infinity : args.length ? Math.max(...args.map((a) => a.end)) : -Infinity
      for (const x of [...sg.tokens.map((tk) => ({ s: tk.w, start: tk.start, end: tk.end })), ...sg.pieces]) {
        if (x.start < from || x.end > to || inValue(x)) continue
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
      // Groups and variables among the arguments are paths unless they are values (above).
      // After a parameter the list above does not know, the word may be its value or a positional:
      // it counts as neither (n = -1), and is checked as a path.
      args.forEach((a) => {
        if (a.n === undefined || !(a.group || a.vary)) return
        if (a.named && !PATH_PARAMS.has(a.named)) return
        if (firstOnly && a.n >= firstPos) return
        targets.push(asTarget(a))
      })
      // New-Item -Path dir -Name file: the item is dir\file (in the current folder without -Path).
      const k = verb === 'new-item' || verb === 'ni' ? args.findIndex((a) => /^-name$/i.test(a.w)) : -1
      const nm = k >= 0 ? args[k + 1] : undefined
      if (nm) {
        const dirs = targets.filter((x) => !x.redir && x.start !== nm.start)
        const kept = targets.filter((x) => x.redir)
        targets.length = 0
        targets.push(...kept)
        for (const x of dirs.length ? dirs : [{ t: '.', start: nm.start, end: nm.end }]) {
          targets.push({ t: x.t === UNRESOLVED || nm.w === UNRESOLVED ? UNRESOLVED : P.join(x.t, nm.w), start: x.start, end: x.end })
        }
      }
      // Rename-Item x -NewName y: y is in x's folder, not the current one.
      if (['rename-item', 'rni', 'ren'].includes(verb) && destIdx >= 0) {
        const nn = args[destIdx]
        const isValue = (j) => j > 0 && VALUE_PARAMS.has(args[j - 1].w.toLowerCase()) && !PATH_PARAMS.has(args[j - 1].w.toLowerCase())
        const src = args.find((a, j) => j !== destIdx && !a.w.startsWith('-') && !isValue(j))
        const from = src ? at(cwd, src.w) : UNKNOWN
        if (from !== OUTSIDE) {
          const t = nn.w === UNRESOLVED || from === UNKNOWN ? UNRESOLVED : P.isAbsolute(expandHome(nn.w, home)) ? nn.w : P.join(P.dirname(from), nn.w)
          targets.push({ t, start: nn.start, end: nn.end })
        }
      }
    }
    for (const x of targets) x.full = at(cwd, x.t)
    let unsure = targets.some((x) => x.full === UNKNOWN)
    // Set-Content @params: the path is in a hashtable the guard does not read.
    if (dialect !== 'bash' && vi >= 0 && args.some((a) => /^@[A-Za-z_]\w*$/.test(a.w))) unsure = true
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

  /**
   * Downloads and unpacked archives: -OutFile, -DestinationPath, curl -o / -O,
   * wget, tar -x, unzip, 7z x and Expand-Archive. A file into log.md, .kb, .git
   * and the like is refused; unpacking into a folder that holds them too, and into
   * any other knowledge base folder asks.
   */
  function checkTransfers(sg, ws, cwd, dialect, resolve) {
    const files = []
    const dirs = []
    const next = (j) => argsOf(sg, j, dialect, resolve).args[0]?.w
    const raw = (j) => sg.text.slice(sg.tokens[j].start, sg.tokens[j].end)
    // The value of an attached form (-OutFile:x, --output=x, -ox) of token j.
    const tail = (j, len) => resolve(raw(j).slice(len), ws[j].slice(len))
    ws.forEach((w, j) => {
      const m = dialect !== 'bash' && /^-(outfile|destinationpath)(:?)/i.exec(w)
      if (!m) return
      const v = m[2] ? tail(j, m[0].length) : next(j)
      const extract = ws.some((x, i) => i < j && /^(expand-archive)$/i.test(programName(x)))
      if (v !== undefined) (extract ? dirs : files).push(v)
    })
    const TRANSFER = new Set(['curl', 'wget', 'tar', 'bsdtar', 'unzip', '7z', '7za', '7zz', 'expand-archive'])
    ws.forEach((w, j) => {
      const p = programName(w)
      if (!TRANSFER.has(p) || !atCommandStart(ws, j)) return
      const { args } = argsOf(sg, j, dialect, resolve)
      const a = args.map((x) => x.w)
      const val = (i) => (a[i + 1] !== undefined && a[i + 1] !== '-' ? a[i + 1] : undefined)
      const add = (list, v) => v !== undefined && v !== '-' && list.push(v)
      if (p === 'curl') {
        a.forEach((x, i) => {
          if (x === '-o' || x === '--output') add(files, val(i))
          else if (x.startsWith('--output=')) add(files, x.slice(9))
          else if (/^-o./.test(x)) add(files, x.slice(2))
          else if (x === '--output-dir') add(dirs, val(i))
          else if (x === '-O' || x === '--remote-name' || x === '--remote-name-all' || /^-[a-zA-Z]*O[a-zA-Z]*$/.test(x)) dirs.push(cwd)
        })
      } else if (p === 'wget') {
        let named = false
        a.forEach((x, i) => {
          if (x === '-O' || x === '--output-document') (named = true), add(files, val(i))
          else if (x.startsWith('--output-document=')) (named = true), add(files, x.slice(18))
          else if (x === '-P' || x === '--directory-prefix') (named = true), add(dirs, val(i))
          else if (x.startsWith('--directory-prefix=')) (named = true), add(dirs, x.slice(19))
        })
        if (!named) dirs.push(cwd)
      } else if (p === 'tar' || p === 'bsdtar') {
        const extract = a.some((x, i) => x === '--extract' || x === '--get' || /^-[a-zA-Z]*x/.test(x) || (i === 0 && /^[a-zA-Z]*x[a-zA-Z]*$/.test(x)))
        if (!extract) return
        let d
        a.forEach((x, i) => {
          if (x === '-C' || x === '--directory') d = val(i)
          else if (x.startsWith('--directory=')) d = x.slice(12)
        })
        dirs.push(d ?? cwd)
      } else if (p === 'unzip') {
        const i = a.indexOf('-d')
        dirs.push(i >= 0 && val(i) !== undefined ? val(i) : cwd)
      } else if (p === '7z' || p === '7za' || p === '7zz') {
        if (!['x', 'e'].includes(a[0])) return
        const o = a.find((x) => /^-o./.test(x))
        dirs.push(o ? o.slice(2) : cwd)
      } else if (p === 'expand-archive') {
        if (a.some((x) => /^-destinationpath(:|$)/i.test(x))) return
        // Expand-Archive <path> <destination>: the second positional.
        const pos = a.filter((x, i) => !x.startsWith('-') && !(i > 0 && VALUE_PARAMS.has(a[i - 1].toLowerCase())))
        dirs.push(pos[1] ?? cwd)
      }
    })
    let unsure = false
    for (const t of files) {
      const full = at(cwd, t)
      if (full === UNKNOWN) unsure = true
      const rel = full === UNKNOWN ? null : relKb(full)
      if (rel === null) continue
      if (rel === '') return rootMsg()
      if (isProtected(rel)) return protectedMsg()
    }
    for (const t of dirs) {
      const full = t === cwd ? cwd : at(cwd, t)
      if (full === UNKNOWN) unsure = true
      const rel = full === UNKNOWN ? null : relKb(full)
      if (rel === null) continue
      if (rel === '' || isProtected(rel) || exists(P.join(full, 'log.md'))) {
        return deny('downloading or unpacking into this folder can overwrite log.md, .kb, .githooks or .git. Unpack somewhere else and copy single files in.')
      }
      return ask('this downloads or unpacks files into a knowledge base folder, where they can overwrite concepts not committed yet. Allow it?')
    }
    if (unsure) return ask('this command may download or unpack into the knowledge base (a path or the folder is an expression the guard cannot read). Allow it?')
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

  /** A copy of the shell state for a command that runs nested (a $( ) body, pwsh -c). */
  const childState = (state, vars) => ({
    cwd: state.cwd,
    stack: [...state.stack],
    env: { ...state.env },
    vars,
    hist: [...(state.hist || [])],
    fwd: [...(state.fwd || [])],
    oldpwd: state.oldpwd,
  })

  /** Whether p is a folder above the knowledge base (8.3 names count as maybe). */
  const aboveKb = (p) => rootKey.startsWith(key(longForm(p)) + '/') || key(p).includes('~')

  /**
   * Follow cd, pushd or popd at word j. `maybe`: it sits inside a block that may
   * not run, so the folder is only followed when the old and new ones are both
   * outside the knowledge base; otherwise it becomes UNKNOWN.
   */
  function changeFolder(sg, j, p, state, dialect, maybe) {
    const old = state.cwd
    let next
    let record = true
    if (POPD.has(p)) {
      if (!state.stack.length) return
      next = state.stack.pop()
    } else {
      const words = argsOf(sg, j, dialect).args.map((a) => a.w)
      if (CD.has(p) && (words.includes('-') || (dialect !== 'bash' && words.includes('+')))) {
        // cd - goes back (bash: to OLDPWD; PowerShell: through its location history), cd + forward.
        record = false
        if (dialect === 'bash') {
          next = state.oldpwd ?? UNKNOWN
          state.oldpwd = old
        } else if (words.includes('-')) {
          next = (state.hist || []).pop() ?? UNKNOWN
          ;(state.fwd ||= []).push(old)
        } else {
          next = (state.fwd || []).pop() ?? UNKNOWN
          ;(state.hist ||= []).push(old)
        }
      } else {
        // One folder per loop value; several known folders outside the knowledge base become OUTSIDE.
        const dests = new Set()
        for (const view of loopViews(sg.text, state.vars, dialect)) {
          const r = (raw, w) => resolveRaw(raw, w, view, dialect)
          const t = argsOf(sg, j, dialect, r).args.find((a) => !a.w.startsWith('-'))?.w
          dests.add(t ? at(old, t) : p === 'cd' ? home : old)
        }
        const all = [...dests]
        next =
          all.length === 1 ? all[0] : all.includes(UNKNOWN) ? UNKNOWN : all.every((d) => d === OUTSIDE || (!inKb(d) && !aboveKb(d))) ? OUTSIDE : UNKNOWN
        if (PUSHD.has(p)) state.stack.push(old)
      }
    }
    if (maybe && !(next === old || (next !== UNKNOWN && old !== UNKNOWN && !inKb(next) && !inKb(old)))) next = UNKNOWN
    if (record && next !== old) {
      ;(state.hist ||= []).push(old)
      state.fwd = []
      state.oldpwd = old
    }
    state.cwd = next
  }

  /** Check one segment; blocks it closes at its end close after the checks. */
  function checkSegment(sg, state, depth, dialect) {
    try {
      return checkSegmentBody(sg, state, depth, dialect)
    } finally {
      const n = state.vars.closeLater
      state.vars.closeLater = 0
      for (let k = 0; k < n; k++) closeFrame(state.vars, dialect)
    }
  }

  function checkSegmentBody(sg, state, depth, dialect) {
    const seg = sg.text.trim()
    const ws = sg.tokens.map((t) => t.w)
    if (!ws.length) return null
    const found = []
    state.vars.cwd = state.cwd
    // Command substitutions run before the command itself: check each as a
    // command of its own. The text around a $( ) inside "..." is only text.
    const inner = sg.subs
    if (inner.length && depth >= MAX_DEPTH) return ask('this command nests command substitutions too deeply to check. Allow it?')
    for (const body of inner) {
      // $( ) runs in this shell: it sees the variables, and what it assigns is unknown afterwards.
      const vars = newVars(state.vars)
      const d = scan(body, childState(state, vars), depth + 1, dialect)
      for (const n of vars.assigned) setVar(state.vars, n, UNRESOLVED, dialect, vars.tainted.has(n))
      if (vars.poisoned) state.vars.poisoned = true
      if (d && d.kind === 'deny') return d
      found.push(d)
    }
    const resolve = (raw, w) => resolveRaw(raw, w, state.vars, dialect)
    trackVars(sg, ws, state.vars, resolve, dialect)
    const first = programName(ws[0])
    if (CD.has(first) || PUSHD.has(first) || POPD.has(first)) {
      changeFolder(sg, 0, first, state, dialect, false)
      return pick(found)
    }
    if (setEnv(sg, seg, ws, state, resolve)) return pick(found)
    // kb.py does its own checks; its arguments (commit messages) are not commands.
    if (ws.some((w) => PYTHON.has(programName(w))) && ws.some((w) => /(^|[\/])kb\.py$/i.test(bare(w)))) return pick(found)

    // cd / pushd / popd later in the segment ({ cd x; ...} inside a block): it may or may not run.
    // A finally { } block always runs. The commands of the segment are checked in each folder
    // it passes through, since the ones before the cd run in the old folder.
    const { blank } = masks(sg, dialect)
    const cwds = [state.cwd]
    ws.forEach((w, j) => {
      const p = programName(w)
      if (j === 0 || !(CD.has(p) || PUSHD.has(p) || POPD.has(p)) || !atCommandStart(ws, j)) return
      const sure = dialect !== 'bash' && /(?:^|\s)finally\s*\{\s*$/i.test(blank.slice(0, sg.tokens[j].start))
      changeFolder(sg, j, p, state, dialect, !sure)
      if (!cwds.includes(state.cwd)) cwds.push(state.cwd)
    })

    for (const cwd of cwds) {
      state.vars.cwd = cwd
      const here = cwd === state.cwd ? state : { ...state, cwd }
      // A loop variable over a literal list: check the commands once per value.
      for (const view of loopViews(sg.text, state.vars, dialect)) {
        const r = view === state.vars ? resolve : (raw, w) => resolveRaw(raw, w, view, dialect)
        const d = checkCommands(sg, ws, here, depth, dialect, r)
        if (d && d.kind === 'deny') return (state.vars.cwd = state.cwd), d
        found.push(d)
      }
    }
    state.vars.cwd = state.cwd
    return pick(found)
  }

  /** The git, okf, write and launcher checks of one segment. They read state; they do not change it. */
  function checkCommands(sg, ws, state, depth, dialect, resolve) {
    const found = []
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
    found.push(checkTransfers(sg, ws, state.cwd, dialect, resolve))
    // cmd /c "...", pwsh -c "...", bash -c '...', iex "...": check the inner command too.
    // It runs in another shell, so none of this command's variables are known there.
    // The program a word names, through a variable too: $b = '...\bash.exe'; & $b -c '...'.
    const progs = ws.map((w, j) => {
      const raw = sg.text.slice(sg.tokens[j].start, sg.tokens[j].end)
      if (!raw.includes('$')) return programName(w)
      const v = resolve(raw, w)
      return v === UNRESOLVED ? '' : programName(v)
    })
    if (depth < MAX_DEPTH && progs.some((p) => LAUNCHERS.has(p))) {
      const inner = progs.some((p) => BASH_LAUNCHERS.has(p)) ? 'bash' : 'pwsh'
      for (const { s: q, start } of sg.pieces) {
        if (!/\s/.test(q)) continue
        // Text in single quotes (or @' '@) reaches the inner shell as written, so the variables it
        // sets itself can be followed there. "..." was expanded by this shell first: unknown.
        const literal = sg.text[start] === "'"
        found.push(scan(q, childState(state, literal ? newVars() : { ...newVars(), poisoned: true }), depth + 1, inner))
      }
    }
    return pick(found)
  }

  function scan(command, state, depth, dialect) {
    const found = []
    const segs = lex(command, dialect)
    markBodies(segs, dialect)
    for (const sg of segs) {
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
      return scan(args.command, { cwd: cwdOf(exec, args), stack: [], env: {}, vars: newVars(), hist: [], fwd: [] }, 0, dialect)
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
