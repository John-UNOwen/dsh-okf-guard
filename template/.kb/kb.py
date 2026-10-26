#!/usr/bin/env python3
r"""kb.py - the one tool agents use to change this knowledge base.

It wraps okf (https://github.com/W4G1/okf) so the mechanical steps are done by
code: quoting frontmatter, index lines, log lines, checks and staging.

  PowerShell:  python "$env:USERPROFILE\knowledge\.kb\kb.py" <command> ...
  sh:          python ~/knowledge/.kb/kb.py <command> ...

Commands
  new <relpath> --type T --title "..." --description "..." --by producer/version
        [--tags a,b] [--status stable|draft] [--source "id|title|resource"]...
        [--stale-after YYYY-MM-DD] [--note "..."]
  touch <relpath> --note "..." [--verb Deprecated]
  log <Added|Updated|Created|Deprecated> <relpath> ["note"]
  check [--staged | <files>...]
  commit -m "kb: ..." <files>...

Paths are relative to the knowledge base root and may use / or \.
Standard library only. Files are written as UTF-8 without a BOM, with LF endings.
"""

import argparse
import collections
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath, PureWindowsPath

ROOT = Path(__file__).resolve().parent.parent
BOM = b"\xef\xbb\xbf"
LOG_VERBS = ("Added", "Updated", "Created", "Deprecated")
NOTE_MAX = 200
SIZE_WARN = 20 * 1024
STATUSES = ("stable", "draft")
PLACEHOLDER = "TODO(kb)"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
HEADING_RE = re.compile(r"^## (\d{4}-\d{2}-\d{2})\s*$")
LOG_LINE_RE = re.compile(
    r"^\* \*\*(?:Added|Updated|Created|Deprecated)\*\*: "
    r"\[(?:[^\]\\]|\\.)+\]\(/[^)\s]+\)(?: (?:\u2014|-) (?P<note>.+))?$")
ACTOR_RE = re.compile(
    r"^(?:[A-Za-z0-9._-]+/[A-Za-z0-9._:+-]+|(?:human|process):[A-Za-z0-9._-]+)$")
SOURCE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PLAIN_WORD_RE = re.compile(r"^[a-z][a-z0-9._-]*$")
KEY_LINE_RE = re.compile(
    r"^(?P<indent>\s*)(?:-\s+)?(?P<key>[A-Za-z_][\w.-]*)\s*:(?:[ \t]+(?P<val>.*?))?\s*$")
USER_PATH_RE = re.compile(
    r"(?i)(?:\b[a-z]:|(?<![\w.])/[a-z](?=/))[\\/]+users[\\/]+"
    r"(?![%$<{])(?!(?:public|default)\b)[^\\/\s\"'`<>|*?]+")
GENERIC_NAMES = {"user", "users", "admin", "administrator", "owner", "default",
                 "public", "guest", "root", "home"}
YAML_WORDS = {"true", "false", "yes", "no", "on", "off", "null", "y", "n"}


class KbError(Exception):
    pass


def fail(msg):
    raise KbError(msg)


def out(msg=""):
    print(msg, flush=True)


# ---------------------------------------------------------------- processes

def dec(data):
    return data.decode("utf-8", "replace")


def run(cmd, cwd=None, data=None):
    try:
        p = subprocess.run(cmd, cwd=str(cwd or ROOT), input=data,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        fail("could not run %s: %s" % (cmd[0], e))
    return p.returncode, p.stdout, p.stderr


def git(*args, data=None, ok=(0,)):
    code, so, se = run(["git", "-c", "core.quotepath=false"] + list(args), data=data)
    if code not in ok:
        fail("git %s failed: %s" % (args[0], (dec(se) or dec(so)).strip()))
    return so


def okf_exe():
    env = os.environ.get("OKF_EXE", "").strip()
    if env:
        if Path(env).is_file():
            return env
        fail("OKF_EXE points to a file that does not exist.")
    found = shutil.which("okf")
    if found:
        return found
    home = os.environ.get("USERPROFILE") or str(Path.home())
    cand = Path(home) / ".cargo" / "bin" / ("okf.exe" if os.name == "nt" else "okf")
    return str(cand) if cand.is_file() else None


def need_okf():
    exe = okf_exe()
    if not exe:
        fail("okf was not found (looked at OKF_EXE, PATH and "
             "%USERPROFILE%\\.cargo\\bin\\okf.exe). Ask the user to install it.")
    return exe


# ---------------------------------------------------------------- privacy

def _win_name(path, long_form):
    if os.name != "nt":
        return None
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        fn = k32.GetLongPathNameW if long_form else k32.GetShortPathNameW
        buf = ctypes.create_unicode_buffer(1024)
        n = fn(str(path), buf, 1024)
        if 0 < n < 1024:
            return PureWindowsPath(buf.value).name
    except Exception:
        pass
    return None


_PRIVATE = []


def private_re():
    """The account name in its usual spellings, worked out at run time."""
    if _PRIVATE:
        return _PRIVATE[0]
    names, homes = set(), set()
    for key in ("USERNAME", "USER", "LOGNAME"):
        v = os.environ.get(key, "").strip()
        if v:
            names.add(v)
    # Optional, for commits made where the name cannot be worked out (another PC, a container):
    # git config kb.privateName "<name>" in this clone's own .git/config, which is never committed.
    code, so, _ = run(["git", "config", "--get-all", "kb.privateName"])
    if code == 0:
        names.update(v.strip() for v in dec(so).splitlines() if v.strip())
    for h in (os.environ.get("USERPROFILE", ""), str(Path.home())):
        if not h:
            continue
        homes.add(h)
        names.add(PureWindowsPath(h).name if os.name == "nt" else PurePosixPath(h).name)
        for long_form in (False, True):
            n = _win_name(h, long_form)
            if n:
                names.add(n)
    forms = set()
    for n in names:
        n = n.strip()
        if len(n) < 3 or n.lower() in GENERIC_NAMES:
            continue
        for sep in (" ", "", "-", "_", "%20", "+"):
            forms.add(n.replace(" ", sep))
    if not forms:
        # The name is too generic to search for, so look for the home path instead.
        for h in homes:
            forms.add(h)
            forms.add(h.replace("\\", "/"))
    pats = sorted((re.escape(f) for f in forms if f), key=len, reverse=True)
    _PRIVATE.append(re.compile("|".join(pats), re.I) if pats else None)
    return _PRIVATE[0]


def has_private(text):
    rx = private_re()
    return bool(rx and rx.search(text))


def mask(text):
    rx = private_re()
    return rx.sub("<account>", text) if rx else text


def no_private(label, text):
    if has_private(text):
        fail("%s contains the Windows account name or the user folder. "
             "Write %%USERPROFILE%% or ~ instead." % label)


# ---------------------------------------------------------------- files

def read_text(path):
    """Text with the BOM removed and LF line endings."""
    raw = Path(path).read_bytes()
    if raw.startswith(BOM):
        raw = raw[3:]
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("%s is not UTF-8 text." % path)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def write_text(path, text):
    """UTF-8, no BOM, LF line endings, one trailing newline."""
    text = text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_bytes(text.encode("utf-8"))


def norm_rel(p, must_exist=False):
    """A path relative to the root, with forward slashes."""
    s = p.strip().strip('"').strip("'")
    if s.startswith("~") or "%" in s:
        s = os.path.expandvars(os.path.expanduser(s))
    s = s.replace("\\", "/")
    absolute = bool(re.match(r"^[A-Za-z]:/", s) or s.startswith("//"))
    if not absolute and os.name != "nt" and s.startswith("/") and Path(s).exists():
        absolute = True
    if absolute:
        try:
            rel = Path(os.path.abspath(s)).resolve().relative_to(ROOT)
        except ValueError:
            fail("%s is outside the knowledge base." % mask(p))
        s = rel.as_posix()
    else:
        while s.startswith("./"):
            s = s[2:]
        s = s.lstrip("/")
        if must_exist and not (ROOT / s).exists():
            cand = Path.cwd() / s
            if cand.exists():
                try:
                    s = cand.resolve().relative_to(ROOT).as_posix()
                except ValueError:
                    pass
    parts = PurePosixPath(s).parts
    if not parts or ".." in parts or parts[0] == ".git":
        fail("bad path: %s" % mask(p))
    if must_exist and not (ROOT / s).exists():
        fail("%s does not exist in the knowledge base." % s)
    return PurePosixPath(s).as_posix()


def is_reserved(rel):
    return PurePosixPath(rel).name in ("index.md", "log.md")


def title_from_name(name):
    words = [w for w in re.split(r"[-_]", name.replace(".md", "")) if w]
    return " ".join(w[:1].upper() + w[1:] for w in words) or "Untitled"


def link_text(title):
    return title.replace("[", "\\[").replace("]", "\\]")


def fm_end(lines):
    """Index of the closing --- of the frontmatter, or None."""
    if not lines or lines[0].strip() != "---":
        return None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return i
    return None


def utc_now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def ysq(s):
    """A YAML single-quoted scalar: safe for backslashes, colons, ? and #."""
    return "'" + s.replace("'", "''") + "'"


def yword(s):
    return s if PLAIN_WORD_RE.match(s) and s.lower() not in YAML_WORDS else ysq(s)


def one_line(label, value, limit=None):
    v = (value or "").strip()
    if not v:
        fail("%s is empty." % label)
    if "\n" in v or "\r" in v:
        fail("%s must be one line." % label)
    if limit and len(v) > limit:
        fail("%s is %d characters; the limit is %d. Keep the log line short; "
             "the full story goes in the commit message." % (label, len(v), limit))
    no_private(label, v)
    return v


def concept_scan():
    """Type spellings in use, and every concept title by path."""
    types, titles = collections.Counter(), {}
    for dirpath, dirnames, filenames in os.walk(str(ROOT)):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        for fn in filenames:
            if not fn.endswith(".md") or fn in ("index.md", "log.md"):
                continue
            p = Path(dirpath) / fn
            try:
                head = p.read_bytes()[:6000].decode("utf-8", "replace").replace("\r\n", "\n")
            except OSError:
                continue
            m = re.search(r"(?m)^type:[ \t]*['\"]?([^'\"\n#]+?)['\"]?[ \t]*$", head)
            if m:
                types[m.group(1).strip()] += 1
            m = re.search(r"(?m)^title:[ \t]*['\"]?(.+?)['\"]?[ \t]*$", head)
            if m:
                titles[p.relative_to(ROOT).as_posix()] = m.group(1).strip()
    return types, titles


def concept_title(rel):
    path = ROOT / rel
    if PurePosixPath(rel).name == "index.md":
        for line in read_text(path).split("\n"):
            if line.startswith("# "):
                return line[2:].strip()
        return title_from_name(PurePosixPath(rel).parent.name or "Knowledge Base")
    exe = okf_exe()
    if exe:
        code, so, _ = run([exe, "parse", rel, "--json"])
        if code == 0:
            try:
                t = json.loads(dec(so)).get("title")
                if isinstance(t, str) and t.strip():
                    return t.strip()
            except ValueError:
                pass
    m = re.search(r"(?m)^title:[ \t]*['\"]?(.+?)['\"]?[ \t]*$", read_text(path)[:6000])
    if m:
        return m.group(1).strip()
    out("note: %s has no readable title, so the log uses its file name." % rel)
    return title_from_name(PurePosixPath(rel).name)


# ---------------------------------------------------------------- log and index

def add_log_line(verb, rel, note=None, title=None):
    verb = {v.lower(): v for v in LOG_VERBS}.get(verb.lower())
    if not verb:
        fail("the log verb must be one of: %s." % ", ".join(LOG_VERBS))
    if note is not None:
        note = one_line("the note", note, NOTE_MAX)
    title = title or concept_title(rel)
    line = "* **%s**: [%s](/%s)" % (verb, link_text(title), rel)
    if note:
        line += " \u2014 " + note
    no_private("the log line", line)
    log = ROOT / "log.md"
    today = dt.date.today().isoformat()
    text = read_text(log) if log.exists() else "# Directory Update Log\n"
    lines = text.rstrip("\n").split("\n")
    if not insert_log_line(lines, today, line):
        out("log: that line is already under ## %s" % today)
        return
    write_text(log, "\n".join(lines))
    out("log: %s %s" % (verb, rel))


def insert_log_line(lines, day, line):
    """Put line at the top of the ## day group, creating the heading in date order if missing."""
    for i, l in enumerate(lines):
        m = HEADING_RE.match(l)
        if not m:
            continue
        d = m.group(1)
        if d == day:
            j = i + 1
            while j < len(lines) and lines[j].strip() and not lines[j].startswith("#"):
                if lines[j] == line:
                    return False
                j += 1
            lines.insert(i + 1, line)
            return True
        if d < day:
            lines[i:i] = ([""] if i > 0 and lines[i - 1].strip() else []) + ["## " + day, line, ""]
            return True
    if lines and lines[-1].strip():
        lines.append("")
    lines += ["## " + day, line]
    return True


def insert_index_line(index_path, line, target):
    """Add a list line to an index without touching its existing lines."""
    text = read_text(index_path)
    if "](/%s)" % target in text:
        return False
    lines = text.rstrip("\n").split("\n")
    last = None
    for i, l in enumerate(lines):
        if re.match(r"^\s*[-*] \[", l):
            last = i
    if last is None:
        lines += ["", line]
    else:
        lines.insert(last + 1, line)
    write_text(index_path, "\n".join(lines))
    return True


def ensure_folder_index(folder, created):
    """Make sure folder/index.md exists and is linked from its parent index."""
    if str(folder) in ("", "."):
        return
    idx = ROOT / folder / "index.md"
    if idx.exists():
        return
    for part in folder.parts:
        if not NAME_RE.match(part):
            fail("folder name '%s' must be lowercase words joined by hyphens." % part)
    title = title_from_name(folder.name)
    write_text(idx, "# %s\n" % title)
    created.append((folder / "index.md").as_posix())
    parent = folder.parent
    ensure_folder_index(parent, created)
    pidx = ROOT / parent / "index.md"
    target = (folder / "index.md").as_posix()
    insert_index_line(pidx, "- [%s](/%s)" % (title, target), target)


# ---------------------------------------------------------------- commands: new, touch, log

def cmd_new(a):
    rel = norm_rel(a.relpath)
    if not rel.endswith(".md"):
        rel += ".md"
    path = PurePosixPath(rel)
    if is_reserved(rel):
        fail("index.md and log.md are reserved; a concept needs its own name.")
    if not NAME_RE.match(path.stem):
        fail("file name '%s' must be lowercase words joined by hyphens, like use-sqlite.md." % path.name)
    for i in range(1, len(path.parts)):
        sub = PurePosixPath(*path.parts[:i])
        if not (ROOT / sub).is_dir() and not NAME_RE.match(path.parts[i - 1]):
            fail("folder name '%s' must be lowercase words joined by hyphens." % path.parts[i - 1])
    if (ROOT / rel).exists():
        fail("%s already exists. To change it, edit it and run kb.py touch." % rel)

    ctype = one_line("--type", a.type)
    title = one_line("--title", a.title)
    desc = one_line("--description", a.description)
    by = one_line("--by", a.by)
    if not ACTOR_RE.match(by):
        fail("--by must look like producer/version (dsh/qwen3.8), human:<id> or process:<id>.")
    status = a.status.lower()
    if status not in STATUSES:
        fail("--status must be stable or draft.")
    tags = [one_line("a tag", t) for t in (a.tags or "").split(",") if t.strip()]
    sources, ids = [], set()
    for s in a.source or []:
        bits = s.split("|", 2)
        if len(bits) != 3:
            fail('--source must be "id|title|resource" (the title may be empty).')
        sid, stitle, sres = (b.strip() for b in bits)
        if not SOURCE_ID_RE.match(sid):
            fail("source id '%s' must be letters, digits, '.', '_' or '-'." % sid)
        if sid in ids:
            fail("source id '%s' is used twice." % sid)
        ids.add(sid)
        sres = one_line("source resource", sres)
        if stitle:
            stitle = one_line("source title", stitle)
        sources.append((sid, stitle, sres))
    stale = None
    if a.stale_after:
        try:
            stale = dt.date.fromisoformat(a.stale_after.strip()[:10]).isoformat() + "T00:00:00Z"
        except ValueError:
            fail("--stale-after must be a date, YYYY-MM-DD.")
    if a.note is not None:
        one_line("the note", a.note, NOTE_MAX)

    types, titles = concept_scan()
    if ctype not in types:
        same = [t for t in types if t.lower() == ctype.lower()]
        if same:
            ctype = max(same, key=lambda t: types[t])
            out("note: using the existing type spelling '%s'." % ctype)
        else:
            out("note: '%s' is a new type. Types in use: %s." % (ctype, ", ".join(sorted(types)) or "none yet"))
    dup = [p for p, t in titles.items() if t.lower() == title.lower()]
    if dup:
        fail("%s already has this title. Update that concept instead, or pick a title "
             "that says how this one differs." % dup[0])

    exe = need_okf()
    code, so, se = run([exe, "new", rel, "--type", ctype, "--title", title,
                        "--description", desc, "--status", status, "--author", by])
    if code != 0 or not (ROOT / rel).exists():
        fail("okf new failed: %s" % (dec(se) or dec(so)).strip())

    lines = read_text(ROOT / rel).split("\n")
    end = fm_end(lines)
    if end is None:
        (ROOT / rel).unlink()
        fail("okf new wrote no frontmatter.")
    fm = lines[1:end]
    if tags:
        at = next((i for i, l in enumerate(fm) if l.startswith("status:")), len(fm))
        fm[at:at] = ["tags:"] + ["  - " + yword(t) for t in tags]
    if sources:
        fm.append("sources:")
        for sid, stitle, sres in sources:
            fm.append("  - id: " + yword(sid))
            if stitle:
                fm.append("    title: " + ysq(stitle))
            fm.append("    resource: " + ysq(sres))
    if stale:
        fm.append('stale_after: "%s"' % stale)
    body = ["# Summary", "", PLACEHOLDER + ": two or three sentences with the current truth.", "",
            "# Details", "", PLACEHOLDER + ": the details. Cite a source with a footnote"
            + (" such as [^%s]." % sources[0][0] if sources else "."), "", "# Related", "",
            PLACEHOLDER + ": links to related concepts, or delete this section."]
    if sources:
        body.append("")
        body += ["[^%s]: %s" % (sid, stitle or sres) for sid, stitle, sres in sources]
    write_text(ROOT / rel, "\n".join(["---"] + fm + ["---", ""] + body))

    code, so, se = run([exe, "validate", rel])
    problems = yaml_style_problems(fm)
    if code != 0 or problems:
        (ROOT / rel).unlink()
        try:
            (ROOT / rel).parent.rmdir()  # only succeeds if okf made it and it is empty
        except OSError:
            pass
        fail("the new file did not validate, so it was removed:\n%s" %
             "\n".join([dec(so).strip()] + problems))

    created = []
    folder = path.parent
    ensure_folder_index(folder, created)
    idx = (folder / "index.md").as_posix() if str(folder) != "." else "index.md"
    insert_index_line(ROOT / idx, "- [%s](/%s) \u2014 %s" % (link_text(title), rel, desc), rel)
    for c in created:
        add_log_line("Created", c)
    add_log_line("Added", rel, a.note, title=title)

    out("new: created %s" % rel)
    out("index: listed in %s" % idx)
    for c in created:
        out("index: created %s" % c)
    out("Next: replace every %s line in %s with real text (keep the frontmatter), then run:" % (PLACEHOLDER, rel))
    out("  kb.py commit -m 'kb: <short message>' %s" % rel)
    return 0


def set_stamp(lines, end, key, now):
    """Refresh <key>.at inside the frontmatter. Returns the new end, or None if <key> is absent."""
    for i in range(1, end):
        m = re.match(r"^%s:[ \t]*(.*?)\s*$" % key, lines[i])
        if not m:
            continue
        rest = m.group(1)
        if rest.startswith("{"):
            if re.search(r"(?<![\w-])at\s*:", rest):
                lines[i] = re.sub(r"((?<![\w-])at\s*:\s*)(\"[^\"]*\"|'[^']*'|[^,}\s]+)",
                                  lambda mm: mm.group(1) + '"%s"' % now, lines[i], count=1)
            else:
                lines[i] = re.sub(r"\s*\}\s*$", ', at: "%s" }' % now, lines[i])
            return end
        if rest == "":
            j, indent = i + 1, None
            while j < end and (lines[j][:1] in (" ", "\t") or not lines[j].strip()):
                if indent is None and lines[j].strip():
                    indent = re.match(r"^\s+", lines[j]).group(0)
                mm = re.match(r"^(\s+)at\s*:", lines[j])
                if mm:
                    lines[j] = '%sat: "%s"' % (mm.group(1), now)
                    return end
                j += 1
            lines.insert(j, '%sat: "%s"' % (indent or "  ", now))
            return end + 1
        fail("`%s` is not a mapping. Fix the frontmatter so it reads %s: then by: and at: lines." % (key, key))
    return None


def cmd_touch(a):
    rel = norm_rel(a.relpath, must_exist=True)
    if is_reserved(rel) or not rel.endswith(".md"):
        fail("touch works on concept files, not on index.md, log.md or other files.")
    verb = {"updated": "Updated", "deprecated": "Deprecated"}.get(a.verb.lower())
    if not verb:
        fail("--verb must be Updated or Deprecated.")
    note = one_line("the note", a.note, NOTE_MAX)
    path = ROOT / rel
    had_bom = path.read_bytes().startswith(BOM)
    lines = read_text(path).split("\n")
    end = fm_end(lines)
    if end is None:
        fail("%s has no frontmatter. Fix it first; check shows what is wrong." % rel)
    now = utc_now()
    new_end = set_stamp(lines, end, "generated", now)
    if new_end is None:
        if not a.by:
            fail("%s has no `generated` key. Run touch again with --by producer/version." % rel)
        by = one_line("--by", a.by)
        if not ACTOR_RE.match(by):
            fail("--by must look like producer/version, human:<id> or process:<id>.")
        lines[end:end] = ["generated:", "  by: " + by, '  at: "%s"' % now]
        new_end = end + 3
    set_stamp(lines, new_end, "updated", now)
    write_text(path, "\n".join(lines))
    add_log_line(verb, rel, note)
    out("touch: refreshed generated.at in %s%s" % (rel, " and removed its BOM" if had_bom else ""))
    out("Next: kb.py commit -m 'kb: <short message>' %s" % rel)
    return 0


def cmd_log(a):
    rel = norm_rel(a.relpath, must_exist=True)
    add_log_line(a.verb, rel, a.note)
    return 0


# ---------------------------------------------------------------- YAML style (strict parsers)

def scan_quoted(text, i):
    """End index of the quoted scalar starting at text[i], or None if unterminated."""
    q, j = text[i], i + 1
    while j < len(text):
        c = text[j]
        if q == '"' and c == "\\":
            j += 2
            continue
        if c == q:
            if q == "'" and j + 1 < len(text) and text[j + 1] == "'":
                j += 2
                continue
            return j
        j += 1
    return None


def dq_problems(quoted, n, key):
    bad = sorted(set(m.group(0) for m in re.finditer(r"\\(.)", quoted) if m.group(1) not in '\\"'))
    if bad:
        return ["line %d: double-quoted text in `%s` has %s, which YAML reads as escapes "
                "(Windows paths break this way). Use single quotes instead, like 'C:\\path'."
                % (n, key, " ".join(bad))]
    return []


def flow_problems(text, n, key):
    """Read a one-line flow collection the way PyYAML does and report what it rejects."""
    probs = []

    def bad(why):
        probs.append("line %d: `%s` uses a one-line { } or [ ] entry with %s. Write it in block "
                     "style, one field per line, with text values in single quotes." % (n, key, why))

    stack, colons, i, L, after = [], [0], 0, len(text), False
    while i < L:
        c = text[i]
        if c in " \t":
            i += 1
            continue
        if c == "#":
            if stack:
                bad("an unquoted ' #'")
            break
        if not stack and after:
            bad("text after the closing bracket")
            break
        if c in "{[":
            if after:
                bad("text glued to a value")
                break
            stack.append(c)
            colons.append(0)
            i += 1
            continue
        if c in "}]":
            if not stack:
                bad("unbalanced brackets")
                break
            stack.pop()
            colons.pop()
            after = True
            i += 1
            continue
        if c == ",":
            colons[-1] = 0
            after = False
            i += 1
            continue
        if c == "?":
            bad("an unquoted '?'")
            break
        if c == ":" and (i + 1 >= L or text[i + 1] in " \t,[]{}"):
            colons[-1] += 1
            if stack and stack[-1] == "{" and colons[-1] > 1:
                bad("an unquoted ': ' inside a value")
                break
            after = False
            i += 1
            continue
        if after:
            bad("text glued to a value")
            break
        if c in "\"'":
            j = scan_quoted(text, i)
            if j is None:
                bad("an unterminated quote")
                break
            if c == '"':
                probs += dq_problems(text[i:j + 1], n, key)
            after = True
            i = j + 1
            continue
        if c in "@`*&!|>%":
            bad("a value starting with '%s'" % c)
            break
        j = i
        while j < L:
            ch = text[j]
            if ch in ",?[]{}":
                break
            if ch == ":" and (j + 1 >= L or text[j + 1] in " \t,[]{}"):
                break
            if ch == "#" and text[j - 1] in " \t":
                break
            j += 1
        after = True
        i = j
    else:
        if stack:
            bad("brackets that do not close on this line")
    return probs


def plain_problems(key, val, n):
    probs = []
    body, comment = val, None
    m = re.search(r"[ \t]#", val)
    if m:
        body, comment = val[:m.start()], val[m.start():]
    body = body.rstrip()
    fix = "Put the whole value in single quotes: %s: '...'" % key
    if comment is not None and key in ("title", "description"):
        probs.append("line %d: `%s` has an unquoted ' #'; YAML drops the rest as a comment. %s" % (n, key, fix))
    if re.search(r":(?:\s|$)", body):
        probs.append("line %d: `%s` has an unquoted ': ' or ends with ':'. %s" % (n, key, fix))
    elif body[:1] in ("@", "`", "%", "*") or body.startswith(("- ", "? ")):
        probs.append("line %d: `%s` starts with '%s', which YAML reserves. %s" % (n, key, body[:1], fix))
    return probs


def value_problems(key, val, n):
    c = val[0]
    if c in "\"'":
        j = scan_quoted(val, 0)
        if j is None:
            return ["line %d: `%s` opens a quote that does not close on the same line. "
                    "Keep quoted values on one line." % (n, key)]
        rest = val[j + 1:].strip()
        if rest and not rest.startswith("#"):
            return ["line %d: `%s` has text after its closing quote. Quote the whole value." % (n, key)]
        return dq_problems(val[:j + 1], n, key) if c == '"' else []
    if c in "{[":
        return flow_problems(val, n, key)
    if c in "|>&!":
        return []
    return plain_problems(key, val, n)


def yaml_style_problems(fm_lines):
    """Frontmatter patterns okf accepts but strict YAML parsers reject (or misread)."""
    probs = []
    for n, raw in enumerate(fm_lines, start=2):
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = re.match(r"^\s*-\s+(?P<v>[\[{].*)$", line)
        if m:
            probs += flow_problems(m.group("v"), n, "list entry")
            continue
        m = KEY_LINE_RE.match(line)
        if m and m.group("val"):
            probs += value_problems(m.group("key"), m.group("val"), n)
    return probs


# ---------------------------------------------------------------- check

def cat_blobs(specs):
    """Contents of 'rev:path' or object names, in one git call. Missing ones map to None."""
    res = {}
    specs = list(dict.fromkeys(specs))
    if not specs:
        return res
    so = git("cat-file", "--batch", data="".join(s + "\n" for s in specs).encode("utf-8"))
    pos = 0
    for s in specs:
        nl = so.index(b"\n", pos)
        header = dec(so[pos:nl])
        pos = nl + 1
        if header.endswith((" missing", " ambiguous")):
            res[s] = None
            continue
        size = int(header.split()[-1])
        res[s] = so[pos:pos + size]
        pos += size + 1
    return res


def parse_name_status(z):
    parts, res, i = dec(z).split("\0"), [], 0
    while i < len(parts) and parts[i]:
        st = parts[i]
        i += 1
        if st[0] in "RC":
            res.append(("R" if st[0] == "R" else "A", parts[i + 1], parts[i]))
            i += 2
        else:
            res.append((st[0], parts[i], None))
            i += 1
    return res


def head_ref():
    code, _, _ = run(["git", "rev-parse", "--verify", "-q", "HEAD"])
    return "HEAD" if code == 0 else EMPTY_TREE


def export_index(dest):
    """Write the staged tree to dest. Returns ({path: bytes}, unmerged paths)."""
    entries, unmerged = [], set()
    for rec in dec(git("ls-files", "-s", "-z")).split("\0"):
        if not rec:
            continue
        meta, p = rec.split("\t", 1)
        mode, sha, stage = meta.split()
        if stage != "0":
            unmerged.add(p)
        elif mode not in ("120000", "160000"):
            entries.append((p, sha))
    blobs = cat_blobs([sha for _, sha in entries])
    content = {}
    for p, sha in entries:
        data = blobs.get(sha) or b""
        target = dest / p
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        content[p] = data
    return content, unmerged


def text_of(data):
    if data is None:
        return None
    if data.startswith(BOM):
        data = data[3:]
    if b"\0" in data[:8000]:
        return None
    try:
        return data.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError:
        return None


def okf_diagnostics(root):
    exe = okf_exe()
    if not exe:
        return None
    code, so, se = run([exe, "validate", ".", "--json"], cwd=root)
    if code not in (0, 65):
        fail("okf validate failed: %s" % (dec(se) or dec(so)).strip())
    try:
        report = json.loads(dec(so))
    except ValueError:
        fail("okf validate printed something that is not JSON.")
    diags = []
    for d in report.get("diagnostics", []):
        p = (d.get("path") or "").replace("\\", "/")
        while p.startswith("./"):
            p = p[2:]
        diags.append((d.get("severity"), p, d.get("message", "")))
    return diags


def concept_id(p):
    return p[:-3] if p.endswith(".md") else p


def do_check(mode, files):
    blocks, warns = [], []

    def block(p, msg):
        blocks.append("BLOCK %s: %s" % (p, mask(msg)))

    def warn(p, msg):
        warns.append("WARN  %s: %s" % (p, mask(msg)))

    base = head_ref()
    tmp = None
    try:
        if mode == "staged":
            changes = parse_name_status(git("diff", "--cached", "--name-status", "-z", "-M", base))
            tmp = Path(tempfile.mkdtemp(prefix="kb-check-"))
            staged, unmerged = export_index(tmp)
            tree = tmp
            new_content = lambda p: staged.get(p)
            for p in sorted(unmerged):
                block(p, "has an unresolved merge conflict.")
        else:
            if files:
                changes = []
                for f in files:
                    rel = norm_rel(f)
                    in_head = cat_blobs(["%s:%s" % (base, rel)]).get("%s:%s" % (base, rel)) is not None
                    exists = (ROOT / rel).is_file()
                    if not in_head and not exists:
                        fail("%s does not exist." % rel)
                    changes.append(("D" if not exists else ("M" if in_head else "A"), rel, None))
            else:
                changes = parse_name_status(git("diff", "--name-status", "-z", "-M", base))
                for p in dec(git("ls-files", "--others", "--exclude-standard", "-z")).split("\0"):
                    if p:
                        changes.append(("A", p, None))
            tree = ROOT

            def new_content(p):
                f = ROOT / p
                return f.read_bytes() if f.is_file() else None

        mode_label = "staged changes" if mode == "staged" else "working tree"
        if not changes:
            out("kb check: nothing to check in the %s." % mode_label)
            return 0

        old_specs = ["%s:%s" % (base, (old or p)) for st, p, old in changes]
        old_blobs = cat_blobs(old_specs)
        head_paths = set(dec(git("ls-tree", "-r", "--name-only", "-z", base)).split("\0"))
        head_dirs = set()
        for hp in head_paths:
            parts = PurePosixPath(hp).parts
            for i in range(1, len(parts)):
                head_dirs.add(PurePosixPath(*parts[:i]).as_posix())

        touched, gone, md_touched = {}, set(), False
        added_lines, old_of = {}, {}
        for st, p, old in changes:
            if st == "U":
                block(p, "has an unresolved merge conflict.")
                continue
            if old:
                gone.add(old)
            if st == "D":
                gone.add(p)
                continue
            data = new_content(p)
            if data is None:
                continue
            touched[p] = (st, data)
            old_of[p] = old or p
            if p.endswith(".md"):
                md_touched = True
            old_text = text_of(old_blobs.get("%s:%s" % (base, old or p))) or ""
            new_text = text_of(data)
            if new_text is None:
                if p.endswith(".md"):
                    block(p, "is not UTF-8 text.")
                continue
            old_set = set(old_text.split("\n"))
            added = [(i + 1, l) for i, l in enumerate(new_text.split("\n")) if l not in old_set]
            added_lines[p] = added
            if has_private(p):
                block(p, "the file path contains the Windows account name. Rename it.")
            for n, l in added:
                if has_private(l):
                    block(p, "line %d has the Windows account name or the user folder. "
                             "Write %%USERPROFILE%% or ~ instead: %s" % (n, l.strip()[:120]))
                elif USER_PATH_RE.search(l):
                    warn(p, "line %d has an absolute user folder path; prefer %%USERPROFILE%% or ~." % n)

        exists_now = (lambda p: p in staged) if mode == "staged" else (lambda p: (ROOT / p).is_file())
        new_paths = set(staged) if mode == "staged" else \
            {p for p in head_paths | set(touched) if p and exists_now(p)}
        new_indexes = sorted(p for p in new_paths if PurePosixPath(p).name == "index.md")
        idx_cache = {}

        def index_text(ip):
            if ip not in idx_cache:
                idx_cache[ip] = text_of(new_content(ip)) or ""
            return idx_cache[ip]

        # Deletions: the log, the indexes of folders that keep files, the tools, and anything an
        # index still links to must stay. Nothing is deleted silently.
        gone_reported = set()
        related = set(touched)
        for g in sorted(gone):
            if exists_now(g):
                continue
            gp = PurePosixPath(g)
            for i in range(len(gp.parts)):
                d = PurePosixPath(*gp.parts[:i])
                related.add("index.md" if str(d) == "." else (d / "index.md").as_posix())
            if g.endswith(".md"):
                md_touched = True
            if g == "log.md":
                block(g, "deleting log.md is not allowed; it is the history of the knowledge base.")
            elif g == "index.md":
                block(g, "deleting the root index.md is not allowed.")
            elif gp.parts[0] in (".kb", ".githooks") or g == ".gitattributes":
                block(g, "deleting the knowledge base tools is not allowed.")
            elif gp.name == "index.md":
                folder = gp.parent.as_posix() + "/"
                left = sorted(p for p in new_paths if p.startswith(folder))
                if left:
                    block(g, "its folder still has %s. A folder index can only go together with "
                             "the last file in its folder." % ", ".join(left[:3]))
            if g.endswith(".md"):
                for ip in new_indexes:
                    if "](/%s)" % g in index_text(ip):
                        gone_reported.add(g)
                        block(g, "is deleted, but %s still links to it. Remove that line in the "
                                 "same commit." % ip)

        diags = None
        if md_touched:
            diags = okf_diagnostics(tree)
            if diags is None:
                block("okf", "okf was not found (looked at OKF_EXE, PATH and "
                             "%USERPROFILE%\\.cargo\\bin\\okf.exe), so the knowledge base "
                             "cannot be checked. Ask the user to install it.")
                diags = []

        # Log lines this change adds, for the "every changed concept is logged" rule.
        head_log = text_of(cat_blobs(["%s:log.md" % base]).get("%s:log.md" % base)) or ""
        head_log_lines = set(head_log.split("\n"))
        new_log = text_of(new_content("log.md")) or ""
        new_log_lines = [l for l in new_log.split("\n") if l not in head_log_lines and LOG_LINE_RE.match(l.strip())]

        for p, (st, data) in sorted(touched.items()):
            if not p.endswith(".md"):
                continue
            path = PurePosixPath(p)
            name = path.name
            if data.startswith(BOM):
                block(p, "starts with a UTF-8 BOM. Remove the first 3 bytes "
                         "(kb.py touch rewrites the file without it).")
            text = text_of(data)
            if text is None:
                continue
            if st in ("A", "R"):
                for i in range(len(path.parts) - 1):
                    d = PurePosixPath(*path.parts[:i + 1]).as_posix()
                    if d not in head_dirs and not NAME_RE.match(path.parts[i]):
                        block(p, "new folder name '%s' must be lowercase words joined by hyphens." % path.parts[i])
                if name == "log.md":
                    if p != "log.md":
                        block(p, "only the root log.md is a log. Use kb.py log instead of a new log file.")
                elif name != "index.md" and not NAME_RE.match(path.stem):
                    block(p, "file name '%s' must be lowercase words joined by hyphens, like use-sqlite.md." % name)
                if name == "index.md" and str(path.parent) != ".":
                    pidx = (path.parent.parent / "index.md").as_posix()
                    ptext = text_of(new_content(pidx)) or ""
                    if "](/%s)" % p not in ptext:
                        warn(p, "is a new folder index that %s does not link to." % pidx)
            if p == "log.md":
                for n, l in added_lines.get(p, []):
                    s = l.strip()
                    if not s or HEADING_RE.match(s) or s.startswith("# "):
                        continue
                    m = LOG_LINE_RE.match(s)
                    if not m:
                        block(p, "line %d is not a kb.py log line. Never edit log.md by hand; "
                                 "use kb.py log: %s" % (n, s[:100]))
                    elif m.group("note") and len(m.group("note")) > NOTE_MAX:
                        block(p, "line %d has a note of %d characters; the limit is %d."
                              % (n, len(m.group("note")), NOTE_MAX))
                new_days = collections.Counter(HEADING_RE.match(l).group(1) for l in text.split("\n")
                                               if HEADING_RE.match(l))
                old_text = text_of(old_blobs.get("%s:%s" % (base, p))) or ""
                old_days = collections.Counter(HEADING_RE.match(l).group(1) for l in old_text.split("\n")
                                               if HEADING_RE.match(l))
                old_dups = []
                for day, cnt in sorted(new_days.items(), reverse=True):
                    if cnt > 1 and cnt > old_days.get(day, 0):
                        block(p, "the heading ## %s now appears %d times. Put the line under the "
                                 "existing heading (kb.py log does this)." % (day, cnt))
                    elif cnt > 1:
                        old_dups.append("%s x%d" % (day, cnt))
                if old_dups:
                    warn(p, "older duplicate day headings, not from this change: %s." % ", ".join(old_dups))
                continue
            if name == "index.md":
                continue
            lines = text.split("\n")
            end = fm_end(lines)
            if end is not None:
                for msg in yaml_style_problems(lines[1:end]):
                    block(p, msg)
            if PLACEHOLDER in text:
                block(p, "still has %s placeholder lines. Write the real text." % PLACEHOLDER)
            if not any("](/%s)" % p in l for l in new_log_lines):
                how = ("kb.py log Added %s" % p) if st == "A" else \
                      ("kb.py touch %s --note 'what changed' (it also refreshes generated.at)" % p)
                block(p, "changed, but log.md has no new line for it. Run %s." % how)
            old_size = len(old_blobs.get("%s:%s" % (base, old_of.get(p, p))) or b"")
            if len(data) > SIZE_WARN and len(data) > old_size:
                block(p, "grows to %.1f KB%s, over the 20 KB limit. A concept holds the current truth: "
                         "rewrite it shorter and put the run history in the commit message, or ask "
                         "the user about splitting it (okf split --section)."
                      % (len(data) / 1024, (" (was %.1f KB)" % (old_size / 1024)) if old_size else ""))
            elif len(data) > SIZE_WARN:
                warn(p, "is %d KB, over 20 KB. A concept holds the current truth: move run history "
                        "into commit messages, or ask the user about splitting it "
                        "(okf split --section)." % (len(data) // 1024))
            idx = (path.parent / "index.md").as_posix()
            if str(path.parent) == ".":
                idx = "index.md"
            if not exists_now(idx):
                block(p, "its folder has no index.md. Create %s with a line that links to /%s." % (idx, p))

        touched_ids = {concept_id(p) for p in touched if p.endswith(".md") and not is_reserved(p)}
        gone_ids = {concept_id(p) for p in gone if p.endswith(".md")}
        for sev, p, msg in diags or []:
            if "is out of sync with its directory" in msg:
                missing = re.search(r"missing from index: ([^;)]+)", msg)
                listed = re.search(r"listed but not on disk: ([^;)]+)", msg)
                for cid in (missing.group(1).split(", ") if missing else []):
                    if cid in touched_ids:
                        block(cid + ".md", "is not listed in %s. Add a line like: "
                                           "- [Title](/%s.md) - description" % (p, cid))
                    elif p in touched:
                        warn(p, "does not list %s.md (not from this change)." % cid)
                for cid in (listed.group(1).split(", ") if listed else []):
                    added = "\n".join(l for _, l in added_lines.get(p, []))
                    if cid in gone_ids:
                        if cid + ".md" not in gone_reported:
                            block(p, "still lists /%s.md, which this change removes. Remove or "
                                     "repoint that line." % cid)
                    elif p in touched and cid in added and not exists_now(cid + ".md"):
                        block(p, "links to /%s.md, which does not exist." % cid)
                    elif p in touched and exists_now(cid + ".md"):
                        pass  # the file is there but okf cannot parse it; reported on that file
                    elif p in touched:
                        warn(p, "lists /%s.md, which does not exist (not from this change)." % cid)
                continue
            if "duplicate date heading" in msg:
                continue
            if p not in related:
                continue
            if sev == "error":
                block(p, "okf: " + msg)
            elif sev == "warning":
                warn(p, "okf: " + msg)
    finally:
        if tmp:
            shutil.rmtree(str(tmp), ignore_errors=True)

    for line in blocks + warns:
        out(line)
    nfiles = len(changes)
    if blocks:
        out("kb check: FAILED (%s, %d file(s)): %d blocking, %d warning(s). Fix every BLOCK line, "
            "then run the same command again." % (mode_label, nfiles, len(blocks), len(warns)))
        return 1
    out("kb check: OK (%s, %d file(s)): %d warning(s)." % (mode_label, nfiles, len(warns)))
    return 0


def cmd_check(a):
    if a.staged and a.files:
        fail("use either --staged or a list of files, not both.")
    return do_check("staged" if a.staged else "files", a.files)


def cmd_check_msg(a):
    text = re.split(r"(?m)^# -+ >8 -+$", read_text(a.file))[0]
    text = "\n".join(l for l in text.split("\n") if not l.startswith("#"))
    if has_private(text):
        out("BLOCK commit message: it contains the Windows account name or the user folder. "
            "Write %USERPROFILE% or ~ instead.")
        return 1
    return 0


# ---------------------------------------------------------------- commit

def changed_paths():
    so = dec(git("status", "--porcelain=v1", "-z", "--untracked-files=all"))
    parts, res, i = so.split("\0"), set(), 0
    while i < len(parts) and parts[i]:
        rec = parts[i]
        res.add(rec[3:])
        i += 1
        if rec[0] in "RC":
            res.add(parts[i])
            i += 1
    return res


def hook_installed():
    hp = dec(git("config", "--get", "core.hooksPath", ok=(0, 1))).strip()
    if not hp:
        return False
    hp_path = Path(hp) if Path(hp).is_absolute() else ROOT / hp
    try:
        same = hp_path.resolve() == (ROOT / ".githooks").resolve()
    except OSError:
        same = False
    return same and (ROOT / ".githooks" / "pre-commit").is_file()


LINK_TARGET_RE = re.compile(r"\]\(/([^)\s#]+)")


def partial_log(head_text, work_text, keep):
    """log.md as committed: HEAD plus only the new lines that link to a file in keep,
    each placed after the line it follows in the working file, so the order matches."""
    lines = head_text.rstrip("\n").split("\n") if head_text else ["# Directory Update Log"]
    head_set, day, prev = set(lines), None, None
    for l in work_text.rstrip("\n").split("\n"):
        m = HEADING_RE.match(l)
        if m:
            day, prev = m.group(1), None
            continue
        if day is None or not l.strip():
            continue
        if l in head_set:
            prev = l
            continue
        t = LINK_TARGET_RE.search(l)
        if not (t and t.group(1) in keep):
            continue
        if prev is not None and prev in lines:
            lines.insert(lines.index(prev) + 1, l)
        else:
            insert_log_line(lines, day, l)
        prev = l
    return "\n".join(lines) + "\n"


def partial_index(head_text, work_text, keep, head_paths):
    """An index as committed: drop new lines that link to files this commit leaves out."""
    head_set = set(head_text.split("\n")) if head_text else set()
    kept = []
    for l in work_text.rstrip("\n").split("\n"):
        if l not in head_set and any(t not in keep and t not in head_paths
                                     for t in LINK_TARGET_RE.findall(l)):
            continue
        kept.append(l)
    return "\n".join(kept) + "\n"


def stage_text(rel, text):
    sha = dec(git("hash-object", "-w", "--stdin", data=text.encode("utf-8"))).strip()
    git("update-index", "--add", "--cacheinfo", "100644,%s,%s" % (sha, rel))


def cmd_commit(a):
    msgs = [m.strip() for m in a.message if m.strip()]
    if not msgs or not msgs[0].startswith("kb: ") or len(msgs[0]) < 6:
        fail('the message must start with "kb: ", e.g. -m "kb: add aq decision use-sqlite".')
    for m in msgs:
        no_private("the commit message", m)
    if not a.files:
        fail("name the files to commit.")
    rels = []
    for f in a.files:
        rel = norm_rel(f)
        if (ROOT / rel).is_dir():
            fail("%s is a folder; name the files." % rel)
        rels.append(rel)
    rels = list(dict.fromkeys(rels))
    changed = changed_paths()
    for p in rels:
        if p not in changed:
            in_index = git("ls-files", "--error-unmatch", "--", p, ok=(0, 1)).strip()
            if not in_index and not (ROOT / p).exists():
                fail("%s does not exist." % p)
    # log.md and the indexes above each file come along, but only with their lines for these files.
    auto = []
    if "log.md" in changed and "log.md" not in rels:
        auto.append("log.md")
    for rel in rels:
        d = PurePosixPath(rel).parent
        while True:
            idx = "index.md" if str(d) == "." else (d / "index.md").as_posix()
            if idx in changed and idx not in rels and idx not in auto:
                auto.append(idx)
            if str(d) == ".":
                break
            d = d.parent
    if not any(p in changed for p in rels + auto):
        fail("none of these files has changes to commit.")
    staged = set(p for p in dec(git("diff", "--cached", "--name-only", "-z")).split("\0") if p)
    others = sorted(staged - set(rels + auto))
    if others:
        fail("other files are already staged: %s. Unstage them with "
             "git restore --staged -- <file>, or name them in this command." % ", ".join(others))
    code, so, se = run(["git", "add", "--"] + rels)
    noise = re.compile(r"^warning: (in the working copy of|LF will be replaced|CRLF will be replaced)")
    for l in (dec(so) + dec(se)).splitlines():
        if l.strip() and not noise.match(l):
            out(mask(l))
    if code != 0:
        fail("git add failed.")
    base = head_ref()
    head_paths = set(dec(git("ls-tree", "-r", "--name-only", "-z", base)).split("\0"))
    keep = set(rels + [p for p in auto if p != "log.md"])
    heads = cat_blobs(["%s:%s" % (base, p) for p in auto])
    paths, partial = list(rels), []
    for p in auto:
        head_text = text_of(heads.get("%s:%s" % (base, p))) or ""
        work_text = read_text(ROOT / p) if (ROOT / p).exists() else ""
        if p == "log.md":
            text = partial_log(head_text, work_text, keep)
        else:
            text = partial_index(head_text, work_text, keep, head_paths)
        if text == (head_text.rstrip("\n") + "\n" if head_text else "\n"):
            continue
        stage_text(p, text)
        paths.append(p)
        if text != work_text.rstrip("\n") + "\n":
            partial.append(p)
    if not hook_installed():
        out("note: the pre-commit hook is not installed in this clone, so kb.py runs the check itself. "
            "(To install it: git config core.hooksPath .githooks)")
        if do_check("staged", []) != 0:
            out("kb commit: blocked. Fix what the check says, then run the same kb.py commit again.")
            return 1
    cmd = ["git", "commit"]
    for m in msgs:
        cmd += ["-m", m]
    code, so, se = run(cmd)
    for l in (dec(se) + dec(so)).splitlines():  # hook output (stderr) before git's summary
        if l.strip() and not noise.match(l):
            out(mask(l))
    if code != 0:
        out("kb commit: blocked. Fix what the check says, then run the same kb.py commit again.")
        return 1
    sha = dec(git("rev-parse", "--short", "HEAD")).strip()
    out("kb commit: %s %s" % (sha, msgs[0]))
    for p in paths:
        out("  " + p + ("  (only the lines for these files)" if p in partial else ""))
    out("Not pushed. Push only when the user asks.")
    return 0


# ---------------------------------------------------------------- main

def main(argv=None):
    for s in (sys.stdout, sys.stderr):
        try:
            # A console gets Unicode either way; piped output (git hooks, agents) gets UTF-8.
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(prog="kb.py", description="Change the knowledge base safely.")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("new", help="create a concept, list it in its folder index, log it")
    p.add_argument("relpath")
    p.add_argument("--type", required=True)
    p.add_argument("--title", required=True)
    p.add_argument("--description", required=True)
    p.add_argument("--by", required=True, help="producer/version, e.g. dsh/qwen3.8")
    p.add_argument("--tags", help="comma separated")
    p.add_argument("--status", default="stable", help="stable (default) or draft")
    p.add_argument("--source", action="append", help='"id|title|resource", repeatable')
    p.add_argument("--stale-after", help="YYYY-MM-DD")
    p.add_argument("--note", help="optional log note")
    p.set_defaults(fn=cmd_new)

    p = sub.add_parser("touch", help="refresh generated.at after an edit, and log it")
    p.add_argument("relpath")
    p.add_argument("--note", required=True)
    p.add_argument("--verb", default="Updated", help="Updated (default), or Deprecated when retiring it")
    p.add_argument("--by", help="only used when the file has no generated key")
    p.set_defaults(fn=cmd_touch)

    p = sub.add_parser("log", help="add one line under today's heading in log.md")
    p.add_argument("verb", help="Added, Updated, Created or Deprecated")
    p.add_argument("relpath")
    p.add_argument("note", nargs="?")
    p.set_defaults(fn=cmd_log)

    p = sub.add_parser("check", help="check changed files (default), named files, or --staged")
    p.add_argument("--staged", action="store_true")
    p.add_argument("files", nargs="*")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("commit", help="stage the named files plus log.md and touched indexes, then commit")
    p.add_argument("-m", "--message", action="append", required=True)
    p.add_argument("files", nargs="*")
    p.set_defaults(fn=cmd_commit)

    p = sub.add_parser("check-msg")
    p.add_argument("file")
    p.set_defaults(fn=cmd_check_msg)

    a = ap.parse_args(argv)
    if not getattr(a, "fn", None):
        ap.print_help()
        return 2
    try:
        return a.fn(a)
    except KbError as e:
        out("kb: error: %s" % mask(str(e)))
        return 2


if __name__ == "__main__":
    sys.exit(main())
