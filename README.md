# dsh-okf-guard

A DeepSeek Harness (DSH) plugin that keeps agents on `kb.py` inside the OKF
knowledge base at `%USERPROFILE%\knowledge`. The knowledge base's own git hooks
check every commit; this plugin stops the common mistakes earlier, before the
tool call runs, and tells the model the right command instead.

## What it does

**Blocks** (a DSH tool guard, so no other plugin or approval setting can allow it):

- `git add` and `git commit` in the knowledge base. Use `kb.py commit`.
- `--no-verify`, and changes to `core.hooksPath`.
- Force-push, deleting remote branches (`--delete`, `--prune`, `:branch`), and history rewrites (`rebase`, `filter-branch`, `filter-repo`, `update-ref`, `reflog expire`).
- `okf index`, `okf validate --fix`, `okf lint --fix`, `okf fmt -w` on a folder, `okf new` and `okf init`.
- `okf mv`, `rm`, `merge` and `split` without `--no-index`, because they regenerate index files.
- Writing, moving or deleting `log.md`, `.kb/`, `.githooks/`, `.git/` or `.gitattributes`, from a shell command or a file tool. Copying them somewhere else is fine.
- Creating a new concept file by hand. Use `kb.py new`.
- Text that contains the Windows account name or the user folder path, written into the knowledge base by a file tool or a shell command. Names match as whole words. The name is worked out at run time and is never stored in this plugin.

**Asks the user first** (the normal DSH approval prompt):

- `git push`.
- Commands that throw away uncommitted edits: `git reset --hard`, `git clean -f`, `git checkout` of files (`.`, a path, `--`, `-f`), `git switch --discard-changes` or `-f`, `git restore` (except only unstaging with `--staged`), `git stash drop`, `git rm`.
- Commands that move commits: `git reset` to another commit or `--soft`, `git pull --rebase`, `git branch -f` or `-D`, `git checkout -B`, `git switch -C`.
- Commands that make commits the pre-commit check never sees: `git cherry-pick`, `git revert`, `git am`, `git merge` (fast-forward-only merges and `--abort` are fine).
- `okf mv`, `rm`, `merge` and `split` with `--no-index`.

When another plugin or hook also has a say, its deny or its own question wins over okf-guard's question.

Commands are found anywhere in a line: after `$x =`, inside `( )`, `$( )` and `{ }` blocks, after `&`, and inside `cmd /c`, `pwsh -c`, `bash -c`, `iex` and `Start-Process`. A block anywhere in a line wins over a question elsewhere in it.

**Adds a short section to the system prompt.** It says where the knowledge base
is, what belongs there and what doesn't (personal preferences, run notes,
handoffs), and that changes go through `kb.py`. The section is only added when `.kb\kb.py` exists.

Everything outside the knowledge base is left alone.

## Set up a knowledge base

The plugin guards an existing knowledge base. This repo ships a starter one in
[`template/`](template): `kb.py` (the tool agents use), the git hooks that check
every commit, and empty root, `general` and `projects` indexes.

You need [git](https://git-scm.com/), Python 3.8 or later, and the
[okf](https://github.com/W4G1/okf) command-line tool:

```powershell
cargo install okf
```

`kb.py` looks for okf in `OKF_EXE`, then on `PATH`, then in
`%USERPROFILE%\.cargo\bin`.

Create the knowledge base at `%USERPROFILE%\knowledge` (PowerShell, from a
clone of this repo; the GitHub install leaves `template/` out):

```powershell
git clone https://github.com/John-UNOwen/dsh-okf-guard.git
cd dsh-okf-guard
$kb = "$env:USERPROFILE\knowledge"
Copy-Item -Recurse .\template $kb
git -C $kb init -b main
git -C $kb config core.hooksPath .githooks
python "$kb\.kb\kb.py" log Created index.md 'knowledge base'
git -C $kb add -A
git -C $kb commit -m "kb: start the knowledge base"
```

The `log` line writes the first dated entry in `log.md`, which okf requires.
On macOS or Linux, use `~/knowledge`, `python3`, and run
`chmod +x ~/knowledge/.githooks/*` before the first commit.

Then try it:

```powershell
python "$kb\.kb\kb.py" new projects/my-app/decisions/use-sqlite.md --type Decision --title 'Use SQLite for the cache' --description 'Why SQLite beats a JSON file for the cache.' --by human:me
```

Open the new file, replace every `TODO(kb)` line with real text, and commit it.
`kb.py commit` stages the concept with its index and log lines, and the hook
checks the result:

```powershell
python "$kb\.kb\kb.py" commit -m 'kb: add my-app decision use-sqlite' projects/my-app/decisions/use-sqlite.md
```

To keep the knowledge base on more than one PC, add a remote and push as usual.
On each other clone, run `git config core.hooksPath .githooks` once, because git
doesn't copy that setting. If your Windows account name could end up in paths
in some other form, add it with `git config kb.privateName "<name>"`; the hooks
and this plugin both block it.

To use a different folder, set `knowledgeRoot` (see Settings).

## Install

From GitHub:

```powershell
dsh plugin --profile web add github:John-UNOwen/dsh-okf-guard
```

Add `#<commit>` to pin a version, e.g. `github:John-UNOwen/dsh-okf-guard#a26ec64`.

Or from a local clone:

```powershell
dsh plugin --profile web add "file:$env:USERPROFILE\Documents\GitHub\dsh-okf-guard"
```

Either way, DSH copies the plugin into the profile and turns it on. Restart DSH
afterwards.

To update, remove the plugin and add it again with the same command:

```powershell
dsh plugin --profile web remove dsh-okf-guard
dsh plugin --profile web add github:John-UNOwen/dsh-okf-guard
```

## Settings

Override them in the profile's `cordis.patch.yml`:

```yaml
- id: okf-guard
  config:
    knowledgeRoot: '~/knowledge'   # ~ and %USERPROFILE% are expanded
    injectPrompt: true             # add the system prompt section
    askBeforePush: true            # false lets agents push without asking
```

`shellTools` (default `pwsh`, `bash`) and `fileTools` (default `write`,
`edit`, `str_replace_editor`) name the tools whose calls are checked.

## Limits

- When a session's approval policy is "never" (the full-access preset), DSH
  turns every "ask" into a refusal, so agents can't push there. Push yourself.
- It reads commands, it doesn't run them. A command that writes in an unusual
  way (for example a `python -c` one-liner, or a path kept in a variable) can
  get past it. The pre-commit hook still checks everything at commit time.
- It knows where a command runs from the session folder, the shell tool's
  `workdir`, `cd`, `pushd` and `popd` in the same command, `git -C`,
  `--git-dir`, `--work-tree`, and `GIT_DIR` or `GIT_WORK_TREE` set in the same
  command.
- The 8.3 short form of the home folder (like `C:\Users\ABCDEF~1`) is looked
  up in the background when the plugin starts, so for the first moment short
  paths are not yet recognized.

## Tests

The tests load the Cordis runtime from the installed DSH, so they need no
`npm install`:

```powershell
node --import ./tests/dsh-runtime.mjs --test tests/*.test.mjs
```
