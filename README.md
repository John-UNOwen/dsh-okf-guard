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
is, what belongs there and what belongs in mnemon, and that changes go
through `kb.py`. The section is only added when `.kb\kb.py` exists.

Everything outside the knowledge base is left alone.

## Install

```powershell
dsh plugin --profile web add "file:$env:USERPROFILE\Documents\GitHub\dsh-okf-guard"
```

DSH copies the plugin into the profile and turns it on. Restart DSH afterwards.

To pick up later edits to this folder, remove and add it again:

```powershell
dsh plugin --profile web remove dsh-okf-guard
dsh plugin --profile web add "file:$env:USERPROFILE\Documents\GitHub\dsh-okf-guard"
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
