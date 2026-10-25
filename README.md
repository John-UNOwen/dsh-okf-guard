# dsh-okf-guard

A DeepSeek Harness (DSH) plugin that keeps agents on `kb.py` inside the OKF
knowledge base at `%USERPROFILE%\knowledge`. The knowledge base's own git hooks
check every commit; this plugin stops the common mistakes earlier, before the
tool call runs, and tells the model the right command instead.

## What it does

**Blocks** (a DSH tool guard, so no other plugin or approval setting can allow it):

- `git add` and `git commit` in the knowledge base. Use `kb.py commit`.
- `--no-verify`, and changes to `core.hooksPath`.
- Force-push, deleting remote branches, and history rewrites (`rebase`, `filter-branch`, `filter-repo`, `update-ref`, `reflog expire`).
- `okf index`, `okf validate --fix`, `okf lint --fix`, `okf fmt -w` on a folder, `okf new` and `okf init`.
- `okf mv`, `rm`, `merge` and `split` without `--no-index`, because they regenerate index files.
- Writing `log.md`, `.kb/`, `.githooks/`, `.git/` or `.gitattributes`, from a shell command or a file tool.
- Creating a new concept file by hand. Use `kb.py new`.
- Text that contains the Windows account name or the user folder path. The name is worked out at run time and is never stored in this plugin.

**Asks the user first** (the normal DSH approval prompt):

- `git push`.
- `git reset --hard`, `git clean -f`, `git checkout -- <path>`, `git restore`, `git stash drop`, `git rm`.
- `okf mv`, `rm`, `merge` and `split` with `--no-index`.

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
  way (for example a `python -c` one-liner) can get past it. The pre-commit
  hook still checks everything at commit time.
- It only knows about the folder a command names, its `workdir`, `cd` inside
  the same command, and the session folder.

## Tests

The tests load the Cordis runtime from the installed DSH, so they need no
`npm install`:

```powershell
node --import ./tests/dsh-runtime.mjs --test tests/*.test.mjs
```
