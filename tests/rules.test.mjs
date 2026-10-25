import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { createGuard, splitSegments, words } from '../lib/rules.js'

// A made-up account, so the tests never print or need the real one.
const WIN = process.platform === 'win32'
const HOME = WIN ? 'C:\\Users\\Test Person' : '/home/Test Person'
const KB = WIN ? `${HOME}\\knowledge` : `${HOME}/knowledge`
const sep = WIN ? '\\' : '/'
const kb = (...parts) => [KB, ...parts].join(sep)
const OTHER = WIN ? 'C:\\work\\proj' : '/work/proj'

const DOCS = `${HOME}${sep}Documents`
const existing = new Set(
  [kb('.kb', 'kb.py'), kb('projects', 'a', 'decisions', 'old.md'), kb('projects', 'a', 'index.md'), kb('projects', 'a.md')].map((p) => p.toLowerCase()),
)
const SHORT = WIN ? 'C:\\Users\\TESTPE~1' : null
const env = { home: HOME, shortHome: SHORT, privateNames: ['Test Person'], exists: (p) => existing.has(String(p).toLowerCase()) }
const guard = createGuard({ knowledgeRoot: '~/knowledge' }, env)

const sh = (command, cwd = OTHER, extra = {}) =>
  guard.decide({ name: 'pwsh', arguments: { command, ...extra }, agent: { session: { header: { cwd } } } })
const file = (name, args, cwd = OTHER) => guard.decide({ name, arguments: args, agent: { session: { header: { cwd } } } })
const kind = (d) => (d ? d.kind : 'allow')

describe('command parsing', () => {
  it('splits on ; && || | and newlines, not inside quotes', () => {
    assert.deepEqual(splitSegments('a; b && c || d | e\nf'), ['a', 'b', 'c', 'd', 'e', 'f'])
    assert.deepEqual(splitSegments("git commit -m 'a; b'"), ["git commit -m 'a; b'"])
  })
  it('keeps quoted words with spaces whole', () => {
    assert.deepEqual(words('git -C "C:\\Users\\Test Person\\knowledge" add -A'), ['git', '-C', 'C:\\Users\\Test Person\\knowledge', 'add', '-A'])
  })
})

describe('git in the knowledge base', () => {
  it('denies git add and git commit, whichever way the folder is named', () => {
    for (const form of ['"$env:USERPROFILE\\knowledge"', '$env:USERPROFILE/knowledge', '~/knowledge', '"%USERPROFILE%\\knowledge"', `"${KB}"`]) {
      assert.equal(kind(sh(`git -C ${form} add -A`)), 'deny', form)
      assert.equal(kind(sh(`git -C ${form} commit -m x`)), 'deny', form)
    }
    assert.equal(kind(sh('git add .', KB)), 'deny')
    assert.equal(kind(sh('cd ~/knowledge; git commit -m "kb: x"')), 'deny')
    assert.equal(kind(sh('Set-Location $env:USERPROFILE\\knowledge && git add projects/a.md')), 'deny')
  })
  it('uses the workdir argument of the shell tool', () => {
    assert.equal(kind(sh('git add -A', OTHER, { workdir: KB })), 'deny')
    assert.equal(kind(sh('git add -A', HOME, { workdir: 'knowledge' })), 'deny')
    assert.equal(kind(sh('git add -A', KB, { workdir: OTHER })), 'allow')
  })
  if (WIN) {
    it('understands Git Bash paths', () => {
      const d = guard.decide({ name: 'bash', arguments: { command: 'git -C "/c/Users/Test Person/knowledge" add -A' }, agent: { session: { header: { cwd: OTHER } } } })
      assert.equal(kind(d), 'deny')
    })
    it('understands 8.3 short paths', () => {
      assert.equal(kind(sh('git -C C:\\Users\\TESTPE~1\\knowledge add -A')), 'deny')
      assert.equal(kind(sh('git add -A', OTHER, { workdir: 'C:\\Users\\TESTPE~1\\knowledge\\projects' })), 'deny')
      assert.equal(kind(sh('Add-Content C:\\Users\\TESTPE~1\\knowledge\\log.md x')), 'deny')
      assert.equal(kind(file('write', { file_path: 'C:\\Users\\TESTPE~1\\knowledge\\log.md', content: 'x' })), 'deny')
      assert.equal(kind(sh('git add -A', 'C:\\Users\\TESTPE~1\\other')), 'allow')
    })
  }
  it('points the model at kb.py commit', () => {
    assert.match(sh('git commit -m x', KB).reason, /kb\.py" commit -m 'kb: <summary>' <files>/)
    assert.doesNotMatch(sh('git commit -m x', KB).reason, /Test Person/)
  })
  it('denies --no-verify and hook changes', () => {
    assert.equal(kind(sh('git commit --no-verify -m x', KB)), 'deny')
    assert.match(sh('git commit -n -m x', KB).reason, /never skip/)
    assert.equal(kind(sh('git -c core.hooksPath=/dev/null status', KB)), 'deny')
    assert.equal(kind(sh('git config core.hooksPath .nohooks', KB)), 'deny')
    assert.equal(kind(sh('git config --unset core.hooksPath', KB)), 'deny')
    assert.equal(kind(sh('git config --get core.hooksPath', KB)), 'allow')
  })
  it('asks before push and denies force-push and history rewrites', () => {
    assert.equal(kind(sh('git push', KB)), 'ask')
    assert.equal(kind(sh('git push origin master', KB)), 'ask')
    for (const c of ['git push --force', 'git push -f', 'git push --force-with-lease', 'git push origin +master', 'git push --delete origin x']) {
      assert.equal(kind(sh(c, KB)), 'deny', c)
    }
    for (const c of ['git rebase -i HEAD~3', 'git filter-branch', 'git filter-repo --path x', 'git update-ref -d HEAD', 'git reflog expire --all']) {
      assert.equal(kind(sh(c, KB)), 'deny', c)
    }
  })
  it('asks before discarding uncommitted work', () => {
    for (const c of ['git reset --hard', 'git clean -fd', 'git checkout -- .', 'git restore projects/a.md', 'git stash drop', 'git rm projects/a.md']) {
      assert.equal(kind(sh(c, KB)), 'ask', c)
    }
    assert.equal(kind(sh('git restore --staged projects/a.md', KB)), 'allow')
    assert.equal(kind(sh('git reset', KB)), 'allow')
  })
  it('leaves reads and kb.py alone', () => {
    for (const c of ['git status', 'git log -p -- projects/a.md', 'git grep -n -i -e "sqlite"', 'git diff --cached', 'git checkout master', 'git pull']) {
      assert.equal(kind(sh(c, KB)), 'allow', c)
    }
    assert.equal(kind(sh(`python "$env:USERPROFILE\\knowledge\\.kb\\kb.py" commit -m 'kb: add x' projects/a/decisions/x.md`)), 'allow')
    assert.equal(kind(sh(`python "$env:USERPROFILE\\knowledge\\.kb\\kb.py" new projects/a/x.md --type Decision --title 'x' --description 'y' --by dsh/t`, KB)), 'allow')
  })
  it('leaves other repos alone', () => {
    for (const c of ['git add -A', 'git commit --no-verify -m x', 'git push --force', 'git reset --hard']) {
      assert.equal(kind(sh(c, OTHER)), 'allow', c)
    }
  })
})

describe('okf commands', () => {
  it('denies bundle-wide rewrites in the knowledge base', () => {
    assert.equal(kind(sh('okf index $env:USERPROFILE\\knowledge')), 'deny')
    assert.equal(kind(sh('okf index', KB)), 'deny')
    assert.equal(kind(sh('& "$env:USERPROFILE\\.cargo\\bin\\okf.exe" index .', KB)), 'deny')
    assert.equal(kind(sh('okf validate --fix .', KB)), 'deny')
    assert.equal(kind(sh('okf lint --fix', KB)), 'deny')
    assert.equal(kind(sh('okf fmt -w .', KB)), 'deny')
    assert.equal(kind(sh('okf fmt -w', KB)), 'deny')
    assert.equal(kind(sh('okf fmt -w projects', KB)), 'deny')
    assert.equal(kind(sh('okf new projects/a/x.md --type Decision --title x', KB)), 'deny')
  })
  it('denies okf mv/rm/merge/split unless they skip index regeneration', () => {
    assert.equal(kind(sh('okf mv projects/a/x.md projects/a/y.md', KB)), 'deny')
    assert.equal(kind(sh('okf rm projects/a/x.md --bundle ~/knowledge')), 'deny')
    assert.equal(kind(sh('okf mv projects/a/x.md projects/a/y.md --no-index --no-log', KB)), 'ask')
    assert.equal(kind(sh('okf mv projects/a/x.md projects/a/y.md --dry-run', KB)), 'allow')
  })
  it('allows checks and one-file formatting', () => {
    assert.equal(kind(sh('okf validate --json .', KB)), 'allow')
    assert.equal(kind(sh('okf fmt -w projects/a/decisions/old.md', KB)), 'allow')
    assert.equal(kind(sh('okf parse --json projects/a/decisions/old.md', KB)), 'allow')
  })
  it('leaves other bundles alone', () => {
    assert.equal(kind(sh('okf index .', OTHER)), 'allow')
    assert.equal(kind(sh('okf validate --fix', OTHER)), 'allow')
  })
})

describe('shell writes to protected files', () => {
  it('denies writes to log.md and the tooling', () => {
    for (const c of [
      'Add-Content -Path "$env:USERPROFILE\\knowledge\\log.md" -Value "* x"',
      `Add-Content "${KB}${sep}log.md" "* x"`,
      '"* x" >> $env:USERPROFILE\\knowledge\\log.md',
      "echo x > '~/knowledge/.kb/kb.py'",
      '[IO.File]::AppendAllText("$env:USERPROFILE\\knowledge\\log.md", "x")',
      'Remove-Item ~/knowledge/.githooks/pre-commit',
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
    assert.equal(kind(sh('Set-Content .githooks/pre-commit "exit 0"', KB)), 'deny')
    assert.equal(kind(sh('"x" | Out-File -Append log.md', KB)), 'deny')
  })
  it('allows reads and harmless redirects', () => {
    assert.equal(kind(sh('Get-Content $env:USERPROFILE\\knowledge\\log.md -TotalCount 20')), 'allow')
    assert.equal(kind(sh('git -C ~/knowledge log --oneline 2>&1 > $null')), 'allow')
    assert.equal(kind(sh('Select-String -Path log.md -Pattern x', KB)), 'allow')
    assert.equal(kind(sh('Add-Content notes.md x', OTHER)), 'allow')
  })
})

describe('file tools', () => {
  it('denies writes to log.md and the tooling', () => {
    assert.equal(kind(file('write', { file_path: '~/knowledge/log.md', content: 'x' })), 'deny')
    assert.equal(kind(file('edit', { file_path: kb('.kb', 'kb.py'), old_string: 'a', new_string: 'b' })), 'deny')
    assert.equal(kind(file('edit', { file_path: 'log.md', old_string: 'a', new_string: 'b' }, KB)), 'deny')
    assert.equal(kind(file('str_replace_editor', { command: 'str_replace', path: kb('log.md'), old_str: 'a', new_str: 'b' })), 'deny')
    assert.equal(kind(file('str_replace_editor', { command: 'view', path: kb('log.md') })), 'allow')
  })
  it('sends new concepts to kb.py new', () => {
    const d = file('write', { file_path: kb('projects', 'a', 'decisions', 'new-thing.md'), content: '---\ntype: Decision\n---\n' })
    assert.equal(kind(d), 'deny')
    assert.match(d.reason, /kb\.py" new/)
    assert.equal(kind(file('str_replace_editor', { command: 'create', path: kb('general', 'x.md'), file_text: 'x' })), 'deny')
  })
  it('allows edits to existing concepts and indexes', () => {
    assert.equal(kind(file('write', { file_path: kb('projects', 'a', 'decisions', 'old.md'), content: 'body' })), 'allow')
    assert.equal(kind(file('edit', { file_path: kb('projects', 'a', 'decisions', 'old.md'), old_string: 'a', new_string: 'b' })), 'allow')
    assert.equal(kind(file('write', { file_path: kb('projects', 'b', 'index.md'), content: '# B' })), 'allow')
    assert.equal(kind(file('write', { file_path: kb('notes.txt'), content: 'x' })), 'allow')
  })
  it('denies the account name in any form', () => {
    const target = kb('projects', 'a', 'decisions', 'old.md')
    for (const text of ['see C:\\Users\\Test Person\\x', 'TESTPE~1', 'test-person', 'Test%20Person', 'TestPerson', 'test_person']) {
      assert.equal(kind(file('edit', { file_path: target, old_string: 'a', new_string: text })), 'deny', text)
    }
    assert.match(file('edit', { file_path: target, old_string: 'a', new_string: 'TESTPE~1' }).reason, /%USERPROFILE%/)
    assert.equal(kind(file('edit', { file_path: target, old_string: 'a', new_string: '%USERPROFILE%\\x and ~/x' })), 'allow')
  })
  it('leaves files outside the knowledge base alone', () => {
    assert.equal(kind(file('write', { file_path: `${OTHER}${sep}log.md`, content: 'Test Person' })), 'allow')
    assert.equal(kind(file('read', { file_path: kb('log.md') })), 'allow')
  })
})

describe('prompt section', () => {
  it('names the root without the account name', () => {
    const text = guard.promptText()
    assert.match(text, /# Knowledge base/)
    assert.match(text, WIN ? /%USERPROFILE%\\knowledge/ : /~\/knowledge/)
    assert.match(text, /AGENTS\.md/)
    assert.doesNotMatch(text, /mnemon/i)
    assert.doesNotMatch(text, /Test Person/i)
  })
  it('is empty when kb.py is missing', () => {
    const bare = createGuard({}, { ...env, exists: () => false })
    assert.equal(bare.promptText(), '')
  })
})

const bash = (command, cwd = OTHER) => guard.decide({ name: 'bash', arguments: { command }, agent: { session: { header: { cwd } } } })

describe('review 1 and 9: git and okf anywhere in a command', () => {
  it('finds git behind assignments, brackets, blocks and the call operator', () => {
    for (const c of [
      '$r = git commit --no-verify -m x 2>&1',
      '(git add -A)',
      'Write-Output $(git add -A)',
      'if ($true) { git commit -m x }',
      '$null = & git add -A',
      'Start-Process git -ArgumentList \'add\',\'-A\' -Wait -NoNewWindow',
    ]) {
      assert.equal(kind(sh(c, KB)), 'deny', c)
    }
    assert.equal(kind(sh('Push-Location ~/knowledge; try { git add -A } finally { Pop-Location }')), 'deny')
    assert.equal(kind(sh('$x = okf index .', KB)), 'deny')
  })
  it('checks the command inside cmd /c, pwsh -c, bash -c and iex', () => {
    assert.equal(kind(sh('cmd /c "git add -A"', KB)), 'deny')
    assert.equal(kind(sh('pwsh -NoProfile -Command "git -C ~/knowledge add -A"')), 'deny')
    assert.equal(kind(sh('pwsh -c "git -C `"$env:USERPROFILE\\knowledge`" add -A"')), 'deny')
    assert.equal(kind(sh('iex "git add -A"', KB)), 'deny')
    assert.equal(kind(bash("bash -c 'cd ~/knowledge && git add -A'")), 'deny')
    assert.equal(kind(bash('GIT_TRACE=1 git add -A', KB)), 'deny')
  })
  it('splits at a background &', () => {
    assert.equal(kind(sh('git status & git add -A', KB)), 'deny')
    assert.equal(kind(sh('& git status', KB)), 'allow')
    assert.equal(kind(sh('git log 2>&1 | Out-String', KB)), 'allow')
  })
  it('a block anywhere beats an earlier ask', () => {
    assert.equal(kind(sh('git push; git add -A', KB)), 'deny')
    assert.equal(kind(sh('git push && Add-Content log.md x', KB)), 'deny')
  })
  it('leaves harmless uses alone', () => {
    for (const c of ['$s = git status --short', 'Write-Output (git log -1)', 'Get-Command git', '$x = & git status', 'Write-Output "git add -A is not allowed here"']) {
      assert.equal(kind(sh(c, KB)), 'allow', c)
    }
    assert.equal(kind(sh(`$out = python "$env:USERPROFILE\\knowledge\\.kb\\kb.py" commit -m 'kb: stop using git add -A' projects/a.md`, KB)), 'allow')
  })
})

describe('review 3: commands that discard uncommitted edits ask first', () => {
  it('asks', () => {
    for (const c of [
      'git checkout .',
      'git checkout projects/a.md',
      'git checkout -f master',
      'git switch --discard-changes master',
      'git switch -f master',
      'git restore --staged --worktree projects/a.md',
      'git restore --source HEAD~1 projects/a.md',
    ]) {
      assert.equal(kind(sh(c, KB)), 'ask', c)
    }
  })
  it('allows branch changes and unstaging', () => {
    for (const c of ['git checkout master', 'git checkout -b feature/new', 'git switch master', 'git restore --staged projects/a.md']) {
      assert.equal(kind(sh(c, KB)), 'allow', c)
    }
  })
})

describe('review 4: history rewrites ask or are blocked', () => {
  it('asks before moving commits', () => {
    for (const c of [
      'git reset HEAD~2',
      'git reset --soft HEAD~1',
      'git reset abc1234',
      'git reset origin/master',
      'git reset master',
      'git pull --rebase',
      'git pull -r',
      'git branch -f master HEAD~1',
      'git branch -D old',
      'git checkout -B master origin/master',
      'git switch -C master',
    ]) {
      assert.equal(kind(sh(c, KB)), 'ask', c)
    }
  })
  it('blocks deleting remote branches', () => {
    assert.equal(kind(sh('git push --prune', KB)), 'deny')
    assert.equal(kind(sh('git push origin :old-branch', KB)), 'deny')
  })
  it('allows unstaging and plain pulls', () => {
    for (const c of ['git reset', 'git reset HEAD', 'git reset projects/a.md', 'git reset HEAD projects/a.md', 'git pull', 'git pull --rebase=false', 'git branch -d merged', 'git branch new-branch']) {
      assert.equal(kind(sh(c, KB)), 'allow', c)
    }
  })
})

describe('review 5: commands that commit without the check ask first', () => {
  it('asks', () => {
    for (const c of ['git cherry-pick abc1234', 'git revert HEAD', 'git am fix.patch', 'git merge feature', 'git cherry-pick --continue']) {
      assert.equal(kind(sh(c, KB)), 'ask', c)
    }
    assert.match(sh('git merge feature', KB).reason, /kb\.py" check/)
  })
  it('allows aborts and fast-forwards', () => {
    for (const c of ['git merge --abort', 'git cherry-pick --abort', 'git revert --quit', 'git merge --ff-only origin/master']) {
      assert.equal(kind(sh(c, KB)), 'allow', c)
    }
  })
})

describe('review 6: --git-dir, --work-tree and GIT_DIR', () => {
  it('finds the knowledge base through them', () => {
    for (const c of [
      'git --git-dir ~/knowledge/.git --work-tree ~/knowledge add -A',
      'git --git-dir=$env:USERPROFILE/knowledge/.git add -A',
      'git --work-tree=~/knowledge --git-dir=~/knowledge/.git commit -m x',
      '$env:GIT_DIR = "$env:USERPROFILE\\knowledge\\.git"; git add -A',
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
    assert.equal(kind(bash('GIT_DIR=~/knowledge/.git GIT_WORK_TREE=~/knowledge git add -A')), 'deny')
    assert.equal(kind(bash('export GIT_DIR=~/knowledge/.git; git add -A')), 'deny')
  })
  it('leaves other repos alone', () => {
    assert.equal(kind(sh('git --git-dir ~/other/.git add -A')), 'allow')
    assert.equal(kind(sh('git --work-tree ~/knowledge status')), 'allow')
    assert.equal(kind(sh('$env:GIT_DIR = "$env:USERPROFILE\\knowledge\\.git"; Remove-Item Env:GIT_DIR; git add -A')), 'allow')
  })
})

describe('review 7: relative paths from another folder', () => {
  it('checks them', () => {
    assert.equal(kind(sh("Add-Content ..\\knowledge\\log.md '* x'", DOCS)), 'deny')
    assert.equal(kind(sh("Set-Content ../knowledge/.githooks/pre-commit 'exit 0'", DOCS)), 'deny')
    assert.equal(kind(sh('"x" > ..\\knowledge\\log.md', DOCS)), 'deny')
  })
})

if (WIN) {
  describe('review 8: a knowledge base set with the short home path', () => {
    it('is still recognized, and the prompt shows no short name', () => {
      const g = createGuard({ knowledgeRoot: 'C:\\Users\\TESTPE~1\\knowledge' }, env)
      const d = g.decide({ name: 'pwsh', arguments: { command: 'git -C ~/knowledge add -A' }, agent: { session: { header: { cwd: OTHER } } } })
      assert.equal(kind(d), 'deny')
      assert.match(g.promptText(), /%USERPROFILE%\\knowledge/)
      assert.doesNotMatch(g.promptText(), /TESTPE~1/i)
    })
    it('learns the short path through update()', () => {
      const g = createGuard({}, { ...env, shortHome: undefined })
      const call = { name: 'pwsh', arguments: { command: 'git -C C:\\Users\\TESTPE~1\\knowledge add -A' }, agent: { session: { header: { cwd: OTHER } } } }
      assert.equal(kind(g.decide(call)), 'allow')
      g.update({ shortHome: SHORT })
      assert.equal(kind(g.decide(call)), 'deny')
    })
  })
}

describe('review 10: folders next to the knowledge base', () => {
  it('are not the knowledge base', () => {
    assert.equal(kind(sh('okf index ~/knowledge-archive')), 'allow')
    assert.equal(kind(sh('Add-Content ~/knowledge-old/log.md x')), 'allow')
    assert.equal(kind(sh('git -C ~/knowledge2 add -A')), 'allow')
  })
})

describe('review 11: pushd and popd', () => {
  it('popd returns to the earlier folder', () => {
    assert.equal(kind(sh('pushd ~/knowledge; git log -1; popd; git add -A')), 'allow')
    assert.equal(kind(sh('Push-Location ~/knowledge; Pop-Location; git add -A')), 'allow')
  })
})

describe('review 12: copy and move', () => {
  it('copying a protected file out is a read', () => {
    assert.equal(kind(sh('Copy-Item ~/knowledge/log.md C:\\tmp\\log.md')), 'allow')
    assert.equal(kind(sh('cp ~/knowledge/log.md /tmp/log.md')), 'allow')
    assert.equal(kind(sh('Copy-Item -Path ~/knowledge/log.md -Destination C:\\tmp')), 'allow')
  })
  it('copying onto or moving a protected file is a write', () => {
    for (const c of [
      'Copy-Item C:\\tmp\\x.md ~/knowledge/log.md',
      'cp x.py ~/knowledge/.kb/kb.py',
      'Move-Item ~/knowledge/log.md C:\\tmp\\',
      'Copy-Item -Destination ~/knowledge/.githooks -Path C:\\tmp\\pre-commit',
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
  })
  it('a verb used as a search word is not a write', () => {
    assert.equal(kind(sh('Select-String -Pattern "del" log.md', KB)), 'allow')
    assert.equal(kind(sh('Get-Content log.md | Select-String copy', KB)), 'allow')
  })
})

describe('review 13: account name in shell writes', () => {
  it('blocks text with the name written into the knowledge base', () => {
    for (const [c, cwd] of [
      ["Add-Content ~/knowledge/projects/a.md 'see C:\\Users\\Test Person\\repo'", OTHER],
      ['"C:\\Users\\Test Person\\x" > projects/a.md', KB],
      ["Set-Content -Path $env:USERPROFILE\\knowledge\\projects\\a.md -Value 'TESTPE~1'", OTHER],
      ['[IO.File]::WriteAllText("$env:USERPROFILE\\knowledge\\projects\\a.md", "Test Person")', OTHER],
    ]) {
      const d = sh(c, cwd)
      assert.equal(kind(d), 'deny', c)
      assert.match(d.reason, /account name/)
    }
  })
  it('ignores the name in the target path and outside the knowledge base', () => {
    for (const c of [
      'Set-Content "C:\\Users\\Test Person\\knowledge\\projects\\a.md" "plain text"',
      'Copy-Item "C:\\Users\\Test Person\\Downloads\\x.md" ~/knowledge/projects/',
      'Add-Content C:\\work\\proj\\notes.md "Test Person"',
      "Add-Content ~/knowledge/projects/a.md 'see %USERPROFILE%\\repo'",
    ]) {
      assert.equal(kind(sh(c)), 'allow', c)
    }
  })
})

describe('review 14: the name matches whole words only', () => {
  const g = createGuard({}, { ...env, privateNames: ['ann'], shortHome: null })
  const edit = (text) =>
    g.decide({ name: 'edit', arguments: { file_path: kb('projects', 'a', 'decisions', 'old.md'), old_string: 'a', new_string: text }, agent: { session: { header: { cwd: OTHER } } } })
  it('does not match inside other words', () => {
    assert.equal(kind(edit('annual review, planned work')), 'allow')
  })
  it('matches the name itself', () => {
    assert.equal(kind(edit("ann's notes")), 'deny')
    assert.equal(kind(edit('C:\\Users\\ann\\x')), 'deny')
  })
})
