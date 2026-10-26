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
const bash = (command, cwd = OTHER) => guard.decide({ name: 'bash', arguments: { command }, agent: { session: { header: { cwd } } } })

describe('command parsing', () => {
  it('splits on ; && || | and newlines, not inside quotes', () => {
    assert.deepEqual(splitSegments('a; b && c || d | e\nf'), ['a', 'b', 'c', 'd', 'e', 'f'])
    assert.deepEqual(splitSegments("git commit -m 'a; b'"), ["git commit -m 'a; b'"])
  })
  it('keeps quoted words with spaces whole', () => {
    assert.deepEqual(words('git -C "C:\\Users\\Test Person\\knowledge" add -A'), ['git', '-C', 'C:\\Users\\Test Person\\knowledge', 'add', '-A'])
  })
  it('joins quoted and unquoted pieces that touch into one word', () => {
    assert.deepEqual(words('Set-Content -Path "~/knowledge/"\'log.md\' -Value x'), ['Set-Content', '-Path', '~/knowledge/log.md', '-Value', 'x'])
    assert.deepEqual(words('a"b c"d'), ['ab cd'])
  })
  it('reads a quote that is never closed as a character', () => {
    assert.deepEqual(splitSegments('echo "x; git add -A'), ['echo "x', 'git add -A'])
  })
})

describe('fix 1: quoting cannot hide a write or a git command', () => {
  it('denies', () => {
    for (const c of [
      'Set-Content -Path "~/knowledge/"\'log.md\'" -Value x',
      'Set-Content -Path "~/knowledge/"\'log.md\' -Value x',
      'Set-Content -Path ~/knowledge/"log".md -Value x',
      'echo "x; git -C ~/knowledge add -A',
      "echo 'it`'; git -C ~/knowledge add -A",
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
    assert.equal(kind(bash('echo \\"; git -C ~/knowledge add -A; echo \\"')), 'deny')
  })
  it('still keeps separators inside closed quotes', () => {
    assert.equal(kind(sh('Write-Output "a; git add -A"', KB)), 'allow')
    assert.equal(kind(bash('echo "a \\" b; git add -A"', KB)), 'allow')
  })
})

describe('fix 2: command substitutions are checked', () => {
  it('denies git and writes inside $( ) and backticks', () => {
    for (const c of [
      'echo "built $(date +%d); git -C ~/knowledge commit -m x"',
      'Write-Host "x $(git -C ~/knowledge commit -m x)"',
      'Write-Host "x $(git -C "~/knowledge" commit -m "y") z"',
      'Write-Output $(cd ~/knowledge; git add -A)',
      'cd $(git -C ~/knowledge commit -m x)',
      `python "$env:USERPROFILE\\knowledge\\.kb\\kb.py" check "$(git -C ~/knowledge add -A)"`,
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
    assert.equal(kind(bash('echo "note `git -C ~/knowledge commit -m x`"')), 'deny')
    assert.equal(kind(bash('echo `git -C ~/knowledge add -A`')), 'deny')
    assert.equal(kind(bash('echo "built `date +%d`"; git -C ~/knowledge commit -m x')), 'deny')
  })
  it('leaves harmless substitutions alone', () => {
    assert.equal(kind(sh('Write-Host "done in $(Get-Date)"', KB)), 'allow')
    assert.equal(kind(bash('echo "today `date +%d`"', KB)), 'allow')
    assert.equal(kind(sh('$x = "git $(git --version)"', KB)), 'allow')
  })
})

describe('fix 3: line continuations', () => {
  it('joins bash \\, PowerShell ` and a newline inside ( )', () => {
    assert.equal(kind(bash('git -C ~/knowledge \\\n  commit -m x')), 'deny')
    assert.equal(kind(bash('git -C ~/knowledge \\\r\n  commit -m x')), 'deny')
    assert.equal(kind(bash('echo "a \\\nb"; git -C ~/knowledge add -A')), 'deny')
    assert.equal(kind(sh('git -C ~/knowledge `\n  commit -m x')), 'deny')
    assert.equal(kind(sh('git -C ~/knowledge `\n  config core.hooksPath .nohooks')), 'deny')
    assert.equal(kind(sh('git -C ~/knowledge `\n  push --force')), 'deny')
    assert.equal(kind(sh('git -C ~/knowledge `\r\n  reset --hard')), 'ask')
    assert.equal(kind(sh('Add-Content -Value "x" `\n -Path "$env:USERPROFILE\\knowledge\\log.md"')), 'deny')
    assert.equal(kind(sh('Write-Output (\n  git -C ~/knowledge add -A)')), 'deny')
  })
  it('still treats other newlines as separators', () => {
    assert.equal(kind(sh('git status\ngit add -A', KB)), 'deny')
    assert.equal(kind(bash('cd ~/knowledge\ngit add -A')), 'deny')
    assert.equal(kind(sh(`cd ~/knowledge\ngit status\ncd "${OTHER}"\ngit add -A`)), 'allow')
  })
})

describe('fix 4: ( ) groups as path values', () => {
  it('reads literal and Join-Path groups', () => {
    for (const c of [
      'git -C (Join-Path $env:USERPROFILE knowledge) commit -m x',
      'git -C ("$env:USERPROFILE\\knowledge") commit -m x',
      'git -C ( "$env:USERPROFILE\\knowledge" ) add -A',
      'git -C (Get-Item ~/knowledge).FullName commit -m x',
      'git -C ("$env:USERPROFILE\\knowledge") config core.hooksPath .nohooks',
      'Set-Location (Join-Path $env:USERPROFILE knowledge); git commit -m x',
      'Add-Content -Path (Join-Path $env:USERPROFILE "knowledge\\log.md") -Value "x"',
      'git -C (\n  "$env:USERPROFILE\\knowledge") commit -m x',
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
    assert.equal(kind(sh('git -C ("$env:USERPROFILE\\knowledge") push')), 'ask')
  })
  it('asks when the group cannot be read', () => {
    for (const c of [
      'git -C (Get-KbPath) commit -m x',
      'git -C $(Get-KbPath) push --force',
      'Set-Location (Get-KbPath); git add -A',
      'Add-Content -Path (Get-KbPath) -Value x',
      'Set-Location (Get-KbPath); Remove-Item log.md',
    ]) {
      assert.equal(kind(sh(c)), 'ask', c)
    }
  })
  it('leaves reads and other folders alone', () => {
    for (const c of [
      'git -C (Get-KbPath) status',
      'git -C (Join-Path C:\\work proj) commit -m x',
      'Set-Location (Get-KbPath); git log -1',
      'Add-Content -Path x.txt -Value (Get-Date)',
      'Write-Output (git log -1)',
      'Copy-Item (Join-Path ~/knowledge log.md) C:\\tmp\\x.md',
    ]) {
      assert.equal(kind(sh(c)), 'allow', c)
    }
  })
})

describe('fix 5: the knowledge base folder itself', () => {
  it('cannot be deleted, moved or renamed', () => {
    for (const c of [
      'Remove-Item ~/knowledge -Recurse -Force',
      'Remove-Item ~\\knowledge\\ -Recurse',
      'Remove-Item -Recurse -Force "$env:USERPROFILE\\knowledge"',
      'Move-Item ~/knowledge ~/knowledge.bak',
      'Rename-Item ~/knowledge knowledge-old',
      'rm -rf ~/knowledge',
      '[IO.Directory]::Delete("$env:USERPROFILE\\knowledge", $true)',
    ]) {
      const d = sh(c)
      assert.equal(kind(d), 'deny', c)
      assert.match(d.reason, /folder itself/, c)
    }
    assert.equal(kind(file('write', { file_path: KB, content: 'x' })), 'deny')
  })
  it('copying into it and naming it in text are fine', () => {
    assert.equal(kind(sh(`Copy-Item -Recurse C:\\tmp\\template\\* ${KB}`)), 'allow')
    assert.equal(kind(sh("Set-Content ~/knowledge/projects/a.md -Value '%USERPROFILE%\\knowledge'")), 'allow')
    assert.equal(kind(sh('Get-ChildItem ~/knowledge')), 'allow')
  })
})

describe('fix 6: recursive deletes in the knowledge base', () => {
  it('deny when they take protected files along', () => {
    for (const [c, cwd] of [
      ['rm -rf .', KB],
      ['rm -rf *', KB],
      ['rm -rf ~/knowledge/*', OTHER],
      ['Remove-Item -Recurse -Force .', KB],
      ['Remove-Item -Recurse -Force *', KB],
      ['cd ~/knowledge; rm -rf .', OTHER],
      ['cd ~/knowledge; Remove-Item -Recurse -Force *', OTHER],
      ['cmd /c "rd /s /q ."', KB],
      ['Move-Item ~/knowledge/* ~/Documents/kb-bak/', OTHER],
      ['rm -rf .kb', KB],
      ['rm log.md', KB],
      ['Remove-Item -Recurse .githooks', KB],
    ]) {
      assert.equal(kind(sh(c, cwd)), 'deny', c)
    }
  })
  it('deny for a folder that holds a log.md', () => {
    const g = createGuard({ knowledgeRoot: '~/knowledge' }, { ...env, exists: (p) => p.toLowerCase() === kb('projects', 'log.md').toLowerCase() })
    const d = g.decide({ name: 'pwsh', arguments: { command: 'Remove-Item -Recurse projects' }, agent: { session: { header: { cwd: KB } } } })
    assert.equal(kind(d), 'deny')
  })
  it('ask for other folders and wildcards', () => {
    for (const c of ['rm -rf projects', 'Remove-Item -Recurse -Force projects', 'rm -r projects/a', 'Remove-Item projects/a/*.md']) {
      assert.equal(kind(sh(c, KB)), 'ask', c)
    }
  })
  it('leave single files, moves into the folder and other folders alone', () => {
    for (const [c, cwd] of [
      ['rm projects/a.md', KB],
      ['Remove-Item -Force projects/a.md', KB],
      ['Move-Item C:\\tmp\\x.md .', KB],
      ['rm -rf build', OTHER],
      ['Remove-Item -Recurse -Force *', OTHER],
    ]) {
      assert.equal(kind(sh(c, cwd)), 'allow', c)
    }
  })
})

describe('fix 7: git commands that change files without a commit', () => {
  it('deny git mv of protected paths', () => {
    for (const c of ['git mv .githooks/pre-commit .githooks/old', 'git mv log.md notes/log.md', 'git mv .kb/kb.py .kb/kb2.py', 'git mv .gitattributes x', 'git mv -- projects/a.md .kb/a.md']) {
      assert.equal(kind(sh(c, KB)), 'deny', c)
    }
    assert.equal(kind(sh('bash -c "git mv .githooks/pre-commit .githooks/old"', KB)), 'deny')
    assert.equal(kind(sh('git -C ~/knowledge mv log.md old.md')), 'deny')
  })
  it('ask for other git mv, git apply and stash apply', () => {
    for (const c of ['git mv projects/a.md projects/b.md', 'git apply kb.patch', 'git stash apply', 'git stash pop', 'git read-tree -u HEAD', 'git checkout-index -a -f']) {
      assert.equal(kind(sh(c, KB)), 'ask', c)
    }
  })
  it('allow checks and other repos', () => {
    assert.equal(kind(sh('git apply --check kb.patch', KB)), 'allow')
    assert.equal(kind(sh('git apply --stat kb.patch', KB)), 'allow')
    assert.equal(kind(sh('git stash list', KB)), 'allow')
    assert.equal(kind(sh('git mv a.md b.md', OTHER)), 'allow')
  })
})

if (WIN) {
  describe('fix 8: the knowledge base spelled with its own 8.3 name', () => {
    const SHORT_ROOT = `${SHORT}\\KNOWLE~1`
    const at = (g, command, cwd = OTHER) => g.decide({ name: 'pwsh', arguments: { command }, agent: { session: { header: { cwd } } } })
    it('is recognized when detection found the short root', () => {
      const g = createGuard({ knowledgeRoot: '~/knowledge' }, { ...env, shortRoot: SHORT_ROOT })
      assert.equal(kind(at(g, `git -C ${SHORT_ROOT} commit -m x`)), 'deny')
      assert.equal(kind(at(g, `Add-Content ${SHORT_ROOT}\\log.md x`)), 'deny')
      assert.equal(kind(at(g, 'git commit -m x', SHORT_ROOT)), 'deny')
      assert.equal(kind(at(g, `Add-Content "${HOME}\\KNOWLE~1\\log.md" x`)), 'deny')
      assert.equal(kind(at(g, `git -C ${SHORT}\\OTHER~1 commit -m x`)), 'allow')
    })
    it('is recognized by shape below the home folder', () => {
      assert.equal(kind(sh(`git -C ${SHORT_ROOT} commit -m x`)), 'deny')
      assert.equal(kind(sh(`Remove-Item ${SHORT_ROOT}\\.kb\\* -Recurse`)), 'deny')
      assert.equal(kind(sh(`git -C ${SHORT_ROOT} reset --hard`)), 'ask')
      assert.equal(kind(file('write', { file_path: `${SHORT_ROOT}\\log.md`, content: 'x' })), 'deny')
    })
    it('works when the configured root is the short one', () => {
      const g = createGuard({ knowledgeRoot: SHORT_ROOT }, env)
      assert.equal(kind(at(g, 'git -C ~/knowledge add -A')), 'deny')
      assert.equal(kind(at(g, `git -C ${SHORT_ROOT} add -A`)), 'deny')
    })
    it('learns the short root through update()', () => {
      const g = createGuard({}, { ...env, shortHome: undefined })
      const call = `git -C ${SHORT_ROOT} add -A`
      assert.equal(kind(at(g, call)), 'allow')
      g.update({ shortRoot: SHORT_ROOT })
      assert.equal(kind(at(g, call)), 'deny')
    })
  })
}

describe('fix 9: kb.privateName', () => {
  it('asks before an agent changes it, anywhere', () => {
    for (const [c, cwd] of [
      ['git config kb.privateName "the"', OTHER],
      ['git config --global kb.privateName "the"', OTHER],
      ['git config --global --add kb.privateName x', OTHER],
      ['git config --unset-all kb.privateName', KB],
      ['git config set kb.privateName x', KB],
      ['git config --remove-section kb', KB],
      ['git -C ~/knowledge config kb.privateName x', OTHER],
    ]) {
      assert.equal(kind(sh(c, cwd)), 'ask', c)
    }
  })
  it('lets reads through', () => {
    for (const c of ['git config kb.privateName', 'git config --get-all kb.privateName', 'git config get kb.privateName', 'git config --list']) {
      assert.equal(kind(sh(c, KB)), 'allow', c)
    }
  })
  it('ignores names too short to match safely', () => {
    const g = createGuard({}, { ...env, privateNames: ['a b', 'xy'], shortHome: null })
    const d = g.decide({ name: 'edit', arguments: { file_path: kb('projects', 'a', 'decisions', 'old.md'), old_string: 'a', new_string: 'ab and xy here' }, agent: { session: { header: { cwd: OTHER } } } })
    assert.equal(kind(d), 'allow')
  })
})

describe('fix 10: setup lines are for the user', () => {
  it('the deny reasons say so', () => {
    const hooks = sh('git -C ~/knowledge config core.hooksPath .githooks')
    assert.equal(kind(hooks), 'deny')
    assert.match(hooks.reason, /ask the user to run this in a terminal/)
    assert.doesNotMatch(hooks.reason, /Test Person/)
    const add = sh('git -C ~/knowledge add -A')
    assert.equal(kind(add), 'deny')
    assert.match(add.reason, /for the user to run in a terminal, not for an agent/)
  })
})

describe('fix 11: okf commands that name a concept by path', () => {
  const old = kb('projects', 'a', 'decisions', 'old.md')
  it('are checked from any folder', () => {
    for (const c of [
      `okf rm "${old}" --force`,
      `okf mv "${old}" C:\\tmp\\y.md`,
      `okf merge "${old}" projects/a/decisions/new.md`,
      `okf split "${old}"`,
      `okf rename "${old}" new-name`,
      `okf delete "${old}"`,
      `okf merge-concepts "${old}" x`,
      `okf studio "${KB}"`,
      'okf rm ~/knowledge/projects/a/decisions/old.md',
    ]) {
      assert.equal(kind(sh(c, OTHER)), 'deny', c)
    }
    assert.equal(kind(sh(`okf rm "${old}" --no-index --no-log`, OTHER)), 'ask')
  })
  it('leave other bundles alone', () => {
    assert.equal(kind(sh('okf rm C:\\other\\x.md', OTHER)), 'allow')
    assert.equal(kind(sh('okf rm projects/a/x', OTHER)), 'allow')
    assert.equal(kind(sh(`okf rm "${old}" --dry-run`, OTHER)), 'allow')
  })
})

describe('fix 12: long commands stay cheap', () => {
  const timed = (fn) => {
    const t = performance.now()
    const d = fn()
    return [d, performance.now() - t]
  }
  it('asks for a command over 64 KB, quickly', () => {
    const [d, ms] = timed(() => sh('git status '.repeat(10000), KB))
    assert.equal(kind(d), 'ask')
    assert.match(d.reason, /command too long to check; split it/)
    assert.ok(ms < 500, `${ms} ms`)
  })
  it('checks a long command in linear time', () => {
    for (const [cmd, cwd] of [
      ['git status '.repeat(5800), KB],
      ['(git status) '.repeat(4800), KB],
      [`Add-Content ${'~/knowledge/projects/a.md '.repeat(2400)}`, OTHER],
      ['sed '.repeat(16000), KB],
      ['$('.repeat(32000), KB],
      [`"${'$(a) '.repeat(13000)}"`, KB],
    ]) {
      const [d, ms] = timed(() => sh(cmd, cwd))
      assert.notEqual(kind(d), 'deny')
      assert.ok(ms < 1000, `${cmd.slice(0, 20)}: ${ms} ms`)
    }
  })
  it('still finds a later git command and the name in written text', () => {
    assert.equal(kind(sh(`${'git status '.repeat(3000)}; git add -A`, KB)), 'deny')
    assert.equal(kind(sh('(git status) (git add -A)', KB)), 'deny')
    assert.equal(kind(sh(`Add-Content ~/knowledge/projects/a.md ~/knowledge/projects/a.md 'Test Person'`)), 'deny')
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
