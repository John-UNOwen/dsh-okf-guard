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

describe('variables in paths', () => {
  // The command that full-access sessions saw refused: variables built with Join-Path, a value group, git -C $u.
  const trigger = (repo) =>
    [
      "$lines = @('bin/', 'obj/')",
      `$repo = '${repo}'`,
      "$u  = Join-Path $repo 'build\\unity-project'",
      "$gi = Join-Path $u '.gitignore'",
      'Set-Content $gi ($lines -join "`r`n") -Encoding utf8',
      'git -C $u add .gitignore',
      "git -C $u commit -m 'ignore build output'",
    ].join('\n')

  it('lets the reported command through when the variables point outside', () => {
    assert.equal(kind(sh(trigger('~\\Documents\\GitHub\\mfg-decomp'))), 'allow')
    assert.equal(kind(sh(trigger('C:\\work\\proj'))), 'allow')
  })
  it('treats the same command inside the knowledge base like a literal path', () => {
    assert.equal(kind(sh(trigger('~\\knowledge'))), 'deny')
    assert.equal(kind(sh(trigger('~\\knowledge\\projects\\a'))), 'deny')
  })
  it('reads $name, "$name\\x", ${name} and Join-Path forms', () => {
    for (const c of [
      "$k = '~\\knowledge'\nSet-Content $k\\log.md x",
      "$k = '~\\knowledge'\nSet-Content \"$k\\log.md\" x",
      "$k = '~\\knowledge'\nSet-Content \"${k}\\log.md\" x",
      "$k = '~\\knowledge'\nSet-Content ${k}\\log.md x",
      "${k} = '~\\knowledge'\nSet-Content \"$k\\log.md\" x",
      "$k = '~\\knowledge'\n$f = Join-Path $k 'log.md'\nSet-Content $f x",
      "$k = '~\\knowledge'\n$f = (Join-Path $k 'log.md')\nAdd-Content -Path $f -Value x",
      "$k = '~\\knowledge'\n$f = \"$k\\.kb\\kb.py\"\nSet-Content -Path $f -Value x",
      "$k = '~\\knowledge'\n$j = $k\ngit -C $j commit -m x",
      "$k = \"$env:USERPROFILE\\knowledge\"; git -C $k add -A",
      '$k = Join-Path $HOME knowledge; git -C $k commit -m x',
      "$k = '~/knowledge'; git -C \"$k\" commit -m x",
      "$k = '~\\knowledge'; Set-Location $k; git commit -m x",
      "$k = '~\\knowledge'; Push-Location $k; git add -A",
      "$k = '~\\knowledge'; cd $k; git commit -m x",
      "$g = '~\\knowledge\\.git'; $env:GIT_DIR = $g; git commit -m x",
      "$k = '~\\knowledge'; \"x\" > \"$k\\log.md\"",
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
  })
  it('uses the last value of a reassigned variable', () => {
    assert.equal(kind(sh("$k = '~\\knowledge'\n$k = 'C:\\work\\proj'\ngit -C $k commit -m x")), 'allow')
    assert.equal(kind(sh("$k = 'C:\\work\\proj'\n$k = '~\\knowledge'\ngit -C $k commit -m x")), 'deny')
    assert.equal(kind(sh("$k = 'C:\\work'\n$k = Join-Path $k 'proj'\ngit -C $k commit -m x")), 'allow')
  })
  it('applies the inside rules to a resolved path', () => {
    assert.equal(kind(sh("$f = '~\\knowledge\\projects\\a\\decisions\\old.md'\nAdd-Content $f 'Test Person was here'")), 'deny')
    assert.equal(kind(sh("$f = '~\\knowledge\\projects\\a\\decisions\\old.md'\nAdd-Content $f 'a fact'")), 'allow')
    assert.equal(kind(sh("$d = '~\\knowledge\\projects\\a'\nRemove-Item $d -Recurse")), 'ask')
    assert.equal(kind(sh("$d = '~\\knowledge'\nRemove-Item $d -Recurse -Force")), 'deny')
    assert.equal(kind(sh("$k = '~\\knowledge'\ngit -C $k status")), 'allow')
  })
  it('asks when a variable is set where its value cannot be followed', () => {
    for (const c of [
      "if ($x) { $k = '~\\knowledge' }\ngit -C $k commit -m x",
      "$k = 'C:\\work\\proj'\nif ($x) {\n  $k = '~\\knowledge'\n}\ngit -C $k commit -m x",
      "$k = 'C:\\work\\proj'\ntry {\n  $k = '~\\knowledge'\n} catch {}\ngit -C $k commit -m x",
      'foreach ($k in $dirs) { git -C $k commit -m x }',
      'foreach ($k in (Get-ChildItem C:\\work)) {\n  git -C $k commit -m x\n}',
      "foreach ($k in @('C:\\work\\proj', $other)) { git -C $k commit -m x }",
      "@('C:\\work\\proj') | ForEach-Object { $k = $_ }\ngit -C $k commit -m x",
      '$k = $(Get-KbPath)\ngit -C $k commit -m x',
      '$k = (Get-KbPath)\ngit -C $k commit -m x',
      '$k = Get-ChildItem ~ -Filter knowledge\ngit -C $k commit -m x',
      "$k = Get-Item ~\\knowledge\ngit -C $k.FullName commit -m x",
      "$k = 'C:\\work\\proj' | Out-String\ngit -C $k commit -m x",
      "$k = 'C:\\work\\proj'\n$null = $($k = '~\\knowledge')\ngit -C $k commit -m x",
      "$k = 'C:\\work\\proj'\nSet-Variable k '~\\knowledge'\ngit -C $k commit -m x",
      "$k = 'C:\\work\\proj'\n. .\\setup.ps1\ngit -C $k commit -m x",
      "$k = 'C:\\work\\proj'\nGet-Item x -OutVariable k\ngit -C $k commit -m x",
      "[string]$k = 'C:\\work\\proj'\ngit -C $k commit -m x",
      "$a, $k = 'x', 'C:\\work\\proj'\ngit -C $k commit -m x",
      "$k = 'C:\\work'\n$k += '\\proj'\ngit -C $k commit -m x",
      'git -C $nowhere commit -m x',
      'Set-Content $nowhere x',
      'Set-Content "$nowhere\\log.md" x',
      "$k = '~\\knowledge'\npwsh -c \"git -C $k commit -m x\"",
    ]) {
      assert.equal(kind(sh(c)), 'ask', c)
    }
  })
  it('leaves reads, other folders and plain values alone', () => {
    for (const c of [
      'git -C $nowhere status',
      'git -C $nowhere log -1',
      "Set-Content 'C:\\work\\proj\\x.txt' ($lines -join ',')",
      "Set-Content -Path C:\\work\\proj\\x.txt -Value ($lines -join ',')",
      "$k = '~\\knowledge'\nSet-Content '$k\\log.md' x",
      "$t = 'some text'\nSet-Content C:\\work\\proj\\x.txt $t",
      "$x = 1\n$x++\nWrite-Output $x",
    ]) {
      assert.equal(kind(sh(c)), 'allow', c)
    }
  })
  it('keeps a name set in a function, scriptblock or block unknown for the rest of the command', () => {
    const safe = "$k = 'C:\\work\\proj'\n"
    const use = '\ngit -C $k commit -m x'
    for (const c of [
      "function f { $script:k = '~\\knowledge' }\n" + safe + 'f' + use,
      "function f {\n  $global:k = '~\\knowledge'\n}\n" + safe + 'f' + use,
      "$sb = { $script:k = '~\\knowledge' }\n" + safe + '& $sb' + use,
      // Set in a loop or an if: it may or may not have happened once the block closes.
      "foreach ($i in 1..2) { $k = '~\\knowledge' }" + use,
      safe + "if ($x) { $k = '~\\knowledge' }" + use,
      safe + "if ($x) { $k = '~\\knowledge' } else { $k = 'C:\\work\\b' }" + use,
    ]) {
      assert.equal(kind(sh(c)), 'ask', c)
    }
    // A loop is not a function: a plain assignment after it holds.
    assert.equal(kind(sh("foreach ($i in 1..2) { $k = '~\\knowledge' }\n" + safe.trim() + use)), 'allow')
  })
  it('checks a loop over a literal list once per value', () => {
    // The command full-access sessions saw refused: a foreach over version strings, writing tools\upstream\fb-$v.js.
    const fetch =
      "cd 'C:\\work\\proj'; New-Item -ItemType Directory -Force -Path 'tools\\upstream' | Out-Null; " +
      "foreach ($v in '0.13.1','0.13.0','0.14.0') { try { $r = Invoke-WebRequest -Uri \"https://unpkg.com/x@$v/dist/index.js\" -UseBasicParsing; " +
      '$b = $r.Content; [System.IO.File]::WriteAllBytes("tools\\upstream\\fb-$v.js", $b); ' +
      '$h = (Get-FileHash -LiteralPath "tools\\upstream\\fb-$v.js").Hash } catch { Write-Host $_ } }'
    for (const c of [
      fetch,
      "foreach ($k in @('C:\\work\\proj')) { git -C $k commit -m x }",
      "foreach ($k in 'C:\\work\\a', 'C:\\work\\b') {\n  git -C $k commit -m x\n}",
      "foreach ($n in 1..3) { Set-Content \"C:\\work\\proj\\part$n.txt\" x }",
      "foreach ($f in 'a.md','b.md') { foreach ($d in 'x','y') { Set-Content \"C:\\work\\$d\\$f\" z } }",
    ]) {
      assert.equal(kind(sh(c)), 'allow', c)
    }
    for (const c of [
      "foreach ($k in 'C:\\work\\proj', '~\\knowledge') { git -C $k commit -m x }",
      "foreach ($f in 'notes.md','log.md') { Set-Content \"~\\knowledge\\$f\" x }",
      "foreach ($n in 1..3) { Add-Content \"~\\knowledge\\projects\\a\\decisions\\old.md\" \"Test Person $n\" }",
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
    // A loop variable set again inside the body is unknown. cd to it is followed per value.
    assert.equal(kind(sh("foreach ($k in 'C:\\work\\proj') { $k = Get-KbPath; git -C $k commit -m x }")), 'ask')
    assert.equal(kind(sh("foreach ($k in 'C:\\work\\proj') { cd $k; git commit -m x }")), 'allow')
    assert.equal(kind(sh("foreach ($k in 'C:\\work\\proj', '~\\knowledge') { cd $k; git commit -m x }")), 'ask')
    assert.equal(kind(bash('for k in /work/a /work/b; do git -C "$k" commit -m x; done')), 'allow')
    assert.equal(kind(bash('for k in /work/a "$HOME/knowledge"; do git -C "$k" commit -m x; done')), 'ask')
  })
  it('follows cd inside a block only between folders outside the knowledge base', () => {
    assert.equal(kind(sh('if ($x) { cd ~\\knowledge; git commit -m x }')), 'ask')
    // On its own line the cd starts its segment and is followed as written: the stricter answer.
    assert.equal(kind(sh('if ($x) {\n  Set-Location ~\\knowledge\n}\ngit add -A')), 'deny')
    assert.equal(kind(sh("try { Set-Location 'C:\\work\\a'; git commit -m x } finally { }")), 'allow')
    assert.equal(kind(sh('try { Push-Location ~\\knowledge; git log -1 } finally { Pop-Location }')), 'allow')
  })
  it('notices variable setters anywhere a command starts', () => {
    const safe = "$k = 'C:\\work\\proj'\n"
    const use = '\ngit -C $k commit -m x'
    for (const c of [
      safe + "if ($true) { Set-Variable k '~\\knowledge' }" + use,
      safe + "$null = Set-Variable k '~\\knowledge' -PassThru" + use,
      safe + "'~\\knowledge' | Tee-Object -Variable k" + use,
      safe + "'~\\knowledge' | Tee-Object -Var k" + use,
      safe + "Get-Item ~\\knowledge -OutVar k" + use,
    ]) {
      assert.equal(kind(sh(c)), 'ask', c)
    }
    assert.equal(kind(bash('k=/work/proj; while read k; do git -C "$k" commit -m x; done')), 'ask')
    assert.equal(kind(bash('k=/work/proj; printf -v k %s ~/knowledge; git -C "$k" commit -m x')), 'ask')
    assert.equal(kind(bash('k=/work/proj; mapfile k < list; git -C "$k" commit -m x')), 'ask')
    assert.equal(kind(sh(safe + 'git add .' + "\n$k = 'C:\\work\\proj'" + use)), 'allow')
  })
  it('ignores # comments', () => {
    // A } in a comment does not close the block, so the assignment inside the if stays unknown.
    assert.equal(kind(sh("$k = '~\\knowledge'\nif ($x) { # close with }\n  $k = 'C:\\work\\proj'\n}\ngit -C $k commit -m x")), 'ask')
    assert.equal(kind(sh("$k = 'C:\\work\\proj'\n# $k = '~\\knowledge'\ngit -C $k commit -m x")), 'allow')
    assert.equal(kind(sh("$k = 'C:\\work\\proj'\n<# $k = '~\\knowledge' #>\ngit -C $k commit -m x")), 'allow')
    assert.equal(kind(sh("$repo = 'C:\\work\\proj'  # the repo\ngit -C $repo commit -m x")), 'allow')
    assert.equal(kind(sh("$k = '~\\knowledge'  # the knowledge base\ngit -C $k commit -m x")), 'deny')
    assert.equal(kind(sh("$k = 'C:\\work\\a #b'\ngit -C $k commit -m x")), 'allow')
    assert.equal(kind(bash('k=/work/proj # the repo\ngit -C "$k" commit -m x')), 'allow')
  })
  it('counts content-verb positionals past parameters it does not know', () => {
    const inA = kb('projects', 'a')
    for (const c of [
      "$f = 'notes'\nOut-File -Width 200 $f -InputObject 'Test Person'",
      "$f = 'notes'\nNew-Item -Type File $f -Value 'Test Person'",
      "$f = 'notes'\nSet-Content -Bogus 1 $f 'Test Person'",
      "$f = 'notes'\nSet-Content -Bogus $f 'Test Person'",
    ]) {
      assert.equal(kind(sh(c, inA)), 'deny', c)
    }
    assert.equal(kind(sh("$f = 'notes'\n$t = 'Test Person'\nSet-Content -Force $f $t", OTHER)), 'allow')
  })
  it('follows bash assignments the same way', () => {
    assert.equal(kind(bash('k=~/knowledge; git -C "$k" commit -m x')), 'deny')
    assert.equal(kind(bash('k=~/knowledge; echo x > "${k}/log.md"')), 'deny')
    assert.equal(kind(bash('k=/work/proj; git -C "$k" commit -m x')), 'allow')
    assert.equal(kind(bash('k=/work/proj; true && k=~/knowledge; git -C "$k" commit -m x')), 'ask')
    assert.equal(kind(bash('for k in ~/knowledge; do git -C "$k" commit -m x; done')), 'ask')
    assert.equal(kind(bash('k=/work/proj\nif true; then\n  k=~/knowledge\nfi\ngit -C "$k" commit -m x')), 'ask')
    assert.equal(kind(bash('k=$(pwd); git -C "$k" commit -m x')), 'ask')
  })
})

describe('variable review: harmless commands pass, writes into the knowledge base are still caught', () => {
  const environ = { TEMP: 'C:\\Temp', LOCALAPPDATA: `${HOME}\\AppData\\Local`, TMPDIR: '/tmp' }
  const g = createGuard({ knowledgeRoot: '~/knowledge' }, { ...env, environ })
  const run = (name, command, cwd = OTHER) => g.decide({ name, arguments: { command }, agent: { session: { header: { cwd } } } })
  const ps = (c, cwd) => kind(run('pwsh', c, cwd))
  const sb = (c, cwd) => kind(run('bash', c, cwd))
  const expect = (want, list, check = ps) => {
    for (const c of list) assert.equal(check(c), want, c)
  }

  it('1: follows variables set inside a block, and forgets them when it closes', () => {
    expect('allow', [
      "foreach ($v in 'a','b') { $p = \"C:\\work\\out\\$v.txt\"; Set-Content -LiteralPath $p -Value 1 }",
      "try {\n  $repo = 'C:\\work\\proj'\n  git -C $repo commit -m x\n} catch { Write-Host $_ }",
      "foreach ($v in 'a','b')\n{\n  $p = \"C:\\work\\$v\"\n  git -C $p commit -m x\n}",
      "if ($x) { $d = 'C:\\work\\a'; git -C $d commit -m x }",
    ])
    expect('deny', [
      "foreach ($v in 'a','log') { $p = \"~\\knowledge\\$v.md\"; Set-Content -LiteralPath $p -Value 1 }",
      "foreach ($v in 'a','b')\n{\n  $p = '~\\knowledge'\n  git -C $p add -A\n}",
    ])
    expect('ask', [
      // Used before it is set in the body: the second pass sees the value from the first.
      "$p = 'C:\\work\\x'\nforeach ($i in 1..2) {\n  git -C $p commit -m x\n  $p = '~\\knowledge'\n}",
      "try {\n  $repo = 'C:\\work\\proj'\n} catch { }\n$repo = $repo\ngit -C $repo commit -m x",
    ])
    assert.equal(sb('for f in a b; do d=/work/$f; git -C "$d" commit -m x; done'), 'allow')
    assert.equal(sb('d="$HOME/knowledge"\nif true; then\n  d=/work/a\nelse\n  git -C "$d" add -A\nfi'), 'ask')
  })

  it('2: reads a list held in a variable', () => {
    expect('allow', [
      "$versions = @('0.13.1','0.14.0')\nforeach ($v in $versions) { Set-Content \"C:\\work\\fb-$v.js\" 1 }",
      "$versions = '0.13.1','0.14.0'\nforeach ($v in $versions) { Set-Content \"C:\\work\\fb-$v.js\" 1 }",
    ])
    expect('deny', [
      "$names = 'a.md','log.md'\nforeach ($n in $names) { Set-Content \"~\\knowledge\\$n\" x }",
      "$files = '~\\knowledge\\a.md','~\\knowledge\\log.md'\nSet-Content $files x",
    ])
  })

  it('3: follows Pop-Location in finally and cd to each value of a loop', () => {
    expect('allow', [
      "foreach ($d in 'C:\\work\\a','C:\\work\\b') { Push-Location $d; git commit -m x; Pop-Location }",
      "try { Push-Location ~\\knowledge; git log -1 } finally { Pop-Location }\ngit commit -m x",
      "foreach ($d in 'C:\\work\\a','C:\\work\\b') { cd $d; cd sub; git commit -m x }",
    ])
    expect('ask', [
      "foreach ($d in 'C:\\work\\a','C:\\work\\b') { cd $d; cd ..\\..; git commit -m x }",
      "foreach ($d in 'C:\\work\\a','C:\\Users') { cd $d; git commit -m x }",
    ])
    assert.equal(ps('Push-Location ~/knowledge; try { git add -A } finally { Pop-Location }'), 'deny')
  })

  it('4: reads environment variables, $PWD and $PSScriptRoot', () => {
    expect('allow', [
      'Set-Content "$env:TEMP\\probe.txt" 1',
      "$d = Join-Path $env:LOCALAPPDATA 'tool'\nNew-Item -ItemType Directory -Force -Path $d",
      'Set-Content "$PWD\\out.txt" 1',
      'Set-Content (Join-Path $PSScriptRoot out.txt) 1',
    ])
    assert.equal(ps('Set-Content "$PWD\\log.md" x', KB), 'deny')
    assert.equal(ps("$env:TEMP = '~\\knowledge'\nSet-Content \"$env:TEMP\\log.md\" x"), 'deny')
    assert.equal(ps("if ($x) { $env:TEMP = '~\\knowledge' }\nSet-Content \"$env:TEMP\\log.md\" x"), 'ask')
    assert.equal(ps('Set-Content "$env:NOT_SET_ANYWHERE\\log.md" x'), 'ask')
    assert.equal(sb('echo x > "$TMPDIR/a.txt"'), 'allow')
  })

  it('5: gives $_ each value of a literal list piped to ForEach-Object', () => {
    expect('allow', [
      "'a','b' | ForEach-Object { Set-Content \"C:\\work\\$_.txt\" 1 }",
      "'a','b' | % { Set-Content \"C:\\work\\$_.txt\" 1 }",
      "$names = 'a','b'\n$names | ForEach-Object {\n  Set-Content \"C:\\work\\$PSItem.txt\" 1\n}",
    ])
    assert.equal(ps("'a.md','log.md' | ForEach-Object { Set-Content \"~\\knowledge\\$_\" x }"), 'deny')
    assert.equal(ps('Get-ChildItem C:\\work | ForEach-Object { Set-Content "$_\\log.md" x }'), 'ask')
  })

  it('6: reads "$($name)"', () => {
    assert.equal(ps("$repo = 'C:\\work\\proj'\nSet-Content \"$($repo)\\x.txt\" 1"), 'allow')
    assert.equal(ps("$k = '~\\knowledge'\nSet-Content \"$($k)\\log.md\" x"), 'deny')
    assert.equal(ps('Set-Content "$($x.Path)\\log.md" x'), 'ask')
  })

  it('7: reads a here-string as one quoted value', () => {
    assert.deepEqual(splitSegments("$t = @'\nIt's { a; b\n'@\nSet-Content x $t"), ["$t = @'\nIt's { a; b\n'@", 'Set-Content x $t'])
    assert.deepEqual(splitSegments("$t = @'\nnever closed\ngit status"), ["$t = @'", 'never closed', 'git status'])
    assert.equal(ps("$text = @'\nIt's a note { with braces\n'@\n$f = 'C:\\work\\note.txt'\nSet-Content -LiteralPath $f -Value $text"), 'allow')
    assert.equal(ps('$t = @"\nhello "there"\n"@\nSet-Content ~\\knowledge\\log.md $t'), 'deny')
  })

  it('8: checks downloads, unpacked archives and splatted writes', () => {
    expect('deny', [
      'Invoke-WebRequest -Uri https://x/y -OutFile ~\\knowledge\\log.md',
      'Invoke-WebRequest https://x/y -OutFile:~\\knowledge\\.kb\\kb.py',
      'Expand-Archive C:\\x\\a.zip -DestinationPath ~\\knowledge -Force',
      'Expand-Archive C:\\x\\a.zip ~\\knowledge',
    ])
    expect('ask', [
      'Expand-Archive C:\\x\\a.zip -DestinationPath ~\\knowledge\\projects\\new',
      'Invoke-WebRequest https://x/y -OutFile $nowhere',
      "$p = @{ Path = '~\\knowledge\\log.md'; Value = 'x' }\nSet-Content @p",
    ])
    expect('allow', ['Invoke-WebRequest -Uri https://x -OutFile C:\\work\\a.zip', 'Expand-Archive C:\\x\\a.zip -DestinationPath C:\\work\\a'])
    expect('deny', ['curl -o ~/knowledge/.kb/kb.py https://x', 'tar -xzf a.tgz -C ~/knowledge', 'wget -O ~/knowledge/log.md https://x', 'unzip a.zip -d ~/knowledge'], sb)
    expect('allow', ['curl -sSLo /tmp/x https://x', 'tar -czf /tmp/kb.tgz -C ~/knowledge .', 'curl https://x', 'wget https://x/a.zip'], sb)
    assert.equal(sb('wget https://x/a.zip', KB), 'deny')
  })

  it('9: joins New-Item -Name to its folder and Rename-Item -NewName to the old folder', () => {
    expect('deny', [
      'New-Item -Path ~\\knowledge -Name log.md -ItemType File -Force',
      'New-Item -Path ~\\knowledge\\.kb -Name x.py -ItemType File',
      'Rename-Item ~\\knowledge\\projects\\a.md -NewName log.md',
      'Rename-Item ~\\knowledge\\projects\\a.md log.md',
    ])
    assert.equal(ps('New-Item -Name log.md -ItemType File', KB), 'deny')
    expect('allow', ['New-Item -Path C:\\work -Name log.md -ItemType File', 'Rename-Item C:\\work\\a.md -NewName log.md'])
  })

  it('10: follows cd - and cd + back into the knowledge base', () => {
    assert.equal(ps('cd ~\\knowledge; cd C:\\work; cd -; git commit -m x'), 'deny')
    assert.equal(ps('cd C:\\work\\a; cd ~\\knowledge; cd -; git commit -m x'), 'allow')
    assert.equal(ps('cd ~\\knowledge; cd C:\\work; cd -; cd +; git commit -m x'), 'allow')
    assert.equal(ps('cd -; git commit -m x'), 'ask')
    assert.equal(sb('cd ~/knowledge; cd /work; cd -; git add -A'), 'deny')
  })
})

describe('a bash script passed in a pwsh string', () => {
  const B = "$b='C:\\Program Files\\Git\\bin\\bash.exe'\n"
  it('reads > inside quotes as text, not a redirect', () => {
    // The reported command: a bash script in a here-string, writing to "$S/..." under a scratch folder.
    const reported =
      "$ProgressPreference='SilentlyContinue'\n" + B + "& $b -c @'\nset -e\nS=/c/mfgtmp/lane_kit_test\nrm -rf \"$S\"\n" +
      "mkdir -p \"$S/core\" \"$S/sec\"\nprintf '%s\\n' 'port=18083' '[mfg@asphyxia]' > \"$S/core/config.ini\"\n" +
      "printf 'x\\n' > \"$S/sec/presenter.secret\"\nchmod 600 \"$S/sec/presenter.secret\"\nls -l \"$S/sec\"\n'@\n\"setup exit $LASTEXITCODE\""
    for (const c of [
      reported,
      B + "& $b -c 'S=/c/x; printf a > \"$S/f\"'",
      "& 'C:\\Program Files\\Git\\bin\\bash.exe' -c @'\nS=/c/x\nprintf a > \"$S/f\"\n'@",
      'Write-Output "a > $x"',
      "git commit -m 'speed > 2x'",
    ]) {
      assert.equal(kind(sh(c)), 'allow', c)
    }
  })
  it('checks the script as bash, also when the program is in a variable', () => {
    for (const c of [
      B + "& $b -c @'\nS=~/knowledge\nprintf a > \"$S/log.md\"\n'@",
      B + "& $b -c 'cd ~/knowledge && git add -A'",
      "& 'C:\\Program Files\\Git\\bin\\bash.exe' -c 'echo x > ~/knowledge/log.md'",
      'cmd /c "echo x > ~\\knowledge\\log.md"',
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
    // "..." is expanded by pwsh first, so the inner script cannot see what $S is.
    assert.equal(kind(sh(B + '& $b -c "printf a > $S/f"')), 'ask')
  })
})

describe('paths joined with +', () => {
  const V = "$src = 'C:\\mfg\\src'\n$bak = 'C:\\mfg\\before'\n$k = '~\\knowledge'\n"
  it('reads strings and variables joined with + when every piece is known', () => {
    for (const c of [
      // The reported command: a backup with ($bak + '\x') paths, then git status elsewhere.
      V + "New-Item -ItemType Directory -Force -LiteralPath ($bak + '\\handlers') | Out-Null\n" +
        "Copy-Item -LiteralPath ($src + '\\handlers\\aog.ts') -Destination ($bak + '\\handlers\\aog.ts') -Force\n" +
        "git -C 'C:\\mfg\\tmp\\asphyxia_plugins' status --porcelain | Select-Object -First 5",
      V + "$p = $bak + '\\a.ts'\nSet-Content -LiteralPath $p x",
      V + "Set-Content ($bak + \"\\$src.txt\") x",
      V + "Set-Content ((Join-Path $bak 'x') + '.txt') x",
    ]) {
      assert.equal(kind(sh(c)), 'allow', c)
    }
  })
  it('still catches the knowledge base, and asks when a piece is unknown', () => {
    for (const c of [
      V + "Set-Content ($k + '\\log.md') x",
      V + "$p = $k + '\\.kb\\kb.py'\nSet-Content $p x",
      V + "Copy-Item C:\\x\\a -Destination ($k + '\\.git\\hooks\\pre-commit')",
      V + "git -C ($k + '') add -A",
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
    for (const c of [
      V + "Set-Content ($nowhere + '\\log.md') x",
      V + "Set-Content ($bak + $x.Name) x",
      V + "Set-Content ((Get-KbPath) + '\\log.md') x",
    ]) {
      assert.equal(kind(sh(c)), 'ask', c)
    }
  })
})

describe('variables in the value of a write', () => {
  it('reads -Value $p.Id and the text of Set-Content as text, not as a path', () => {
    const start =
      "$p = Start-Process -FilePath 'node' -ArgumentList 'a.js' -WorkingDirectory 'C:\\work\\my dir' -PassThru -WindowStyle Hidden " +
      "-RedirectStandardOutput 'C:\\work\\my dir\\out.log' -RedirectStandardError 'C:\\work\\my dir\\err.log'\n"
    for (const c of [
      // The reported command: save the started process's id next to its logs.
      start + "Set-Content -LiteralPath 'C:\\mfg\\tmp\\lane_pid.txt' -Value $p.Id -Encoding utf8\n\"pid=$($p.Id)\"",
      "Set-Content -Path C:\\work\\a.txt -Value $p.Id",
      "Set-Content C:\\work\\a.txt $p.Id",
      "Add-Content -LiteralPath 'C:\\work\\a.txt' -Value $r.Content -Encoding $enc",
    ]) {
      assert.equal(kind(sh(c)), 'allow', c)
    }
  })
  it('still checks a variable in the path itself', () => {
    assert.equal(kind(sh('Set-Content -LiteralPath $f.FullName -Value $p.Id')), 'ask')
    assert.equal(kind(sh('Set-Content $f.FullName $p.Id')), 'ask')
    assert.equal(kind(sh("$f = '~\\knowledge\\log.md'\nSet-Content -Value $p.Id -LiteralPath $f")), 'deny')
    assert.equal(kind(sh("Set-Content -LiteralPath '~\\knowledge\\log.md' -Value $p.Id")), 'deny')
  })
})

describe('review of 2026-11-06', () => {
  it('a protected file that is only read is not a write target', () => {
    for (const c of [
      'Out-File C:\\work\\note.md (Get-Content ~/knowledge/log.md)',
      'Set-Content C:\\work\\note.md (Get-Content ~/knowledge/log.md)',
      'Add-Content C:\\work\\note.md -Value (Get-Content ~/knowledge/log.md)',
      'Remove-Item C:\\work\\* -Exclude ~/knowledge/log.md',
      'if (Test-Path ~/knowledge/log.md) { Set-Content C:\\work\\x 1 }',
      'Set-Content -LiteralPath C:\\work\\a.txt -Value ~/knowledge/log.md',
      'Add-Content C:\\work\\a.md "see ~/knowledge/log.md for history"',
    ]) {
      assert.equal(kind(sh(c)), 'allow', c)
    }
    for (const c of [
      'if ($a) { Set-Content C:\\x 1 } else { Set-Content ~/knowledge/log.md 1 }',
      'Set-Content -Path:~/knowledge/log.md x',
      'Set-Content x -Path ~/knowledge/log.md',
      'Get-Item x | Out-Null; Add-Content -Path ~/knowledge/log.md -Value y',
      '[IO.File]::AppendAllText("~/knowledge/log.md", "x")',
    ]) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
    assert.equal(kind(bash("sed -i 's/a/b/' ~/knowledge/log.md")), 'deny')
  })
  it('refuses a global or system core.hooksPath from any folder', () => {
    for (const c of ['git config --global core.hooksPath C:\\empty', 'git config --system core.hooksPath x', 'git config --global --unset core.hooksPath']) {
      assert.equal(kind(sh(c)), 'deny', c)
    }
    for (const c of ['git config --global --get core.hooksPath', 'git config core.hooksPath .husky', 'git config --global user.name x']) {
      assert.equal(kind(sh(c)), 'allow', c)
    }
  })
})
