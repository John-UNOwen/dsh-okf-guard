// Loads the plugin into the Cordis runtime that ships with DSH (see
// dsh-runtime.mjs) and drives it through the same calls DSH's tool runtime makes.
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { homedir, userInfo } from 'node:os'
import path from 'node:path'
import { describe, it } from 'node:test'
import { Context } from '@deepseek-ai/cordis'
import * as plugin from '../lib/index.js'
import { createGuard } from '../lib/rules.js'

async function setup(config = {}) {
  const ctx = new Context()
  const guards = []
  const sections = []
  ctx.provide('tools')
  ctx.provide('systemPrompt')
  ctx.set('tools', { guard: (fn) => (guards.push(fn), () => {}) })
  ctx.set('systemPrompt', { section: (s) => (sections.push(s), () => {}) })
  await ctx.plugin(plugin, config)
  return { ctx, guards, sections }
}

const call = (command, cwd = homedir()) => ({
  name: 'pwsh',
  arguments: { command },
  agent: { id: 'agent-1', session: { header: { cwd } } },
  callId: 'call-1',
})
const preExecute = (ctx, exec) => ctx.waterfall(ctx, 'tools/pre-execute', exec, () => Promise.resolve({ kind: 'allow' }))

describe('plugin in a real Cordis context', () => {
  it('registers one guard and one prompt section', async () => {
    const { guards, sections } = await setup()
    assert.equal(guards.length, 1)
    assert.equal(sections.length, 1)
    assert.equal(sections[0].name, 'okf-guard:knowledge-base')
    assert.equal(sections[0].interpolate, false)
    assert.equal(typeof sections[0].text, 'function')
  })

  it('the guard denies hard rules and leaves asks to the waterfall', async () => {
    const { guards } = await setup()
    assert.match(guards[0](call('git -C "$env:USERPROFILE\\knowledge" add -A')), /^okf-guard: /)
    assert.equal(guards[0](call('git -C "$env:USERPROFILE\\knowledge" push')), undefined)
    assert.equal(guards[0](call('git status')), undefined)
  })

  it('tools/pre-execute returns deny, ask or allow', async () => {
    const { ctx } = await setup()
    assert.equal((await preExecute(ctx, call('git -C ~/knowledge commit -m x'))).kind, 'deny')
    const ask = await preExecute(ctx, call('git -C ~/knowledge push'))
    assert.equal(ask.kind, 'ask')
    assert.match(ask.displayReason.en, /push/)
    assert.equal((await preExecute(ctx, call('git status'))).kind, 'allow')
  })

  it('runs ahead of a listener that allows everything', async () => {
    const { ctx } = await setup()
    ctx.on('tools/pre-execute', async () => ({ kind: 'allow' }))
    assert.equal((await preExecute(ctx, call('git -C ~/knowledge push'))).kind, 'ask')
  })

  it('askBeforePush false lets push through', async () => {
    const { ctx } = await setup({ askBeforePush: false })
    assert.equal((await preExecute(ctx, call('git -C ~/knowledge push'))).kind, 'allow')
  })

  it('injectPrompt false adds no section', async () => {
    const { sections } = await setup({ injectPrompt: false })
    assert.equal(sections.length, 0)
  })

  it('the prompt text on this PC never contains the account name', async () => {
    const { sections } = await setup()
    const text = sections[0].text({})
    const name = path.basename(homedir())
    assert.equal(text.toLowerCase().includes(name.toLowerCase()), false)
  })
})

describe('account name detection on this PC', () => {
  const guard = createGuard({})
  const target = path.join(guard.root, 'projects', 'x', 'decisions', 'y.md')
  const edit = (text) => guard.decide({ name: 'edit', arguments: { file_path: target, old_string: 'a', new_string: text }, agent: { session: { header: { cwd: homedir() } } } })

  it('catches the user name and the home folder name', () => {
    for (const n of [userInfo().username, path.basename(homedir())]) {
      if (n.length < 3) continue
      assert.equal(edit(`path ${n} here`)?.kind, 'deny')
      assert.equal(edit(`path ${n.toUpperCase().split(' ').join('-')} here`)?.kind, 'deny')
    }
  })

  if (process.platform === 'win32') {
    it('catches the 8.3 short name of the home folder', () => {
      const short = execFileSync('cmd.exe', ['/d', '/c', `for %I in ("${homedir()}") do @echo %~sI`], {
        encoding: 'utf8',
        windowsVerbatimArguments: true,
      }).trim()
      const base = path.win32.basename(short)
      if (base.toLowerCase() !== path.basename(homedir()).toLowerCase()) {
        assert.equal(edit(`C:\\Users\\${base}\\x`)?.kind, 'deny')
      }
    })
  }

  it('allows %USERPROFILE% and ~', () => {
    assert.equal(edit('%USERPROFILE%\\knowledge and ~/knowledge'), null)
  })
})
