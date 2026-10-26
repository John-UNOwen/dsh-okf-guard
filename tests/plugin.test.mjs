// Loads the plugin into the Cordis runtime that ships with DSH (see
// dsh-runtime.mjs) and drives it through the same calls DSH's tool runtime makes.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { homedir, userInfo } from 'node:os'
import path from 'node:path'
import { describe, it } from 'node:test'
import { setTimeout as sleep } from 'node:timers/promises'
import { Context } from '@deepseek-ai/cordis'
import * as plugin from '../lib/index.js'
import { createGuard, detectEnvironment } from '../lib/rules.js'

const found = await detectEnvironment()
const shortHome = found.shortHome && found.shortHome.toLowerCase() !== homedir().toLowerCase() ? found.shortHome : null

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

  it('review 2: a later listener can still deny a call okf-guard would ask about', async () => {
    const { ctx } = await setup()
    ctx.on('tools/pre-execute', async () => ({ kind: 'deny', reason: 'hook says no' }))
    const d = await preExecute(ctx, call('git -C ~/knowledge push'))
    assert.equal(d.kind, 'deny')
    assert.equal(d.reason, 'hook says no')
  })

  it("review 2: a later listener's own ask and cancel are kept", async () => {
    const asks = await setup()
    asks.ctx.on('tools/pre-execute', async () => ({ kind: 'ask', reason: 'other plugin' }))
    assert.equal((await preExecute(asks.ctx, call('git -C ~/knowledge push'))).reason, 'other plugin')
    const cancels = await setup()
    cancels.ctx.on('tools/pre-execute', async () => ({ kind: 'cancel' }))
    assert.equal((await preExecute(cancels.ctx, call('git -C ~/knowledge push'))).kind, 'cancel')
  })

  it('review 2: a deny does not wait for later listeners', async () => {
    const { ctx } = await setup()
    let reached = false
    ctx.on('tools/pre-execute', async (exec, next) => {
      reached = true
      return next()
    })
    assert.equal((await preExecute(ctx, call('git -C ~/knowledge add -A'))).kind, 'deny')
    assert.equal(reached, false)
  })

  it('review 15: learns the short home path in the background', async (t) => {
    if (!shortHome) return t.skip('no 8.3 short name for the home folder on this PC')
    const { ctx } = await setup()
    const exec = call(`git -C "${shortHome}\\knowledge" add -A`, path.parse(homedir()).root)
    let d
    for (let i = 0; i < 100; i++) {
      d = await preExecute(ctx, exec)
      if (d.kind === 'deny') break
      await sleep(50)
    }
    assert.equal(d.kind, 'deny')
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
    const text = sections[0].text({}).toLowerCase()
    for (const name of [path.basename(homedir()), userInfo().username, process.env.USERNAME, shortHome && path.basename(shortHome)]) {
      if (name) assert.equal(text.includes(name.toLowerCase()), false)
    }
  })

  it('review 15: no blocking child processes', () => {
    for (const file of ['../lib/rules.js', '../lib/index.js']) {
      const src = readFileSync(new URL(file, import.meta.url), 'utf8')
      assert.doesNotMatch(src, /execFileSync|execSync|spawnSync/, file)
    }
  })
})

describe('account name detection on this PC', () => {
  const guard = createGuard({}, found)
  const target = path.join(guard.root, 'projects', 'x', 'decisions', 'y.md')
  const edit = (text) => guard.decide({ name: 'edit', arguments: { file_path: target, old_string: 'a', new_string: text }, agent: { session: { header: { cwd: homedir() } } } })

  it('catches the user name and the home folder name', () => {
    for (const n of [userInfo().username, path.basename(homedir())]) {
      if (n.length < 3) continue
      assert.equal(edit(`path ${n} here`)?.kind, 'deny')
      assert.equal(edit(`path ${n.toUpperCase().split(' ').join('-')} here`)?.kind, 'deny')
    }
  })

  it('catches the 8.3 short name of the home folder', (t) => {
    if (!shortHome) return t.skip('no 8.3 short name for the home folder on this PC')
    assert.equal(edit(`C:\\Users\\${path.win32.basename(shortHome)}\\x`)?.kind, 'deny')
  })

  it('detectEnvironment returns the short home path and extra names', () => {
    assert.ok(found.shortHome === null || typeof found.shortHome === 'string')
    assert.ok(found.shortRoot === null || typeof found.shortRoot === 'string')
    assert.ok(Array.isArray(found.extraNames))
  })

  it('allows %USERPROFILE% and ~', () => {
    assert.equal(edit('%USERPROFILE%\\knowledge and ~/knowledge'), null)
  })
})
