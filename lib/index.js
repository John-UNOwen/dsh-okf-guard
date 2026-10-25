/**
 * okf-guard: keep DSH agents on kb.py inside the user's OKF knowledge base.
 *
 * - Hard rules (git add/commit, --no-verify, okf index, writes to log.md ...)
 *   are registered as a DSH tool guard, which no other plugin or approval
 *   setting can turn back into an allow.
 * - Softer rules (git push, git reset --hard ...) return `ask` from a
 *   prepended `tools/pre-execute` listener, so the user gets the approval
 *   prompt. The listener still lets later listeners deny or ask first, and
 *   only turns their allow into an ask. Under an approval policy of "never",
 *   DSH turns `ask` into a denial.
 * - A short system prompt section tells the model where the knowledge base is
 *   and how to change it.
 *
 * @module dsh-okf-guard
 */

import Schema from '@deepseek-ai/schemastery'
import { createGuard, detectEnvironment } from './rules.js'

export const name = 'okf-guard'
export const inject = ['tools']

/** Between MCP_SERVERS (3100) and TOOLS_SDK (5000). */
const PROMPT_ORDER = 3150

export const Config = Schema.object({
  knowledgeRoot: Schema.string()
    .default('~/knowledge')
    .description('Knowledge base folder. ~ and %USERPROFILE% are expanded.'),
  injectPrompt: Schema.boolean()
    .default(true)
    .description('Add a short knowledge base section to the system prompt.'),
  askBeforePush: Schema.boolean()
    .default(true)
    .description('Ask the user before an agent pushes the knowledge base.'),
  shellTools: Schema.array(Schema.string().min(1))
    .default(['pwsh', 'bash'])
    .description('Shell tools whose command argument is checked.'),
  fileTools: Schema.array(Schema.string().min(1))
    .default(['write', 'edit', 'str_replace_editor'])
    .description('File tools whose path argument is checked.'),
})

export function apply(ctx, config = {}) {
  const guard = createGuard(config)
  // The short home path and extra private names need child processes: look
  // them up off the event loop and apply them when they arrive.
  detectEnvironment(guard.home, guard.root).then(
    (found) => guard.update(found),
    () => {},
  )

  // Hard denials, final whatever other listeners decide.
  ctx.tools.guard((exec) => {
    const d = guard.decide(exec)
    return d && d.kind === 'deny' ? d.reason : undefined
  })

  // Questions for the user. Prepended so an auto-approving listener can't
  // skip it; later listeners still run, and their deny, cancel or ask wins.
  ctx.on(
    'tools/pre-execute',
    async (exec, next) => {
      const d = guard.decide(exec)
      if (!d) return next()
      if (d.kind === 'deny') return d
      const downstream = await next()
      return downstream && downstream.kind !== 'allow' ? downstream : d
    },
    { prepend: true },
  )

  if (config.injectPrompt !== false && typeof ctx.inject === 'function') {
    ctx.inject(['systemPrompt'], (scope) => {
      scope.systemPrompt.section({
        name: 'okf-guard:knowledge-base',
        order: PROMPT_ORDER,
        interpolate: false,
        text: () => guard.promptText(),
      })
    })
  }
}
