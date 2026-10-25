// Lets the tests import @deepseek-ai/* from the installed DSH, so they need no
// npm install. Set DSH_MODULES to use another DSH install.
import { registerHooks } from 'node:module'
import { existsSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const base =
  process.env.DSH_MODULES ||
  path.join(process.env.APPDATA || '', 'npm', 'node_modules', '@deepseek-ai', 'dsh', 'node_modules', '@deepseek-ai')

function entry(pkg) {
  const dir = path.join(base, pkg)
  const manifest = JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8'))
  let e = manifest.exports && (manifest.exports['.'] ?? manifest.exports)
  if (e && typeof e === 'object') e = e.import ?? e.default ?? e.node
  if (e && typeof e === 'object') e = e.default
  return path.join(dir, e || manifest.module || manifest.main || 'index.js')
}

registerHooks({
  resolve(specifier, context, nextResolve) {
    const m = /^@deepseek-ai\/([^/]+)$/.exec(specifier)
    if (m && existsSync(path.join(base, m[1]))) {
      return { url: pathToFileURL(entry(m[1])).href, shortCircuit: true, format: 'module' }
    }
    return nextResolve(specifier, context)
  },
})
