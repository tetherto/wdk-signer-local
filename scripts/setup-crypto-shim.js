// Bare runtime has no built-in 'crypto' module. ton-crypto-primitives
// does require('crypto') expecting Node.js crypto API. bare-crypto
// exposes the same functions (createHash, createHmac, pbkdf2,
// randomBytes, randomFillSync), so we create a thin shim package.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const shimDir = path.join(__dirname, '..', 'node_modules', 'crypto')

if (!fs.existsSync(shimDir)) {
  fs.mkdirSync(shimDir, { recursive: true })
}

fs.writeFileSync(
  path.join(shimDir, 'package.json'),
  JSON.stringify({ name: 'crypto', version: '1.0.0', main: 'index.js' }, null, 2) + '\n'
)

fs.writeFileSync(
  path.join(shimDir, 'index.js'),
  "module.exports = require('bare-crypto')\n"
)
