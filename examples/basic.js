import { sign, verify, decode } from '../src/index.js'
import { generateApiKey, hashApiKey, validateApiKey } from '../src/index.js'
import { hasPermission, hasAnyPermission } from '../src/index.js'

const SECRET = 'super-secret-key'

// JWT
const token = sign({ userId: 42, role: 'admin' }, SECRET, { expiresIn: 3600 })
console.log('Token:', token)

const payload = verify(token, SECRET)
console.log('Verified payload:', payload)

const decoded = decode(token)
console.log('Decoded header:', decoded.header)

// API Keys
const apiKey = generateApiKey({ prefix: 'sk' })
console.log('API Key:', apiKey)

const hash = hashApiKey(apiKey, SECRET)
console.log('Hashed:', hash)

console.log('Valid?', validateApiKey(apiKey, hash, SECRET))
console.log('Invalid?', validateApiKey('wrong-key', hash, SECRET))

// Permissions
const perms = ['users:read', 'posts:write']
console.log('Has users:read?', hasPermission(perms, 'users:read')) // true
console.log('Has users:delete?', hasPermission(perms, 'users:delete')) // false
console.log('Has any?', hasAnyPermission(perms, ['users:delete', 'posts:write'])) // true
console.log('Wildcard?', hasPermission(['*'], 'anything')) // true
