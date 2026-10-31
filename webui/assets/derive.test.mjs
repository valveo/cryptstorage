// node webui/assets/derive.test.mjs : the browser derivation must match the Go client (keys_test.go).
import { createRequire } from 'module';
import { webcrypto } from 'crypto';
const require = createRequire(import.meta.url);
globalThis.hashwasm = require('./argon2.umd.min.js');
globalThis.crypto ??= webcrypto;
require('./derive.js');
const got = await globalThis.cryptstorageDerive.authKey(' Alice ', 'correct horse battery');
const want = '267d874caa4f5ad25ba061432ded57a0b369e31f327032d509f2a88363a569c4';
if (got !== want) { console.error('MISMATCH', got); process.exit(1); }
console.log('ok: browser key matches the Go client');
