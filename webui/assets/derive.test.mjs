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
const salt = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join('');
const got2 = await globalThis.cryptstorageDerive.authKey(' Alice ', 'correct horse battery', salt);
const want2 = 'b38ae6047a72ec83205ac71fd8d8d9bf839c49575263db45e2630787162ee5d5';   // e2ee_test.go TestDeriveV2Vector
if (got2 !== want2) { console.error('MISMATCH v2', got2); process.exit(1); }
console.log('ok: browser keys (versions 1 and 2) match the Go client');
