import test from 'brittle'
import { createMnemonic, sign, getPublicKey, importMnemonic, readMnemonic, deleteMnemonic, importPrivateKey, readPrivateKey, deletePrivateKey, Signer, parseTonHdPath } from './src/index.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { mnemonicNew, mnemonicValidate, mnemonicToPrivateKey, mnemonicToHDSeed, deriveEd25519Path } from 'ton-crypto'

const TEST_MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

const tonWords = await mnemonicNew(24)
const TON_MNEMONIC = tonWords.join(' ')

test('ton-crypto smoke test - mnemonicNew works', async (t) => {
  const words = await mnemonicNew(24)
  t.is(words.length, 24)
  const valid = await mnemonicValidate(words)
  t.ok(valid)

  const keyPair = await mnemonicToPrivateKey(words)
  t.is(keyPair.secretKey.length, 64)
  t.is(keyPair.publicKey.length, 32)

  const hdSeed = await mnemonicToHDSeed(words)
  t.is(hdSeed.length, 64)

  const derived = await deriveEd25519Path(hdSeed, [0, 1, 2])
  t.is(derived.length, 32)
})

// Detect if secure storage (Keychain/KeyStore) is accessible in this environment
let storageAvailable = false
try {
  const probeKey = new Uint8Array([1, 2, 3])
  await importPrivateKey({ privateKey: probeKey, name: '_test_probe' })
  await deletePrivateKey({ name: '_test_probe' })
  storageAvailable = true
} catch {}

const storageTest = storageAvailable ? test : test.skip

test('createMnemonic - creates 12 word mnemonic', async (t) => {
  const mnemonic = await createMnemonic({
    wordCount: 12,
    returnMnemonic: true,
    storeMnemonic: false
  })
  const words = Buffer.from(mnemonic).toString('utf8').split(' ')
  t.is(words.length, 12)
})

test('createMnemonic - creates 24 word mnemonic', async (t) => {
  const mnemonic = await createMnemonic({
    wordCount: 24,
    returnMnemonic: true,
    storeMnemonic: false
  })
  const words = Buffer.from(mnemonic).toString('utf8').split(' ')
  t.is(words.length, 24)
})

test('sign with secp256k1', async (t) => {
  const data = Buffer.from('test message to sign')
  const sig = await sign({
    mnemonic: TEST_MNEMONIC,
    path: "m/44'/60'/0'/0/0",
    curve: 'secp256k1',
    data
  })
  t.ok(sig instanceof Uint8Array)
  t.is(sig.length, 65)
})

test('getPublicKey with secp256k1', async (t) => {
  const pubKey = await getPublicKey({
    mnemonic: TEST_MNEMONIC,
    path: "m/44'/60'/0'/0/0",
    curve: 'secp256k1'
  })
  t.is(pubKey.length, 33)
})

test('sign with ed25519', async (t) => {
  const data = Buffer.from('test message to sign')
  const sig = await sign({
    mnemonic: TEST_MNEMONIC,
    path: "m/44'/60'/0'/0'/0'",
    curve: 'ed25519',
    data
  })
  t.is(sig.length, 64)
})

test('getPublicKey with ed25519', async (t) => {
  const pubKey = await getPublicKey({
    mnemonic: TEST_MNEMONIC,
    path: "m/44'/60'/0'/0'/0'",
    curve: 'ed25519'
  })
  t.is(pubKey.length, 32)
})

test('different paths produce different keys', async (t) => {
  const pubKey1 = await getPublicKey({
    mnemonic: TEST_MNEMONIC,
    path: "m/44'/60'/0'/0/0",
    curve: 'secp256k1'
  })
  const pubKey2 = await getPublicKey({
    mnemonic: TEST_MNEMONIC,
    path: "m/44'/60'/0'/0/1",
    curve: 'secp256k1'
  })
  t.not(Buffer.from(pubKey1).toString('hex'), Buffer.from(pubKey2).toString('hex'))
})

test('password changes derived keys', async (t) => {
  const pubKey1 = await getPublicKey({
    mnemonic: TEST_MNEMONIC,
    password: '',
    path: "m/44'/60'/0'/0/0",
    curve: 'secp256k1'
  })
  const pubKey2 = await getPublicKey({
    mnemonic: TEST_MNEMONIC,
    password: 'secret',
    path: "m/44'/60'/0'/0/0",
    curve: 'secp256k1'
  })
  t.not(Buffer.from(pubKey1).toString('hex'), Buffer.from(pubKey2).toString('hex'))
})

test('importPrivateKey - rejects non-Uint8Array', async (t) => {
  await t.exception(async () => {
    await importPrivateKey({ privateKey: 'string key' })
  }, /must be a Uint8Array/)

  await t.exception(async () => {
    await importPrivateKey({ privateKey: null })
  }, /must be a Uint8Array/)
})

test('importPrivateKey - rejects when no privateKey provided', async (t) => {
  await t.exception(async () => {
    await importPrivateKey({})
  }, /must be a Uint8Array/)
})

test('importMnemonic - rejects non-Uint8Array', async (t) => {
  await t.exception(async () => {
    await importMnemonic({ mnemonic: 'string mnemonic' })
  }, /must be a Uint8Array/)

  await t.exception(async () => {
    await importMnemonic({ mnemonic: null })
  }, /must be a Uint8Array/)
})

test('importMnemonic - rejects invalid mnemonic when validate=true', async (t) => {
  const invalidMnemonic = Buffer.from('invalid mnemonic words here', 'utf8')
  await t.exception(async () => {
    await importMnemonic({ mnemonic: invalidMnemonic, validate: true })
  }, /invalid mnemonic/)
})

test('Signer - isUnlocked returns false initially', (t) => {
  const s = new Signer()
  t.is(s.isUnlocked(), false)
})

test('Signer - lock clears state', (t) => {
  const s = new Signer()
  s._secret = Buffer.from(TEST_MNEMONIC, 'utf8')
  t.is(s.isUnlocked(), true)

  s.lock()
  t.is(s.isUnlocked(), false)
  t.is(s._secret, null)
})

test('Signer - lock zeroes buffer before clearing', (t) => {
  const s = new Signer()
  const original = Buffer.from(TEST_MNEMONIC, 'utf8')
  s._secret = original

  s.lock()

  const allZeros = original.every(byte => byte === 0)
  t.is(allZeros, true)
})

test('Signer - auto-lock timer clears mnemonic', async (t) => {
  const s = new Signer({ autoLockMs: 50 })
  s._secret = Buffer.from(TEST_MNEMONIC, 'utf8')
  s._resetAutoLockTimer()

  t.is(s.isUnlocked(), true)

  await new Promise(resolve => setTimeout(resolve, 100))

  t.is(s.isUnlocked(), false)
})

test('Signer - manual lock cancels auto-lock timer', (t) => {
  const s = new Signer({ autoLockMs: 1000 })
  s._secret = Buffer.from(TEST_MNEMONIC, 'utf8')
  s._resetAutoLockTimer()

  t.ok(s._autoLockTimer !== null)

  s.lock()

  t.is(s._autoLockTimer, null)
})

test('Signer - autoLockMs 0 disables auto-lock', (t) => {
  const s = new Signer({ autoLockMs: 0 })
  s._secret = Buffer.from(TEST_MNEMONIC, 'utf8')
  s._resetAutoLockTimer()

  t.is(s._autoLockTimer, null)
})

test('sign with seedDerivation ton', async (t) => {
  const data = Buffer.from('test message to sign')
  const sig = await sign({
    mnemonic: TON_MNEMONIC,
    curve: 'ed25519',
    seedDerivation: 'ton',
    data
  })
  t.is(sig.length, 64)
})

test('getPublicKey with seedDerivation ton', async (t) => {
  const pubKey = await getPublicKey({
    mnemonic: TON_MNEMONIC,
    curve: 'ed25519',
    seedDerivation: 'ton'
  })
  t.is(pubKey.length, 32)
})

test('seedDerivation ton sign/verify round-trip', async (t) => {
  const data = Buffer.from('ton verify test')
  const sig = await sign({
    mnemonic: TON_MNEMONIC,
    curve: 'ed25519',
    seedDerivation: 'ton',
    data
  })
  const pubKey = await getPublicKey({
    mnemonic: TON_MNEMONIC,
    curve: 'ed25519',
    seedDerivation: 'ton'
  })
  const valid = ed25519.verify(sig, data, pubKey)
  t.ok(valid)
})

test('seedDerivation ton matches ton-crypto mnemonicToPrivateKey', async (t) => {
  const words = TON_MNEMONIC.split(/\s+/)
  const keyPair = await mnemonicToPrivateKey(words)
  const expectedPubKey = keyPair.publicKey

  const pubKey = await getPublicKey({
    mnemonic: TON_MNEMONIC,
    curve: 'ed25519',
    seedDerivation: 'ton'
  })
  t.alike(pubKey, new Uint8Array(expectedPubKey))
})

test('seedDerivation ton produces different keys than bip39', async (t) => {
  const tonKey = await getPublicKey({
    mnemonic: TON_MNEMONIC,
    curve: 'ed25519',
    seedDerivation: 'ton'
  })
  const bip39Key = await getPublicKey({
    mnemonic: TON_MNEMONIC,
    path: "m/44'/607'/0'",
    curve: 'ed25519',
    seedDerivation: 'bip39'
  })
  t.not(Buffer.from(tonKey).toString('hex'), Buffer.from(bip39Key).toString('hex'))
})

test('seedDerivation ton rejects secp256k1', async (t) => {
  await t.exception(async () => {
    await sign({
      mnemonic: TEST_MNEMONIC,
      curve: 'secp256k1',
      seedDerivation: 'ton',
      data: Buffer.from('test')
    })
  }, /TON derivation only supports ed25519/)
})

test('seedDerivation ton throws when path is provided', async (t) => {
  await t.exception(async () => {
    await sign({
      mnemonic: TEST_MNEMONIC,
      path: "m/44'/607'/0'",
      curve: 'ed25519',
      seedDerivation: 'ton',
      data: Buffer.from('test')
    })
  }, /path is not supported for TON standard derivation/)

  await t.exception(async () => {
    await getPublicKey({
      mnemonic: TEST_MNEMONIC,
      path: "m/44'/607'/0'",
      curve: 'ed25519',
      seedDerivation: 'ton'
    })
  }, /path is not supported for TON standard derivation/)
})

// --- parseTonHdPath tests ---

test('parseTonHdPath - valid path', (t) => {
  t.alike(parseTonHdPath("m/0'/1'/2'"), [0, 1, 2])
  t.alike(parseTonHdPath("m/44'"), [44])
  t.alike(parseTonHdPath("m/0'/0'/0'"), [0, 0, 0])
})

test('parseTonHdPath - missing m/ prefix', async (t) => {
  await t.exception(() => parseTonHdPath("0'/1'/2'"), /must start with 'm\//)
  await t.exception(() => parseTonHdPath(''), /must start with 'm\//)
  await t.exception(() => parseTonHdPath(undefined), /must start with 'm\//)
})

test('parseTonHdPath - non-hardened index', async (t) => {
  await t.exception(() => parseTonHdPath('m/0/1/2'), /must be hardened/)
  await t.exception(() => parseTonHdPath("m/0'/1/2'"), /must be hardened/)
})

test('parseTonHdPath - empty segments', async (t) => {
  await t.exception(() => parseTonHdPath('m/'), /at least one segment/)
})

test('parseTonHdPath - negative numbers', async (t) => {
  await t.exception(() => parseTonHdPath("m/-1'"), /Invalid TON HD path index/)
})

test('parseTonHdPath - index at hardened offset boundary', async (t) => {
  t.alike(parseTonHdPath("m/2147483647'"), [0x7FFFFFFF])
  await t.exception(() => parseTonHdPath("m/2147483648'"), /Invalid TON HD path index/)
})

// --- ton-hd signing tests ---

test('sign with seedDerivation ton-hd', async (t) => {
  const data = Buffer.from('test message to sign')
  const sig = await sign({
    mnemonic: TON_MNEMONIC,
    path: "m/0'/1'/2'",
    curve: 'ed25519',
    seedDerivation: 'ton-hd',
    data
  })
  t.is(sig.length, 64)
})

test('getPublicKey with seedDerivation ton-hd', async (t) => {
  const pubKey = await getPublicKey({
    mnemonic: TON_MNEMONIC,
    path: "m/0'/1'/2'",
    curve: 'ed25519',
    seedDerivation: 'ton-hd'
  })
  t.is(pubKey.length, 32)
})

test('seedDerivation ton-hd sign/verify round-trip', async (t) => {
  const data = Buffer.from('ton-hd verify test')
  const sig = await sign({
    mnemonic: TON_MNEMONIC,
    path: "m/0'/1'/2'",
    curve: 'ed25519',
    seedDerivation: 'ton-hd',
    data
  })
  const pubKey = await getPublicKey({
    mnemonic: TON_MNEMONIC,
    path: "m/0'/1'/2'",
    curve: 'ed25519',
    seedDerivation: 'ton-hd'
  })
  const valid = ed25519.verify(sig, data, pubKey)
  t.ok(valid)
})

test('seedDerivation ton-hd different paths produce different keys', async (t) => {
  const pubKey1 = await getPublicKey({
    mnemonic: TON_MNEMONIC,
    path: "m/0'/1'/2'",
    curve: 'ed25519',
    seedDerivation: 'ton-hd'
  })
  const pubKey2 = await getPublicKey({
    mnemonic: TON_MNEMONIC,
    path: "m/0'/1'/3'",
    curve: 'ed25519',
    seedDerivation: 'ton-hd'
  })
  t.not(Buffer.from(pubKey1).toString('hex'), Buffer.from(pubKey2).toString('hex'))
})

test('seedDerivation ton-hd throws when path is missing', async (t) => {
  await t.exception(async () => {
    await sign({
      mnemonic: TEST_MNEMONIC,
      curve: 'ed25519',
      seedDerivation: 'ton-hd',
      data: Buffer.from('test')
    })
  }, /path is required for TON HD derivation/)

  await t.exception(async () => {
    await getPublicKey({
      mnemonic: TEST_MNEMONIC,
      curve: 'ed25519',
      seedDerivation: 'ton-hd'
    })
  }, /path is required for TON HD derivation/)
})

test('seedDerivation ton-hd rejects non-hardened path segments', async (t) => {
  await t.exception(async () => {
    await sign({
      mnemonic: TEST_MNEMONIC,
      path: 'm/0/1/2',
      curve: 'ed25519',
      seedDerivation: 'ton-hd',
      data: Buffer.from('test')
    })
  }, /must be hardened/)
})

test('seedDerivation ton-hd rejects secp256k1 curve', async (t) => {
  await t.exception(async () => {
    await sign({
      mnemonic: TEST_MNEMONIC,
      path: "m/0'/1'/2'",
      curve: 'secp256k1',
      seedDerivation: 'ton-hd',
      data: Buffer.from('test')
    })
  }, /TON HD derivation only supports ed25519/)

  await t.exception(async () => {
    await getPublicKey({
      mnemonic: TEST_MNEMONIC,
      path: "m/0'/1'/2'",
      curve: 'secp256k1',
      seedDerivation: 'ton-hd'
    })
  }, /TON HD derivation only supports ed25519/)
})

// --- createMnemonic TON tests ---

test('createMnemonic with seedDerivation ton generates valid TON mnemonic', async (t) => {
  const result = await createMnemonic({
    wordCount: 24,
    returnMnemonic: true,
    storeMnemonic: false,
    seedDerivation: 'ton'
  })
  const words = Buffer.from(result).toString('utf8').split(' ')
  t.is(words.length, 24)
  const valid = await mnemonicValidate(words)
  t.ok(valid)
})

test('createMnemonic with password generates password-type TON mnemonic', async (t) => {
  const result = await createMnemonic({
    wordCount: 24,
    returnMnemonic: true,
    storeMnemonic: false,
    seedDerivation: 'ton',
    password: 'my-secret'
  })
  const words = Buffer.from(result).toString('utf8').split(' ')
  t.is(words.length, 24)
  const isBasic = await mnemonicValidate(words)
  t.is(isBasic, false, 'password-protected mnemonic should not validate as basic')
  const isValidWithPassword = await mnemonicValidate(words, 'my-secret')
  t.ok(isValidWithPassword, 'validates with the same password used during creation')
})

test('importMnemonic with seedDerivation ton validates TON mnemonic', async (t) => {
  const words = await mnemonicNew(24)
  const valid = await mnemonicValidate(words)
  t.ok(valid, 'generated mnemonic is valid per ton-crypto')

  const mnemonicBytes = Buffer.from(words.join(' '), 'utf8')
  try {
    await importMnemonic({
      mnemonic: mnemonicBytes,
      seedDerivation: 'ton',
      validate: true
    })
  } catch (e) {
    // Validation errors must propagate; storage errors are OK (keychain may be unavailable)
    if (/invalid mnemonic|must be/.test(e.message)) throw e
  }
  t.pass('importMnemonic did not reject valid TON mnemonic')
})

test('importMnemonic rejects invalid TON mnemonic', async (t) => {
  const invalidBytes = Buffer.from('invalid words that are not a ton mnemonic at all here now', 'utf8')
  await t.exception(async () => {
    await importMnemonic({
      mnemonic: invalidBytes,
      seedDerivation: 'ton',
      validate: true
    })
  }, /invalid mnemonic/)
})

test('importMnemonic with password validates password-type TON mnemonic', async (t) => {
  const words = await mnemonicNew(24, 'test-pass')
  const isBasic = await mnemonicValidate(words)
  t.is(isBasic, false, 'password-type mnemonic should not validate as basic')

  const mnemonicBytes = Buffer.from(words.join(' '), 'utf8')
  try {
    await importMnemonic({
      mnemonic: mnemonicBytes,
      seedDerivation: 'ton',
      password: 'test-pass',
      validate: true
    })
  } catch (e) {
    if (/invalid mnemonic|must be/.test(e.message)) throw e
  }
  t.pass('importMnemonic did not reject password-type mnemonic')
})

test('importMnemonic rejects password-type TON mnemonic when no password provided', async (t) => {
  const words = await mnemonicNew(24, 'x')
  const mnemonicBytes = Buffer.from(words.join(' '), 'utf8')
  await t.exception(async () => {
    await importMnemonic({
      mnemonic: mnemonicBytes,
      seedDerivation: 'ton',
      validate: true
    })
  }, /invalid mnemonic/)
})

test('importMnemonic rejects basic TON mnemonic when password provided', async (t) => {
  const words = await mnemonicNew(24)
  const mnemonicBytes = Buffer.from(words.join(' '), 'utf8')
  await t.exception(async () => {
    await importMnemonic({
      mnemonic: mnemonicBytes,
      seedDerivation: 'ton',
      password: 'anything',
      validate: true
    })
  }, /invalid mnemonic/)
})

test('createMnemonic rejects password with bip39 seedDerivation', async (t) => {
  await t.exception(async () => {
    await createMnemonic({
      seedDerivation: 'bip39',
      password: 'secret',
      returnMnemonic: true,
      storeMnemonic: false
    })
  }, /password is only supported with TON seed derivation/)
})

test('importMnemonic rejects password with bip39 seedDerivation', async (t) => {
  const mnemonicBytes = Buffer.from(TEST_MNEMONIC, 'utf8')
  await t.exception(async () => {
    await importMnemonic({
      mnemonic: mnemonicBytes,
      seedDerivation: 'bip39',
      password: 'secret',
      validate: true
    })
  }, /password is only supported with TON seed derivation/)
})

test('sign with secretType privateKey - secp256k1', async (t) => {
  const privateKey = secp256k1.utils.randomSecretKey()
  const data = Buffer.from('test message to sign')
  const sig = await sign({
    mnemonic: privateKey,
    curve: 'secp256k1',
    secretType: 'privateKey',
    data
  })
  t.ok(sig instanceof Uint8Array)
  t.is(sig.length, 65)
})

test('sign with secretType privateKey - ed25519', async (t) => {
  const privateKey = ed25519.utils.randomSecretKey()
  const data = Buffer.from('test message to sign')
  const sig = await sign({
    mnemonic: privateKey,
    curve: 'ed25519',
    secretType: 'privateKey',
    data
  })
  t.is(sig.length, 64)
})

test('getPublicKey with secretType privateKey - secp256k1', async (t) => {
  const privateKey = secp256k1.utils.randomSecretKey()
  const pubKey = await getPublicKey({
    mnemonic: privateKey,
    curve: 'secp256k1',
    secretType: 'privateKey'
  })
  const expected = secp256k1.getPublicKey(privateKey, true)
  t.alike(pubKey, expected)
})

test('getPublicKey with secretType privateKey - ed25519', async (t) => {
  const privateKey = ed25519.utils.randomSecretKey()
  const pubKey = await getPublicKey({
    mnemonic: privateKey,
    curve: 'ed25519',
    secretType: 'privateKey'
  })
  const expected = ed25519.getPublicKey(privateKey)
  t.alike(pubKey, expected)
})

test('sign with secretType privateKey verifies correctly - secp256k1', async (t) => {
  const privateKey = secp256k1.utils.randomSecretKey()
  const data = Buffer.from('verify this message')
  const sig = await sign({
    mnemonic: privateKey,
    curve: 'secp256k1',
    secretType: 'privateKey',
    data
  })
  const pubKey = await getPublicKey({
    mnemonic: privateKey,
    curve: 'secp256k1',
    secretType: 'privateKey'
  })
  // Recovery byte is first; compact r,s is bytes 1-64
  // prehash: false must match what sign() uses
  const valid = secp256k1.verify(sig.subarray(1, 65), data, pubKey, { prehash: false })
  t.ok(valid)
})

test('sign with secretType privateKey verifies correctly - ed25519', async (t) => {
  const privateKey = ed25519.utils.randomSecretKey()
  const data = Buffer.from('verify this message')
  const sig = await sign({
    mnemonic: privateKey,
    curve: 'ed25519',
    secretType: 'privateKey',
    data
  })
  const pubKey = await getPublicKey({
    mnemonic: privateKey,
    curve: 'ed25519',
    secretType: 'privateKey'
  })
  const valid = ed25519.verify(sig, data, pubKey)
  t.ok(valid)
})

test('Signer with secretType privateKey - sign and getPublicKey', async (t) => {
  const privateKey = secp256k1.utils.randomSecretKey()
  const s = new Signer({ secretType: 'privateKey' })
  s._secret = Buffer.from(privateKey)

  const data = Buffer.from('signer test message')
  const sig = await s.sign({ curve: 'secp256k1', data })
  t.ok(sig instanceof Uint8Array)
  t.is(sig.length, 65)

  const pubKey = await s.getPublicKey({ curve: 'secp256k1' })
  const expected = secp256k1.getPublicKey(privateKey, true)
  t.alike(pubKey, expected)

  s.lock()
})

// --- Storage tests (skipped when Keychain/KeyStore is not accessible) ---

storageTest('importPrivateKey stores raw bytes, readPrivateKey retrieves them unchanged', async (t) => {
  const name = 'test_pk_roundtrip'
  const privateKey = secp256k1.utils.randomSecretKey()
  await importPrivateKey({ privateKey, name })
  const retrieved = await readPrivateKey({ name })
  t.alike(retrieved, privateKey)
  await deletePrivateKey({ name })
})

storageTest('binary round-trip: 32 bytes with embedded 0x00 survive storage', async (t) => {
  const name = 'test_pk_nullbytes'
  const privateKey = new Uint8Array(32)
  privateKey[0] = 0x00
  privateKey[1] = 0xff
  privateKey[2] = 0x00
  privateKey[3] = 0x00
  privateKey[15] = 0xab
  privateKey[16] = 0x00
  privateKey[31] = 0x01
  await importPrivateKey({ privateKey, name })
  const retrieved = await readPrivateKey({ name })
  t.is(retrieved.length, 32, 'retrieved length must match original')
  t.alike(retrieved, privateKey)
  await deletePrivateKey({ name })
})

storageTest('store two mnemonics under different names, read both back correctly', async (t) => {
  const name1 = 'test_mn_one'
  const name2 = 'test_mn_two'
  const mn1 = Buffer.from(TEST_MNEMONIC, 'utf8')
  const mn2Str = 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'
  const mn2 = Buffer.from(mn2Str, 'utf8')
  await importMnemonic({ mnemonic: mn1, name: name1, validate: true })
  await importMnemonic({ mnemonic: mn2, name: name2, validate: true })
  const read1 = await readMnemonic({ name: name1 })
  const read2 = await readMnemonic({ name: name2 })
  t.is(Buffer.from(read1).toString('utf8'), TEST_MNEMONIC)
  t.is(Buffer.from(read2).toString('utf8'), mn2Str)
  await deleteMnemonic({ name: name1 })
  await deleteMnemonic({ name: name2 })
})

storageTest('deleteMnemonic({ name: x }) removes only that entry', async (t) => {
  const nameA = 'test_del_a'
  const nameB = 'test_del_b'
  const mnA = Buffer.from(TEST_MNEMONIC, 'utf8')
  const mnB = Buffer.from('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong', 'utf8')
  await importMnemonic({ mnemonic: mnA, name: nameA, validate: true })
  await importMnemonic({ mnemonic: mnB, name: nameB, validate: true })
  await deleteMnemonic({ name: nameA })
  const readB = await readMnemonic({ name: nameB })
  t.is(Buffer.from(readB).toString('utf8'), 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong')
  await t.exception(async () => {
    await readMnemonic({ name: nameA })
  })
  await deleteMnemonic({ name: nameB })
})

storageTest('createMnemonic with explicit name stores under that name', async (t) => {
  const name = 'test_create_named'
  await createMnemonic({ wordCount: 12, storeMnemonic: true, name })
  const read = await readMnemonic({ name })
  const words = Buffer.from(read).toString('utf8').split(' ')
  t.is(words.length, 12)
  await deleteMnemonic({ name })
})

storageTest('default names - createMnemonic uses mnemonic, importPrivateKey uses private_key', async (t) => {
  await createMnemonic({ wordCount: 12, storeMnemonic: true })
  const mn = await readMnemonic()
  const words = Buffer.from(mn).toString('utf8').split(' ')
  t.is(words.length, 12)
  await deleteMnemonic()

  const pk = secp256k1.utils.randomSecretKey()
  await importPrivateKey({ privateKey: pk })
  const readPk = await readPrivateKey()
  t.alike(readPk, pk)
  await deletePrivateKey()
})

storageTest('sign/getPublicKey with secretType privateKey reading from storage - secp256k1', async (t) => {
  const name = 'test_stored_pk_secp'
  const privateKey = secp256k1.utils.randomSecretKey()
  await importPrivateKey({ privateKey, name })

  const data = Buffer.from('test stored sign secp256k1')
  const sig = await sign({ curve: 'secp256k1', secretType: 'privateKey', name, data })
  t.ok(sig instanceof Uint8Array)
  t.is(sig.length, 65)

  const pubKey = await getPublicKey({ curve: 'secp256k1', secretType: 'privateKey', name })
  const expected = secp256k1.getPublicKey(privateKey, true)
  t.alike(pubKey, expected)

  const valid = secp256k1.verify(sig.subarray(1, 65), data, pubKey, { prehash: false })
  t.ok(valid)

  await deletePrivateKey({ name })
})

storageTest('sign/getPublicKey with secretType privateKey reading from storage - ed25519', async (t) => {
  const name = 'test_stored_pk_ed'
  const privateKey = ed25519.utils.randomSecretKey()
  await importPrivateKey({ privateKey, name })

  const data = Buffer.from('test stored sign ed25519')
  const sig = await sign({ curve: 'ed25519', secretType: 'privateKey', name, data })
  t.is(sig.length, 64)

  const pubKey = await getPublicKey({ curve: 'ed25519', secretType: 'privateKey', name })
  const expected = ed25519.getPublicKey(privateKey)
  t.alike(pubKey, expected)

  const valid = ed25519.verify(sig, data, pubKey)
  t.ok(valid)

  await deletePrivateKey({ name })
})
