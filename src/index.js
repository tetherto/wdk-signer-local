'use strict'

// Polyfills must be set up before importing modules that need them
import './polyfills.js'

import binding from './binding.js'
import * as bip39 from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { mnemonicToSeedSync } from '@scure/bip39'
import { HDKey } from '@scure/bip32'
import { HDKey as HDKeyEd25519 } from 'micro-key-producer/slip10.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'
import { ed25519 } from '@noble/curves/ed25519.js'
import { mnemonicNew, mnemonicValidate, mnemonicToPrivateKey, mnemonicToHDSeed, deriveEd25519Path } from 'ton-crypto'

/** @param {string} path */
export function parseTonHdPath (path) {
  if (typeof path !== 'string' || !path.startsWith('m/')) {
    throw new Error("TON HD path must start with 'm/'")
  }

  const segments = path.slice(2).split('/')
  if (segments.length === 0 || (segments.length === 1 && segments[0] === '')) {
    throw new Error('TON HD path must have at least one segment')
  }

  const indices = []
  for (const seg of segments) {
    if (!seg.endsWith("'")) {
      throw new Error(`TON HD path segment '${seg}' must be hardened (end with "'")`)
    }
    const raw = seg.slice(0, -1)
    if (!/^\d+$/.test(raw)) {
      throw new Error(`Invalid TON HD path index: '${seg}'`)
    }
    const num = Number(raw)
    if (num >= 0x80000000) {
      throw new Error(`Invalid TON HD path index: '${seg}'`)
    }
    indices.push(num)
  }

  return indices
}

/**
 * @typedef {Object} SignOptions
 * @property {string|Uint8Array} [mnemonic] - When secretType is 'mnemonic': BIP39 phrase.
 *   When secretType is 'privateKey': raw private key bytes (Uint8Array).
 *   If omitted, read from secure storage by name.
 * @property {string} [password=''] - BIP39 passphrase (ignored when secretType is 'privateKey')
 * @property {string} [path="m/44'/60'/0'/0/0"] - Derivation path (ignored when secretType is 'privateKey')
 * @property {'secp256k1'|'ed25519'} [curve='secp256k1'] - Curve to use
 * @property {'bip39'|'ton'|'ton-hd'} [seedDerivation='bip39'] - Seed derivation method (ignored when secretType is 'privateKey')
 * @property {Uint8Array} data - Data to sign
 * @property {string} [name] - Storage entry name (defaults to 'private_key' when secretType is 'privateKey', else 'mnemonic')
 * @property {'mnemonic'|'privateKey'} [secretType='mnemonic'] - Secret type
 * @property {KeychainOptions} [opts={}] - Keychain options
 */

/**
 * @typedef {Object} KeychainOptions
 * @property {string} [service] - Keychain service name (Apple: kSecAttrService)
 * @property {string} [title] - Biometric prompt title
 * @property {'UserPresence'|'BiometryAny'|'BiometryCurrentSet'} [access_control] - Access control (Apple)
 * @property {boolean} [requireBiometric] - Require biometric authentication (Android)
 * @property {boolean} [allowDeviceCredential] - Allow device credential fallback (Android)
 * @property {string} [subtitle] - Biometric prompt subtitle (Android)
 * @property {string} [description] - Biometric prompt description (Android)
 * @property {string} [cancel] - Biometric prompt cancel button text (Android)
 */

/**
 * Sign data with a derived key.
 * @param {SignOptions} options - Sign options
 * @returns {Promise<Uint8Array>} Signature
 */
export async function sign ({
  mnemonic,
  password = '',
  path,
  curve = 'secp256k1',
  seedDerivation = 'bip39',
  data,
  name,
  secretType = 'mnemonic',
  opts = {}
} = {}) {
  if (typeof name === 'undefined') {
    name = secretType === 'privateKey' ? 'private_key' : 'mnemonic'
  }
  if (secretType === 'privateKey') {
    let privateKey = mnemonic
    if (typeof privateKey === 'undefined') {
      privateKey = new Uint8Array(await binding.readData({ ...opts, name }))
    }
    if (curve === 'ed25519') {
      return ed25519.sign(data, privateKey)
    } else if (curve === 'secp256k1') {
      return secp256k1.sign(data, privateKey, { format: 'recovered', prehash: false })
    } else {
      throw new Error(`Unsupported curve: ${curve}`)
    }
  }

  if (seedDerivation !== 'bip39' && seedDerivation !== 'ton' && seedDerivation !== 'ton-hd') {
    throw new Error(`Unsupported seedDerivation: ${seedDerivation}`)
  }

  if (typeof mnemonic === 'undefined') {
    const mnemonicBytes = await binding.readData({ ...opts, name })
    mnemonic = Buffer.from(mnemonicBytes).toString('utf8')
  }

  if (seedDerivation === 'ton') {
    if (curve !== 'ed25519') {
      throw new Error('TON derivation only supports ed25519')
    }
    if (typeof path !== 'undefined') {
      throw new Error('path is not supported for TON standard derivation')
    }
    const words = mnemonic.trim().split(/\s+/)
    const valid = await mnemonicValidate(words, password || undefined)
    if (!valid) throw new Error('invalid mnemonic or password')
    const keyPair = await mnemonicToPrivateKey(words, password)
    const seed = keyPair.secretKey.slice(0, 32)
    return ed25519.sign(data, seed)
  }

  if (seedDerivation === 'ton-hd') {
    if (curve !== 'ed25519') {
      throw new Error('TON HD derivation only supports ed25519')
    }
    if (typeof path === 'undefined') {
      throw new Error('path is required for TON HD derivation')
    }
    const indices = parseTonHdPath(path)
    const words = mnemonic.trim().split(/\s+/)
    const valid = await mnemonicValidate(words, password || undefined)
    if (!valid) throw new Error('invalid mnemonic or password')
    const hdSeed = await mnemonicToHDSeed(words, password)
    const privateKey = await deriveEd25519Path(hdSeed, indices)
    return ed25519.sign(data, privateKey)
  }

  if (typeof path === 'undefined') {
    path = "m/44'/60'/0'/0/0"
  }

  const seed = mnemonicToSeedSync(mnemonic, password)

  if (curve === 'ed25519') {
    const masterKey = HDKeyEd25519.fromMasterSeed(seed)
    const childKey = masterKey.derive(path)
    return ed25519.sign(data, childKey.privateKey)
  } else if (curve === 'secp256k1') {
    const masterKey = HDKey.fromMasterSeed(seed)
    const childKey = masterKey.derive(path)
    // prehash: false is CRITICAL - we receive already-hashed data (keccak256 for ETH, sha256 for BTC)
    // Without this, @noble/curves will sha256 hash it again, producing wrong signatures
    return secp256k1.sign(data, childKey.privateKey, { format: 'recovered', prehash: false })
  } else {
    throw new Error(`Unsupported curve: ${curve}`)
  }
}

/**
 * Get the public key for a derivation path.
 * @param {Object} options - Options
 * @param {string|Uint8Array} [options.mnemonic] - Mnemonic phrase or raw private key bytes
 * @param {string} [options.password=''] - BIP39 passphrase
 * @param {string} [options.path] - Derivation path
 * @param {'secp256k1'|'ed25519'} [options.curve='secp256k1'] - Curve to use
 * @param {'bip39'|'ton'|'ton-hd'} [options.seedDerivation='bip39'] - Seed derivation method
 * @param {string} [options.name] - Storage entry name
 * @param {'mnemonic'|'privateKey'} [options.secretType='mnemonic'] - Secret type
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<Uint8Array>} Public key
 */
export async function getPublicKey ({
  mnemonic,
  password = '',
  path,
  curve = 'secp256k1',
  seedDerivation = 'bip39',
  name,
  secretType = 'mnemonic',
  opts = {}
} = {}) {
  if (typeof name === 'undefined') {
    name = secretType === 'privateKey' ? 'private_key' : 'mnemonic'
  }
  if (secretType === 'privateKey') {
    let privateKey = mnemonic
    if (typeof privateKey === 'undefined') {
      privateKey = new Uint8Array(await binding.readData({ ...opts, name }))
    }
    if (curve === 'ed25519') {
      return ed25519.getPublicKey(privateKey)
    } else if (curve === 'secp256k1') {
      return secp256k1.getPublicKey(privateKey, true)
    } else {
      throw new Error(`Unsupported curve: ${curve}`)
    }
  }

  if (seedDerivation !== 'bip39' && seedDerivation !== 'ton' && seedDerivation !== 'ton-hd') {
    throw new Error(`Unsupported seedDerivation: ${seedDerivation}`)
  }

  if (typeof mnemonic === 'undefined') {
    const mnemonicBytes = await binding.readData({ ...opts, name })
    mnemonic = Buffer.from(mnemonicBytes).toString('utf8')
  }

  if (seedDerivation === 'ton') {
    if (curve !== 'ed25519') {
      throw new Error('TON derivation only supports ed25519')
    }
    if (typeof path !== 'undefined') {
      throw new Error('path is not supported for TON standard derivation')
    }
    const words = mnemonic.trim().split(/\s+/)
    const valid = await mnemonicValidate(words, password || undefined)
    if (!valid) throw new Error('invalid mnemonic or password')
    const keyPair = await mnemonicToPrivateKey(words, password)
    const seed = keyPair.secretKey.slice(0, 32)
    return ed25519.getPublicKey(seed)
  }

  if (seedDerivation === 'ton-hd') {
    if (curve !== 'ed25519') {
      throw new Error('TON HD derivation only supports ed25519')
    }
    if (typeof path === 'undefined') {
      throw new Error('path is required for TON HD derivation')
    }
    const indices = parseTonHdPath(path)
    const words = mnemonic.trim().split(/\s+/)
    const valid = await mnemonicValidate(words, password || undefined)
    if (!valid) throw new Error('invalid mnemonic or password')
    const hdSeed = await mnemonicToHDSeed(words, password)
    const privateKey = await deriveEd25519Path(hdSeed, indices)
    return ed25519.getPublicKey(privateKey)
  }

  if (typeof path === 'undefined') {
    path = "m/44'/60'/0'/0/0"
  }

  const seed = mnemonicToSeedSync(mnemonic, password)

  if (curve === 'ed25519') {
    const masterKey = HDKeyEd25519.fromMasterSeed(seed)
    const childKey = masterKey.derive(path)
    // SLIP-0010 HDKey returns 33-byte keys (0x00 prefix); strip to standard 32-byte ed25519 format
    const raw = new Uint8Array(childKey.publicKey)
    return raw.length === 33 && raw[0] === 0x00 ? raw.subarray(1) : raw
  } else if (curve === 'secp256k1') {
    const masterKey = HDKey.fromMasterSeed(seed)
    const childKey = masterKey.derive(path)
    return new Uint8Array(childKey.publicKey)
  } else {
    throw new Error(`Unsupported curve: ${curve}`)
  }
}

/**
 * Create a new mnemonic.
 * @param {Object} options - Options
 * @param {number} [options.wordCount=12] - Number of words
 * @param {boolean} [options.returnMnemonic=false] - Return mnemonic bytes
 * @param {boolean} [options.storeMnemonic=true] - Store in keychain
 * @param {string} [options.name='mnemonic'] - Storage entry name
 * @param {'bip39'|'ton'|'ton-hd'} [options.seedDerivation='bip39'] - Seed derivation method
 * @param {string} [options.password=''] - If non-empty, generates a password-protected TON mnemonic
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<Uint8Array>} Mnemonic bytes if returnMnemonic is true
 */
export async function createMnemonic ({
  wordCount = 12,
  returnMnemonic = false,
  storeMnemonic = true,
  name = 'mnemonic',
  seedDerivation = 'bip39',
  password = '',
  opts = {}
} = {}) {
  let mnemonic

  if (seedDerivation !== 'bip39' && seedDerivation !== 'ton' && seedDerivation !== 'ton-hd') {
    throw new Error(`Unsupported seedDerivation: ${seedDerivation}`)
  }

  if (password && seedDerivation === 'bip39') {
    throw new Error('password is only supported with TON seed derivation')
  }

  const validWordCounts = [12, 15, 18, 21, 24]
  if (!validWordCounts.includes(wordCount)) {
    throw new Error('wordCount must be 12, 15, 18, 21, or 24')
  }

  if (seedDerivation === 'ton' || seedDerivation === 'ton-hd') {
    const words = await mnemonicNew(wordCount, password || undefined)
    mnemonic = words.join(' ')
  } else {
    const strengthMap = {
      12: 128,
      15: 160,
      18: 192,
      21: 224,
      24: 256
    }

    const strength = strengthMap[wordCount]

    mnemonic = bip39.generateMnemonic(wordlist, strength)
  }

  if (storeMnemonic) {
    const mnemonicBytes = Buffer.from(mnemonic, 'utf8')
    await binding.storeData(mnemonicBytes.buffer, mnemonicBytes.byteOffset, mnemonicBytes.byteLength, { ...opts, name })
  }

  if (returnMnemonic) {
    return Buffer.from(mnemonic, 'utf8')
  }

  return new Uint8Array(0)
}

/**
 * Delete stored mnemonic.
 * @param {Object} options - Options
 * @param {string} [options.name='mnemonic'] - Storage entry name
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<void>}
 */
export function deleteMnemonic ({ name = 'mnemonic', opts = {} } = {}) {
  return binding.deleteData({ ...opts, name })
}

/**
 * Read stored mnemonic.
 * @param {Object} options - Options
 * @param {string} [options.name='mnemonic'] - Storage entry name
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<Uint8Array>}
 */
export function readMnemonic ({ name = 'mnemonic', opts = {} } = {}) {
  return binding.readData({ ...opts, name })
    .then(arrayBuffer => new Uint8Array(arrayBuffer))
}

/**
 * Import a mnemonic to secure storage.
 * @param {Object} options - Options
 * @param {Uint8Array} options.mnemonic - Mnemonic bytes
 * @param {string} [options.name='mnemonic'] - Storage entry name
 * @param {boolean} [options.validate=true] - Validate mnemonic
 * @param {'bip39'|'ton'|'ton-hd'} [options.seedDerivation='bip39'] - Seed derivation method
 * @param {string} [options.password=''] - Password for TON mnemonic; if non-empty, validates as password-protected
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<void>}
 */
export async function importMnemonic ({
  mnemonic,
  name = 'mnemonic',
  validate = true,
  seedDerivation = 'bip39',
  password = '',
  opts = {}
} = {}) {
  if (!mnemonic || !(mnemonic instanceof Uint8Array)) {
    throw new Error('mnemonic must be a Uint8Array')
  }

  if (seedDerivation !== 'bip39' && seedDerivation !== 'ton' && seedDerivation !== 'ton-hd') {
    throw new Error(`Unsupported seedDerivation: ${seedDerivation}`)
  }

  if (password && seedDerivation === 'bip39') {
    throw new Error('password is only supported with TON seed derivation')
  }

  if (validate) {
    const mnemonicStr = Buffer.from(mnemonic).toString('utf8')

    if (seedDerivation === 'ton' || seedDerivation === 'ton-hd') {
      const words = mnemonicStr.trim().split(/\s+/)
      const valid = await mnemonicValidate(words, password || undefined)
      if (!valid) {
        throw new Error('invalid mnemonic')
      }
    } else {
      if (!bip39.validateMnemonic(mnemonicStr, wordlist)) {
        throw new Error('invalid mnemonic')
      }
    }
  }

  return binding.storeData(mnemonic.buffer, mnemonic.byteOffset, mnemonic.byteLength, { ...opts, name })
}

/**
 * Import a raw private key to secure storage.
 * @param {Object} options - Options
 * @param {Uint8Array} options.privateKey - Raw private key bytes
 * @param {string} [options.name='private_key'] - Storage entry name
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<void>}
 */
export function importPrivateKey ({
  privateKey,
  name = 'private_key',
  opts = {}
} = {}) {
  if (!privateKey || !(privateKey instanceof Uint8Array)) {
    return Promise.reject(new Error('privateKey must be a Uint8Array'))
  }

  return binding.storeData(privateKey.buffer, privateKey.byteOffset, privateKey.byteLength, { ...opts, name })
}

/**
 * Read a stored private key.
 * @param {Object} options - Options
 * @param {string} [options.name='private_key'] - Storage entry name
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<Uint8Array>}
 */
export function readPrivateKey ({ name = 'private_key', opts = {} } = {}) {
  return binding.readData({ ...opts, name })
    .then(arrayBuffer => new Uint8Array(arrayBuffer))
}

/**
 * Delete a stored private key.
 * @param {Object} options - Options
 * @param {string} [options.name='private_key'] - Storage entry name
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<void>}
 */
export function deletePrivateKey ({ name = 'private_key', opts = {} } = {}) {
  return binding.deleteData({ ...opts, name })
}

/**
 * Stateful signer with auto-lock support.
 */
export class Signer {
  /**
   * @param {Object} options - Options
   * @param {(opts: KeychainOptions) => Promise<Uint8Array>} [options.mnemonicGetter] - Custom async function to retrieve the secret
   * @param {number} [options.autoLockMs=30000] - Auto-lock timeout in ms
   * @param {string} [options.name='mnemonic'] - Storage entry name
   * @param {'mnemonic'|'privateKey'} [options.secretType='mnemonic'] - Secret type
   * @param {KeychainOptions} [options.opts={}] - Keychain options
   */
  constructor ({
    mnemonicGetter,
    autoLockMs = 30000,
    name,
    secretType = 'mnemonic',
    opts = {}
  } = {}) {
    this._autoLockMs = autoLockMs
    this._name = typeof name === 'undefined'
      ? (secretType === 'privateKey' ? 'private_key' : 'mnemonic')
      : name
    this._secretType = secretType
    this._opts = opts
    this._secret = null
    this._autoLockTimer = null
    this._mnemonicGetter = mnemonicGetter || null
  }

  /** @private */
  async _ensureUnlocked () {
    if (!this._secret) {
      if (this._mnemonicGetter) {
        const result = await this._mnemonicGetter(this._opts)
        this._secret = Buffer.from(result)
      } else {
        const bytes = await binding.readData({ ...this._opts, name: this._name })
        this._secret = Buffer.from(bytes)
      }
    }
    this._resetAutoLockTimer()
  }

  /** @private */
  _resetAutoLockTimer () {
    if (this._autoLockTimer) {
      clearTimeout(this._autoLockTimer)
      this._autoLockTimer = null
    }
    if (this._autoLockMs > 0) {
      this._autoLockTimer = setTimeout(() => this.lock(), this._autoLockMs)
    }
  }

  /**
   * Lock the signer and clear secret material.
   */
  lock () {
    if (this._autoLockTimer) {
      clearTimeout(this._autoLockTimer)
      this._autoLockTimer = null
    }
    if (this._secret) {
      this._secret.fill(0)
      this._secret = null
    }
  }

  /**
   * Check if the signer is unlocked.
   * @returns {boolean}
   */
  isUnlocked () {
    return this._secret !== null
  }

  /**
   * Read the stored secret (mnemonic bytes or private key, depending on secretType).
   * @returns {Promise<Uint8Array>}
   */
  async readSecret () {
    await this._ensureUnlocked()
    return new Uint8Array(this._secret)
  }

  /** @returns {Promise<Uint8Array>} */
  async readMnemonic () {
    return this.readSecret()
  }

  /**
   * Sign data.
   * @param {Object} options - Sign options
   * @param {string} [options.password=''] - Passphrase
   * @param {string} [options.path] - Derivation path
   * @param {'secp256k1'|'ed25519'} [options.curve='secp256k1'] - Curve
   * @param {'bip39'|'ton'|'ton-hd'} [options.seedDerivation='bip39'] - Seed derivation method
   * @param {Uint8Array} options.data - Data to sign
   * @returns {Promise<Uint8Array>}
   */
  async sign ({
    password = '',
    path,
    curve = 'secp256k1',
    seedDerivation = 'bip39',
    data
  } = {}) {
    await this._ensureUnlocked()

    if (this._secretType === 'privateKey') {
      const privateKey = new Uint8Array(this._secret)
      if (curve === 'ed25519') {
        return ed25519.sign(data, privateKey)
      } else if (curve === 'secp256k1') {
        return secp256k1.sign(data, privateKey, { format: 'recovered', prehash: false })
      } else {
        throw new Error(`Unsupported curve: ${curve}`)
      }
    }

    if (seedDerivation !== 'bip39' && seedDerivation !== 'ton' && seedDerivation !== 'ton-hd') {
      throw new Error(`Unsupported seedDerivation: ${seedDerivation}`)
    }

    if (seedDerivation === 'ton') {
      if (curve !== 'ed25519') {
        throw new Error('TON derivation only supports ed25519')
      }
      if (typeof path !== 'undefined') {
        throw new Error('path is not supported for TON standard derivation')
      }
      const words = this._secret.toString('utf8').trim().split(/\s+/)
      const valid = await mnemonicValidate(words, password || undefined)
      if (!valid) throw new Error('invalid mnemonic or password')
      const keyPair = await mnemonicToPrivateKey(words, password)
      const seed = keyPair.secretKey.slice(0, 32)
      return ed25519.sign(data, seed)
    }

    if (seedDerivation === 'ton-hd') {
      if (curve !== 'ed25519') {
        throw new Error('TON HD derivation only supports ed25519')
      }
      if (typeof path === 'undefined') {
        throw new Error('path is required for TON HD derivation')
      }
      const indices = parseTonHdPath(path)
      const words = this._secret.toString('utf8').trim().split(/\s+/)
      const valid = await mnemonicValidate(words, password || undefined)
      if (!valid) throw new Error('invalid mnemonic or password')
      const hdSeed = await mnemonicToHDSeed(words, password)
      const privateKey = await deriveEd25519Path(hdSeed, indices)
      return ed25519.sign(data, privateKey)
    }

    if (typeof path === 'undefined') {
      path = "m/44'/60'/0'/0/0"
    }

    const seed = mnemonicToSeedSync(this._secret.toString('utf8'), password)
    if (curve === 'ed25519') {
      const masterKey = HDKeyEd25519.fromMasterSeed(seed)
      const childKey = masterKey.derive(path)
      return ed25519.sign(data, childKey.privateKey)
    } else if (curve === 'secp256k1') {
      const masterKey = HDKey.fromMasterSeed(seed)
      const childKey = masterKey.derive(path)
      // prehash: false - data is already hashed (keccak256 for ETH, sha256 for BTC)
      return secp256k1.sign(data, childKey.privateKey, { format: 'recovered', prehash: false })
    } else {
      throw new Error(`Unsupported curve: ${curve}`)
    }
  }

  /**
   * Get public key.
   * @param {Object} options - Options
   * @param {string} [options.password=''] - Passphrase
   * @param {string} [options.path] - Derivation path
   * @param {'secp256k1'|'ed25519'} [options.curve='secp256k1'] - Curve
   * @param {'bip39'|'ton'|'ton-hd'} [options.seedDerivation='bip39'] - Seed derivation method
   * @returns {Promise<Uint8Array>}
   */
  async getPublicKey ({
    password = '',
    path,
    curve = 'secp256k1',
    seedDerivation = 'bip39'
  } = {}) {
    await this._ensureUnlocked()

    if (this._secretType === 'privateKey') {
      const privateKey = new Uint8Array(this._secret)
      if (curve === 'ed25519') {
        return ed25519.getPublicKey(privateKey)
      } else if (curve === 'secp256k1') {
        return secp256k1.getPublicKey(privateKey, true)
      } else {
        throw new Error(`Unsupported curve: ${curve}`)
      }
    }

    if (seedDerivation !== 'bip39' && seedDerivation !== 'ton' && seedDerivation !== 'ton-hd') {
      throw new Error(`Unsupported seedDerivation: ${seedDerivation}`)
    }

    if (seedDerivation === 'ton') {
      if (curve !== 'ed25519') {
        throw new Error('TON derivation only supports ed25519')
      }
      if (typeof path !== 'undefined') {
        throw new Error('path is not supported for TON standard derivation')
      }
      const words = this._secret.toString('utf8').trim().split(/\s+/)
      const valid = await mnemonicValidate(words, password || undefined)
      if (!valid) throw new Error('invalid mnemonic or password')
      const keyPair = await mnemonicToPrivateKey(words, password)
      const seed = keyPair.secretKey.slice(0, 32)
      return ed25519.getPublicKey(seed)
    }

    if (seedDerivation === 'ton-hd') {
      if (curve !== 'ed25519') {
        throw new Error('TON HD derivation only supports ed25519')
      }
      if (typeof path === 'undefined') {
        throw new Error('path is required for TON HD derivation')
      }
      const indices = parseTonHdPath(path)
      const words = this._secret.toString('utf8').trim().split(/\s+/)
      const valid = await mnemonicValidate(words, password || undefined)
      if (!valid) throw new Error('invalid mnemonic or password')
      const hdSeed = await mnemonicToHDSeed(words, password)
      const privateKey = await deriveEd25519Path(hdSeed, indices)
      return ed25519.getPublicKey(privateKey)
    }

    if (typeof path === 'undefined') {
      path = "m/44'/60'/0'/0/0"
    }

    const seed = mnemonicToSeedSync(this._secret.toString('utf8'), password)
    if (curve === 'ed25519') {
      const masterKey = HDKeyEd25519.fromMasterSeed(seed)
      const childKey = masterKey.derive(path)
      const raw = new Uint8Array(childKey.publicKey)
      return raw.length === 33 && raw[0] === 0x00 ? raw.subarray(1) : raw
    } else if (curve === 'secp256k1') {
      const masterKey = HDKey.fromMasterSeed(seed)
      const childKey = masterKey.derive(path)
      return new Uint8Array(childKey.publicKey)
    } else {
      throw new Error(`Unsupported curve: ${curve}`)
    }
  }
}

export default Signer
