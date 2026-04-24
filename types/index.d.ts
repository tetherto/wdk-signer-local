/** @param {string} path */
export function parseTonHdPath(path: string): number[];
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
export function sign({ mnemonic, password, path, curve, seedDerivation, data, name, secretType, opts }?: SignOptions): Promise<Uint8Array>;
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
export function getPublicKey({ mnemonic, password, path, curve, seedDerivation, name, secretType, opts }?: {
    mnemonic?: string | Uint8Array;
    password?: string;
    path?: string;
    curve?: "secp256k1" | "ed25519";
    seedDerivation?: "bip39" | "ton" | "ton-hd";
    name?: string;
    secretType?: "mnemonic" | "privateKey";
    opts?: KeychainOptions;
}): Promise<Uint8Array>;
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
export function createMnemonic({ wordCount, returnMnemonic, storeMnemonic, name, seedDerivation, password, opts }?: {
    wordCount?: number;
    returnMnemonic?: boolean;
    storeMnemonic?: boolean;
    name?: string;
    seedDerivation?: "bip39" | "ton" | "ton-hd";
    password?: string;
    opts?: KeychainOptions;
}): Promise<Uint8Array>;
/**
 * Delete stored mnemonic.
 * @param {Object} options - Options
 * @param {string} [options.name='mnemonic'] - Storage entry name
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<void>}
 */
export function deleteMnemonic({ name, opts }?: {
    name?: string;
    opts?: KeychainOptions;
}): Promise<void>;
/**
 * Read stored mnemonic.
 * @param {Object} options - Options
 * @param {string} [options.name='mnemonic'] - Storage entry name
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<Uint8Array>}
 */
export function readMnemonic({ name, opts }?: {
    name?: string;
    opts?: KeychainOptions;
}): Promise<Uint8Array>;
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
export function importMnemonic({ mnemonic, name, validate, seedDerivation, password, opts }?: {
    mnemonic: Uint8Array;
    name?: string;
    validate?: boolean;
    seedDerivation?: "bip39" | "ton" | "ton-hd";
    password?: string;
    opts?: KeychainOptions;
}): Promise<void>;
/**
 * Import a raw private key to secure storage.
 * @param {Object} options - Options
 * @param {Uint8Array} options.privateKey - Raw private key bytes
 * @param {string} [options.name='private_key'] - Storage entry name
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<void>}
 */
export function importPrivateKey({ privateKey, name, opts }?: {
    privateKey: Uint8Array;
    name?: string;
    opts?: KeychainOptions;
}): Promise<void>;
/**
 * Read a stored private key.
 * @param {Object} options - Options
 * @param {string} [options.name='private_key'] - Storage entry name
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<Uint8Array>}
 */
export function readPrivateKey({ name, opts }?: {
    name?: string;
    opts?: KeychainOptions;
}): Promise<Uint8Array>;
/**
 * Delete a stored private key.
 * @param {Object} options - Options
 * @param {string} [options.name='private_key'] - Storage entry name
 * @param {KeychainOptions} [options.opts={}] - Keychain options
 * @returns {Promise<void>}
 */
export function deletePrivateKey({ name, opts }?: {
    name?: string;
    opts?: KeychainOptions;
}): Promise<void>;
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
    constructor({ mnemonicGetter, autoLockMs, name, secretType, opts }?: {
        mnemonicGetter?: (opts: KeychainOptions) => Promise<Uint8Array>;
        autoLockMs?: number;
        name?: string;
        secretType?: "mnemonic" | "privateKey";
        opts?: KeychainOptions;
    });
    _autoLockMs: number;
    _name: string;
    _secretType: "mnemonic" | "privateKey";
    _opts: KeychainOptions;
    _secret: any;
    _autoLockTimer: number;
    _mnemonicGetter: (opts: KeychainOptions) => Promise<Uint8Array>;
    /** @private */
    private _ensureUnlocked;
    /** @private */
    private _resetAutoLockTimer;
    /**
     * Lock the signer and clear secret material.
     */
    lock(): void;
    /**
     * Check if the signer is unlocked.
     * @returns {boolean}
     */
    isUnlocked(): boolean;
    /**
     * Read the stored secret (mnemonic bytes or private key, depending on secretType).
     * @returns {Promise<Uint8Array>}
     */
    readSecret(): Promise<Uint8Array>;
    /** @returns {Promise<Uint8Array>} */
    readMnemonic(): Promise<Uint8Array>;
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
    sign({ password, path, curve, seedDerivation, data }?: {
        password?: string;
        path?: string;
        curve?: "secp256k1" | "ed25519";
        seedDerivation?: "bip39" | "ton" | "ton-hd";
        data: Uint8Array;
    }): Promise<Uint8Array>;
    /**
     * Get public key.
     * @param {Object} options - Options
     * @param {string} [options.password=''] - Passphrase
     * @param {string} [options.path] - Derivation path
     * @param {'secp256k1'|'ed25519'} [options.curve='secp256k1'] - Curve
     * @param {'bip39'|'ton'|'ton-hd'} [options.seedDerivation='bip39'] - Seed derivation method
     * @returns {Promise<Uint8Array>}
     */
    getPublicKey({ password, path, curve, seedDerivation }?: {
        password?: string;
        path?: string;
        curve?: "secp256k1" | "ed25519";
        seedDerivation?: "bip39" | "ton" | "ton-hd";
    }): Promise<Uint8Array>;
}
export default Signer;
export type SignOptions = {
    /**
     * - When secretType is 'mnemonic': BIP39 phrase.
     * When secretType is 'privateKey': raw private key bytes (Uint8Array).
     * If omitted, read from secure storage by name.
     */
    mnemonic?: string | Uint8Array;
    /**
     * - BIP39 passphrase (ignored when secretType is 'privateKey')
     */
    password?: string;
    /**
     * - Derivation path (ignored when secretType is 'privateKey')
     */
    path?: string;
    /**
     * - Curve to use
     */
    curve?: "secp256k1" | "ed25519";
    /**
     * - Seed derivation method (ignored when secretType is 'privateKey')
     */
    seedDerivation?: "bip39" | "ton" | "ton-hd";
    /**
     * - Data to sign
     */
    data: Uint8Array;
    /**
     * - Storage entry name (defaults to 'private_key' when secretType is 'privateKey', else 'mnemonic')
     */
    name?: string;
    /**
     * - Secret type
     */
    secretType?: "mnemonic" | "privateKey";
    /**
     * - Keychain options
     */
    opts?: KeychainOptions;
};
export type KeychainOptions = {
    /**
     * - Keychain service name (Apple: kSecAttrService)
     */
    service?: string;
    /**
     * - Biometric prompt title
     */
    title?: string;
    /**
     * - Access control (Apple)
     */
    access_control?: "UserPresence" | "BiometryAny" | "BiometryCurrentSet";
    /**
     * - Require biometric authentication (Android)
     */
    requireBiometric?: boolean;
    /**
     * - Allow device credential fallback (Android)
     */
    allowDeviceCredential?: boolean;
    /**
     * - Biometric prompt subtitle (Android)
     */
    subtitle?: string;
    /**
     * - Biometric prompt description (Android)
     */
    description?: string;
    /**
     * - Biometric prompt cancel button text (Android)
     */
    cancel?: string;
};
