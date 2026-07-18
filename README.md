# wdk-signer-local

A Bare native addon for secure mnemonic and private key storage with cryptographic signing using HD wallets (BIP-32/BIP-39/SLIP-10/TON).

## Features

- Named multi-entry storage: store multiple mnemonics and private keys under distinct names
- Secure storage using platform keychain (iOS/macOS) and Android KeyStore with biometric protection
- Raw private key import/export with direct signing (no HD derivation)
- HD key derivation using industry-standard libraries:
  - BIP-32/BIP-39 via [@scure/bip32](https://github.com/paulmillr/scure-bip32) and [@scure/bip39](https://github.com/paulmillr/scure-bip39)
  - SLIP-10 via [micro-key-producer](https://github.com/paulmillr/micro-key-producer)
- TON blockchain support via [ton-crypto](https://github.com/ton-community/ton-crypto):
  - Standard TON key derivation (`seedDerivation: 'ton'`)
  - TON HD key derivation with hardened paths (`seedDerivation: 'ton-hd'`)
  - Password-protected TON mnemonic generation and validation
- Signing with secp256k1 and ed25519 curves via [@noble/curves](https://github.com/paulmillr/noble-curves)
- `Signer` class for caching unlocked secrets with auto-lock
- Pure JavaScript cryptographic operations (no universal-signer dependency)

## Installation

The package is published to GitHub Packages as
`@tetherto/wdk-signer-local`. See
[Publishing](#publishing) below for the one-time `.npmrc` setup required
to authenticate against GitHub Packages, then install with:

```console
npm install @tetherto/wdk-signer-local@beta
```

## Building

This package requires building the native addon before use. The project uses [@noble/curves](https://github.com/paulmillr/noble-curves), [@scure/bip32](https://github.com/paulmillr/scure-bip32), [@scure/bip39](https://github.com/paulmillr/scure-bip39), and [micro-key-producer](https://github.com/paulmillr/micro-key-producer) for cryptographic operations.

### Prerequisites

- Node.js and npm
- [bare-make](https://github.com/holepunchto/bare-make) for building native addons
- Platform-specific build tools:
  - macOS: Xcode Command Line Tools
  - iOS: Xcode with iOS SDK
  - Android: Android NDK

### Quick Build

For a quick build of all iOS and macOS targets, use the provided build script:

```console
./rebuild.sh
```

This script will build:

- iOS arm64 (device)
- iOS arm64 simulator
- macOS arm64 (darwin)

### Manual Build Steps

1. **Install dependencies:**

   ```console
   npm install
   ```

2. **Generate the build system:**

   ```console
   npx bare-make generate
   ```

   Optional flags:
   - `--debug` - Enable debug symbols and assertions
   - `--platform <platform>` - Target platform (darwin, ios, android)
   - `--arch <arch>` - Target architecture (arm64, x64, arm, ia32)
   - `--simulator` - Build for iOS simulator
   - `-b <dir>` - Custom build directory

3. **Build the addon:**

   ```console
   npx bare-make build
   ```

   Add `-b <dir>` if you used a custom build directory.

4. **Install the built addon:**

   ```console
   npx bare-make install --link
   ```

   The `--link` flag creates a symlink instead of copying, useful during development.

### Multi-Platform Builds

To build for specific platforms:

```console
# macOS ARM64
npx bare-make generate --platform darwin --arch arm64 -b build/darwin-arm64
npx bare-make build -b build/darwin-arm64
npx bare-make install --link -b build/darwin-arm64

# iOS ARM64 (device)
npx bare-make generate --platform ios --arch arm64 -b build/ios-arm64
npx bare-make build -b build/ios-arm64
npx bare-make install --link -b build/ios-arm64

# iOS ARM64 (simulator)
npx bare-make generate --platform ios --arch arm64 --simulator -b build/ios-sim-arm64
npx bare-make build -b build/ios-sim-arm64
npx bare-make install --link -b build/ios-sim-arm64

# Android ARM64
export ANDROID_HOME=${HOME}/Library/Android/sdk
npx bare-make generate --platform android --arch arm64 -b build/android-arm64
npx bare-make build -b build/android-arm64
npx bare-make install --link -b build/android-arm64
```

### Rebuilding

If you update `bare-make` or your compiler toolchain, regenerate the build system:

```console
npx bare-make generate --no-cache
```

### Running Tests

After building, run the test suite:

```console
npm test
```

All tests must pass before publishing.

## API

### Standalone Functions

These functions read from the keychain on each call, requiring biometric authentication every time.

#### `createMnemonic(options)`

Creates a new mnemonic and optionally stores it in the system keychain. Generates BIP-39 mnemonics by default, or TON-compatible mnemonics when `seedDerivation` is `'ton'` or `'ton-hd'`.

```js
const signer = require('@tetherto/wdk-signer-local')

// Create and store a 12-word BIP-39 mnemonic
await signer.createMnemonic()

// Create a 24-word mnemonic and return it
const mnemonic = await signer.createMnemonic({
  wordCount: 24,
  returnMnemonic: true
})

// Create a TON mnemonic
const tonMnemonic = await signer.createMnemonic({
  seedDerivation: 'ton',
  returnMnemonic: true
})

// Create a password-protected TON mnemonic
const protectedMnemonic = await signer.createMnemonic({
  seedDerivation: 'ton',
  password: 'my-secret-password',
  returnMnemonic: true
})
```

**Options:**

- `wordCount` - Number of words: 12, 15, 18, 21, or 24 (default: 12)
- `returnMnemonic` - Return the mnemonic as a `Uint8Array` (default: false)
- `storeMnemonic` - Store in system keychain (default: true)
- `name` - Storage entry name (default: "mnemonic")
- `seedDerivation` - `"bip39"`, `"ton"`, or `"ton-hd"` (default: "bip39"). When `"ton"` or `"ton-hd"`, generates a TON-compatible mnemonic using `ton-crypto` instead of BIP-39.
- `password` - When provided with `seedDerivation` `"ton"` or `"ton-hd"`, generates a password-protected TON mnemonic compatible with external TON wallets. Not supported with BIP-39 (throws an error).
- `opts.service` - Keychain service name (default: "bare-signer-service")
- `opts.access_control` - Biometric requirement (iOS/macOS):
  - `"UserPresence"` - Device passcode or biometrics (default)
  - `"BiometryAny"` - Any enrolled biometric
  - `"BiometryCurrentSet"` - Current enrolled biometrics only

#### `importMnemonic(options)`

Imports an existing mnemonic into the system keychain. Validates as BIP-39 by default, or as a TON mnemonic when `seedDerivation` is `'ton'` or `'ton-hd'`.

```js
const mnemonic = Buffer.from('abandon abandon abandon ...', 'utf8')
await signer.importMnemonic({ mnemonic })

// Import a TON mnemonic
await signer.importMnemonic({
  mnemonic: tonMnemonicBytes,
  seedDerivation: 'ton'
})

// Import a password-protected TON mnemonic
await signer.importMnemonic({
  mnemonic: protectedMnemonicBytes,
  seedDerivation: 'ton',
  password: 'my-secret-password'
})
```

**Options:**

- `mnemonic` - `Uint8Array` containing the mnemonic (required)
- `validate` - Validate mnemonic before storing (default: true)
- `name` - Storage entry name (default: "mnemonic")
- `seedDerivation` - `"bip39"`, `"ton"`, or `"ton-hd"` (default: "bip39"). When `"ton"` or `"ton-hd"`, validates using `ton-crypto` instead of BIP-39 checksum.
- `password` - When provided with `seedDerivation` `"ton"` or `"ton-hd"`, validates the mnemonic as password-protected using the given password. Not supported with BIP-39 (throws an error).
- `opts` - Keychain options (same as `createMnemonic`)

#### `readMnemonic(options)`

Reads the mnemonic from the system keychain.

```js
const mnemonic = await signer.readMnemonic({
  opts: { title: 'Authenticate to read wallet' }
})
```

**Options:**

- `name` - Storage entry name (default: "mnemonic")
- `opts.service` - Keychain service name
- `opts.title` - Biometric prompt title (iOS/macOS)

**Returns:** `Uint8Array`

#### `deleteMnemonic(options)`

Deletes the mnemonic from the system keychain.

```js
await signer.deleteMnemonic()
```

**Options:**

- `name` - Storage entry name (default: "mnemonic")
- `opts` - Keychain options

#### `importPrivateKey(options)`

Imports a raw private key into secure storage.

```js
const privateKey = secp256k1.utils.randomSecretKey()
await signer.importPrivateKey({ privateKey, name: 'my_key' })
```

**Options:**

- `privateKey` - `Uint8Array` containing the private key (required)
- `name` - Storage entry name (default: "private_key")
- `opts` - Keychain options

#### `readPrivateKey(options)`

Reads a private key from secure storage.

```js
const key = await signer.readPrivateKey({ name: 'my_key' })
```

**Options:**

- `name` - Storage entry name (default: "private_key")
- `opts` - Keychain options

**Returns:** `Uint8Array`

#### `deletePrivateKey(options)`

Deletes a private key from secure storage.

```js
await signer.deletePrivateKey({ name: 'my_key' })
```

**Options:**

- `name` - Storage entry name (default: "private_key")
- `opts` - Keychain options

#### `sign(options)`

Signs data using a derived key.

```js
const signature = await signer.sign({
  data: messageHash,
  path: "m/44'/60'/0'/0/0",
  curve: 'secp256k1'
})
```

**Options:**

- `mnemonic` - Use this mnemonic (or private key when `secretType` is `"privateKey"`) instead of reading from storage
- `password` - BIP-39 passphrase (default: '', ignored when `secretType` is `"privateKey"`). When `seedDerivation` is `"ton"` or `"ton-hd"`, used as the TON mnemonic password for password-protected mnemonics.
- `path` - Derivation path (default: "m/44'/60'/0'/0/0", ignored when `secretType` is `"privateKey"`)
- `curve` - `"secp256k1"` or `"ed25519"` (default: "secp256k1")
- `seedDerivation` - `"bip39"`, `"ton"`, or `"ton-hd"` (default: "bip39"). When `"ton"`, uses TON-specific seed derivation via `ton-crypto` (no HD path). When `"ton-hd"`, uses TON HD derivation with hardened paths. Both require `curve: "ed25519"`.
- `data` - Data to sign
- `name` - Storage entry name (default: "mnemonic")
- `secretType` - `"mnemonic"` or `"privateKey"` (default: "mnemonic")
- `opts` - Keychain options for reading from storage

#### `getPublicKey(options)`

Gets the public key for a derived key.

```js
const pubkey = await signer.getPublicKey({
  path: "m/44'/60'/0'/0/0",
  curve: 'secp256k1'
})
```

**Options:** Same as `sign()` except `data`.

#### TON examples

```js
// Standard TON signing (no derivation path)
const signature = await signer.sign({
  data: messageHash,
  curve: 'ed25519',
  seedDerivation: 'ton'
})

const pubkey = await signer.getPublicKey({
  curve: 'ed25519',
  seedDerivation: 'ton'
})

// TON HD signing (with hardened derivation path)
const hdSignature = await signer.sign({
  data: messageHash,
  curve: 'ed25519',
  seedDerivation: 'ton-hd',
  path: "m/0'/1'/2'"
})

const hdPubkey = await signer.getPublicKey({
  curve: 'ed25519',
  seedDerivation: 'ton-hd',
  path: "m/0'/1'/2'"
})

// TON signing with password-protected mnemonic
const sig = await signer.sign({
  data: messageHash,
  curve: 'ed25519',
  seedDerivation: 'ton',
  password: 'my-secret-password'
})
```

**Returns:** `Uint8Array`

### Signer Class

The `Signer` class caches the unlocked secret (mnemonic or private key) in memory, allowing multiple signing operations with a single biometric authentication. The secret is automatically locked after a timeout.

```js
const { Signer } = require('bare-signer')

const signer = new Signer({ autoLockMs: 30000 })

// First call triggers biometric auth, subsequent calls use cached mnemonic
const sig1 = await signer.sign({ data: hash1 })
const sig2 = await signer.sign({ data: hash2 })

// Manually lock when done
signer.lock()
```

#### `new Signer(options)`

**Options:**

- `mnemonicGetter` - Custom async function `(opts) => Uint8Array` to retrieve the mnemonic. When provided, this is used instead of the native keychain binding.
- `autoLockMs` - Auto-lock timeout in milliseconds (default: 30000). Set to `0` to disable auto-lock.
- `name` - Storage entry name (default: "mnemonic")
- `secretType` - `"mnemonic"` or `"privateKey"` (default: "mnemonic")
- `opts` - Keychain options reused for all operations

#### `signer.sign(options)`

Signs data using the cached mnemonic.

**Options:**

- `password` - BIP-39 passphrase (default: ''). When `seedDerivation` is `"ton"` or `"ton-hd"`, used as the TON mnemonic password for password-protected mnemonics.
- `path` - Derivation path (default: "m/44'/60'/0'/0/0")
- `curve` - `"secp256k1"` or `"ed25519"` (default: "secp256k1")
- `seedDerivation` - `"bip39"`, `"ton"`, or `"ton-hd"` (default: "bip39")
- `data` - Data to sign

#### `signer.getPublicKey(options)`

Gets the public key using the cached mnemonic.

**Options:** Same as `sign()` except `data`.

#### `signer.readSecret()`

Returns the cached secret (mnemonic or private key) as a `Uint8Array`.

#### `signer.readMnemonic()`

Alias for `readSecret()`. Returns the cached secret as a `Uint8Array`.

#### `signer.lock()`

Clears the cached secret from memory (zeroes the buffer).

#### `signer.isUnlocked()`

Returns `true` if the secret is currently cached.

## Dependencies

This project uses the following cryptographic libraries from Paul Miller ([@paulmillr](https://github.com/paulmillr)):

- **[@noble/curves](https://github.com/paulmillr/noble-curves)** - Audited, minimal elliptic curve cryptography
  - Used for secp256k1 and ed25519 signing operations
- **[@scure/bip32](https://github.com/paulmillr/scure-bip32)** - BIP-32 HD key derivation
  - Implements hierarchical deterministic wallet key generation
- **[@scure/bip39](https://github.com/paulmillr/scure-bip39)** - BIP-39 mnemonic phrases
  - Handles mnemonic generation, validation, and seed derivation
- **[micro-key-producer](https://github.com/paulmillr/micro-key-producer)** - SLIP-10 key derivation
  - Used for ed25519 hierarchical key derivation

- **[ton-crypto](https://github.com/ton-community/ton-crypto)** - TON blockchain cryptographic functions
  - Used for TON mnemonic generation, validation, and key derivation (standard and HD)

These libraries provide secure, audited, and well-maintained implementations of cryptographic standards, replacing the previous universal-signer dependency.

## Technical Details

### Polyfills

The package automatically sets up necessary polyfills for the Bare runtime:

- `TextEncoder` / `TextDecoder` - From `bare-encoding`
- `crypto.getRandomValues` - Using `bare-crypto.randomBytes()`

These are initialized before any cryptographic libraries are loaded to ensure compatibility.

### ES Module Support

The package uses ES modules (`type: "module"` in package.json). The native addon is loaded using `import.meta.addon()` with proper path resolution for the Bare runtime.

## Building

<https://github.com/holepunchto/bare-make> is used for compiling the native bindings in [`binding.c`](binding.c).

```console
git submodule update --remote --recursive --init
npm install
```

Script to build ios & ios-simulator bundles:

```console
./rebuild.sh
```

Or manually. Generate the build system for compiling the bindings, optionally setting the `--debug` flag to enable debug symbols and assertions:

```console
npx bare-make generate [--debug]
```

This only has to be run once per repository checkout. When updating `bare-make` or your compiler toolchain it might also be necessary to regenerate the build system. To do so, run the command again with the `--no-cache` flag set to disregard the existing build system cache:

```console
npx bare-make generate [--debug] --no-cache
```

With a build system generated, the bindings can be compiled:

```console
npx bare-make build
```

This will compile the bindings and output the resulting shared library module to the `build/` directory. To install it into the `prebuilds/` directory where the Bare addon resolution algorithm expects to find it, do:

```console
npx bare-make install
```

To make iteration faster during development, the shared library module can also be linked into the `prebuilds/` directory rather than copied. To do so, set the `--link` flag:

```console
npx bare-make install --link
```

Prior to publishing the module, make sure that no links exist within the `prebuilds/` directory as these will not be included in the resulting package archive.

## Publishing

The package is published to GitHub Packages as
[`@tetherto/wdk-signer-local`](https://github.com/tetherto/wdk-signer-local/packages)
on each manual run of the
[`publish-tetherto`](.github/workflows/publish-tetherto.yml)
workflow.

**Trigger:** dispatch the `publish-tetherto` workflow from the GitHub
Actions UI (or `gh workflow run publish-tetherto`). Each dispatch
produces one published version.

**What gets built:**

- Native prebuilds for all 13 platforms `bare-crypto` ships
  (`android-{arm,arm64,ia32,x64}`, `darwin-{arm64,x64}`,
  `ios-arm64`, `ios-arm64-simulator`, `ios-x64-simulator`,
  `linux-{x64,arm64}`, `win32-{x64,arm64}`) on native runners.
- Android companion AAR at `libs/android/bare-signer-android.aar`,
  built by `build-android-lib.sh` on an Ubuntu runner with JDK 17 and
  the Android SDK.

**Version cadence:** versions follow `1.0.0-beta.N`, auto-incremented
by [`.github/scripts/compute-next-beta.js`](.github/scripts/compute-next-beta.js)
from `max(registryMax, localBetaSuffix) + 1`. The committed
`package.json` stays on `1.0.0-beta.0`; the first publish becomes
`1.0.0-beta.1`. The on-disk `package.json` is only rewritten on the
ephemeral runner, never committed.

**Required secret:**
[`SUBMODULE_SIGNER_TOKEN`](https://github.com/tetherto/wdk-signer-local/settings/secrets/actions)
— PAT with read access to the private git submodules the prebuild
uses. `GITHUB_TOKEN` is supplied automatically by Actions thanks to
`permissions: packages: write` on the publish job.

**Required environment:** `github-packages-publish` — must be created
under repo Settings → Environments. Protection rules (required
reviewers, branch restriction) are optional and can be added later.

## External Dependencies

Addons are rarely self-contained and most often need to pull in external native libraries. For this, <https://github.com/holepunchto/cmake-fetch> should be used. Start by installing the package as a development dependency:

```console
npm i -D cmake-fetch
```

Next, import the package in the [`CMakeLists.txt`](CMakeLists.txt) build definition:

```cmake
find_package(cmake-fetch REQUIRED PATHS node_modules/cmake-fetch)
```

This will make the `fetch_package()` function available. To fetch an external native library, such as <https://github.com/holepunchto/liburl>, add the following line _after_ the `project()` declaration in the build definition:

```cmake
fetch_package("github:holepunchto/liburl")
```

Finally, link the imported native library to the addon:

```cmake
target_link_libraries(
  ${bare_addon}
  PUBLIC
    url
)
```

## Troubleshooting

### Local changes not being reflected after installation

The `bare` CLI statically links built-in native addons using `link_bare_module()` in [`bare/bin/CMakeLists.txt`](https://github.com/holepunchto/bare/blob/main/bin/CMakeLists.txt). If you are working on one of those, `bare` may be loading a cached version of it.

To check the current cache state, do:

```sh
bare --print 'Bare.Addon.cache'
```

To bypass this issue during development, manually bump the `version` field in the `package.json` to invalidate the cache.

## License

Apache-2.0
