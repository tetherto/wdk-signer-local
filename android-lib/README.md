# bare-signer

Lightweight native signer packaged as an Android `.aar`, distributed via `npm`.

## Build

```bash
npm install
./build-android-lib.sh
```

This generates:

```text
node_modules/bare-signer/libs/android/bare-signer-android.aar
```

## Usage (Android)

Add to your **app module** `build.gradle.kts`:

```kotlin
dependencies {
    implementation(
        files("$rootDir/node_modules/bare-signer/libs/android/bare-signer-android.aar")
    )
}
```

Load the native library once (e.g. in your Application or before first use):

```kotlin
    init {
        System.loadLibrary("bare-signer-android")
    }
```

Initialize helpers in your entry `FragmentActivity`:

```kotlin
SecureDataHelper.initialize(this)
```

Clean up when done (e.g. in `onDestroy`):

```kotlin
SecureDataHelper.deinitialize()
```

## Packages

- npm: `bare-signer`
- Android package: `com.tetherto.bare.signer`
