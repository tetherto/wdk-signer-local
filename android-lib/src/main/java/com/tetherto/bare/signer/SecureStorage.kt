package com.tetherto.bare.signer

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class SecureStorage(private val context: Context) {

    companion object {
        private const val KEY_ALIAS = "secure_text_key"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_LENGTH = 128
        private const val PREFS_NAME = "secure_prefs"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
        load(null)
    }

    private fun createKeyIfNotExists() {
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )

            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                )
                .build()

            keyGenerator.init(keyGenParameterSpec)
            keyGenerator.generateKey()
        }
    }

    fun getEncryptCipher(): Cipher {
        createKeyIfNotExists()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = keyStore.getKey(KEY_ALIAS, null) as SecretKey
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher
    }

    fun getDecryptCipher(entryName: String): Cipher {
        val ivKey = "encryption_iv_$entryName"
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val ivString = prefs.getString(ivKey, null)
            ?: throw IllegalStateException("No IV found")

        val iv = Base64.decode(ivString, Base64.DEFAULT)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        val secretKey = keyStore.getKey(KEY_ALIAS, null) as SecretKey
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        return cipher
    }

    fun saveEncryptedData(cipher: Cipher, data: ByteArray, entryName: String) {
        val encryptedDataKey = "encrypted_text_$entryName"
        val ivKey = "encryption_iv_$entryName"
        val encrypted = cipher.doFinal(data)
        val iv = cipher.iv

        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        prefs.edit().apply {
            putString(encryptedDataKey, Base64.encodeToString(encrypted, Base64.DEFAULT))
            putString(ivKey, Base64.encodeToString(iv, Base64.DEFAULT))
            apply()
        }
    }

    fun decryptData(cipher: Cipher, entryName: String): ByteArray {
        val encryptedDataKey = "encrypted_text_$entryName"
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encryptedString = prefs.getString(encryptedDataKey, null)
            ?: throw IllegalStateException("No encrypted data found")

        val encrypted = Base64.decode(encryptedString, Base64.DEFAULT)
        return cipher.doFinal(encrypted)
    }

    fun hasStoredData(entryName: String): Boolean {
        val encryptedDataKey = "encrypted_text_$entryName"
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        return prefs.contains(encryptedDataKey)
    }

    @Throws(Exception::class)
    fun clearEncryptedText(entryName: String, preserveKey: Boolean = true) {
        val encryptedDataKey = "encrypted_text_$entryName"
        val ivKey = "encryption_iv_$entryName"
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        if (!prefs.contains(encryptedDataKey) && !prefs.contains(ivKey)) {
            Log.d("SecureStorage", "No encrypted data found. Treat as success.")
            return
        }

        val ok = prefs.edit()
            .remove(encryptedDataKey)
            .remove(ivKey)
            .commit()

        if (!ok) {
            throw IllegalStateException("Failed to clear encrypted data from SharedPreferences")
        } else {
            Log.d("SecureStorage", "Encrypted data and IV removed from SharedPreferences")
        }

        if (!preserveKey) {
            try {
                if (keyStore.containsAlias(KEY_ALIAS)) {
                    keyStore.deleteEntry(KEY_ALIAS)
                    Log.d("SecureStorage", "Keystore alias '$KEY_ALIAS' deleted")
                } else {
                    Log.d(
                        "SecureStorage",
                        "Keystore alias '$KEY_ALIAS' not found (nothing to delete)"
                    )
                }
            } catch (e: Exception) {
                throw IllegalStateException(
                    "Failed to delete keystore key '$KEY_ALIAS': ${e.message}",
                    e
                )
            }
        }
    }

}
