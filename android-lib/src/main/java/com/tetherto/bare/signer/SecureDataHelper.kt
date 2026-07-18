package com.tetherto.bare.signer

import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.fragment.app.FragmentActivity
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class SecureDataHelper private constructor() {

    @Volatile private var activity: FragmentActivity? = null
    @Volatile private var storage: SecureStorage? = null
    @Volatile private var biometricHelper: BiometricHelper? = null
    // Incremented on initialize/deinitialize so in-flight operations
    // can detect that lifecycle state changed beneath them.
    @Volatile private var generation: Long = 0

    fun saveEncryptedDataSync(
        data: ByteArray,
        name: String,
        timeoutSeconds: Long = 60,
        requireBiometric: Boolean = true,
        allowDeviceCredential: Boolean = true,
        title: String? = null,
        subtitle: String? = null,
        description: String? = null,
        cancel: String? = null,
    ) {

        Log.d(
            "SecureDataHelper",
            "saveEncryptedDataSync called with data length: ${data.size}, name: $name"
        )

        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw IllegalStateException("saveEncryptedDataSync() must not be called on the main thread")
        }
        val gen = generation
        val bio = biometricHelper
        val stor = storage
        if (activity == null || bio == null || stor == null) {
            throw IllegalStateException("Security components not initialized")
        }
        if (data.isEmpty()) {
            throw IllegalArgumentException("Data cannot be empty")
        }
        if (!bio.canAuthenticate(requireBiometric, allowDeviceCredential)) {
            throw IllegalStateException("Please set up a screen lock (PIN/password/biometric) in device settings first")
        }
        val latch = CountDownLatch(1)
        var error: Exception? = null

        Handler(Looper.getMainLooper()).post {
            if (generation != gen) {
                error = Exception("Security components reinitialized during operation")
                latch.countDown()
                return@post
            }
            try {
                val cipher = stor.getEncryptCipher()

                bio.showBiometricPrompt(
                    cipher = cipher,
                    title = title ?: "Authenticate to Save",
                    subtitle = subtitle ?: "Confirm your identity to encrypt and save the text",
                    description = description ?: "Description",
                    cancel = cancel ?: "Cancel",
                    requireBiometric = requireBiometric,
                    allowDeviceCredential = allowDeviceCredential,
                    onSuccess = { c ->
                        try {
                            if (generation != gen) {
                                throw Exception("Security components reinitialized during operation")
                            }
                            stor.saveEncryptedData(c, data, name)
                            Log.d("SecureDataHelper", "Data saved successfully")
                        } catch (e: Exception) {
                            error = Exception("Failed to save: ${e.message}", e)
                            Log.e("SecureDataHelper", "Save failed", e)
                        } finally {
                            latch.countDown()
                        }
                    },
                    onError = { err ->
                        error = Exception("Authentication failed: $err")
                        Log.e("SecureDataHelper", "Auth error: $err")
                        latch.countDown()
                    }
                )
            } catch (e: Exception) {
                error = Exception("Failed to initialize encryption: ${e.message}", e)
                Log.e("SecureDataHelper", "Encryption init failed", e)
                latch.countDown()
            }
        }

        if (!latch.await(timeoutSeconds, TimeUnit.SECONDS)) {
            throw Exception("Authentication timeout after $timeoutSeconds seconds")
        }
        error?.let { throw it }
    }

    @Throws(Exception::class)
    fun getDecryptedDataSync(
        name: String,
        timeoutSeconds: Long = 60,
        requireBiometric: Boolean = true,
        allowDeviceCredential: Boolean = true,
        title: String? = null,
        subtitle: String? = null,
        description: String? = null,
        cancel: String? = null,
    ): ByteArray {

        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw IllegalStateException("getDecryptedDataSync() must not be called on the main thread")
        }
        val gen = generation
        val bio = biometricHelper
        val stor = storage
        if (activity == null || bio == null || stor == null) {
            throw IllegalStateException("Security components not initialized")
        }
        if (!bio.canAuthenticate(requireBiometric, allowDeviceCredential)) {
            throw IllegalStateException("Please set up a screen lock (PIN/password/biometric) in device settings first")
        }
        if (!stor.hasStoredData(name)) {
            throw IllegalStateException("No encrypted data found. Please save text first.")
        }
        val latch = CountDownLatch(1)
        var result: ByteArray? = null
        var error: Exception? = null

        Handler(Looper.getMainLooper()).post {
            if (generation != gen) {
                error = Exception("Security components reinitialized during operation")
                latch.countDown()
                return@post
            }
            try {
                val cipher = stor.getDecryptCipher(name)
                bio.showBiometricPrompt(
                    cipher = cipher,
                    title = title ?: "Authenticate to Load",
                    subtitle = subtitle ?: "Confirm your identity to decrypt and load the text",
                    description = description ?: "",
                    cancel = cancel ?: "Cancel",
                    requireBiometric = requireBiometric,
                    allowDeviceCredential = allowDeviceCredential,
                    onSuccess = { authenticatedCipher ->
                        try {
                            if (generation != gen) {
                                throw Exception("Security components reinitialized during operation")
                            }
                            result = stor.decryptData(authenticatedCipher, name)
                            Log.d("SecureDataHelper", "Data decrypted successfully")
                        } catch (e: Exception) {
                            error = Exception("Failed to decrypt: ${e.message}", e)
                            Log.e("SecureDataHelper", "Decrypt failed", e)
                        } finally {
                            latch.countDown()
                        }
                    },
                    onError = { errorMsg ->
                        error = Exception("Authentication failed: $errorMsg")
                        Log.e("SecureDataHelper", "Auth error: $errorMsg")
                        latch.countDown()
                    }
                )
            } catch (e: Exception) {
                error = Exception("Failed to initialize decryption: ${e.message}", e)
                Log.e("SecureDataHelper", "Decryption init failed", e)
                latch.countDown()
            }
        }

        if (!latch.await(timeoutSeconds, TimeUnit.SECONDS)) {
            throw Exception("Authentication timeout after $timeoutSeconds seconds")
        }

        error?.let { throw it }
        return result ?: throw Exception("Unknown error: result is null")
    }

    @Throws(Exception::class)
    fun deleteEncryptedTextSync(
        name: String,
        timeoutSeconds: Long = 60,
        requireBiometric: Boolean = true,
        allowDeviceCredential: Boolean = true,
        title: String? = null,
        subtitle: String? = null,
        description: String? = null,
        cancel: String? = null,
        preserveKey: Boolean = true,
    ) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw IllegalStateException("deleteEncryptedTextSync() must not be called on the main thread")
        }
        val gen = generation
        val stor = storage
        if (activity == null || stor == null) {
            throw IllegalStateException("Security components not initialized")
        }
        if (!stor.hasStoredData(name)) {
            Log.d("SecureDataHelper", "No encrypted data to delete — treat as success")
            return
        }

        val wantsPrompt = (requireBiometric || allowDeviceCredential)
        val latch = CountDownLatch(1)
        var error: Exception? = null

        if (!wantsPrompt) {
            synchronized(Companion) {
                if (generation != gen) {
                    throw Exception("Security components reinitialized during operation")
                }
                stor.clearEncryptedText(name, preserveKey)
            }
            return
        }

        val bio = biometricHelper
            ?: throw IllegalStateException("Security components not initialized")

        Handler(Looper.getMainLooper()).post {
            if (generation != gen) {
                error = Exception("Security components reinitialized during operation")
                latch.countDown()
                return@post
            }
            try {
                val cipher = stor.getEncryptCipher()
                bio.showBiometricPrompt(
                    cipher = cipher,
                    title = title ?: "Authenticate to Delete",
                    subtitle = subtitle ?: "Confirm your identity to delete the stored data",
                    description = description ?: "",
                    cancel = cancel ?: "Cancel",
                    requireBiometric = requireBiometric,
                    allowDeviceCredential = allowDeviceCredential,
                    onSuccess = {
                        try {
                            if (generation != gen) {
                                throw Exception("Security components reinitialized during operation")
                            }
                            stor.clearEncryptedText(name, preserveKey)
                            Log.d("SecureDataHelper", "Encrypted data deleted successfully")
                        } catch (e: Exception) {
                            error = Exception("Failed to delete: ${e.message}", e)
                            Log.e("SecureDataHelper", "Delete failed", e)
                        } finally {
                            latch.countDown()
                        }
                    },
                    onError = { err ->
                        error = Exception("Authentication failed: $err")
                        Log.e("SecureDataHelper", "Auth error: $err")
                        latch.countDown()
                    }
                )
            } catch (e: Exception) {
                error = Exception("Failed to initialize auth: ${e.message}", e)
                Log.e("SecureDataHelper", "Delete init failed", e)
                latch.countDown()
            }
        }

        if (!latch.await(timeoutSeconds, TimeUnit.SECONDS)) {
            throw Exception("Authentication timeout after $timeoutSeconds seconds")
        }
        error?.let { throw it }
    }

    companion object {
        @Volatile
        private var instance: SecureDataHelper? = null

        @JvmStatic
        fun getInstance(): SecureDataHelper {
            return instance ?: synchronized(this) {
                instance ?: SecureDataHelper().also { instance = it }
            }
        }

        @JvmStatic
        fun initialize(activity: FragmentActivity) {
            check(Looper.myLooper() == Looper.getMainLooper()) {
                "initialize() must be called on the main thread"
            }
            val newBio = BiometricHelper(activity)
            val newStorage = SecureStorage(activity.applicationContext)
            synchronized(this) {
                val helper = getInstance()
                helper.biometricHelper = null
                helper.storage = null
                helper.activity = activity
                helper.biometricHelper = newBio
                helper.storage = newStorage
                helper.generation++
            }
        }

        @JvmStatic
        fun deinitialize() {
            check(Looper.myLooper() == Looper.getMainLooper()) {
                "deinitialize() must be called on the main thread"
            }
            synchronized(this) {
                instance?.apply {
                    biometricHelper = null
                    storage = null
                    activity = null
                    generation++
                }
            }
        }

        @JvmStatic
        fun saveEncryptedDataNative(
            data: ByteArray,
            name: String,
            timeoutSeconds: Long = 60,
            requireBiometric: Boolean,
            allowDeviceCredential: Boolean,
            title: String?,
            subtitle: String?,
            description: String?,
            cancel: String?
        ) {
            getInstance().saveEncryptedDataSync(
                data,
                name,
                timeoutSeconds,
                requireBiometric,
                allowDeviceCredential,
                title,
                subtitle,
                description,
                cancel
            )
        }

        @JvmStatic
        @Throws(Exception::class)
        fun getDecryptedDataNative(
            name: String,
            timeoutSeconds: Long = 60,
            requireBiometric: Boolean,
            allowDeviceCredential: Boolean,
            title: String?,
            subtitle: String?,
            description: String?,
            cancel: String?
        ): ByteArray {
            return getInstance().getDecryptedDataSync(
                name,
                timeoutSeconds,
                requireBiometric,
                allowDeviceCredential,
                title,
                subtitle,
                description,
                cancel
            )
        }

        @JvmStatic
        @Throws(Exception::class)
        fun deleteEncryptedTextNative(
            name: String,
            timeoutSeconds: Long = 60,
            requireBiometric: Boolean,
            allowDeviceCredential: Boolean,
            title: String?,
            subtitle: String?,
            description: String?,
            cancel: String?,
            preserveKey: Boolean = true
        ) {
            getInstance().deleteEncryptedTextSync(
                name,
                timeoutSeconds,
                requireBiometric,
                allowDeviceCredential,
                title,
                subtitle,
                description,
                cancel,
                preserveKey
            )
        }
    }
}
