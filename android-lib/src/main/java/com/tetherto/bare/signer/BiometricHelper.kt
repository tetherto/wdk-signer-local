package com.tetherto.bare.signer

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.crypto.Cipher

class BiometricHelper(private val activity: FragmentActivity) {

    fun canAuthenticate(
        requireBiometric: Boolean = true,
        allowDeviceCredential: Boolean = true
    ): Boolean {
        val authFlags = buildAuthFlags(requireBiometric, allowDeviceCredential)
        val bm = BiometricManager.from(activity)
        return bm.canAuthenticate(authFlags) == BiometricManager.BIOMETRIC_SUCCESS
    }

    private fun buildAuthFlags(
        requireBiometric: Boolean,
        allowDeviceCredential: Boolean
    ): Int {
        return when {
            requireBiometric && allowDeviceCredential ->
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL

            requireBiometric ->
                BiometricManager.Authenticators.BIOMETRIC_STRONG

            else ->
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        }
    }

    fun showBiometricPrompt(
        cipher: Cipher,
        title: String,
        subtitle: String,
        description: String,
        cancel: String,
        requireBiometric: Boolean = true,
        allowDeviceCredential: Boolean = true,
        onSuccess: (Cipher) -> Unit,
        onError: (String) -> Unit
    ) {

        val executor = ContextCompat.getMainExecutor(activity)

        val authFlags = buildAuthFlags(requireBiometric, allowDeviceCredential)

        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setDescription(description)
            .setAllowedAuthenticators(authFlags)

        // setNegativeButtonText and DEVICE_CREDENTIAL are mutually exclusive in AndroidX Biometric
        if (!allowDeviceCredential && requireBiometric) {
            builder.setNegativeButtonText(cancel)
        }

        val promptInfo = builder.build()

        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    result.cryptoObject?.cipher?.let { authenticatedCipher ->
                        onSuccess(authenticatedCipher)
                    } ?: onError("Cipher not available")
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onError("Authentication error: $errString")
                }

                override fun onAuthenticationFailed() {
                    // Non-terminal: prompt stays open for retry (e.g. wrong finger).
                    // Only onAuthenticationError is terminal.
                    super.onAuthenticationFailed()
                }
            }
        )
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }
}
