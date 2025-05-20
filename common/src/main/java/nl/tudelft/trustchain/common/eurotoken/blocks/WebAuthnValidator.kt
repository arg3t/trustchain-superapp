package nl.tudelft.trustchain.common.eurotoken.blocks

import android.util.Log
import nl.tudelft.ipv8.attestation.trustchain.TrustChainBlock
import nl.tudelft.ipv8.attestation.trustchain.store.TrustChainStore
import nl.tudelft.ipv8.attestation.trustchain.validation.TransactionValidator
import nl.tudelft.ipv8.attestation.trustchain.validation.ValidationResult
import nl.tudelft.trustchain.common.eurotoken.TransactionRepository
import nl.tudelft.trustchain.common.eurotoken.webauthn.WebAuthnSignature
import nl.tudelft.trustchain.common.util.WebAuthnIdentityProviderChecker

private const val TAG = "WebAuthnValidator"

class WebAuthnValidator(
    val transactionRepository: TransactionRepository
) : TransactionValidator {

    companion object {
        const val KEY_WEBAUTHN_PUBLIC_KEY = "webauthn_public_key"
        const val KEY_WEBAUTHN_SIGNATURE = "webauthn_signature"
    }

    override fun validate(
        block: TrustChainBlock,
        database: TrustChainStore
    ): ValidationResult {
        // Only validate eurotoken blocks
        if (!TransactionRepository.EUROTOKEN_TYPES.contains(block.type)) {
            return ValidationResult.Valid
        }

        // Skip validation if no webauthn data is present
        if (!block.transaction.containsKey(KEY_WEBAUTHN_PUBLIC_KEY) ||
            !block.transaction.containsKey(KEY_WEBAUTHN_SIGNATURE)) {
            Log.d(TAG, "Block doesn't contain WebAuthn signature data")
            return ValidationResult.Valid
        }

        try {
            val webAuthnPublicKey = block.transaction[KEY_WEBAUTHN_PUBLIC_KEY] as ByteArray
            val webAuthnSignature = block.transaction[KEY_WEBAUTHN_SIGNATURE] as WebAuthnSignature

            val checker = WebAuthnIdentityProviderChecker(
                id = webAuthnPublicKey.toString(Charsets.UTF_8),
                publicKey = webAuthnPublicKey
            )

            val isValid = checker.verify(webAuthnSignature.signature)

            if (!isValid) {
                Log.e(TAG, "WebAuthn signature verification failed for block ${block.blockId}")
                return ValidationResult.Invalid(listOf("WebAuthn signature verification failed"))
            }

            Log.d(TAG, "WebAuthn signature verification successful for block ${block.blockId}")
            return ValidationResult.Valid

        } catch (e: Exception) {
            Log.e(TAG, "Error during WebAuthn validation", e)
            return ValidationResult.Invalid(listOf("WebAuthn validation error: ${e.message}"))
        }
    }
}
