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

/**
 * Verifies incoming **euro-token** blocks that embed a WebAuthn signature.
 *
 * The validator looks for two extra fields inside `block.transaction`:
 *
 * | Key constant | Value type | Meaning |
 * |--------------|------------|---------|
 * | [KEY_WEBAUTHN_PUBLIC_KEY] | `ByteArray` | Public key of the WebAuthn credential.|
 * | [KEY_WEBAUTHN_SIGNATURE]  | `WebAuthnSignature` | Signature object created by the authenticator for this block’s payload. |
 *
 * If either key is missing the block is accepted without further checks; otherwise
 * the signature is verified with a [WebAuthnIdentityProviderChecker].
 *
 * @property transactionRepository Used only for the `EUROTOKEN_TYPES` constant that
 *                                 decides whether a block requires WebAuthn validation.
 */
class WebAuthnValidator(
    val transactionRepository: TransactionRepository
) : TransactionValidator {

    companion object {
        const val KEY_WEBAUTHN_PUBLIC_KEY = "webauthn_public_key"
        const val KEY_WEBAUTHN_SIGNATURE = "webauthn_signature"
    }


    /**
     * Performs WebAuthn signature verification **only** on euro-token blocks.
     *
     * Validation flow:
     * 1. Quickly return **`Valid`** when the block’s `type` is *not* in
     *    [TransactionRepository.EUROTOKEN_TYPES].
     * 2. Return **`Valid`** when either WebAuthn field is absent (legacy or
     *    non-signed block).
     * 3. Otherwise:
     *    * Instantiate a [WebAuthnIdentityProviderChecker] with the supplied public key.
     *    * Verify the signature against the block payload.
     *    * Return [ValidationResult.Invalid] if the check fails, logging details.
     *
     * Any unexpected exception is caught and mapped to **`Invalid`** so that callers
     * treat runtime errors as hard validation failures.
     *
     * @param block    The TrustChain block to be validated.
     * @param database Unused in the current implementation but required by the
     *                 [TransactionValidator] interface.
     *
     * @return `Valid` when the block does not need WebAuthn validation *or* passes the
     *         check; `Invalid` otherwise.
     */
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
