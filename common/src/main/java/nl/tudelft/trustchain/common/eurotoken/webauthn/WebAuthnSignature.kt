package nl.tudelft.trustchain.common.eurotoken.webauthn

import nl.tudelft.ipv8.keyvault.IPSignature
import java.io.Serializable

/**
 * Wraps a **WebAuthn signature** that authenticates an *euro-token* transaction.
 *
 * An instance contains the raw signature data returned by the authenticator
 * (**`IPSignature`**) and the credential’s COSE-encoded **public key**.
 *
 * @property signature  Parsed WebAuthn payload (`authenticatorData`, `clientDataHash`,
 *                      etc.) plus the raw ECDSA signature bytes.
 * @property publicKey  The credential’s public key, used later for on-chain
 *                      verification.
 */
data class WebAuthnSignature(
    val signature: IPSignature,
    val publicKey: ByteArray
) : Serializable {

    /**
     * Deep-content equality: every nested byte array inside [signature] **and**
     * [publicKey] must match bit-for-bit for the objects to be considered equal.
     */
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as WebAuthnSignature

        if (!signature.data.contentEquals(other.signature.data)) return false
        if (!signature.signature.contentEquals(other.signature.signature)) return false
        if (!signature.authenticatorData.contentEquals(other.signature.authenticatorData)) return false
        if (!signature.challenge.contentEquals(other.signature.challenge)) return false
        if (!publicKey.contentEquals(other.publicKey)) return false

        return true
    }

    /**
     * Hash-code implementation consistent with the deep-content logic of [equals].
     * Uses `contentHashCode()` for byte arrays instead of their default identity hash.
     */
    override fun hashCode(): Int {
        var result = signature.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        return result
    }
}
