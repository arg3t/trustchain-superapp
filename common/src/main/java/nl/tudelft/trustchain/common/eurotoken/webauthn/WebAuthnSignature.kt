package nl.tudelft.trustchain.common.eurotoken.webauthn

import nl.tudelft.ipv8.keyvault.IPSignature
import java.io.Serializable

/**
 * WebAuthn signature wrapper for eurotoken transactions
 */
data class WebAuthnSignature(
    val signature: IPSignature,
    val publicKey: ByteArray
) : Serializable {
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

    override fun hashCode(): Int {
        var result = signature.hashCode()
        result = 31 * result + publicKey.contentHashCode()
        return result
    }
}
