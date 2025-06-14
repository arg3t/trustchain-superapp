package nl.tudelft.ipv8.keyvault

import org.json.JSONObject
import java.util.Base64

data class IPSignature(
    val data: String,
    val challenge: ByteArray,
    val authenticatorData: ByteArray,
    val signature: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IPSignature) return false
        return data == other.data && signature.contentEquals(other.signature)
    }

    override fun hashCode(): Int {
        var result = data.hashCode()
        result = 31 * result + challenge.contentHashCode()
        result = 31 * result + authenticatorData.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "IPSignature(data='$data', " +
            "challenge=${challenge.contentToString()}, " +
            "authenticatorData=${authenticatorData.contentToString()}, " +
            "signature=${signature.contentToString()})"
    }

    fun toJsonString(): String {
        val encoder = Base64.getEncoder()
        val json = JSONObject()
        json.put("data", data)
        json.put("challenge", encoder.encodeToString(challenge))
        json.put("authenticatorData", encoder.encodeToString(authenticatorData))
        json.put("IPsignature", encoder.encodeToString(signature))
        return json.toString()
    }

    companion object {
        fun fromJsonString(jsonString: String): IPSignature {
            val decoder = Base64.getDecoder()
            val json = JSONObject(jsonString)
            return IPSignature(
                data = json.getString("data"),
                challenge = decoder.decode(json.getString("challenge")),
                authenticatorData = decoder.decode(json.getString("authenticatorData")),
                signature = decoder.decode(json.getString("IPsignature"))
            )
        }
    }
}


interface IdentityProviderChecker {
    val id: String;

    fun verify(signature: IPSignature): Boolean
    fun toHexString(): String

}

interface IdentityProviderOwner: IdentityProviderChecker {
    suspend fun sign(data: ByteArray): IPSignature?
}

