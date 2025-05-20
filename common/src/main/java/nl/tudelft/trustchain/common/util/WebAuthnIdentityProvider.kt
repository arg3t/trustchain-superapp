package nl.tudelft.trustchain.common.util

import android.annotation.SuppressLint
import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import nl.tudelft.ipv8.keyvault.IPSignature
import nl.tudelft.ipv8.keyvault.IdentityProviderChecker
import nl.tudelft.ipv8.keyvault.IdentityProviderOwner
import nl.tudelft.ipv8.util.toHex
import org.json.JSONObject
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

private const val TAG = "WebAuthnIdentity"

object SignatureUtils {
    fun hash(data: ByteArray): ByteArray {
        return java.security.MessageDigest.getInstance("SHA-256").digest(data)
    }
}


class WebAuthnIdentityProviderChecker (
    override val id: String,
    val publicKey: ByteArray
): IdentityProviderChecker {

    override fun verify(signature: IPSignature): Boolean {
        return try {
            val clientData = JSONObject(signature.data)
            val base64Challenge = clientData.getString("challenge")
            val decodedChallenge = Base64.decode(base64Challenge, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

            if (!signature.challenge.contentEquals(decodedChallenge)) {
                Log.e(TAG, "Challenge mismatch")
                return false
            }

            val clientDataHash = SignatureUtils.hash(signature.data.toByteArray())

            val signedData = signature.authenticatorData + clientDataHash

            val keySpec = X509EncodedKeySpec(publicKey)
            val keyFactory = KeyFactory.getInstance("EC") // Adjust if not using ECDSA
            val pubKey = keyFactory.generatePublic(keySpec)

            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(pubKey)
            sig.update(signedData)

            val isValid = sig.verify(signature.signature)
            if (!isValid) {
                Log.e(TAG, "Signature verification failed")
            }
            isValid
        } catch (e: Exception) {
            Log.e(TAG, "Error verifying WebAuthn signature", e)
            false
        }
    }

    override fun toHexString(): String {
        return publicKey.toHex()
    }
}


class WebAuthnIdentityProviderOwner(
    override val id: String,
    val publicKey: ByteArray,
    val context: Context? = null,
    private val checker: WebAuthnIdentityProviderChecker
) : IdentityProviderOwner {

    constructor(id: String, publicKey: ByteArray, context: Context? = null) :
        this(id, publicKey, context, WebAuthnIdentityProviderChecker(id, publicKey))

    override fun verify(signature: IPSignature): Boolean {
        return checker.verify(signature)
    }

    override fun toHexString(): String {
        return publicKey.toHex()
    }

    @SuppressLint("PublicKeyCredential")
    override suspend fun sign(data: ByteArray): IPSignature? {
        if (context == null) {
            throw IllegalStateException("Context is required for WebAuthn signing")
        }

        return withContext(Dispatchers.IO) {
            try {
                val credentialManager = CredentialManager.create(context)

                val requestJson = createAssertionRequestJson(data)
                Log.d(TAG, requestJson)

                val getCredRequest = GetCredentialRequest(
                    listOf(
                        GetPublicKeyCredentialOption(
                            requestJson = requestJson,
                        )
                    )
                )

                val result = credentialManager.getCredential(
                    request = getCredRequest,
                    context = context
                )

                val credential = result.credential as PublicKeyCredential
                val responseJson = credential.authenticationResponseJson

                val response = JSONObject(responseJson).getJSONObject("response")
                val authenticatorData = Base64.decode(response.getString("authenticatorData"), Base64.URL_SAFE)
                val signature = Base64.decode(response.getString("signature"), Base64.URL_SAFE)
                val challenge = data // original challenge passed in
                val clientDataJSON = Base64.decode(response.getString("clientDataJSON"), Base64.URL_SAFE).toString(Charsets.UTF_8)

                val sig = IPSignature(
                    data = clientDataJSON,
                    challenge = challenge,
                    authenticatorData = authenticatorData,
                    signature = signature
                )

                sig
            } catch (e: Exception) {
                Log.e(TAG, "Error during WebAuthn signing", e)
                null
            }
        }
    }

    private fun createAssertionRequestJson(challenge: ByteArray): String {
        return """
        {
            "challenge": "${Base64.encodeToString(challenge, Base64.URL_SAFE or Base64.NO_WRAP)}",
            "rpId": "trustchain.yigit.run",
            "allowCredentials": [
                {
                    "id": "$id",
                    "type": "public-key",
                    "transports": ["internal", "usb", "nfc", "ble"]
                }
            ],
            "userVerification": "preferred",
            "timeout": 60000
        }
        """.trimIndent()
    }
}
