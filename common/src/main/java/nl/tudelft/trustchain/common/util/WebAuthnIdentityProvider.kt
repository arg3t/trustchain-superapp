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
import kotlin.text.*

private const val TAG = "WebAuthnIdentity"

object SignatureUtils {
    fun hash(data: ByteArray): ByteArray {
        return java.security.MessageDigest.getInstance("SHA-256").digest(data)
    }
}

/**
 * Identity-provider **checker** that validates WebAuthn assertions.
 *
 * Given the credential’s X.509 public key bytes the checker:
 * 1. Parses the `clientDataJSON` inside [IPSignature.data] and compares its
 *    Base64-URL‐encoded *challenge* to [IPSignature.challenge].
 * 2. Re-creates the signed buffer (`authenticatorData || SHA-256(clientDataJSON)`).
 * 3. Verifies the raw ECDSA signature with the supplied public key.
 *
 * @property id        Credential ID (Base64URL) – doubles as **user handle**.
 * @property publicKey COSE/X.509 public key bytes of the WebAuthn credential.
 */
class WebAuthnIdentityProviderChecker (
    override val id: String,
    val publicKey: ByteArray
): IdentityProviderChecker {

    /**
     * Verifies a detached WebAuthn signature produced by an authenticator.
     *
     * @param signature Complete [IPSignature] object containing:
     * * `data` –   raw `clientDataJSON`
     * * `challenge` – original SHA-256 challenge issued by the RP
     * * `authenticatorData` – flags + counter + RP ID hash
     * * `signature` – DER-encoded ECDSA bytes
     *
     * @return **`true`** when the challenge matches *and* the ECDSA check passes;
     *         **`false`** otherwise.
     */
    override fun verify(signature: IPSignature): Boolean {
        return try {
            val clientData = JSONObject(signature.data.decodeToString())
            val base64Challenge = clientData.getString("challenge")
            val decodedChallenge = Base64.decode(base64Challenge, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

            if (!signature.challenge.contentEquals(decodedChallenge)) {
                Log.e(TAG, "Challenge mismatch")
                return false
            }

            val clientDataHash = SignatureUtils.hash(signature.data)

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

    /**
     * @return Hex-encoded form of [publicKey] – handy for logging or JSON payloads.
     */
    override fun toHexString(): String {
        return publicKey.toHex()
    }
}


/**
 * Identity-provider **owner** that lets the TrustChain node *sign* and *verify*
 * payloads through a WebAuthn credential stored on the device.
 *
 * A lightweight [WebAuthnIdentityProviderChecker] instance is kept internally for
 * verification, while the **sign** operation is delegated to the Android
 * **Credential Manager API** using an *assertion* request.
 *
 * @constructor Primary constructor accepts an already-built checker; the
 *              secondary one bootstraps the checker automatically.
 *
 * @property id        Credential ID (Base64URL) presented to the authenticator.
 * @property publicKey Raw public-key bytes (COSE/X.509).
 * @property context   Android [Context] needed to invoke the Credential Manager.
 */
class WebAuthnIdentityProviderOwner(
    override val id: String,
    val publicKey: ByteArray,
    var context: Context, // i made this mutable bc im evil >:)
    private val checker: WebAuthnIdentityProviderChecker
) : IdentityProviderOwner {

    /**
     * Convenience secondary constructor that instantiates its own
     * [WebAuthnIdentityProviderChecker].
     */
    constructor(id: String, publicKey: ByteArray, context: Context) :
        this(id, publicKey, context, WebAuthnIdentityProviderChecker(id, publicKey))

    /**
     * Delegates verification to the internal [checker]; see its docs for details.
     *
     * @return `true` when the signature is cryptographically valid.
     */
    override fun verify(signature: IPSignature): Boolean {
        return checker.verify(signature)
    }

    override fun toHexString(): String {
        return publicKey.toHex()
    }

    /**
     * Launches a **WebAuthn assertion ceremony** to sign the supplied [data].
     *
     * Steps performed on `Dispatchers.IO`:
     * 1. Build an assertion JSON using [createAssertionRequestJson].
     * 2. Ask the **Credential Manager** for an authentication response.
     * 3. Extract `authenticatorData`, `clientDataJSON`, `signature`, re-attach the
     *    original challenge and return a fully populated [IPSignature].
     *
     * When the user cancels or an error occurs the function returns **`null`**.
     *
     * @param data SHA-256 challenge issued by the RP (and echoed back later).
     * @return Signed [IPSignature] or `null` on failure/cancel.
     */
    @SuppressLint("PublicKeyCredential")
    override suspend fun sign(data: ByteArray): IPSignature? {
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
                    data = clientDataJSON.toByteArray(),
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
