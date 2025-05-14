package nl.tudelft.trustchain.app.keyvault

import android.content.Context
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import android.util.Log
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException
import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import nl.tudelft.ipv8.keyvault.LibNaClPK
import nl.tudelft.ipv8.keyvault.PrivateKey
import nl.tudelft.ipv8.keyvault.PublicKey
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/*
private val lazySodium = LazySodiumAndroid(SodiumAndroid())
private const val TAG = "WebAuthnCrypto"

// Concrete implementation of PrivateKey using WebAuthn
class WebAuthnPrivateKey(
    val id: String,
    private val publicKey: PublicKey,
    private val context: Context,
    private val scope: CoroutineScope? = null,
) : PrivateKey {

    companion object {
        private const val TAG = "WebAuthnPrivateKey"
    }

    private val internalScope by lazy {
        CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }

    // Choose the appropriate scope
    private val operationScope: CoroutineScope
        get() = scope ?: internalScope

    override fun sign(msg: ByteArray): ByteArray {
        val lock = Object()
        var signature: ByteArray = ByteArray(0)
        var error: Exception? = null

        try {
            val challenge = MessageDigest.getInstance("SHA-256").digest(msg)
            val credentialManager = CredentialManager.create(context)
            val getCredRequest = GetCredentialRequest(
                listOf(
                    GetPublicKeyCredentialOption(
                        requestJson = createAuthenticationRequestJson(challenge, id),
                    )
                )
            )

            // Use the selected scope
            operationScope.launch {
                try {
                    val result = credentialManager.getCredential(
                        request = getCredRequest,
                        context = context,
                    )
                    synchronized(lock) {
                        try {
                            val credential = result.credential as PublicKeyCredential
                            signature = credential.authenticationResponseJson.toByteArray()
                        } catch (e: Exception) {
                            error = e
                            Log.e(TAG, "Error processing WebAuthn authentication response", e)
                        }
                        lock.notify()
                    }
                } catch (e: Exception) {
                    synchronized(lock) {
                        error = e
                        Log.e(TAG, "Error during WebAuthn authentication", e)
                        lock.notify()
                    }
                }
            }

            // Wait for the operation to complete
            synchronized(lock) {
                try {
                    lock.wait(30000) // Wait up to 30 seconds
                } catch (e: InterruptedException) {
                    Log.e(TAG, "Operation interrupted", e)
                }
            }

            // Throw any error that occurred during the async operation
            if (error != null) {
                throw error as Exception
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error initiating WebAuthn authentication", e)
        }

        return signature
    }

    // Clean up resources when this key is no longer needed
    fun close() {
        // Only cancel our internal scope if we created it ourselves
        if (scope == null) {
            internalScope.cancel()
        }
    }

    // Other methods remain the same...
    override fun decrypt(msg: ByteArray): ByteArray {
        throw NotImplementedError("EC decryption not supported")
    }

    override fun keyToBin(): ByteArray {
        return id.toByteArray()
    }

    override fun pub(): PublicKey {
        return publicKey
    }

    private fun createAuthenticationRequestJson(challenge: ByteArray, credentialId: String): String {
        return """
        {
            "challenge": "${android.util.Base64.encodeToString(challenge, android.util.Base64.NO_WRAP)}",
            "allowCredentials": [{
                "id": "${android.util.Base64.encodeToString(credentialId.toByteArray(), android.util.Base64.URL_SAFE)}",
                "type": "public-key"
            }],
            "timeout": 60000,
            "userVerification": "preferred",
            "rpId": "trustchain.yigit.run"
        }
        """.trimIndent()
    }
}

 */
