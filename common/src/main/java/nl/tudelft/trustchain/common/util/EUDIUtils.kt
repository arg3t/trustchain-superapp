package nl.tudelft.trustchain.common.util

import android.app.Activity
import android.content.Intent
import android.util.Log
import android.widget.Toast
import androidx.core.net.toUri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import nl.tudelft.ipv8.keyvault.IPSignature
import nl.tudelft.ipv8.keyvault.IdentityProviderChecker
import okhttp3.FormBody
import org.json.JSONObject
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import kotlin.text.*

const val EUDI_LOG_MSG = "EUDIStuff"

/**
 * Helper methods for interacting with the **European Digital Identity (EUDI) Wallet**
 * proof-of-concept verifier backend and for making generic JSON HTTP calls.
 *
 * All public functions are `suspend` and shift network I/O to `Dispatchers.IO`;
 * callers can therefore invoke them safely from `lifecycleScope` or other
 * structured-concurrency contexts.
 */
class EUDIUtils {

    /**
     * Performs an **end-to-end verification** of a *Signed Disclosure JWT VC* (SD-JWT VC)
     * issued by an EUDI wallet.
     *
     * Verification pipeline:
     * 1. **Local cryptographic check** – the supplied [checker] confirms that
     *    the detached WebAuthn signature [signedEUDIToken] is valid for the
     *    credential’s public key.
     * 2. **Remote semantics check** – the raw JWT (extracted from
     *    `signedEUDIToken.challenge`) and the anti-replay [nonce] are POSTed to
     *    `https://verifier-backend.eudiw.dev/utilities/validations/sdJwtVc`.
     *    The JSON response is accepted when it exposes at least one of the
     *    `given_name` or `family_name` claims, proving the backend trusted the VC.
     *
     * Any exception during network or JSON processing is caught and logged; the
     * function then returns `false` so that callers treat the token as unverified.
     *
     * @param checker          Component capable of verifying WebAuthn or other
     *                         identity-provider signatures.
     * @param signedEUDIToken  Detached signature container (`IPSignature`) that
     *                         carries the JWT in its `challenge` field.
     * @param nonce            Server-supplied nonce binding the proof to a session.
     * @return `true` when **both** the local and remote checks succeed, `false` otherwise.
     */
    suspend fun verifyEudiToken(checker: IdentityProviderChecker, signedEUDIToken: IPSignature, nonce: String): Boolean {
        if (!checker.verify(signedEUDIToken)) {
            Log.d(EUDI_LOG_MSG, "Failed to verify EUDI token with identity provider")
            return false;
        }

        try {
            Log.d(EUDI_LOG_MSG, "Starting EUDI token verification")

            val token = signedEUDIToken.challenge.decodeToString()

            Log.d(EUDI_LOG_MSG, "Extracted JWT: $token")

            val formBody = FormBody.Builder()
                .add("sd_jwt_vc", token)
                .add("nonce", nonce)
                .build()

            val request = Request.Builder()
                .url("https://verifier-backend.eudiw.dev/utilities/validations/sdJwtVc")
                .addHeader("Accept-Encoding", "application/json")
                .addHeader("Content-Type", "application/x-www-form-urlencoded")
                .post(formBody)
                .build()

            return withContext(Dispatchers.IO) {
                try {
                    OkHttpClient().newCall(request).execute().use { response ->
                        val body = response.body?.string() ?: return@use false
                        val json = JSONObject(body)

                        // top-level fields, not inside "claims"
                        val givenName = json.optString("given_name", "")
                        val familyName = json.optString("family_name", "")

                        if (givenName.isNotEmpty() || familyName.isNotEmpty()) {
                            Log.d(EUDI_LOG_MSG, "Name: $givenName $familyName")
                            true
                        } else {
                            Log.d(EUDI_LOG_MSG, "No birth name in response")
                            false
                        }
                    }
                } catch (e: Exception) {
                    Log.e(EUDI_LOG_MSG, "Error verifying token: ${e.message}")
                    e.printStackTrace()
                    false
                }
            }
        } catch (e: Exception) {
            Log.e(EUDI_LOG_MSG, "Error in verification process: ${e.message}")
            e.printStackTrace()
            return false
        }
    }

    /**
     * Convenience wrapper around **OkHttp** that performs a single HTTP request and
     * returns the body parsed as a [JSONObject].
     *
     * The call is executed on `Dispatchers.IO`; the response stream is closed
     * automatically by the `use` block.
     *
     * @param url    Absolute URL to contact.
     * @param method HTTP verb (`"GET"`, `"POST"`, `"PUT"`, …).
     * @param body   Optional JSON payload; pass `null` for verbs that do not
     *               require a body.
     * @return A parsed JSON object, or `null` when the body is empty, malformed,
     *         or an I/O exception occurs.
     */
    suspend fun makeApiCall(url: String, method: String, body: String?): JSONObject? = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(url)
            .method(method, body?.toRequestBody("application/json; charset=utf-8".toMediaTypeOrNull()))
            .build()
        try {
            OkHttpClient().newCall(request).execute().use { response ->
                Log.d(EUDI_LOG_MSG, "received status: ${response.code}")
                Log.d(EUDI_LOG_MSG, "received response: ${response.body?.toString()}")
                val str = response.body?.string() // TODO: Unsafe, what to do in case of malformed body?

                val data = str?.let { s -> JSONObject(s) }
                return@withContext data
            }
        } catch (e: Exception) {
            Log.d(EUDI_LOG_MSG, "Exception during API call: $e")
        }
        return@withContext null
    }
}
