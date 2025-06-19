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

class EUDIUtils {
    suspend fun verifyEudiToken(checker: IdentityProviderChecker, signedEUDIToken: IPSignature, nonce: String): Boolean {
        if (!checker.verify(signedEUDIToken)) {
            Log.d("YeatsStuff", "Failed to verify EUDI token with identity provider")
            return false;
        }

        try {
            Log.d("ToonsStuff", "Starting EUDI token verification")

            val token = signedEUDIToken.challenge.decodeToString()

            Log.d("ToonsStuff", "Extracted JWT: $token")

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
                            Log.d("ToonsStuff", "Name: $givenName $familyName")
                            /*
                            withContext(Dispatchers.Main) {
                                Toast.makeText(
                                    requireContext(),
                                    "Verified Name: $givenName $familyName",
                                    Toast.LENGTH_LONG
                                ).show()
                            }
                            */
                            true
                        } else {
                            Log.d("ToonsStuff", "No birth name in response")
                            false
                        }
                    }
                } catch (e: Exception) {
                    Log.e("ToonsStuff", "Error verifying token: ${e.message}")
                    e.printStackTrace()
                    false
                }
            }
        } catch (e: Exception) {
            Log.e("ToonsStuff", "Error in verification process: ${e.message}")
            e.printStackTrace()
            return false
        }
    }

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
