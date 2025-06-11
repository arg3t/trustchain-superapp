package nl.tudelft.trustchain.common.util

import android.app.Activity
import android.content.Intent
import android.util.Log
import androidx.core.net.toUri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import org.json.JSONObject
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

const val EUDI_LOG_MSG = "EUDIStuff"

class EUDIUtils {
    suspend fun getEudiToken(): Pair<JSONObject, String> {
        Log.d(EUDI_LOG_MSG, "Opening EUDI app")

        val content = """
                    {
                    "type": "vp_token",
                    "presentation_definition": {
                        "id": "1e7896b5-bbcc-4730-94b2-8232cfac2658",
                        "input_descriptors": [
                        {
                            "id": "f290d465-3fff-4637-89f1-08f8606ccd7b",
                            "name": "Person Identification Data (PID)",
                            "purpose": "",
                            "format": {
                            "dc+sd-jwt": {
                                "sd-jwt_alg_values": [
                                "ES256",
                                "ES384",
                                "ES512"
                                ],
                                "kb-jwt_alg_values": [
                                "RS256",
                                "RS384",
                                "RS512",
                                "ES256",
                                "ES384",
                                "ES512"
                                ]
                            }
                            },
                            "constraints": {
                            "fields": [
                                {
                                "path": [
                                    "$.vct"
                                ],
                                "filter": {
                                    "type": "string",
                                    "const": "urn:eu.europa.ec.eudi:pid:1"
                                }
                                },
                                {
                                "path": [
                                    "$.family_name"
                                ],
                                "intent_to_retain": false
                                },
                                {
                                "path": [
                                    "$.given_name"
                                ],
                                "intent_to_retain": false
                                }
                            ]
                            }
                        }
                        ]
                    },
                    "nonce": "2418429c-f59f-4b48-99c1-4f4bfaff8116",
                    "request_uri_method": "get"
                    }
                """.trimIndent()
        val verifierData = makeApiCall("https://verifier-backend.eudiw.dev/ui/presentations", "POST", content) ?: JSONObject() // Unsafe, how to handle null case?
        Log.d(EUDI_LOG_MSG, "Found my cool URL: $verifierData")

        val transactionId = verifierData.getString("transaction_id")
        val clientId = verifierData.getString("client_id")
        val requestUri = verifierData.getString("request_uri")
        val requestUriMethod = verifierData.getString("request_uri_method")

        val url = "eudi-openid4vp://?client_id=$clientId&request_uri=$requestUri&request_uri_method=$requestUriMethod"

        val getWalletUrl = "https://verifier-backend.eudiw.dev/ui/presentations/$transactionId"
        // Primitive handling of EUDIW stuff, is there no better way?
        while (true) {
            delay(1000)
            val walletResult = makeApiCall(getWalletUrl, "GET", body = null)
            if (walletResult != null) {
                val vpTokenarray = walletResult.getJSONArray("vp_token")
                val vpToken = vpTokenarray[0].toString()
                Log.d(EUDI_LOG_MSG, "Received VP token from thingy: $vpToken")
                return Pair(walletResult, url)
            } else {
                Log.d(EUDI_LOG_MSG, "Failed to get wallet results")
            }
        }
    }

    suspend fun verifyEudiToken(token: JSONObject? = null): Boolean {
        try {
            Log.d(EUDI_LOG_MSG, "Starting EUDI token verification")

            val walletResult = token ?: getEudiToken().first

            val vpTokenArray = walletResult.getJSONArray("vp_token")
            val vpTokenString = vpTokenArray.getString(0)

            Log.d(EUDI_LOG_MSG, "Extracted JWT: $vpTokenString")

            val verifyRequestBody = JSONObject().apply {
                put("sd_jwt_vc", vpTokenString)
                put("nonce", "2418429c-f59f-4b48-99c1-4f4bfaff8116")
            }.toString()

            val verificationResponse = makeApiCall(
                "https://verifier-backend.eudiw.dev/utilities/validations/sdJwtVc",
                "POST",
                verifyRequestBody
            )

            if (verificationResponse == null) {
                Log.e(EUDI_LOG_MSG, "Validation failed - null response")
                return false
            }

            val isValid = verificationResponse.optBoolean("valid", false)

            if (isValid) {
                Log.d(EUDI_LOG_MSG, "SD-JWT verified successfully by EUDI validator")
                return true
            } else {
                val errorMessage = verificationResponse.optString("error", "Unknown validation error")
                Log.e(EUDI_LOG_MSG, "Token validation failed: $errorMessage")
                return false
            }

        } catch (e: Exception) {
            Log.e(EUDI_LOG_MSG, "Error verifying token: ${e.message}")
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
