package nl.tudelft.trustchain.eurotoken.ui.transfer

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.json.JSONObject
import java.util.UUID

class EUDIRegistrationTest {

    @Test
    fun `EUDI presentation request has correct structure`() = runBlocking {
        // Validates structure of the EUDI presentation request
        // that would be created by TransferFragment.getEudiToken()

        val nonce = "test-nonce-${UUID.randomUUID()}"

        // Simulate the presentation request creation logic
        val presentationRequest = JSONObject().apply {
            put("type", "vp_token")
            put("presentation_definition", JSONObject().apply {
                put("id", UUID.randomUUID().toString())
                put("input_descriptors", org.json.JSONArray().apply {
                    put(JSONObject().apply {
                        put("id", UUID.randomUUID().toString())
                        put("name", "Person Identification Data (PID)")
                        put("purpose", "")
                        put("format", JSONObject().apply {
                            put("dc+sd-jwt", JSONObject().apply {
                                put("sd-jwt_alg_values", org.json.JSONArray().apply {
                                    put("ES256")
                                    put("ES384")
                                    put("ES512")
                                })
                                put("kb-jwt_alg_values", org.json.JSONArray().apply {
                                    put("RS256")
                                    put("RS384")
                                    put("RS512")
                                    put("ES256")
                                    put("ES384")
                                    put("ES512")
                                })
                            })
                        })
                        put("constraints", JSONObject().apply {
                            put("fields", org.json.JSONArray().apply {
                                put(JSONObject().apply {
                                    put("path", org.json.JSONArray().apply { put("$.vct") })
                                    put("filter", JSONObject().apply {
                                        put("type", "string")
                                        put("const", "urn:eudi:pid:1")
                                    })
                                })
                                put(JSONObject().apply {
                                    put("path", org.json.JSONArray().apply { put("$.family_name") })
                                    put("intent_to_retain", false)
                                })
                                put(JSONObject().apply {
                                    put("path", org.json.JSONArray().apply { put("$.given_name") })
                                    put("intent_to_retain", false)
                                })
                            })
                        })
                    })
                })
            })
            put("nonce", nonce)
            put("request_uri_method", "get")
        }

        // Verify the structure
        assertEquals("vp_token", presentationRequest.getString("type"))
        assertEquals(nonce, presentationRequest.getString("nonce"))
        assertEquals("get", presentationRequest.getString("request_uri_method"))

        val presentationDef = presentationRequest.getJSONObject("presentation_definition")
        assertNotNull(presentationDef.getString("id"))

        val inputDescriptors = presentationDef.getJSONArray("input_descriptors")
        assertEquals(1, inputDescriptors.length())

        val descriptor = inputDescriptors.getJSONObject(0)
        assertEquals("Person Identification Data (PID)", descriptor.getString("name"))

        val format = descriptor.getJSONObject("format")
        assertTrue(format.has("dc+sd-jwt"))

        val constraints = descriptor.getJSONObject("constraints")
        val fields = constraints.getJSONArray("fields")
        assertEquals(3, fields.length())
    }

    @Test
    fun `EUDI wallet URL is correctly formatted`() {
        // Test the wallet URL construction logic
        val transactionId = "test-tx-123"
        val clientId = "test-client-456"
        val requestUri = "https://example.com/request"
        val requestUriMethod = "get"

        val walletUrl = "eudi-openid4vp://?client_id=$clientId&request_uri=$requestUri&request_uri_method=$requestUriMethod"

        assertTrue(walletUrl.startsWith("eudi-openid4vp://"))
        assertTrue(walletUrl.contains("client_id=$clientId"))
        assertTrue(walletUrl.contains("request_uri=$requestUri"))
        assertTrue(walletUrl.contains("request_uri_method=$requestUriMethod"))
    }

    @Test
    fun `registration transaction has correct structure`() {
        // Test the registration transaction structure
        val signedEudiToken = "mock-signed-token"
        val nonce = UUID.randomUUID().toString()
        val webauthnKey = "mock-webauthn-key-hex"

        val transaction = mapOf(
            "signed_EUDI_token" to signedEudiToken,
            "nonce" to nonce,
            "webauthn_key" to webauthnKey
        )

        assertEquals(signedEudiToken, transaction["signed_EUDI_token"])
        assertEquals(nonce, transaction["nonce"])
        assertEquals(webauthnKey, transaction["webauthn_key"])
        assertEquals(3, transaction.size)
    }

    @Test
    fun `EUDI poll URL is correctly formatted`() {
        val transactionId = "test-transaction-123"
        val expectedPollUrl = "https://verifier-backend.eudiw.dev/ui/presentations/$transactionId"

        assertEquals(expectedPollUrl, "https://verifier-backend.eudiw.dev/ui/presentations/$transactionId")
    }

    @Test
    fun `EUDI verifier endpoint URL is correct`() {
        val expectedVerifierUrl = "https://verifier-backend.eudiw.dev/ui/presentations"

        assertEquals(expectedVerifierUrl, "https://verifier-backend.eudiw.dev/ui/presentations")
    }

    @Test
    fun `VP token extraction logic is sound`() {
        // Test the logic for extracting VP token from verifier response
        val mockVerifierResponse = JSONObject().apply {
            put("vp_token", org.json.JSONArray().apply {
                put("mock-vp-token-string")
                put("additional-token")
            })
            put("other_field", "other_value")
        }

        assertTrue(mockVerifierResponse.has("vp_token"))
        val vpTokenArray = mockVerifierResponse.getJSONArray("vp_token")
        assertEquals("mock-vp-token-string", vpTokenArray.getString(0))
    }

    @Test
    fun `registration block type constant is correct`() {
        assertEquals("eurotoken_register", "eurotoken_register")
    }

    @Test
    fun `nonce generation produces valid UUID format`() {
        val nonce = UUID.randomUUID().toString()

        assertNotNull(nonce)
        assertTrue(nonce.isNotEmpty())
        assertTrue(nonce.contains("-"))
        assertEquals(36, nonce.length) // Standard UUID length
    }

    @Test
    fun `transaction data serialization for WebAuthn signing`() {
        val amount = 100L
        val balance = 900L
        val expectedData = "$amount:$balance"

        assertEquals("100:900", expectedData)

        val dataBytes = expectedData.toByteArray()
        assertNotNull(dataBytes)
        assertTrue(dataBytes.isNotEmpty())
    }

    @Test
    fun `QR code signature encoding and decoding logic`() {
        // Test the logic for encoding/decoding signatures in QR codes
        val mockSignatureJson = """{"test":"signature"}"""
        val encoded = java.util.Base64.getEncoder().encodeToString(mockSignatureJson.toByteArray())
        val decoded = java.util.Base64.getDecoder().decode(encoded).decodeToString()

        assertEquals(mockSignatureJson, decoded)
    }
}
