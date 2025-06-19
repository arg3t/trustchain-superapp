package nl.tudelft.trustchain.eurotoken


import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */

class ExampleUnitTest {

    private val verificationUrl =
        "https://verifier-backend.eudiw.dev/utilities/validations/sdJwtVc"

    private suspend fun verifyEudiToken(nonce: String, token: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                val formBody = FormBody.Builder()
                    .add("sd_jwt_vc", token)
                    .add("nonce", nonce)
                    .build()

                val request = Request.Builder()
                    .url(verificationUrl)
                    .addHeader("Accept", "application/json")
                    .post(formBody)
                    .build()

                OkHttpClient().newCall(request).execute().use { resp ->
                    if (!resp.isSuccessful) return@use false
                    val body = resp.body?.string() ?: return@use false
                    val json = JSONObject(body)
                    val given = json.optString("given_name", "")
                    val family = json.optString("family_name", "")
                    return@use (given.isNotEmpty() || family.isNotEmpty())
                }
            } catch (e: Exception) {
                return@withContext false
            }
        }

    private val validToken = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJ4NWMiOiBbIk1JSUMzekNDQW9XZ0F3SUJBZ0lVZjNsb2hUbURNQW1TL1lYL3E0aHFvUnlKQjU0d0NnWUlLb1pJemowRUF3SXdYREVlTUJ3R0ExVUVBd3dWVUVsRUlFbHpjM1ZsY2lCRFFTQXRJRlZVSURBeU1TMHdLd1lEVlFRS0RDUkZWVVJKSUZkaGJHeGxkQ0JTWldabGNtVnVZMlVnU1cxd2JHVnRaVzUwWVhScGIyNHhDekFKQmdOVkJBWVRBbFZVTUI0WERUSTFNRFF4TURFME16YzFNbG9YRFRJMk1EY3dOREUwTXpjMU1Wb3dVakVVTUJJR0ExVUVBd3dMVUVsRUlFUlRJQzBnTURFeExUQXJCZ05WQkFvTUpFVlZSRWtnVjJGc2JHVjBJRkpsWm1WeVpXNWpaU0JKYlhCc1pXMWxiblJoZEdsdmJqRUxNQWtHQTFVRUJoTUNWVlF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVM3V0FBV3FQemUwVXMzejhwYWp5VlBXQlJtclJiQ2k1WDJzOUd2bHliUXl0d1R1bWNabmVqOUJrTGZBZ2xsb1g1dHYrTmdXZkRmZ3QvMDZzKzV0VjRsbzRJQkxUQ0NBU2t3SHdZRFZSMGpCQmd3Rm9BVVlzZVVSeWk5RDZJV0lLZWF3a21VUlBFQjA4Y3dHd1lEVlIwUkJCUXdFb0lRYVhOemRXVnlMbVYxWkdsM0xtUmxkakFXQmdOVkhTVUJBZjhFRERBS0JnZ3JnUUlDQUFBQkFqQkRCZ05WSFI4RVBEQTZNRGlnTnFBMGhqSm9kSFJ3Y3pvdkwzQnlaWEJ5YjJRdWNHdHBMbVYxWkdsM0xtUmxkaTlqY213dmNHbGtYME5CWDFWVVh6QXlMbU55YkRBZEJnTlZIUTRFRmdRVXFsL29weGtRbFl5MGxsYVRvUGJERS9teUVjRXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1GMEdBMVVkRWdSV01GU0dVbWgwZEhCek9pOHZaMmwwYUhWaUxtTnZiUzlsZFMxa2FXZHBkR0ZzTFdsa1pXNTBhWFI1TFhkaGJHeGxkQzloY21Ob2FYUmxZM1IxY21VdFlXNWtMWEpsWm1WeVpXNWpaUzFtY21GdFpYZHZjbXN3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQU5KVlNEc3FUM0lrR2NLV1dnU2V1YmtET2RpNS9VRTliMUdGL1g1ZlFSRmFBaUJwNXQ2dEhoOFh3RmhQc3R6T0hNb3B2QkQvR3dtczBSQVVnbVNuNmt1OEdnPT0iXX0.eyJfc2QiOiBbIjFFLTNrd2w0akZvcXNlYVlTX19TR0FWQmRILUg1NnhwQlpVS3RKUXhNZ3ciLCAiNm1hRnY1bEQtSFM4ZEZLdzJkZDRPYXpZTUJud0RxdVdJMHpSdEZ5RFdKSSIsICJEdlhkUlhCT3AwR2pxSnNwUlN3amo4X0NyNklYVlhlZVRZVFp4bnhlN3d3IiwgImJVNWtfM3RQelduZ0RGOGlXejh3VDZMTlF1Y2NEYnBDUWRKNUc5MHRzYzgiLCAiaDRTWGpIQ0VvaG5DdHFpTzFyb0JuWFM5SjdabUpST3RlRUp2WGFKQXBCQSIsICJoSmtteXJLc24yVkRneDNnTWxuR2t3LXpnazJBVlVoQVJMYmY0UUhZREowIiwgIms0dTJHUWxCTU1qb1dFYVVrc191cWs3T3RUUVE0RTNkeWlJSHplWHREelkiLCAiek81NThyQ0JXbmxlYjBvWFJLOXJLWGpmV0VLVGZfaW1MT2hHdFR5VjZkMCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV1ZGl3LmRldiIsICJpYXQiOiAxNzQ4NDczMjAwLCAiZXhwIjogMTc1NjI0OTIwMCwgInZjdCI6ICJ1cm46ZXVkaTpwaWQ6MSIsICJzdGF0dXMiOiB7ImlkZW50aWZpZXJfbGlzdCI6IHsiaWQiOiAiNjEzNiIsICJ1cmkiOiAiaHR0cHM6Ly9pc3N1ZXIuZXVkaXcuZGV2L2lkZW50aWZpZXJfbGlzdC9GQy9ldS5ldXJvcGEuZWMuZXVkaS5waWQuMS85OTg3ZGNhNS1mMzAxLTRmNzUtYTllZi1kNjJiMDk1YTBlZjQifSwgInN0YXR1c19saXN0IjogeyJpZHgiOiA2MTM2LCAidXJpIjogImh0dHBzOi8vaXNzdWVyLmV1ZGl3LmRldi90b2tlbl9zdGF0dXNfbGlzdC9GQy9ldS5ldXJvcGEuZWMuZXVkaS5waWQuMS85OTg3ZGNhNS1mMzAxLTRmNzUtYTllZi1kNjJiMDk1YTBlZjQifX0sICJfc2RfYWxnIjogInNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0yNTYiLCAieCI6ICJrU1NFdEhNOThnRVRHNjdONEpTclppdkU4U2NaamFmOE5Zb3o3WnJWNVZVIiwgInkiOiAiZEZvSHhEMy0zTlVMMDB3Q2dFNlllNUh0MXlWbndacEMtYzNGQTJUOElucyJ9fX0.E-WXmMnLwRkM-zqBX2mM1gNrpduFS6bls2ZXz81jAm0kHciLHAAInLaKrIA7KsdTz14XtwaD1N8Ysr2w-kSnGw~WyJPOW1uejNvUzh5Mi1UOUlKSzZtSG1RIiwgImlzc3VpbmdfYXV0aG9yaXR5IiwgIlRlc3QgUElEIGlzc3VlciJd~WyJyM2xFRHAtQXVDWlZrS0xhNVZmRTFRIiwgImlzc3VpbmdfY291bnRyeSIsICJGQyJd~WyJhZWZpLXJEMThvR1RSSDJjT0tUOERRIiwgImdpdmVuX25hbWUiLCAiVGVzdCJd~WyJiUTZyX1V0anIxOWY3alBiV1IxazVBIiwgIm5hdGlvbmFsaXRpZXMiLCBbInRyIl1d~WyJMWkRIVlNWZG4zQmhzZlgwTml1VWRRIiwgImZhbWlseV9uYW1lIiwgIlRlc3QiXQ~WyI1TGd5THdtbl9tOERHZDZhdDRkeUNRIiwgInBsYWNlX29mX2JpcnRoIiwgeyJfc2QiOiBbImpaaTdOTzdNZzVNME5Qc09GZ1RaMTAyUE0zR3RISDVoU1BtVkFBNHVSWGMiLCAibkgwTWRxR3g2eWpyTmR5QlNJcTE2ZldKUmRxMFVJSmcxWlRoUTdHQmtTayIsICJwcERmNDhFVkhuVDROMHFZbm1vN0lkWS00VTdoS3ptdlFlanRlVVVTeEprIl19XQ~WyJza0kzaXZYT0xBZEJLTzVHUGlOYmx3IiwgImxvY2FsaXR5IiwgIjEyMyJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJzZF9oYXNoIjoiWWJIY3hKaDNFMWlqM1libVVyeXllVzA3RWlFSFJoY1FydGtncXEyZlhTRSIsImF1ZCI6Ing1MDlfc2FuX2Ruczp2ZXJpZmllci1iYWNrZW5kLmV1ZGl3LmRldiIsIm5vbmNlIjoiYTk4NTk3NWUtZmU3Yy00MzgyLThlN2UtZjYyMWM2MWFlMmZhIiwiaWF0IjoxNzQ5MDc0NDQ5fQ.Ioo3sN5TqvQiIz9DMq35INdg15DaUgjCHsH3aapDQADQHjw039zaTlHNItbvRKfQdTQsUU08dbz7yX1zWY7RSQ"

    @Test
    fun testVerifyEudiToken_withValidToken_shouldReturnTrue() = runBlocking {
        val nonce = "a985975e-fe7c-4382-8e7e-f621c61ae2fa"
        val result = verifyEudiToken(nonce, validToken)
        assertTrue("Expected a known-good token to verify successfully", result)
    }

    @Test
    fun testVerifyEudiToken_withInvalidToken_shouldReturnFalse() = runBlocking {
        val nonce = "a985975e-fe7c-4382-8e7e-f621c61ae2fa"
        val fakeToken = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJ4NWMiOiBbIk"
        val result = verifyEudiToken(nonce, fakeToken)
        assertFalse("Expected an invalid token to fail verification", result)
    }

    @Test
    fun testVerifyEudiToken_withInvalidNonce_shouldReturnFalse() = runBlocking {
        val nonce = "invalid-nonce"
        val result = verifyEudiToken(nonce, validToken)
        assertFalse("Expected an invalid nonce to fail verification", result)
    }

    @Test
    fun testVerifyEudiToken_withInvalidNonceAndToken_shouldReturnFalse() = runBlocking {
        val nonce = "invalid-nonce"
        val fakeToken = "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImRjK3NkLWp3dCIsICJ4NWMiOiBbIk"
        val result = verifyEudiToken(nonce, fakeToken)
        assertFalse("Expected both invalid nonce and token to fail verification", result)
    }

    @Test
    fun testVerifyEudiToken_withEmptyNonce_shouldReturnFalse() = runBlocking {
        val nonce = ""
        val result = verifyEudiToken(nonce, validToken)
        assertFalse("Expected an empty nonce to fail verification", result)
    }

    @Test
    fun testVerifyEudiToken_withEmptyToken_shouldReturnFalse() = runBlocking {
        val nonce = "a985975e-fe7c-4382-8e7e-f621c61ae2fa"
        val emptyToken = ""
        val result = verifyEudiToken(nonce, emptyToken)
        assertFalse("Expected an empty token to fail verification", result)
    }

}
