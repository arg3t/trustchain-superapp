package nl.tudelft.trustchain.eurotoken

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
class ExampleUnitTest {
    @Test
    fun addition_isCorrect() {
        assertEquals(4, (2 + 2))
    }

    private val fragment = TransferFragment()

    private val validToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.…"

    @Test
    fun testVerifyEudiToken_withValidToken_shouldReturnTrue() = runBlocking {
        val nonce = "2418429c-f59f-4b48-99c1-4f4bfaff8116"
        val result = fragment.verifyEudiToken(nonce, validToken)
        assertTrue("Expected a known-good token to verify successfully", result)
    }

    @Test
    fun testVerifyEudiToken_withInvalidToken_shouldReturnFalse() = runBlocking {
        val nonce = "2418429c-f59f-4b48-99c1-4f4bfaff8116"
        val fakeToken = "invalid.jwt.token"
        val result = fragment.verifyEudiToken(nonce, fakeToken)
        assertFalse("Expected an invalid token to fail verification", result)
    }

    @Test
    fun testVerifyEudiToken_withInvalidNonce_shouldReturnFalse() = runBlocking {
        val nonce = "invalid-nonce"
        val result = fragment.verifyEudiToken(nonce, validToken)
        assertFalse("Expected an invalid nonce to fail verification", result)
    }

    @Test
    fun testVerifyEudiToken_withInvalidNonceAndToken_shouldReturnFalse() = runBlocking {
        val nonce = "invalid-nonce"
        val fakeToken = "invalid.jwt.token"
        val result = fragment.verifyEudiToken(nonce, fakeToken)
        assertFalse("Expected both invalid nonce and token to fail verification", result)
    }

    @Test 
    fun testVerifyEudiToken_withEmptyNonce_shouldReturnFalse() = runBlocking {
        val nonce = ""
        val result = fragment.verifyEudiToken(nonce, validToken)
        assertFalse("Expected an empty nonce to fail verification", result)
    }

    @Test
    fun testVerifyEudiToken_withEmptyToken_shouldReturnFalse() = runBlocking {
        val nonce = "2418429c-f59f-4b48-99c1-4f4bfaff8116"
        val emptyToken = ""
        val result = fragment.verifyEudiToken(nonce, emptyToken)
        assertFalse("Expected an empty token to fail verification", result)
    }

}
