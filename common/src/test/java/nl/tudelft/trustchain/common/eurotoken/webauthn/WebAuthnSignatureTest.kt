package nl.tudelft.trustchain.common.eurotoken.webauthn

import nl.tudelft.ipv8.keyvault.IPSignature
import org.junit.Assert.*
import org.junit.Test
import io.mockk.*

class WebAuthnSignatureTest {

    private fun createMockIPSignature(
        data: ByteArray = "test-data".toByteArray(),
        signature: ByteArray = "test-signature".toByteArray(),
        authenticatorData: ByteArray = "test-auth-data".toByteArray(),
        challenge: ByteArray = "test-challenge".toByteArray()
    ): IPSignature {
        val mock = mockk<IPSignature>(relaxed = true)
        every { mock.data } returns data
        every { mock.signature } returns signature
        every { mock.authenticatorData } returns authenticatorData
        every { mock.challenge } returns challenge
        every { mock.hashCode() } returns (data.contentHashCode() + signature.contentHashCode())
        return mock
    }

    @Test
    fun `constructor sets properties correctly`() {
        // Arrange
        val mockSignature = createMockIPSignature()
        val publicKey = "test-public-key".toByteArray()

        // Act
        val webAuthnSignature = WebAuthnSignature(mockSignature, publicKey)

        // Assert
        assertEquals(mockSignature, webAuthnSignature.signature)
        assertArrayEquals(publicKey, webAuthnSignature.publicKey)
    }

    @Test
    fun `equals returns true for identical objects`() {
        // Arrange
        val data = "test-data".toByteArray()
        val signature = "test-sig".toByteArray()
        val authData = "test-auth".toByteArray()
        val challenge = "test-challenge".toByteArray()
        val publicKey = "test-key".toByteArray()

        val mockSignature1 = createMockIPSignature(data, signature, authData, challenge)
        val mockSignature2 = createMockIPSignature(data, signature, authData, challenge)

        val signature1 = WebAuthnSignature(mockSignature1, publicKey)
        val signature2 = WebAuthnSignature(mockSignature2, publicKey)

        // Act & Assert
        assertTrue(signature1.equals(signature2))
    }

    @Test
    fun `equals returns false for different signatures`() {
        // Arrange
        val mockSignature1 = createMockIPSignature(signature = "sig1".toByteArray())
        val mockSignature2 = createMockIPSignature(signature = "sig2".toByteArray())
        val publicKey = "test-key".toByteArray()

        val signature1 = WebAuthnSignature(mockSignature1, publicKey)
        val signature2 = WebAuthnSignature(mockSignature2, publicKey)

        // Act & Assert
        assertFalse(signature1.equals(signature2))
    }

    @Test
    fun `equals returns false for different public keys`() {
        // Arrange
        val mockSignature = createMockIPSignature()
        val publicKey1 = "test-key-1".toByteArray()
        val publicKey2 = "test-key-2".toByteArray()

        val signature1 = WebAuthnSignature(mockSignature, publicKey1)
        val signature2 = WebAuthnSignature(mockSignature, publicKey2)

        // Act & Assert
        assertFalse(signature1.equals(signature2))
    }

    @Test
    fun `equals returns false for null object`() {
        // Arrange
        val mockSignature = createMockIPSignature()
        val publicKey = "test-key".toByteArray()
        val signature = WebAuthnSignature(mockSignature, publicKey)

        // Act & Assert
        assertFalse(signature.equals(null))
    }

    @Test
    fun `equals returns false for different class type`() {
        // Arrange
        val mockSignature = createMockIPSignature()
        val publicKey = "test-key".toByteArray()
        val signature = WebAuthnSignature(mockSignature, publicKey)

        // Act & Assert
        assertFalse(signature.equals("not a WebAuthnSignature"))
    }

    @Test
    fun `equals returns true for same instance`() {
        // Arrange
        val mockSignature = createMockIPSignature()
        val publicKey = "test-key".toByteArray()
        val signature = WebAuthnSignature(mockSignature, publicKey)

        // Act & Assert
        assertTrue(signature.equals(signature))
    }

}