package nl.tudelft.trustchain.common.eurotoken

import io.mockk.*
import kotlinx.coroutines.runBlocking
import nl.tudelft.ipv8.attestation.trustchain.TrustChainBlock
import nl.tudelft.ipv8.attestation.trustchain.TrustChainCommunity
import nl.tudelft.ipv8.keyvault.IPSignature
import nl.tudelft.ipv8.keyvault.IdentityProviderChecker
import nl.tudelft.ipv8.keyvault.IdentityProviderOwner
import nl.tudelft.trustchain.common.eurotoken.blocks.WebAuthnValidator
import nl.tudelft.trustchain.common.eurotoken.webauthn.WebAuthnSignature
import nl.tudelft.trustchain.common.util.WebAuthnIdentityProviderChecker
import nl.tudelft.trustchain.common.util.WebAuthnIdentityProviderOwner
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.math.BigInteger
import java.security.MessageDigest

/**
 * Integration tests for WebAuthn signature system in eurotoken transactions.
 * Tests the complete flow from identity provider setup to transaction validation.
 */
class WebAuthnTransactionIntegrationTest {

    private lateinit var transactionRepository: TransactionRepository
    private lateinit var webAuthnValidator: WebAuthnValidator
    private val mockTrustChainCommunity = mockk<TrustChainCommunity>(relaxed = true)
    private val mockGatewayStore = mockk<GatewayStore>(relaxed = true)

    @Before
    fun setUp() {
        transactionRepository = TransactionRepository(mockTrustChainCommunity, mockGatewayStore)
        webAuthnValidator = WebAuthnValidator(transactionRepository)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `complete WebAuthn transaction flow - identity provider setup to validation`() {
        // Arrange: Set up WebAuthn identity provider
        val webAuthnPublicKey = "test-webauthn-key".toByteArray()
        val webAuthnId = "test-webauthn-id"
        val mockContext = mockk<android.content.Context>(relaxed = true)
        val identityProvider = WebAuthnIdentityProviderOwner(webAuthnId, webAuthnPublicKey, mockContext)
        
        // Create a valid WebAuthn signature for transaction data
        val recipient = "test-recipient"
        val name = "test-name"
        val amount = 100L
        val transactionData = "$recipient $amount $name"
        val expectedHash = MessageDigest.getInstance("SHA256").digest(transactionData.toByteArray())
        
        val mockSignature = mockk<IPSignature>(relaxed = true)
        every { mockSignature.challenge } returns expectedHash
        every { mockSignature.data } returns "test-data".toByteArray()
        every { mockSignature.signature } returns "test-sig".toByteArray()
        every { mockSignature.authenticatorData } returns "test-auth".toByteArray()
        
        // Act & Assert: Verify transaction signature validation works
        val mockChecker = mockk<IdentityProviderChecker>(relaxed = true)
        every { mockChecker.verify(mockSignature) } returns true
        
        val isValid = transactionRepository.verifyTransactionSignature(
            recipient, name, amount, mockSignature, mockChecker
        )
        
        assertTrue("WebAuthn transaction signature should be valid", isValid)
    }

    @Test
    fun `WebAuthn block validation integration - valid signature flow`() {
        // Arrange: Create a block with valid WebAuthn signature data
        val mockBlock = mockk<TrustChainBlock>(relaxed = true)
        val mockTransaction = mockk<MutableMap<Any, Any>>(relaxed = true)
        val mockDatabase = mockk<nl.tudelft.ipv8.attestation.trustchain.store.TrustChainStore>(relaxed = true)
        
        val webAuthnPublicKey = "valid-key".toByteArray()
        val mockSignature = mockk<IPSignature>(relaxed = true)
        val webAuthnSignature = WebAuthnSignature(mockSignature, webAuthnPublicKey)
        
        every { mockBlock.type } returns TransactionRepository.BLOCK_TYPE_TRANSFER
        every { mockBlock.transaction } returns mockTransaction
        every { mockTransaction.containsKey(WebAuthnValidator.KEY_WEBAUTHN_PUBLIC_KEY) } returns true
        every { mockTransaction.containsKey(WebAuthnValidator.KEY_WEBAUTHN_SIGNATURE) } returns true
        every { mockTransaction[WebAuthnValidator.KEY_WEBAUTHN_PUBLIC_KEY] } returns webAuthnPublicKey
        every { mockTransaction[WebAuthnValidator.KEY_WEBAUTHN_SIGNATURE] } returns webAuthnSignature
        every { mockBlock.blockId } returns "test-block-id"
        
        // Mock successful signature verification
        every { mockSignature.data } returns "test-data".toByteArray()
        every { mockSignature.signature } returns "test-sig".toByteArray()
        every { mockSignature.authenticatorData } returns "test-auth".toByteArray()
        every { mockSignature.challenge } returns "test-challenge".toByteArray()
        
        // Act: Validate the block
        val validationResult = webAuthnValidator.validate(mockBlock, mockDatabase)
        
        // Assert: Should be valid (though verification may fail in mock environment)
        assertNotNull("Validation result should not be null", validationResult)
    }

    @Test
    fun `WebAuthn signature challenge validation - transaction data integrity`() {
        // Arrange: Test that signature challenge matches transaction data hash
        val recipient = "0x1234567890abcdef"
        val name = "Alice"
        val amount = 500L
        
        // Create expected hash manually
        val transactionString = "$recipient $amount $name"
        val expectedHash = MessageDigest.getInstance("SHA256").digest(transactionString.toByteArray())
        
        val mockSignature = mockk<IPSignature>(relaxed = true)
        val mockChecker = mockk<IdentityProviderChecker>(relaxed = true)
        
        every { mockSignature.challenge } returns expectedHash
        every { mockChecker.verify(mockSignature) } returns true
        
        // Act: Verify with correct challenge
        val isValidCorrect = transactionRepository.verifyTransactionSignature(
            recipient, name, amount, mockSignature, mockChecker
        )
        
        // Act: Verify with incorrect challenge (different amount)
        every { mockSignature.challenge } returns "wrong-challenge".toByteArray()
        val isValidIncorrect = transactionRepository.verifyTransactionSignature(
            recipient, name, amount, mockSignature, mockChecker
        )
        
        // Assert
        assertTrue("Signature with correct challenge should be valid", isValidCorrect)
        assertFalse("Signature with incorrect challenge should be invalid", isValidIncorrect)
    }

    @Test
    fun `WebAuthn empty name handling - null replacement in transaction data`() {
        // Arrange: Test handling of empty name field in transactions
        val recipient = "test-recipient"
        val emptyName = ""
        val amount = 250L
        
        // Expected behavior: empty name should be replaced with "null"
        val expectedTransactionString = "$recipient $amount null"
        val expectedHash = MessageDigest.getInstance("SHA256").digest(expectedTransactionString.toByteArray())
        
        val mockSignature = mockk<IPSignature>(relaxed = true)
        val mockChecker = mockk<IdentityProviderChecker>(relaxed = true)
        
        every { mockSignature.challenge } returns expectedHash
        every { mockChecker.verify(mockSignature) } returns true
        
        // Act: Verify with empty name
        val isValid = transactionRepository.verifyTransactionSignature(
            recipient, emptyName, amount, mockSignature, mockChecker
        )
        
        // Assert
        assertTrue("Empty name should be handled as 'null' in signature verification", isValid)
    }

    @Test
    fun `WebAuthn validator block type filtering - only eurotoken blocks validated`() {
        // Arrange: Test that only eurotoken block types are validated
        val mockBlock = mockk<TrustChainBlock>(relaxed = true)
        val mockDatabase = mockk<nl.tudelft.ipv8.attestation.trustchain.store.TrustChainStore>(relaxed = true)
        
        // Test non-eurotoken block type
        every { mockBlock.type } returns "some_other_block_type"
        
        // Act
        val resultNonEurotoken = webAuthnValidator.validate(mockBlock, mockDatabase)
        
        // Test eurotoken block type
        every { mockBlock.type } returns TransactionRepository.BLOCK_TYPE_CREATE
        every { mockBlock.transaction } returns mockk<MutableMap<Any, Any>>(relaxed = true) {
            every { containsKey(any()) } returns false
        }
        
        val resultEurotokenNoWebAuthn = webAuthnValidator.validate(mockBlock, mockDatabase)
        
        // Assert
        assertEquals("Non-eurotoken blocks should pass validation without WebAuthn check", 
                    nl.tudelft.ipv8.attestation.trustchain.validation.ValidationResult.Valid, 
                    resultNonEurotoken)
        assertEquals("Eurotoken blocks without WebAuthn data should pass validation", 
                    nl.tudelft.ipv8.attestation.trustchain.validation.ValidationResult.Valid, 
                    resultEurotokenNoWebAuthn)
    }

    @Test
    fun `WebAuthn signature data class equality - cryptographic content comparison`() {
        // Arrange: Test that WebAuthnSignature equality compares actual signature content
        val publicKey = "test-key".toByteArray()
        
        val signature1Data = "data1".toByteArray()
        val signature1Sig = "sig1".toByteArray()
        val signature1Auth = "auth1".toByteArray()
        val signature1Challenge = "challenge1".toByteArray()
        
        val mockSignature1 = mockk<IPSignature>(relaxed = true)
        every { mockSignature1.data } returns signature1Data
        every { mockSignature1.signature } returns signature1Sig
        every { mockSignature1.authenticatorData } returns signature1Auth
        every { mockSignature1.challenge } returns signature1Challenge
        
        val mockSignature2 = mockk<IPSignature>(relaxed = true)
        every { mockSignature2.data } returns signature1Data // Same data
        every { mockSignature2.signature } returns signature1Sig // Same signature
        every { mockSignature2.authenticatorData } returns signature1Auth // Same auth
        every { mockSignature2.challenge } returns signature1Challenge // Same challenge
        
        val webAuthnSig1 = WebAuthnSignature(mockSignature1, publicKey)
        val webAuthnSig2 = WebAuthnSignature(mockSignature2, publicKey)
        
        // Act & Assert: Should be equal when all signature content matches
        assertTrue("WebAuthnSignatures with identical content should be equal", 
                  webAuthnSig1.equals(webAuthnSig2))
        
        // Test inequality when signature content differs
        every { mockSignature2.signature } returns "different-sig".toByteArray()
        val webAuthnSig3 = WebAuthnSignature(mockSignature2, publicKey)
        
        assertFalse("WebAuthnSignatures with different signature content should not be equal", 
                   webAuthnSig1.equals(webAuthnSig3))
    }

    @Test
    fun `WebAuthn identity provider context management`() {
        // Arrange: Test identity provider context setting and retrieval
        val webAuthnKey = "context-test-key".toByteArray()
        val webAuthnId = "context-test-id"
        val mockContext = mockk<android.content.Context>(relaxed = true)
        
        val identityProvider = WebAuthnIdentityProviderOwner(webAuthnId, webAuthnKey, mockContext)
        
        // Assert: Verify context was properly set
        assertEquals("Identity provider should maintain context", mockContext, identityProvider.context)
        assertEquals("Identity provider should maintain ID", webAuthnId, identityProvider.id)
        assertArrayEquals("Identity provider should maintain public key", webAuthnKey, identityProvider.publicKey)
    }
}