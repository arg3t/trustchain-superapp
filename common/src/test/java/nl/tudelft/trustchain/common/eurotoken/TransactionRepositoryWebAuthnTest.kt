package nl.tudelft.trustchain.common.eurotoken

import io.mockk.*
import kotlinx.coroutines.runBlocking
import nl.tudelft.ipv8.IPv8
import nl.tudelft.ipv8.Peer
import nl.tudelft.ipv8.android.IPv8Android
import nl.tudelft.ipv8.attestation.trustchain.TrustChainBlock
import nl.tudelft.ipv8.attestation.trustchain.TrustChainCommunity
import nl.tudelft.ipv8.keyvault.IPSignature
import nl.tudelft.ipv8.keyvault.IdentityProviderChecker
import nl.tudelft.ipv8.keyvault.IdentityProviderOwner
import nl.tudelft.trustchain.common.eurotoken.blocks.WebAuthnValidator
import nl.tudelft.trustchain.common.eurotoken.webauthn.WebAuthnSignature
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class TransactionRepositoryWebAuthnTest {

    private lateinit var transactionRepository: TransactionRepository
    private val mockTrustChainCommunity = mockk<TrustChainCommunity>(relaxed = true)
    private val mockGatewayStore = mockk<GatewayStore>(relaxed = true)

    @Before
    fun setUp() {
        transactionRepository = TransactionRepository(mockTrustChainCommunity, mockGatewayStore)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `verifyTransactionSignature returns true for valid signature`() {
        // Arrange
        val recipient = "test-recipient"
        val name = "test-name"
        val amount = 100L
        val mockSignature = mockk<IPSignature>(relaxed = true)
        val mockChecker = mockk<IdentityProviderChecker>(relaxed = true)
        
        val expectedHash = java.security.MessageDigest.getInstance("SHA256")
            .digest("$recipient $amount $name".toByteArray())
        
        every { mockSignature.challenge } returns expectedHash
        every { mockChecker.verify(mockSignature) } returns true

        // Act
        val result = transactionRepository.verifyTransactionSignature(recipient, name, amount, mockSignature, mockChecker)

        // Assert
        assertTrue(result)
    }

    @Test
    fun `verifyTransactionSignature returns false for invalid challenge`() {
        // Arrange
        val recipient = "test-recipient"
        val name = "test-name"
        val amount = 100L
        val mockSignature = mockk<IPSignature>(relaxed = true)
        val mockChecker = mockk<IdentityProviderChecker>(relaxed = true)
        
        every { mockSignature.challenge } returns "wrong-hash".toByteArray()
        every { mockChecker.verify(mockSignature) } returns true

        // Act
        val result = transactionRepository.verifyTransactionSignature(recipient, name, amount, mockSignature, mockChecker)

        // Assert
        assertFalse(result)
    }

    @Test
    fun `verifyTransactionSignature returns false for invalid signature verification`() {
        // Arrange
        val recipient = "test-recipient"
        val name = "test-name"
        val amount = 100L
        val mockSignature = mockk<IPSignature>(relaxed = true)
        val mockChecker = mockk<IdentityProviderChecker>(relaxed = true)
        
        val expectedHash = java.security.MessageDigest.getInstance("SHA256")
            .digest("$recipient $amount $name".toByteArray())
        
        every { mockSignature.challenge } returns expectedHash
        every { mockChecker.verify(mockSignature) } returns false

        // Act
        val result = transactionRepository.verifyTransactionSignature(recipient, name, amount, mockSignature, mockChecker)

        // Assert
        assertFalse(result)
    }

}