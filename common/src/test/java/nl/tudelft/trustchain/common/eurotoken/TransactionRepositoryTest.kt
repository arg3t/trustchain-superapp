package nl.tudelft.trustchain.common.eurotoken

import io.mockk.*
import nl.tudelft.ipv8.attestation.trustchain.TrustChainCommunity
import nl.tudelft.ipv8.keyvault.IPSignature
import nl.tudelft.ipv8.keyvault.IdentityProviderChecker
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest

class TransactionRepositoryTest {

    private lateinit var transactionRepository: TransactionRepository
    private val mockTrustChainCommunity = mockk<TrustChainCommunity>()
    private val mockGatewayStore = mockk<GatewayStore>()
    private val mockIdentityProviderChecker = mockk<IdentityProviderChecker>()
    private val mockSignature = mockk<IPSignature>()

    @Before
    fun setUp() {
        transactionRepository = TransactionRepository(mockTrustChainCommunity, mockGatewayStore)
        MockKAnnotations.init(this)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun testInit() {
        // Original test for backwards compatibility
        assertNotNull(transactionRepository)
    }

    @Test
    fun `verifyTransactionSignature returns true when signature is valid and challenge matches hash`() {
        // Arrange
        val recipient = "test-recipient"
        val name = "test-name"
        val amount = 100L
        
        val expectedMessage = "$recipient $amount $name"
        val expectedHash = MessageDigest.getInstance("SHA256").digest(expectedMessage.toByteArray())
        
        every { mockIdentityProviderChecker.verify(mockSignature) } returns true
        every { mockSignature.challenge } returns expectedHash

        // Act
        val result = transactionRepository.verifyTransactionSignature(
            recipient, name, amount, mockSignature, mockIdentityProviderChecker
        )

        // Assert
        assertTrue(result)
        verify { mockIdentityProviderChecker.verify(mockSignature) }
    }

    @Test
    fun `verifyTransactionSignature returns false when identity provider verification fails`() {
        // Arrange
        val recipient = "test-recipient"
        val name = "test-name"
        val amount = 100L
        
        every { mockIdentityProviderChecker.verify(mockSignature) } returns false
        every { mockSignature.challenge } returns ByteArray(32) // any hash

        // Act
        val result = transactionRepository.verifyTransactionSignature(
            recipient, name, amount, mockSignature, mockIdentityProviderChecker
        )

        // Assert
        assertFalse(result)
        verify { mockIdentityProviderChecker.verify(mockSignature) }
    }

    @Test
    fun `verifyTransactionSignature returns false when challenge does not match expected hash`() {
        // Arrange
        val recipient = "test-recipient"
        val name = "test-name"
        val amount = 100L
        
        val wrongHash = ByteArray(32) { 0xFF.toByte() } // Different hash
        
        every { mockIdentityProviderChecker.verify(mockSignature) } returns true
        every { mockSignature.challenge } returns wrongHash

        // Act
        val result = transactionRepository.verifyTransactionSignature(
            recipient, name, amount, mockSignature, mockIdentityProviderChecker
        )

        // Assert
        assertFalse(result)
    }

    @Test
    fun `verifyTransactionSignature handles empty name correctly`() {
        // Arrange
        val recipient = "test-recipient"
        val name = ""
        val amount = 100L
        
        // When name is empty, it should be replaced with "null" in the hash calculation
        val expectedMessage = "$recipient $amount null"
        val expectedHash = MessageDigest.getInstance("SHA256").digest(expectedMessage.toByteArray())
        
        every { mockIdentityProviderChecker.verify(mockSignature) } returns true
        every { mockSignature.challenge } returns expectedHash

        // Act
        val result = transactionRepository.verifyTransactionSignature(
            recipient, name, amount, mockSignature, mockIdentityProviderChecker
        )

        // Assert
        assertTrue(result)
    }

    @Test
    fun `verifyTransactionSignature handles negative amount correctly`() {
        // Arrange
        val recipient = "test-recipient"
        val name = "test-name"
        val amount = -50L
        
        val expectedMessage = "$recipient $amount $name"
        val expectedHash = MessageDigest.getInstance("SHA256").digest(expectedMessage.toByteArray())
        
        every { mockIdentityProviderChecker.verify(mockSignature) } returns true
        every { mockSignature.challenge } returns expectedHash

        // Act
        val result = transactionRepository.verifyTransactionSignature(
            recipient, name, amount, mockSignature, mockIdentityProviderChecker
        )

        // Assert
        assertTrue(result)
    }

    @Test
    fun `verifyTransactionSignature handles zero amount correctly`() {
        // Arrange
        val recipient = "test-recipient"
        val name = "test-name"
        val amount = 0L
        
        val expectedMessage = "$recipient $amount $name"
        val expectedHash = MessageDigest.getInstance("SHA256").digest(expectedMessage.toByteArray())
        
        every { mockIdentityProviderChecker.verify(mockSignature) } returns true
        every { mockSignature.challenge } returns expectedHash

        // Act
        val result = transactionRepository.verifyTransactionSignature(
            recipient, name, amount, mockSignature, mockIdentityProviderChecker
        )

        // Assert
        assertTrue(result)
    }

    @Test
    fun `verifyTransactionSignature handles special characters in recipient and name`() {
        // Arrange
        val recipient = "test-recipient@example.com"
        val name = "Test Name with Spaces & Special Ch@rs"
        val amount = 100L
        
        val expectedMessage = "$recipient $amount $name"
        val expectedHash = MessageDigest.getInstance("SHA256").digest(expectedMessage.toByteArray())
        
        every { mockIdentityProviderChecker.verify(mockSignature) } returns true
        every { mockSignature.challenge } returns expectedHash

        // Act
        val result = transactionRepository.verifyTransactionSignature(
            recipient, name, amount, mockSignature, mockIdentityProviderChecker
        )

        // Assert
        assertTrue(result)
    }
}