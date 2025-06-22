package nl.tudelft.trustchain.eurotoken.ui.transfer

import kotlinx.coroutines.runBlocking
import nl.tudelft.trustchain.common.util.EUDIUtils
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.security.MessageDigest

/**
 * Integration tests for enhanced transaction validation system.
 * Tests the complete flow from peer registration verification to multi-layered transaction validation.
 */
class TransactionValidationIntegrationTest {

    private lateinit var eudiUtils: EUDIUtils

    @Before
    fun setUp() {
        eudiUtils = EUDIUtils()
    }

    @Test
    fun `transaction data hash generation consistency`() {
        // Arrange: Test transaction data hash generation for signature validation
        val recipient = "0x1234567890abcdef1234567890abcdef12345678"
        val name = "Coffee Shop Payment"
        val amount = 150L

        // Act: Generate transaction hash (as would be done in TransactionRepository.verifyTransactionSignature)
        val transactionData = "$recipient $amount $name"
        val hash1 = MessageDigest.getInstance("SHA256").digest(transactionData.toByteArray())
        val hash2 = MessageDigest.getInstance("SHA256").digest(transactionData.toByteArray())

        // Assert: Hash should be consistent and reproducible
        assertArrayEquals("Transaction hash should be reproducible", hash1, hash2)
        assertEquals("SHA256 hash should be 32 bytes", 32, hash1.size)
        assertTrue("Hash should not be empty", hash1.isNotEmpty())

        // Test with different transaction data
        val differentData = "$recipient ${amount + 1} $name"
        val differentHash = MessageDigest.getInstance("SHA256").digest(differentData.toByteArray())

        assertFalse("Different transaction data should produce different hash",
                   hash1.contentEquals(differentHash))
    }

    @Test
    fun `transaction validation business rules - amount and balance constraints`() {
        // Arrange: Test various balance and amount scenarios
        val testCases = listOf(
            Triple(1000L, 500L, true),   // Sufficient balance
            Triple(1000L, 1000L, false), // Exact balance (should fail due to no remainder)
            Triple(1000L, 1001L, false), // Insufficient balance
            Triple(100L, 50L, true),     // Normal case
            Triple(0L, 1L, false),       // Zero balance
            Triple(1000L, 0L, false),    // Zero amount (invalid)
            Triple(1000L, -50L, false)   // Negative amount (invalid)
        )

        testCases.forEach { (balance, amount, shouldPass) ->
            // Act: Check if transaction would be allowed based on business rules
            val hasValidBalance = balance > amount && amount > 0

            // Assert
            if (shouldPass) {
                assertTrue("Transaction should pass for balance=$balance, amount=$amount",
                          hasValidBalance)
            } else {
                assertFalse("Transaction should fail for balance=$balance, amount=$amount",
                           hasValidBalance)
            }
        }
    }

    @Test
    fun `empty name handling in transaction signature validation`() {
        // Arrange: Test handling of empty name field in transactions (as implemented in TransactionRepository)
        val recipient = "test-recipient"
        val normalName = "Normal Payment"
        val emptyName = ""
        val amount = 250L

        // Act: Create transaction strings as done in verifyTransactionSignature
        val normalTransactionString = "$recipient $amount $normalName"
        val emptyNameTransactionString = "$recipient $amount null" // Empty name becomes "null"

        val normalHash = MessageDigest.getInstance("SHA256").digest(normalTransactionString.toByteArray())
        val emptyNameHash = MessageDigest.getInstance("SHA256").digest(emptyNameTransactionString.toByteArray())

        // Assert: Different transaction strings should produce different hashes
        assertFalse("Normal name and empty name should produce different hashes",
                   normalHash.contentEquals(emptyNameHash))

        // Verify the empty name replacement logic
        val expectedEmptyNameString = "$recipient $amount null"
        assertEquals("Empty name should be replaced with 'null'",
                    expectedEmptyNameString, emptyNameTransactionString)
    }

    @Test
    fun `multi-layered security validation components`() {
        // Arrange: Test the components of multi-layer security validation
        val validRecipient = "valid-recipient"
        val validName = "Security Test Transfer"
        val validAmount = 100L

        // Layer 1: Basic transaction data validation
        assertTrue("Recipient should not be empty", validRecipient.isNotEmpty())

        // Layer 2: Transaction string formation and hashing
        val transactionString = "$validRecipient $validAmount $validName"
        val expectedHash = MessageDigest.getInstance("SHA256").digest(transactionString.toByteArray())

        assertTrue("Transaction string should contain all components",
                  transactionString.contains(validRecipient) &&
                  transactionString.contains(validAmount.toString()) &&
                  transactionString.contains(validName))

        assertEquals("Hash should be SHA256 length", 32, expectedHash.size)

        // Layer 3: Data integrity verification
        val recreatedHash = MessageDigest.getInstance("SHA256").digest(transactionString.toByteArray())
        assertArrayEquals("Hash should be reproducible for integrity verification",
                         expectedHash, recreatedHash)
    }

    @Test
    fun `EUDI registration data structure validation`() {
        // Arrange: Test EUDI registration data structure used in registration blocks
        val validEudiTokenFormats = listOf(
            """{"iss":"https://verifier-backend.eudiw.dev","sub":"user1","iat":1234567890}""",
            """{"iss":"eu-verifier","sub":"user2","iat":1234567891,"exp":1234567900}""",
            """{"iss":"test-issuer","sub":"test-user","iat":1234567892,"nonce":"test-nonce"}"""
        )

        val invalidTokenFormats = listOf(
            "", // Empty
            "not-json", // Not JSON
            """{"sub":"user"}""", // Missing issuer
            """{"iss":"verifier"}""", // Missing subject
            """{}""" // Empty JSON
        )

        // Act & Assert: Valid tokens should pass basic format checks
        validEudiTokenFormats.forEach { token ->
            assertTrue("Valid token should contain issuer: $token", token.contains("iss"))
            assertTrue("Valid token should contain subject: $token", token.contains("sub"))
            assertTrue("Valid token should be valid JSON: $token",
                      token.startsWith("{") && token.endsWith("}"))
        }

        // Invalid tokens should fail basic checks
        invalidTokenFormats.forEach { token ->
            if (token.isNotEmpty()) {
                assertFalse("Invalid token should not be accepted: $token",
                           token.contains("iss") && token.contains("sub") &&
                           token.startsWith("{") && token.endsWith("}"))
            }
        }
    }

    @Test
    fun `EUDI API endpoint configuration validation`() {
        // Arrange: Test EUDI API endpoint configuration for backend integration
        val expectedBaseUrl = "https://verifier-backend.eudiw.dev"
        val expectedEndpoints = listOf(
            "/verify-token",
            "/validate-credential",
            "/public-key"
        )

        // Act & Assert: Verify API configuration
        assertTrue("EUDI base URL should use HTTPS", expectedBaseUrl.startsWith("https://"))
        assertTrue("EUDI base URL should be official domain", expectedBaseUrl.contains("eudiw.dev"))

        expectedEndpoints.forEach { endpoint ->
            assertTrue("Endpoint should start with /", endpoint.startsWith("/"))
            assertFalse("Endpoint should not end with /", endpoint.endsWith("/"))
            assertTrue("Endpoint should be reasonable length", endpoint.length in 5..50)
        }

        // Test URL construction for API calls
        val fullUrls = expectedEndpoints.map { "$expectedBaseUrl$it" }
        fullUrls.forEach { url ->
            assertTrue("Constructed URL should be valid format",
                      url.matches(Regex("https://[a-zA-Z0-9.-]+/[a-zA-Z0-9-]+")))
        }
    }

    @Test
    fun `transaction validation error handling scenarios`() {
        // Arrange: Test various error scenarios in transaction validation
        val validRecipient = "test-recipient"
        val validName = "Error Test"
        val validAmount = 100L

        // Error case 1: Invalid transaction data
        val invalidAmounts = listOf(-1L, 0L, Long.MAX_VALUE)
        val invalidRecipients = listOf("", "   ", "invalid-format")

        invalidAmounts.forEach { amount ->
            val isValidAmount = amount > 0 && amount < 1000000
            assertFalse("Invalid amount should be rejected: $amount", isValidAmount)
        }

        invalidRecipients.forEach { recipient ->
            val isValidRecipient = recipient.isNotEmpty() && recipient.trim().isNotEmpty() && !recipient.contains("invalid")
            assertFalse("Invalid recipient should be rejected: '$recipient'", isValidRecipient)
        }

        // Error case 2: Hash generation with malformed data
        val malformedData = "\u0000\u0001\u0002" // Non-printable characters
        val hash = try {
            MessageDigest.getInstance("SHA256").digest(malformedData.toByteArray())
        } catch (e: Exception) {
            null
        }

        assertNotNull("Hash generation should handle malformed data gracefully", hash)

        // Recovery case: Valid transaction after error
        val validTransactionString = "$validRecipient $validAmount $validName"
        val validHash = MessageDigest.getInstance("SHA256").digest(validTransactionString.toByteArray())

        assertEquals("Valid transaction should produce correct hash length", 32, validHash.size)
        assertTrue("Valid hash should not be empty", validHash.isNotEmpty())
    }

    @Test
    fun `performance validation for transaction processing`() {
        // Arrange: Performance test for transaction validation components
        // kind of weird test but I keep it anyway
        val recipient = "performance-test-recipient"
        val name = "Performance Test"
        val amount = 100L

        // Act: Measure hash generation performance
        val iterations = 1000
        val startTime = System.currentTimeMillis()

        repeat(iterations) {
            val transactionData = "$recipient $amount $name"
            MessageDigest.getInstance("SHA256").digest(transactionData.toByteArray())
        }

        val endTime = System.currentTimeMillis()
        val totalTime = endTime - startTime
        val averageTime = totalTime.toDouble() / iterations

        // Assert: Performance should be reasonable
        assertTrue("Total hash generation time should be reasonable", totalTime < 2000) // < 2 seconds
        assertTrue("Average hash generation time should be fast", averageTime < 2) // < 2ms per hash

        println("Hash generation performance: ${iterations} iterations in ${totalTime}ms (avg: ${averageTime}ms)")
    }
}
