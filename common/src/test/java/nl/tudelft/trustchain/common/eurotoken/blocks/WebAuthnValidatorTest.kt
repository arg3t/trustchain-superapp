package nl.tudelft.trustchain.common.eurotoken.blocks

import io.mockk.*
import nl.tudelft.ipv8.attestation.trustchain.TrustChainBlock
import nl.tudelft.ipv8.attestation.trustchain.store.TrustChainStore
import nl.tudelft.ipv8.attestation.trustchain.validation.ValidationResult
import nl.tudelft.trustchain.common.eurotoken.TransactionRepository
import nl.tudelft.trustchain.common.eurotoken.webauthn.WebAuthnSignature
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class WebAuthnValidatorTest {

    private lateinit var webAuthnValidator: WebAuthnValidator
    private val mockTransactionRepository = mockk<TransactionRepository>(relaxed = true)
    private val mockBlock = mockk<TrustChainBlock>(relaxed = true)
    private val mockDatabase = mockk<TrustChainStore>(relaxed = true)

    @Before
    fun setUp() {
        webAuthnValidator = WebAuthnValidator(mockTransactionRepository)
    }

    @After
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `validate returns Valid for non-eurotoken block types`() {
        // Arrange
        every { mockBlock.type } returns "some_other_type"

        // Act
        val result = webAuthnValidator.validate(mockBlock, mockDatabase)

        // Assert
        assertEquals(ValidationResult.Valid, result)
    }

    @Test
    fun `validate returns Valid for eurotoken block without webauthn data`() {
        // Arrange
        val mockTransaction = mockk<MutableMap<Any, Any>>(relaxed = true)
        every { mockBlock.type } returns TransactionRepository.BLOCK_TYPE_TRANSFER
        every { mockBlock.transaction } returns mockTransaction
        every { mockTransaction.containsKey(WebAuthnValidator.KEY_WEBAUTHN_PUBLIC_KEY) } returns false
        every { mockTransaction.containsKey(WebAuthnValidator.KEY_WEBAUTHN_SIGNATURE) } returns false

        // Act
        val result = webAuthnValidator.validate(mockBlock, mockDatabase)

        // Assert
        assertEquals(ValidationResult.Valid, result)
    }

    @Test
    fun `validate returns Invalid for eurotoken block with invalid webauthn data`() {
        // Arrange
        val mockTransaction = mockk<MutableMap<Any, Any>>(relaxed = true)
        every { mockBlock.type } returns TransactionRepository.BLOCK_TYPE_TRANSFER
        every { mockBlock.transaction } returns mockTransaction
        every { mockTransaction.containsKey(WebAuthnValidator.KEY_WEBAUTHN_PUBLIC_KEY) } returns true
        every { mockTransaction.containsKey(WebAuthnValidator.KEY_WEBAUTHN_SIGNATURE) } returns true
        every { mockTransaction[WebAuthnValidator.KEY_WEBAUTHN_PUBLIC_KEY] } returns "invalid_data"
        every { mockBlock.blockId } returns "test_block_id"

        // Act
        val result = webAuthnValidator.validate(mockBlock, mockDatabase)

        // Assert
        assertTrue(result is ValidationResult.Invalid)
    }

}