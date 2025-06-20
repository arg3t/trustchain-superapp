package nl.tudelft.trustchain.eurotoken.ui.transfer

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.util.UUID

class TransferFragmentTest {

    @Test
    fun `getAmount returns 0 for empty string`() {
        // Act
        val result = TransferFragment.getAmount("")

        // Assert
        assertEquals(0L, result)
    }

    @Test
    fun `getAmount extracts numeric value from string with non-digits`() {
        // Act
        val result = TransferFragment.getAmount("€123.45")

        // Assert
        assertEquals(12345L, result)
    }

    @Test
    fun `getAmount extracts numeric value from string with multiple non-digits`() {
        // Act
        val result = TransferFragment.getAmount("$1,234.56 USD")

        // Assert
        assertEquals(123456L, result)
    }

    @Test
    fun `getAmount handles pure numeric string`() {
        // Act
        val result = TransferFragment.getAmount("98765")

        // Assert
        assertEquals(98765L, result)
    }

    @Test
    fun `getAmount handles string with only non-digits throws exception`() {
        // TODO: This is a bug in the implementation
        // TODO: The method should probably return 0L when no digits remain after regex

        // Act & Assert - This currently throws NumberFormatException
        try {
            TransferFragment.getAmount("€$.,")
            fail("Expected NumberFormatException")
        } catch (e: NumberFormatException) {
            // Current behavior - the method doesn't handle empty string after regex
            assertTrue("Method currently throws exception for strings with no digits", true)
        }
    }

    @Test
    fun `getAmount handles mixed alphanumeric string`() {
        // Act
        val result = TransferFragment.getAmount("abc123def456ghi")

        // Assert
        assertEquals(123456L, result)
    }

    @Test
    fun `getAmount handles string with leading zeros`() {
        // Act
        val result = TransferFragment.getAmount("000123")

        // Assert
        assertEquals(123L, result)
    }

    @Test
    fun `getAmount handles decimal with dots and commas`() {
        // Act
        val result = TransferFragment.getAmount("1,234.56")

        // Assert
        assertEquals(123456L, result)
    }

    @Test
    fun `getAmount handles very large numbers`() {
        // Act
        val result = TransferFragment.getAmount("999999999999")

        // Assert
        assertEquals(999999999999L, result)
    }

    @Test
    fun `getAmount handles strings with spaces`() {
        // Act
        val result = TransferFragment.getAmount("1 2 3 4 5")

        // Assert
        assertEquals(12345L, result)
    }

    @Test
    fun `getAmount handles single digit`() {
        // Act
        val result = TransferFragment.getAmount("7")

        // Assert
        assertEquals(7L, result)
    }

    @Test
    fun `getAmount handles negative sign (removes it)`() {
        // Act
        val result = TransferFragment.getAmount("-123")

        // Assert
        assertEquals(123L, result) // Negative sign is removed as it's a non-digit
    }

    @Test
    fun `getAmount handles plus sign (removes it)`() {
        // Act
        val result = TransferFragment.getAmount("+456")

        // Assert
        assertEquals(456L, result) // Plus sign is removed as it's a non-digit
    }

    @Test
    fun `getAmount handles currency symbols`() {
        // Act
        val result = TransferFragment.getAmount("¥789¢")

        // Assert
        assertEquals(789L, result)
    }

    @Test
    fun `getAmount handles parentheses`() {
        // Act
        val result = TransferFragment.getAmount("(123)")

        // Assert
        assertEquals(123L, result)
    }
}
