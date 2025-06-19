package nl.tudelft.trustchain.eurotoken.ui.transfer

import org.junit.Assert.*
import org.junit.Test

class SendMoneyFragmentTest {

    @Test
    fun `ARG_SIGNATURE constant has correct value`() {
        // Assert
        assertEquals("signature", SendMoneyFragment.ARG_SIGNATURE)
    }

    @Test
    fun `ARG_PUBLIC_KEY constant exists and has expected value`() {
        // Assert
        assertEquals("pubkey", SendMoneyFragment.ARG_PUBLIC_KEY)
    }

    @Test
    fun `ARG_AMOUNT constant exists and has expected value`() {
        // Assert
        assertEquals("amount", SendMoneyFragment.ARG_AMOUNT)
    }

    @Test
    fun `ARG_NAME constant exists and has expected value`() {
        // Assert
        assertEquals("name", SendMoneyFragment.ARG_NAME)
    }

    @Test 
    fun `TRUSTSCORE_AVERAGE_BOUNDARY constant has expected value`() {
        // Assert
        assertEquals(70, SendMoneyFragment.TRUSTSCORE_AVERAGE_BOUNDARY)
    }

    @Test
    fun `TRUSTSCORE_LOW_BOUNDARY constant has expected value`() {
        // Assert
        assertEquals(30, SendMoneyFragment.TRUSTSCORE_LOW_BOUNDARY)
    }
}