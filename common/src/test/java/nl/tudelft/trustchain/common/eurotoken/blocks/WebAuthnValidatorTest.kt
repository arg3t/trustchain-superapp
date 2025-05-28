package nl.tudelft.trustchain.common.eurotoken.blocks

import io.mockk.mockk
import org.junit.Test


class WebAuthnValidatorTest {
    val validator = WebAuthnValidator(mockk())

    @Test
    fun validate() {


        assert(true)
    }

}
