package nl.tudelft.trustchain.offlineeuro.community.message

import nl.tudelft.trustchain.offlineeuro.cryptography.BilinearGroupElementsBytes
import nl.tudelft.trustchain.offlineeuro.cryptography.CRSBytes

class BilinearGroupCRSReplyMessage(
    val groupDescription: BilinearGroupElementsBytes,
    val crs: CRSBytes,
    val addressMessage: AddressMessage
) : ICommunityMessage {
    override val messageType = CommunityMessageType.GroupDescriptionCRSReplyMessage
}
