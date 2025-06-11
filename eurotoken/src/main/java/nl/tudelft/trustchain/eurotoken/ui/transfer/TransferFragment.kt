package nl.tudelft.trustchain.eurotoken.ui.transfer

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.util.Log
import android.view.View
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputMethodManager
import android.widget.EditText
import android.widget.Toast
import androidx.core.net.toUri
import androidx.lifecycle.lifecycleScope
import androidx.navigation.fragment.findNavController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import nl.tudelft.ipv8.Peer
import nl.tudelft.ipv8.attestation.trustchain.BlockListener
import nl.tudelft.ipv8.attestation.trustchain.TrustChainBlock
import nl.tudelft.ipv8.keyvault.defaultCryptoProvider
import nl.tudelft.ipv8.util.hexToBytes
import nl.tudelft.ipv8.util.toHex
import nl.tudelft.trustchain.common.contacts.ContactStore
import nl.tudelft.trustchain.common.eurotoken.TransactionRepository
import nl.tudelft.trustchain.common.util.QRCodeUtils
import nl.tudelft.trustchain.common.util.EUDIUtils
import nl.tudelft.trustchain.common.util.WebAuthnIdentityProviderOwner
import nl.tudelft.trustchain.common.util.viewBinding
import nl.tudelft.trustchain.eurotoken.EuroTokenMainActivity
import nl.tudelft.trustchain.eurotoken.R
import nl.tudelft.trustchain.eurotoken.community.EuroTokenCommunity
import nl.tudelft.trustchain.eurotoken.databinding.FragmentTransferEuroBinding
import nl.tudelft.trustchain.eurotoken.ui.EurotokenBaseFragment
import org.json.JSONException
import org.json.JSONObject

const val TOON_MSG = "ToonsStuff"
const val EUROTOKEN_MSG = "EUROTOKEN"
class TransferFragment : EurotokenBaseFragment(R.layout.fragment_transfer_euro) {
    private val binding by viewBinding(FragmentTransferEuroBinding::bind)

    private val qrCodeUtils by lazy {
        QRCodeUtils(requireContext())
    }

    private val eudiUtils by lazy {
        EUDIUtils()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        lifecycleScope.launchWhenResumed {
            while (isActive) {
                val ownKey = transactionRepository.trustChainCommunity.myPeer.publicKey
                val ownContact =
                    ContactStore.getInstance(requireContext()).getContactFromPublicKey(ownKey)
                val pref =
                    requireContext().getSharedPreferences(
                        EuroTokenMainActivity.EurotokenPreferences.EUROTOKEN_SHARED_PREF_NAME,
                        Context.MODE_PRIVATE
                    )
                val demoModeEnabled =
                    pref.getBoolean(
                        EuroTokenMainActivity.EurotokenPreferences.DEMO_MODE_ENABLED,
                        false
                    )

                if (demoModeEnabled) {
                    binding.txtBalance.text =
                        TransactionRepository.prettyAmount(transactionRepository.getMyBalance())
                } else {
                    binding.txtBalance.text =
                        TransactionRepository.prettyAmount(transactionRepository.getMyVerifiedBalance())
                }
                if (ownContact?.name != null) {
                    binding.missingNameLayout.visibility = View.GONE
                    binding.txtOwnName.text = "Your balance (" + ownContact.name + ")"
                } else {
                    binding.missingNameLayout.visibility = View.VISIBLE
                    binding.txtOwnName.text = "Your balance"
                }
                delay(1000L)
            }
        }
    }

    override fun onViewCreated(
        view: View,
        savedInstanceState: Bundle?
    ) {
        super.onViewCreated(view, savedInstanceState)

        val ownKey = transactionRepository.trustChainCommunity.myPeer.publicKey
        val ownContact = ContactStore.getInstance(view.context).getContactFromPublicKey(ownKey)

        val pref =
            requireContext().getSharedPreferences(
                EuroTokenMainActivity.EurotokenPreferences.EUROTOKEN_SHARED_PREF_NAME,
                Context.MODE_PRIVATE
            )
        val demoModeEnabled =
            pref.getBoolean(
                EuroTokenMainActivity.EurotokenPreferences.DEMO_MODE_ENABLED,
                false
            )

        if (demoModeEnabled) {
            binding.txtBalance.text =
                TransactionRepository.prettyAmount(transactionRepository.getMyBalance())
        } else {
            binding.txtBalance.text =
                TransactionRepository.prettyAmount(transactionRepository.getMyVerifiedBalance())
        }
        binding.txtOwnPublicKey.text = ownKey.keyToHash().toHex()

        if (ownContact?.name != null) {
            binding.missingNameLayout.visibility = View.GONE
            binding.txtOwnName.text = "Your balance (" + ownContact.name + ")"
        }

        fun addName() {
            val newName = binding.edtMissingName.text.toString()
            if (newName.isNotEmpty()) {
                ContactStore.getInstance(requireContext())
                    .addContact(ownKey, newName)
                if (ownContact?.name != null) {
                    binding.missingNameLayout.visibility = View.GONE
                    binding.txtOwnName.text = "Your balance (" + ownContact.name + ")"
                }
                val inputMethodManager =
                    requireContext().getSystemService(Activity.INPUT_METHOD_SERVICE) as InputMethodManager
                inputMethodManager.hideSoftInputFromWindow(view.windowToken, 0)
            }
        }

        binding.btnAdd.setOnClickListener {
            addName()
        }

        binding.edtMissingName.onSubmit {
            addName()
        }

        binding.edtAmount.addDecimalLimiter()

        binding.btnRequest.setOnClickListener {
            val amount = getAmount(binding.edtAmount.text.toString())
            if (amount > 0) {
                val myPeer = transactionRepository.trustChainCommunity.myPeer
                val contact =
                    ContactStore.getInstance(view.context).getContactFromPublicKey(ownKey)

                val connectionData = JSONObject()
                connectionData.put("public_key", myPeer.publicKey.keyToBin().toHex())
                connectionData.put("amount", amount)
                connectionData.put("name", contact?.name ?: "")
                connectionData.put("type", "transfer")

                val args = Bundle()

                args.putString(RequestMoneyFragment.ARG_DATA, connectionData.toString())

                findNavController().navigate(
                    R.id.action_transferFragment_to_requestMoneyFragment,
                    args
                )
            }
        }

        binding.btnSend.setOnClickListener {
            qrCodeUtils.startQRScanner(this)
        }

        binding.btnRegister.setOnClickListener {
            lifecycleScope.launch {
                val myPublicKey = transactionRepository.getGatewayPeer()?.publicKey?.keyToBin()
                    ?: throw Error("Could not find public key")
                 val verifyResult = eudiUtils.verifyEudiToken()
                 if (verifyResult == false) {
                     Log.d(TOON_MSG, "Failed to verify EUDI token")
                     Toast.makeText(requireActivity(), "Failed to verify EUDI token", Toast.LENGTH_LONG).show()
                     return@launch
                 }
                val eudiToken = getEudiToken().toString()
                Log.d(TOON_MSG, "EudiToken $eudiToken")

                val myIdentityProvider: WebAuthnIdentityProviderOwner =
                    (getIpv8().myPeer.identityProvider ?: throw Error("big problems bro")) as WebAuthnIdentityProviderOwner
                Log.d(TOON_MSG, "Identity provider: $myIdentityProvider")
                // I don't like this ^ :(
                // also fixing it will be a bit of a mess but oh well

                myIdentityProvider.context = requireActivity()
                val signedKey = myIdentityProvider.sign(eudiToken.toByteArray())
                Log.d(TOON_MSG, "Signed token: $signedKey")

                val transaction = mapOf("signed_EUDI_key" to signedKey?.toJsonString())

                val block = transactionRepository.trustChainCommunity.createProposalBlock(
                    "eurotoken_register",
                    transaction,
                    myPublicKey
                )
                transactionRepository.trustChainCommunity.getPeers().forEach { peer ->
                    Log.d(TOON_MSG, "Sending to peer: " + peer.address)
                    transactionRepository.trustChainCommunity.sendBlock(block, peer)
                }
                transactionRepository.trustChainCommunity.addListener(
                    "eurotoken_register",
                    object : BlockListener {
                        override fun onBlockReceived(block: TrustChainBlock) {
                            Log.d(TOON_MSG, "blockReceived: ${block.blockId} ${block.transaction}")
                        }
                    }
                )
                Log.d(TOON_MSG, "Size of db:  ${transactionRepository.trustChainCommunity.database.getAllBlocks().size}")
                Log.d(TOON_MSG, transactionRepository.trustChainCommunity.getChainLength().toString())
                Toast.makeText(requireActivity(), "Registered on the ⛓\uFE0Fchain\uD83D\uDE80", Toast.LENGTH_LONG).show()
            }
        }
    }

    suspend fun getEudiToken(): JSONObject {
        val tokenPair = eudiUtils.getEudiToken()
        val url = tokenPair.second

        val intent = Intent(Intent.ACTION_VIEW).apply {
            data = url.toUri()
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }

        Log.d(TOON_MSG, "Starting activity")
        startActivity(intent)

        return tokenPair.first
    }

    /**
     * Find a [Peer] in the network by its public key.
     * @param pubKey : The public key of the peer to find.
     */
    private fun findPeer(pubKey: String): Peer? {
        val itr = transactionRepository.trustChainCommunity.getPeers().listIterator()
        while (itr.hasNext()) {
            val cur: Peer = itr.next()
            Log.d(EUROTOKEN_MSG, cur.key.pub().toString())
            if (cur.key.pub().toString() == pubKey) {
                return cur
            }
        }

        return null
    }

    override fun onActivityResult(
        requestCode: Int,
        resultCode: Int,
        data: Intent?
    ) {
        qrCodeUtils.parseActivityResult(requestCode, resultCode, data)?.let {
            try {
                val connectionData = ConnectionData(it)

                val args = Bundle()
                args.putString(SendMoneyFragment.ARG_PUBLIC_KEY, connectionData.publicKey)
                args.putLong(SendMoneyFragment.ARG_AMOUNT, connectionData.amount)
                args.putString(SendMoneyFragment.ARG_NAME, connectionData.name)

                // Try to send the addresses of the last X transactions to the peer we have just scanned.
                try {
                    val peer =
                        findPeer(
                            defaultCryptoProvider.keyFromPublicBin(connectionData.publicKey.hexToBytes())
                                .toString()
                        )
                    if (peer == null) {
                        logger.warn { "Could not find peer from QR code by public key " + connectionData.publicKey }
                        Toast.makeText(
                            requireContext(),
                            "Could not find peer from QR code",
                            Toast.LENGTH_LONG
                        )
                            .show()
                    }
                    val euroTokenCommunity = getIpv8().getOverlay<EuroTokenCommunity>()
                    if (euroTokenCommunity == null) {
                        Toast.makeText(
                            requireContext(),
                            "Could not find community",
                            Toast.LENGTH_LONG
                        )
                            .show()
                    }
                    if (peer != null && euroTokenCommunity != null) {
                        euroTokenCommunity.sendAddressesOfLastTransactions(peer)
                    }
                } catch (e: Exception) {
                    logger.error { e }
                    Toast.makeText(
                        requireContext(),
                        "Failed to send transactions",
                        Toast.LENGTH_LONG
                    )
                        .show()
                }

                if (connectionData.type == "transfer") {
                    findNavController().navigate(
                        R.id.action_transferFragment_to_sendMoneyFragment,
                        args
                    )
                } else {
                    Toast.makeText(requireContext(), "Invalid QR", Toast.LENGTH_LONG).show()
                }
            } catch (e: JSONException) {
                Toast.makeText(requireContext(), "Scan failed, try again", Toast.LENGTH_LONG).show()
            }
        } ?: Toast.makeText(requireContext(), "Scan failed", Toast.LENGTH_LONG).show()
        return
    }

    companion object {
        private const val KEY_PUBLIC_KEY = "public_key"

        fun EditText.onSubmit(func: () -> Unit) {
            setOnEditorActionListener { _, actionId, _ ->

                if (actionId == EditorInfo.IME_ACTION_DONE) {
                    func()
                }

                true
            }
        }

        class ConnectionData(json: String) : JSONObject(json) {
            var publicKey = this.optString("public_key")
            var amount = this.optLong("amount", -1L)
            var name = this.optString("name")
            var type = this.optString("type")
        }

        fun getAmount(amount: String): Long {
            val regex = """\D""".toRegex()
            if (amount.isEmpty()) {
                return 0L
            }
            return regex.replace(amount, "").toLong()
        }

        fun Context.hideKeyboard(view: View) {
            val inputMethodManager =
                getSystemService(Activity.INPUT_METHOD_SERVICE) as InputMethodManager
            inputMethodManager.hideSoftInputFromWindow(view.windowToken, 0)
        }

        fun EditText.decimalLimiter(string: String): String {
            var amount = getAmount(string)

            if (amount == 0L) {
                return ""
            }

            // val amount = string.replace("[^\\d]", "").toLong()
            return (amount / 100).toString() + "." + (amount % 100).toString().padStart(2, '0')
        }

        fun EditText.addDecimalLimiter() {
            this.addTextChangedListener(
                object : TextWatcher {
                    override fun afterTextChanged(s: Editable?) {
                        val str = this@addDecimalLimiter.text!!.toString()
                        if (str.isEmpty()) return
                        val str2 = decimalLimiter(str)

                        if (str2 != str) {
                            this@addDecimalLimiter.setText(str2)
                            val pos = this@addDecimalLimiter.text!!.length
                            this@addDecimalLimiter.setSelection(pos)
                        }
                    }

                    override fun beforeTextChanged(
                        s: CharSequence?,
                        start: Int,
                        count: Int,
                        after: Int
                    ) {
                    }

                    override fun onTextChanged(
                        s: CharSequence?,
                        start: Int,
                        before: Int,
                        count: Int
                    ) {}
                }
            )
        }
    }
}
