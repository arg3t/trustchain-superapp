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
import nl.tudelft.ipv8.keyvault.IPSignature
import nl.tudelft.ipv8.keyvault.IdentityProviderChecker
import nl.tudelft.ipv8.keyvault.defaultCryptoProvider
import nl.tudelft.ipv8.util.hexToBytes
import nl.tudelft.ipv8.util.random
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
import okhttp3.FormBody
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.ethereum.geth.Nonce
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import kotlin.collections.get
import kotlin.math.sign

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
            lifecycleScope.launch {
                val amount = getAmount(binding.edtAmount.text.toString())
                if (amount > 0) {
                    val myPeer = transactionRepository.trustChainCommunity.myPeer
                    val contact =
                        ContactStore.getInstance(view.context).getContactFromPublicKey(ownKey)

                    val connectionData = JSONObject()
                    val publicKey = myPeer.publicKey.keyToBin().toHex()
                    connectionData.put("public_key", publicKey)
                    connectionData.put("amount", amount)
                    connectionData.put("name", contact?.name ?: "")
                    connectionData.put("type", "transfer")

                    // TODO: :(((
                    val myIdentityProvider: WebAuthnIdentityProviderOwner =
                        (getIpv8().myPeer.identityProvider
                            ?: throw Error("big problems bro")) as WebAuthnIdentityProviderOwner
                    Log.d("ToonsStuff", "Identity provider: $myIdentityProvider")

                    myIdentityProvider.context = requireActivity()

                    val tmp = publicKey + " " + amount + " " + contact?.name
                    val hasher = MessageDigest.getInstance("SHA256")
                    val hash = hasher.digest(tmp.toByteArray())

                    val ip = myPeer.identityProvider?.sign(hash)
                    ip?.let {
                        val encoder = Base64.getEncoder();
                        Log.d("ToonsStuff", "ip: $ip")
                        connectionData.put("signature", encoder.encodeToString(ip.toJsonString().toByteArray()))
                    }
                    transactionRepository.getSelfRegistrationBlock()?.let { block ->
                        connectionData.put("rb", block.blockId)
                    }

                    val args = Bundle()

                    args.putString(RequestMoneyFragment.ARG_DATA, connectionData.toString())

                    findNavController().navigate(
                        R.id.action_transferFragment_to_requestMoneyFragment,
                        args
                    )
                }
            }
        }

        binding.btnSend.setOnClickListener {
            qrCodeUtils.startQRScanner(this)
        }

        binding.btnRegister.setOnClickListener {
            lifecycleScope.launch {
                val myPublicKey = transactionRepository.getGatewayPeer()?.publicKey?.keyToBin()
                    ?: throw Error("Could not find public key")

                val nonce = UUID.randomUUID().toString()
                val eudiToken = getEudiToken(nonce)
                Log.d("ToonsStuff", "EudiToken $eudiToken")

                val myIdentityProvider: WebAuthnIdentityProviderOwner =
                    (getIpv8().myPeer.identityProvider
                        ?: throw Error("big problems bro")) as WebAuthnIdentityProviderOwner
                Log.d("ToonsStuff", "Identity provider: $myIdentityProvider")

                myIdentityProvider.context = requireActivity()
                val signedEudiToken = myIdentityProvider.sign(eudiToken.toByteArray())
                if (signedEudiToken == null) {
                    Log.d("ToonsStuff", "Failed to sign EUDI token")
                    Toast.makeText(
                        requireContext(),
                        "Failed to sign EUDI token",
                        Toast.LENGTH_LONG
                    ).show()
                    return@launch
                }
                Log.d("ToonsStuff", "Signed EUDI token: $signedEudiToken")

                val transaction = mapOf(
                    "signed_EUDI_token" to signedEudiToken?.toJsonString(),
                    "nonce" to nonce,
                    "webauthn_key" to myIdentityProvider.publicKey.toHex()
                )

                val block = transactionRepository.trustChainCommunity.createProposalBlock(
                    "eurotoken_register",
                    transaction,
                    myPublicKey
                )
                transactionRepository.trustChainCommunity.sendBlock(block, ttl=2048)
                transactionRepository.trustChainCommunity.addListener(
                    "eurotoken_register",
                    object : BlockListener {
                        override fun onBlockReceived(block: TrustChainBlock) {
                            Log.d(
                                "ToonsStuff",
                                "blockReceived: ${block.blockId} ${block.transaction}"
                            )
                        }
                    }
                )
                Log.d(
                    "ToonsStuff",
                    "Size of db:  ${transactionRepository.trustChainCommunity.database.getAllBlocks().size}"
                )
                Log.d(
                    "ToonsStuff",
                    transactionRepository.trustChainCommunity.getChainLength().toString()
                )
                Toast.makeText(
                    requireActivity(),
                    "Registered on the ⛓\uFE0Fchain\uD83D\uDE80",
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    /**
     * Requests a EUDI VP token from the wallet app using the given nonce.
     * Launches the wallet app for user interaction and polls for the result.
     *
     * @param nonce The nonce to use in the presentation request.
     * @return JSONObject containing the VP token response.
     */
    suspend fun getEudiToken(nonce: String): String {
        val presentationRequest = JSONObject().apply {
            put("type", "vp_token")
            put("presentation_definition", JSONObject().apply {
                put("id", UUID.randomUUID().toString())
                put(
                    "input_descriptors", JSONArray(listOf(
                    JSONObject().apply {
                        put("id", UUID.randomUUID().toString())
                        put("name", "Person Identification Data (PID)")
                        put("purpose", "")
                        put("format", JSONObject().apply {
                            put("dc+sd-jwt", JSONObject().apply {
                                put("sd-jwt_alg_values", JSONArray(listOf("ES256", "ES384", "ES512")))
                                put(
                                    "kb-jwt_alg_values",
                                    JSONArray(listOf("RS256", "RS384", "RS512", "ES256", "ES384", "ES512"))
                                )
                            })
                        })
                        put("constraints", JSONObject().apply {
                            put(
                                "fields", JSONArray(listOf(
                                JSONObject().apply {
                                    put("path", JSONArray(listOf("$.vct")))
                                    put("filter", JSONObject().apply {
                                        put("type", "string")
                                        put("const", "urn:eudi:pid:1")
                                    })
                                },
                                JSONObject().apply {
                                    put("path", JSONArray(listOf("$.family_name")))
                                    put("intent_to_retain", false)
                                },
                                JSONObject().apply {
                                    put("path", JSONArray(listOf("$.given_name")))
                                    put("intent_to_retain", false)
                                }
                            )))
                        })
                    }
                )))
            })
            put("nonce", nonce)
            put("request_uri_method", "get")
        }

        Log.d("YeatStuff", "Body: $presentationRequest")
        val verifierData = eudiUtils.makeApiCall(
            url = "https://verifier-backend.eudiw.dev/ui/presentations",
            method = "POST",
            body = presentationRequest.toString()
        ) ?: throw Exception("Failed to create presentation request")
        Log.d("YeatStuff", "Verifier data: $verifierData")

        val transactionId = verifierData.getString("transaction_id")
        val clientId = verifierData.getString("client_id")
        val requestUri = verifierData.getString("request_uri")
        val requestUriMethod = verifierData.getString("request_uri_method")

        val walletUrl =
            "eudi-openid4vp://?client_id=$clientId&request_uri=$requestUri&request_uri_method=$requestUriMethod"
        val intent = Intent(Intent.ACTION_VIEW, walletUrl.toUri()).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        startActivity(intent)

        val pollUrl = "https://verifier-backend.eudiw.dev/ui/presentations/$transactionId"
        while (true) {
            delay(1000)
            val walletResult = eudiUtils.makeApiCall(pollUrl, "GET", null)
            if (walletResult != null && walletResult.has("vp_token")) {
                return walletResult.getJSONArray("vp_token").getString(0)

            }
        }
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
                args.putString(SendMoneyFragment.ARG_SIGNATURE, connectionData.signature)
                args.putString(SendMoneyFragment.ARG_REGISTRATION_BLOCK, connectionData.registrationBlock)

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
            var registrationBlock = this.optString("rb")
            var signature = this.optString("signature")
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
