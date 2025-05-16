package nl.tudelft.trustchain.app.ui.dashboard

import android.annotation.SuppressLint
import android.content.Context
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import nl.tudelft.ipv8.android.keyvault.AndroidCryptoProvider
import nl.tudelft.ipv8.keyvault.IdentityProviderOwner
import nl.tudelft.ipv8.keyvault.PrivateKey
import nl.tudelft.ipv8.util.hexToBytes
import nl.tudelft.ipv8.util.toHex
import nl.tudelft.trustchain.app.TrustChainApplication
import nl.tudelft.trustchain.app.databinding.FragmentDashboardIdentityBinding
import nl.tudelft.trustchain.app.keyvault.WebAuthnIdentityProviderOwner
import nl.tudelft.trustchain.common.util.viewBinding
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.util.UUID

private const val TAG = "IdentityManager"

private var selectedIdIdx = 0;

class DashboardIdentityActivity : AppCompatActivity() {
    private val binding by viewBinding(FragmentDashboardIdentityBinding::inflate)

    private var selectedIdentity: Identity? = null
    private val savedIdentities = mutableListOf<Identity>()

    private lateinit var savedIdentitiesAdapter: ArrayAdapter<String>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)
        loadIdentities()
        title = "Pick Your Identity";

        setupIdentitySelector()
        setupSaveButton()
        setupDeleteButton()
        setupSelectIdentityButton()
        setupTestSignatureButton()

    }

    private fun loadIdentities() {
        savedIdentities.clear()
        savedIdentities.addAll(savedIdentities(this))
        if (savedIdentities.isNotEmpty()) {
            selectedIdentity = savedIdentities.first()
        }
    }


    private fun saveIdentities() {
        val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this)
        val jsonArray = JSONArray()
        for (identity in savedIdentities) {
            val obj = JSONObject()
            obj.put("name", identity.name)
            obj.put("privateKey", identity.privateKey.keyToBin().toHexString())
            obj.put("identityPublicKey", identity.identity.toHexString())
            obj.put("identityId", identity.identity.id)
            jsonArray.put(obj)
        }
        prefs.edit().putString(PREF_IDENTITIES, jsonArray.toString()).apply()
    }


    private fun setupIdentitySelector() {
        savedIdentitiesAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            savedIdentities.map { it.name }
        ).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        binding.currentIdentitySelector.adapter = savedIdentitiesAdapter

        // Handle selection
        binding.currentIdentitySelector.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                val identity = savedIdentities[position]

                (application as TrustChainApplication).privateKey = identity.privateKey
                (application as TrustChainApplication).identityProvider = identity.identity
                (application as TrustChainApplication).initIPv8()
                selectedIdentity = identity
                selectedIdIdx = position
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {
            }
        }

        if (selectedIdIdx < savedIdentities.size) {
            binding.currentIdentitySelector.setSelection(selectedIdIdx)
            selectedIdentity = savedIdentities[selectedIdIdx]
        }
    }

    private fun setupSaveButton() {
        binding.saveIdBtn.setOnClickListener {
            val identityName = binding.newIdentityName.text.toString().trim()
            val privateKey = AndroidCryptoProvider.generateKey()
            val context = this

            if (identityName.isEmpty()) {
                Toast.makeText(this, "Please enter an identity name", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }


            lifecycleScope.launch {
                val pk = registerWebAuthn(identityName)

                if (pk == null) {
                    Toast.makeText(context, "Could not get register using WebAuthn.", Toast.LENGTH_SHORT).show()
                } else {
                    binding.newIdentityName.text?.clear()
                    addNewIdentity(Identity(identityName, privateKey, pk))

                    Toast.makeText(context, "Identity saved", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    @SuppressLint("ShowToast")
    private fun setupTestSignatureButton() {
        binding.testSignature.setOnClickListener {
            if (selectedIdentity == null) {
                return@setOnClickListener
            }

            val context = this

            lifecycleScope.launch {
                val sig = selectedIdentity!!.identity.sign("yeet".toByteArray())
                if (sig == null) {
                    Toast.makeText(context, "Error during WebAuthn signing", Toast.LENGTH_SHORT)
                        .show()
                } else {
                    Log.d(TAG, "Generated test signature for \"yeet\": " + sig.toString())
                    Log.d(
                        TAG,
                        "Signature Verification: " + if (selectedIdentity!!.identity.verify(
                                sig
                            )
                        ) "OK" else "FAIL"
                    )
                    Toast.makeText(
                        context,
                        "Signature Verification: " + if (selectedIdentity!!.identity.verify(
                                sig
                            )
                        ) "OK" else "FAIL",
                        Toast.LENGTH_SHORT
                    ).show()
                }

            }
        }
    }


    private fun setupDeleteButton() {
        binding.clearIdentities.setOnClickListener {
            if (savedIdentities.isEmpty()) {
                Toast.makeText(this, "No identities to delete", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            val selectedPosition = binding.currentIdentitySelector.selectedItemPosition
            if (selectedPosition != AdapterView.INVALID_POSITION && selectedPosition < savedIdentities.size) {
                val identityToDelete = savedIdentities[selectedPosition]
                savedIdentities.removeAt(selectedPosition)
                saveIdentities()

                // Update the adapter with the new data
                savedIdentitiesAdapter.clear()
                savedIdentitiesAdapter.addAll(savedIdentities.map { it.name })
                savedIdentitiesAdapter.notifyDataSetChanged()

                // Set a new selected identity if available
                if (savedIdentities.isNotEmpty()) {
                    val newPosition = if (selectedPosition < savedIdentities.size) selectedPosition else savedIdentities.size - 1
                    binding.currentIdentitySelector.setSelection(newPosition)
                    selectedIdentity = savedIdentities[newPosition]
                    selectedIdIdx = newPosition

                    // Update application with the new identity
                    (application as TrustChainApplication).privateKey = selectedIdentity!!.privateKey
                    (application as TrustChainApplication).identityProvider = selectedIdentity!!.identity
                    (application as TrustChainApplication).initIPv8()
                } else {
                    selectedIdentity = null
                }

                Toast.makeText(this, "Deleted identity: ${identityToDelete.name}", Toast.LENGTH_SHORT).show()
            }
        }
    }


    private fun setupSelectIdentityButton() {
        binding.selectIdentity.setOnClickListener {
            val selectedPosition = binding.currentIdentitySelector.selectedItemPosition

            if (savedIdentities.isEmpty()) {
                Toast.makeText(this, "No identities available. Please create one.", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (selectedPosition != AdapterView.INVALID_POSITION && selectedPosition < savedIdentities.size) {
                val selectedIdentity = savedIdentities[selectedPosition]

                // TODO: Update the IPv8Android instance in the main app with the new identity
                Toast.makeText(this, "Selected identity: ${selectedIdentity.name}", Toast.LENGTH_SHORT).show()

                // Example of returning a result to the caller
                setResult(RESULT_OK)
                finish()
            }
        }
    }

    private fun addNewIdentity(identity: Identity) {
        // Create and add the new identity
        savedIdentities.add(identity)
        saveIdentities()

        if (savedIdentities.size == 1) /* Select this identity */ {
            (application as TrustChainApplication).privateKey = identity.privateKey
            (application as TrustChainApplication).identityProvider = identity.identity
            (application as TrustChainApplication).initIPv8()
            selectedIdentity = identity
        }


        // Update the adapter with the new data
        savedIdentitiesAdapter.clear()
        savedIdentitiesAdapter.addAll(savedIdentities.map { it.name })
        savedIdentitiesAdapter.notifyDataSetChanged()
    }

    @SuppressLint("PublicKeyCredential")
    suspend fun registerWebAuthn(name: String): IdentityProviderOwner? {
        try {
            val id = UUID.randomUUID().toString()
            val credentialManager = CredentialManager.create(this)

            val request = CreatePublicKeyCredentialRequest(
                requestJson = createRegistrationRequestJson(name, id),
                preferImmediatelyAvailableCredentials = true
            )
            val result = credentialManager.createCredential(
                request = request,
                context = this,
            )

            try {
                val credential = result as CreatePublicKeyCredentialResponse
                val responseJson = credential.registrationResponseJson

                Log.d(TAG, responseJson)
                // Extract public key from registration response
                val resp = JSONObject(responseJson)
                val response = resp.getJSONObject("response")

                val pKeyStr = response.getString("publicKey")
                val rawId = resp.getString("rawId")

                val pk = Base64.decode(pKeyStr, Base64.URL_SAFE)
                return WebAuthnIdentityProviderOwner(rawId, pk, this)
            } catch (e: Exception) {
                Log.e(TAG, "Error processing WebAuthn registration response", e)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error during WebAuthn registration", e)
        }
        return null

    }

    private fun createRegistrationRequestJson(name: String, id: String): String {
        // Generate a random challenge
        val challenge = ByteArray(32).apply {
            java.security.SecureRandom().nextBytes(this)
        }

        // WebAuthn registration request in JSON format
        return """
        {
            "challenge": "${android.util.Base64.encodeToString(challenge, android.util.Base64.URL_SAFE).trim()}",
            "rp": {
                "name": "TrustChain",
                "id": "trustchain.yigit.run"
            },
            "user": {
                "id": "${android.util.Base64.encodeToString(id.toByteArray(), android.util.Base64.URL_SAFE).trim()}",
                "name": "$id",
                "displayName": "TrustChain $name"
            },
            "pubKeyCredParams": [
                {
                    "type": "public-key",
                    "alg": -7
                }
            ],
            "timeout": 60000,
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "requireResidentKey": true,
                "userVerification": "preferred"
            },
            "attestation": "none"
        }
        """.trimIndent()
    }


    /**
     * Simple data class to represent an identity
     */
    data class Identity(
        val name: String,
        val privateKey: PrivateKey,
        val identity: IdentityProviderOwner
    )

    companion object {
        private const val PREF_IDENTITIES = "identities_json"

        fun savedIdentities(context: Context): List<Identity> {
            val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(context)

            val json = prefs.getString(PREF_IDENTITIES, "[]")
            val identities = mutableListOf<Identity>()

            val jsonArray = JSONArray(json)
            for (i in 0 until jsonArray.length()) {
                try {
                    val obj = jsonArray.getJSONObject(i)
                    val name = obj.getString("name")
                    val privateKeyHex = obj.getString("privateKey")
                    val identityId = obj.getString("identityId")
                    val identityKeyHex = obj.getString("identityPublicKey")

                    val privateKey = AndroidCryptoProvider.keyFromPrivateBin(privateKeyHex.hexToBytes())
                    val identity = WebAuthnIdentityProviderOwner(identityId, identityKeyHex.hexToBytes(), context)

                    identities.add(Identity(name, privateKey, identity))
                } catch (e: JSONException) {
                    Log.e(TAG, "Error loading identity data: " + jsonArray.getJSONObject(i).toString(), e)
                    continue;
                }
            }
            return identities;
        }
    }
}
