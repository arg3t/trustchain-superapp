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
import androidx.preference.PreferenceManager
import kotlinx.coroutines.launch
import nl.tudelft.ipv8.android.IPv8Android
import nl.tudelft.ipv8.android.keyvault.AndroidCryptoProvider
import nl.tudelft.ipv8.keyvault.IdentityProviderOwner
import nl.tudelft.ipv8.keyvault.PrivateKey
import nl.tudelft.ipv8.util.hexToBytes
import nl.tudelft.trustchain.app.TrustChainApplication
import nl.tudelft.trustchain.app.databinding.FragmentDashboardIdentityBinding
import nl.tudelft.trustchain.common.util.WebAuthnIdentityProviderOwner
import nl.tudelft.trustchain.common.util.viewBinding
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.util.UUID

private const val TAG = "IdentityManager"

private var selectedIdIdx = 0;

/**
 * Activity that lets the user **view, create, select and delete** identities stored on-device.
 *
 * The screen bridges the **Registration** (creating a WebAuthn credential and saving
 * the resulting block) and **Verification** phases (selecting an identity and testing signatures).
 */
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

    /**
     * Persists the current in-memory list of identities to the default
     * {@link SharedPreferences} as a compact JSON array.
     *
     * Each element stores:
     * * `name`               – user-friendly label
     * * `privateKey`         – raw private-key bytes
     * * `identityPublicKey`  – WebAuthn public key
     * * `identityId`         – WebAuthn credential ID
     */
    @OptIn(ExperimentalStdlibApi::class)
    private fun saveIdentities() {
        val prefs = PreferenceManager.getDefaultSharedPreferences(this)
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

    /**
     * Configures the **identity selector** (`Spinner`) that shows every stored identity.
     *
     * * Populates the adapter with the names of all identities.
     * * Listens for user selection changes and, when they occur, updates the global
     *   [TrustChainApplication] instance **and** the active IPv8 peer so that subsequent
     *   on-chain operations are signed with the chosen identity.
     * * Restores the spinner’s selection after configuration-changes by using
     *   the cached index in `selectedIdIdx`.
     */
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
                IPv8Android.getInstance().myPeer.identityProvider = identity.identity
                IPv8Android.getInstance().myPeer.key = identity.privateKey
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {
            }
        }

        if (selectedIdIdx < savedIdentities.size) {
            binding.currentIdentitySelector.setSelection(selectedIdIdx)
            selectedIdentity = savedIdentities[selectedIdIdx]
        }
    }

    /**
     * Wires the **“Save”** button that registers a brand-new identity:
     *
     * 1. Validates the entered name.
     * 2. Generates a fresh EC key-pair locally.
     * 3. Launches a WebAuthn **registration** ceremony via [registerWebAuthn].
     * 4. Combines the local key and the returned credential into an [Identity],
     *    persists it and refreshes the UI.
     *
     * Errors and status updates are surfaced through `Toast` messages; the long-running
     * registration happens inside `lifecycleScope.launch { … }`.
     */
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

    /**
     * Adds a **diagnostic** button that signs a hardcoded string with the currently
     * selected identity *and immediately verifies the result*.
     *
     * This is a quick smoke-test for the **Verification** step shown in the project diagram.
     * The generated signature and its verification outcome are logged to *logcat* and
     * displayed to the user via a `Toast`.
     */
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


    /**
     * Wires the **“Delete”** button that removes the identity currently selected in the spinner.
     *
     * After deletion the method:
     * * Calls [saveIdentities] to persist the updated list.
     * * Refreshes the spinner adapter and, if any identities remain, selects a sensible default.
     * * Re-initialises the IPv8 subsystem so that the application continues to operate with a
     *   valid identity.
     */
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

    /**
     * Completes the picker workflow: returns `RESULT_OK` to the caller and finishes the activity.
     *
     * The actual identity switch already happened in [setupIdentitySelector]; here we merely
     * acknowledge the choice and close the screen.
     */
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

    /**
     * Inserts a freshly created [identity] into the in-memory list and persists it.
     *
     * If this is the **first** identity ever created, it is automatically activated and the
     * IPv8 stack is boot-strapped so the user can start transacting immediately.
     *
     * @param identity Newly minted identity returned from [setupSaveButton].
     */
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

    /**
     * Performs a WebAuthn **registration ceremony** using the Android *Credential Manager* API and
     * converts the result into an [IdentityProviderOwner].
     *
     * Steps performed inside the coroutine:
     * 1. Build a [CreatePublicKeyCredentialRequest] using [createRegistrationRequestJson].
     * 2. Launch the platform-provided registration flow.
     * 3. Extract the credential’s raw public key and ID from the response JSON.
     * 4. Wrap them into a [WebAuthnIdentityProviderOwner].
     *
     * @param name Friendly display-name chosen by the user; incorporated into the RP data.
     * @return The newly created credential wrapper, or **`null`** when the user cancels or an
     *         error occurs.
     *
     * @throws Exception Propagates any unexpected failures coming from the credential APIs.
     */
    @SuppressLint("PublicKeyCredential")
    suspend fun registerWebAuthn(name: String): IdentityProviderOwner? {
        try {
            val id = UUID.randomUUID().toString()
            val credentialManager = CredentialManager.create(this)

            val request = CreatePublicKeyCredentialRequest(
                requestJson = createRegistrationRequestJson(name, id),
                // preferImmediatelyAvailableCredentials = true
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

    /**
     * Builds the JSON payload expected by a WebAuthn
     * [CreatePublicKeyCredentialRequest] **registration** call.
     *
     * A fresh 32-byte random challenge is generated for every invocation.
     *
     * @param name Display-name of the user (shown in authenticator UI).
     * @param id   Randomly generated user-handle (base64url encoded).
     * @return Minified JSON string suitable for the `requestJson` argument.
     */
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
                "residentKey": "preferred",
                "requireResidentKey": false,
                "userVerification": "preferred"
            },
            "attestation": "none"
        }
        """.trimIndent()
    }


    /**
     * Simple value-object that groups everything required to represent an identity.
     *
     * @property name        Human-readable label shown in the UI.
     * @property privateKey  EC private key that signs TrustChain/IPv8 blocks.
     * @property identity    WebAuthn-backed identity provider whose public key ends up on-chain.
     */
    data class Identity(
        val name: String,
        val privateKey: PrivateKey,
        val identity: IdentityProviderOwner
    )

    companion object {
        private const val PREF_IDENTITIES = "identities_json"

        /**
         * Reads all identities previously stored by [saveIdentities] from
         * {@link SharedPreferences} and deserialises them.
         *
         * Corrupt records are skipped but logged so that a single bad entry does not
         * prevent the app from starting.
         *
         * @param context Any valid Android [Context].
         * @return Immutable list of valid [Identity] objects.
         */
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
