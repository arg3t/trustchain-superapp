package nl.tudelft.trustchain.app.ui.dashboard

import android.os.Bundle
import android.preference.PreferenceManager
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import nl.tudelft.ipv8.android.keyvault.AndroidCryptoProvider
import nl.tudelft.ipv8.util.hexToBytes
import nl.tudelft.ipv8.util.toHex
import nl.tudelft.trustchain.app.TrustChainApplication
import nl.tudelft.trustchain.app.databinding.FragmentDashboardIdentityBinding
import nl.tudelft.trustchain.app.keyvault.WebAuthnCryptoProvider
import nl.tudelft.trustchain.common.util.viewBinding
import org.json.JSONArray
import org.json.JSONObject


class DashboardIdentityActivity : AppCompatActivity() {
    private val binding by viewBinding(FragmentDashboardIdentityBinding::inflate)

    // Define identity types for the first spinner
    private val identityTypes = listOf("New Regular", "New WebAuthn")

    // Store the list of saved identities
    private val savedIdentities = mutableListOf<Identity>()

    // Adapters for the spinners
    private lateinit var identityTypeAdapter: ArrayAdapter<String>
    private lateinit var savedIdentitiesAdapter: ArrayAdapter<String>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(binding.root)
        loadIdentities()
        title = "Pick Your Identity";

        setupIdentityTypePicker()
        setupIdentitySelector()
        setupSaveButton()
        setupSelectIdentityButton()
    }

    private fun loadIdentities() {
        val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this)
        val json = prefs.getString(PREF_IDENTITIES, "[]")

        val jsonArray = JSONArray(json)
        for (i in 0 until jsonArray.length()) {
            val obj = jsonArray.getJSONObject(i)
            val name = obj.getString("name")
            val type = IdentityType.valueOf(obj.getString("type"))
            val data = obj.getString("data")
            savedIdentities.add(Identity(name, type, data))
        }
    }


    private fun saveIdentities() {
        val prefs = androidx.preference.PreferenceManager.getDefaultSharedPreferences(this)
        val jsonArray = JSONArray()
        for (identity in savedIdentities) {
            val obj = JSONObject()
            obj.put("name", identity.name)
            obj.put("type", identity.type.name)
            obj.put("data", identity.data)
            jsonArray.put(obj)
        }
        prefs.edit().putString(PREF_IDENTITIES, jsonArray.toString()).apply()
    }


    private fun setupIdentityTypePicker() {
        identityTypeAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            identityTypes
        ).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        binding.newIdentityTypePicker.adapter = identityTypeAdapter
    }

    private fun setupIdentitySelector() {
        savedIdentitiesAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            listOf("default") + savedIdentities.map { it.name }
        ).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        binding.currentIdentitySelector.adapter = savedIdentitiesAdapter

        // Handle selection
        binding.currentIdentitySelector.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (position == 0) {
                    (application as TrustChainApplication).defaultPrivateKey()
                    return
                } else {
                    val selectedIdentity = savedIdentities[position - 1]

                    if (selectedIdentity.type == IdentityType.REGULAR) {
                        (application as TrustChainApplication).privateKey =
                            AndroidCryptoProvider.keyFromPrivateBin(selectedIdentity.data.hexToBytes());
                    } else {
                        // TODO: Handle WebAuthn Identities
                        //(application as TrustChainApplication).privateKey = AndroidCryptoProvider.keyFromPrivateBin(selectedIdentity.data.hexToBytes());
                    }
                }
                (application as TrustChainApplication).initIPv8()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {
            }
        }
    }

    private fun setupSaveButton() {
        binding.saveIdBtn.setOnClickListener {
            val identityName = binding.newIdentityName.text.toString().trim()
            val selectedTypePosition = binding.newIdentityTypePicker.selectedItemPosition

            if (identityName.isEmpty()) {
                Toast.makeText(this, "Please enter an identity name", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }

            if (selectedTypePosition != AdapterView.INVALID_POSITION) {
                val type = identityTypes[selectedTypePosition]
                if (type == "New Regular") {
                    addNewIdentity(identityName, IdentityType.REGULAR, generateRegularKey())
                }
                else if (type == "New WebAuthn") {
                    addNewIdentity(identityName, IdentityType.WEBAUTHN, generateWebAuthnKey())
                }

                // Clear the input field
                binding.newIdentityName.text?.clear()

                Toast.makeText(this, "Identity saved", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun generateRegularKey(): String {
        return AndroidCryptoProvider.generateKey().keyToBin().toHex()
    }

    private fun generateWebAuthnKey(): String {
        val provider = WebAuthnCryptoProvider(context = this, scope = (application as TrustChainApplication).applicationScope)
        val sk = provider.generateKey()!!
        val keymap = mapOf("id" to sk.id, "pub" to sk.pub().keyToBin())
        return JSONObject(keymap).toString();
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

    private fun addNewIdentity(name: String, type: IdentityType, data: String) {
        // Create and add the new identity
        val newIdentity = Identity(name, type, data)
        savedIdentities.add(newIdentity)
        saveIdentities()

        // Update the adapter with the new data
        savedIdentitiesAdapter.clear()
        savedIdentitiesAdapter.addAll(savedIdentities.map { it.name })
        savedIdentitiesAdapter.notifyDataSetChanged()
    }

    enum class IdentityType {
        REGULAR, WEBAUTHN
    }

    /**
     * Simple data class to represent an identity
     */
    data class Identity(
        val name: String,
        val type: IdentityType,
        val data: String,
    )

    companion object {
        private const val PREF_IDENTITIES = "identities_json"
    }
}
