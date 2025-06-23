# 🇪🇺 Offline Digital Euro with EUDI Integration
**Blockchain Engineering MSc Project | Euro 1 Team 2 | Class of 2025**

[![Build Status](https://github.com/Tribler/trustchain-superapp/workflows/build/badge.svg)](https://github.com/Tribler/trustchain-superapp/actions) [![European Digital Identity](https://img.shields.io/badge/EUDI-compliant-blue.svg)](https://eudiw.dev) [![WebAuthn](https://img.shields.io/badge/WebAuthn-FIDO2-green.svg)](https://webauthn.io/) [![Zero Knowledge](https://img.shields.io/badge/ZK-proofs-purple.svg)](https://en.wikipedia.org/wiki/Zero-knowledge_proof)

> *Creating the future of digital currency: A production-ready digital Euro system combining EUDI government identity verification, WebAuthn biometric authentication, and TrustChain blockchain technology with 89+ comprehensive tests.*

## 🎯 Project Vision

This project was developed as part of the **Blockchain Engineering MSc Course** in collaboration with [Tribler](https://github.com/Tribler/tribler). Our goal was to create an **offline digital Euro system** that combines the security of blockchain technology with the convenience of passport-grade European digital identity standards.


### 🌟 Core Innovation

We've developed integration of **EUDI (European Digital Identity) wallets** with **WebAuthn biometric authentication** on a **TrustChain blockchain**, creating a triple-layer security system that ensures:

- ✅ **Government-verified identity** through EUDI certificates
- ✅ **Biometric transaction signing** via WebAuthn/FIDO2
- ✅ **Tamper-proof transaction history** on TrustChain blockchain
- ✅ **Offline transaction capability** with later synchronization

## 🏗️ Technical Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Digital Euro Transaction System              │
├─────────────────┬─────────────────┬─────────────────┬───────────┤
│   🇪🇺 EUDI       │    🔐 WebAuthn   │  ⛓️ TrustChain │  🛡️ ZK     │
│   Identity      │   Biometric      │   Blockchain   │  Privacy  │
│   Verification  │   Authentication │   Ledger       │  Layer    │
└─────────────────┴─────────────────┴─────────────────┴───────────┘
         │                   │                   │           │
         └───────────────────┼───────────────────┼───────────┘
                             │                   │
                    ┌─────────────────┐ ┌─────────────────┐
                    │   Credential    │ │   Transaction   │
                    │     Block       │ │   Validation    │
                    │   (On-Chain)    │ │    Engine       │
                    └─────────────────┘ └─────────────────┘
```

<!-- ### 🔧 Technical Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Blockchain** | TrustChain + IPv8 | Distributed ledger |
| **Identity** | EUDI Wallet + Digital Certificates | Government-verified user identity |
| **Authentication** | WebAuthn + FIDO2 | Biometric transaction signing |
| **Privacy** | Groth-Sahai Zero-Knowledge Proofs | Anonymous transactions when required |
| **Security** | SHA256 + Cryptographic Signatures | Transaction integrity and validation | -->

### 🔒 Multi-Layered Security Model

```
┌─────────────────────────────────────────────────────────────────┐
│                        Security Layers                          │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: Government Identity Verification (EUDI)               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ • Official EU digital identity certificates                 ││
│  │ • Connection to verifier-backend.eudiw.dev                  ││
│  │ • Prevents unregistered user transactions                   ││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: Biometric Authentication (WebAuthn/FIDO2)             │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ • Biometric key generation that's backed by hardware        ││
│  │ • Fingerprint/Face ID transaction signing                   ││
│  │ • Secure enclave protection                                 ││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: Blockchain (TrustChain)                               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ • Distributed ledger with tamper-proof blocks               ││
│  │ • Cryptographic transaction signatures                      ││
│  │ • Double-spending prevention mechanisms                     ││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: Privacy Protection (Zero-Knowledge)                   │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ • Anonymous transactions using ZK proofs                    ││
│  │ • Selective identity disclosure                             ││
│  │ • Privacy-preserving audit trails                           ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```
## 🚀 Key Features & Innovations

### 🆔 **EUDI (European Digital Identity) Integration**

Our implementation connects directly to the official European Digital Identity backend:

- **Live Backend Integration**: Direct API calls to `verifier-backend.eudiw.dev/utilities/validations/sdJwtVc`
- **JWT Token Validation**: Verification of signed EUDI tokens with nonce-based replay protection
- **Identity Extraction**: Parsing of `given_name` and `family_name` from official EU identity certificates
- **Registration Enforcement**: `getUserRegistrationBlock()` prevents unregistered users from transacting
<!-- 
```kotlin
// Actual EUDI Verification Implementation
suspend fun verifyEudiToken(checker: IdentityProviderChecker, signedEUDIToken: IPSignature, nonce: String): Boolean {
    val token = signedEUDIToken.challenge.decodeToString()
    
    val formBody = FormBody.Builder()
        .add("sd_jwt_vc", token)
        .add("nonce", nonce)
        .build()

    val request = Request.Builder()
        .url("https://verifier-backend.eudiw.dev/utilities/validations/sdJwtVc")
        .post(formBody)
        .build()
    
    return withContext(Dispatchers.IO) {
        OkHttpClient().newCall(request).execute().use { response ->
            val json = JSONObject(response.body?.string() ?: return@use false)
            val givenName = json.optString("given_name", "")
            val familyName = json.optString("family_name", "")
            givenName.isNotEmpty() || familyName.isNotEmpty()
        }
    }
}
``` -->

### 🔐 **WebAuthn/FIDO2 Biometric Authentication**

Complete biometric authentication system implementing IPv8 identity interfaces:

- **Identity Provider Classes**: `WebAuthnIdentityProviderOwner` and `WebAuthnIdentityProviderChecker` for IPv8 integration
- **Credential Manager Integration**: Android's official biometric authentication framework
- **ECDSA Signature Verification**: SHA256withECDSA validation with X.509 key specifications
- **Challenge-Response Protocol**: Client data validation preventing replay attacks
- **TrustChain Integration**: `WebAuthnValidator` validates all eurotoken transaction types

<!-- ```kotlin
// Actual WebAuthn Signature Verification Implementation
override fun verify(signature: IPSignature): Boolean {
    return try {
        val clientData = JSONObject(signature.data.decodeToString())
        val base64Challenge = clientData.getString("challenge")
        val decodedChallenge = Base64.decode(base64Challenge, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        if (!signature.challenge.contentEquals(decodedChallenge)) {
            return false
        }

        val clientDataHash = SignatureUtils.hash(signature.data)
        val signedData = signature.authenticatorData + clientDataHash

        val keySpec = X509EncodedKeySpec(publicKey)
        val keyFactory = KeyFactory.getInstance("EC")
        val pubKey = keyFactory.generatePublic(keySpec)

        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(pubKey)
        sig.update(signedData)
        sig.verify(signature.signature)
    } catch (e: Exception) {
        false
    }
}
``` -->

<!-- ```kotlin
// TrustChain WebAuthn Integration
fun initTrustChainCommunity() {
    // Register WebAuthn validator for all eurotoken transaction types
    val webAuthnValidator = WebAuthnValidator(this)
    EUROTOKEN_TYPES.forEach { type ->
        trustChainCommunity.registerTransactionValidator(type, webAuthnValidator)
    }
}

// Transaction signature verification with SHA256 challenge
fun verifyTransactionSignature(
    recipient: String, 
    name: String, 
    amount: Long, 
    signature: IPSignature, 
    checker: IdentityProviderChecker
): Boolean {
    val transactionData = "$recipient $amount $name"
    val expectedHash = MessageDigest.getInstance("SHA256").digest(transactionData.toByteArray())
    
    return signature.challenge.contentEquals(expectedHash) && checker.verify(signature)
}
``` -->

### 🔗 **Blockchain Utilization**

Our team leveraged blockchain technology in the following ways:

#### **Registration Blocks for Identity Verification**
- Created `BLOCK_TYPE_REGISTER` for permanent EUDI identity registration
- Each user's EUDI token and WebAuthn public key recorded on-chain
- `getUserRegistrationBlock()` ensures only verified users can transact
- No central authority required for identity verification after initial registration

#### ** Transaction Validation via Blockchain**
- Extended TrustChain with `WebAuthnValidator` for automatic biometric validation
- Every eurotoken transaction requires both blockchain consensus AND biometric approval
- Cryptographic linking of EUDI identity + WebAuthn signatures + transaction data
- P2P network validates both identity credentials and transaction signatures

<!-- ```kotlin
// Blockchain Registration Implementation
const val BLOCK_TYPE_REGISTER = "eurotoken_register"

fun getUserRegistrationBlock(userKey: ByteArray): TrustChainBlock? {
    return trustChainHelper
        .getChainByUser(userKey)
        .reversed()
        .lastOrNull { block ->
            block.type == BLOCK_TYPE_REGISTER &&
            block.publicKey.contentEquals(userKey)
        }
}

// Blockchain-integrated validation for all eurotoken types
val EUROTOKEN_TYPES = listOf(
    BLOCK_TYPE_TRANSFER, BLOCK_TYPE_CREATE, BLOCK_TYPE_DESTROY,
    BLOCK_TYPE_CHECKPOINT, BLOCK_TYPE_ROLLBACK, BLOCK_TYPE_REGISTER
)
``` -->

## 📊 Performance & Testing

Our testing ensures production-ready security and performance:

| Test File | Focus | Key Tests |
|-----------|-------|-----------|
| **WebAuthnTransactionIntegrationTest** | Complete authentication workflow | Identity provider setup, transaction validation flow |
| **EUDIRegistrationIntegrationTest** | European identity verification | Registration block validation, EUDI token structure |
| **QRSignatureIntegrationTest** | Tamper-proof QR validation | Signature generation, tampering detection, hash validation |
| **TransactionValidationIntegrationTest** | Multi-layered security testing | Performance benchmarks, validation pipeline testing |
| **WebAuthnValidatorTest** | Blockchain validation integration | Eurotoken type validation, signature verification |
| **WebAuthnSignatureTest** | Signature wrapper functionality | IPSignature binding, public key validation |
| **TransactionRepositoryTest** | Core transaction logic | Balance validation, signature verification methods |
| **EUDIUtilsTest** | Backend integration testing | API calls to verifier-backend.eudiw.dev |
| **Blockchain Integration Tests** | 14+ | TrustChain functionality and reliability |

### 🔬 **Technical Publications & Research**

Building upon and contributing to existing research:

- *"Double spending prevention of digital Euros using a web-of-trust"*
- *"Offline Digital Euro: a Minimum Viable CBDC using Groth-Sahai proofs"*
- *OpenID Protocol Specification for EUDI integration*
- *Novel approaches to biometric authentication in blockchain systems*

## 🚀 Getting Started

### Prerequisites
- Android device with biometric authentication (fingerprint/Face ID)
- Android 8.0+ (API level 26+)
- EUDI-compatible wallet app (available in EU App Stores)

### Installation
```bash
# Clone the repository
git clone --recurse-submodules https://github.com/Tribler/trustchain-superapp.git

# Build the application
./gradlew :app:assembleDebug

# Install on connected device
./gradlew :app:installDebug
```

### Quick Start Guide
1. **Install EUDI Wallet**: Download official EU digital identity app
2. **Register Identity**: Complete government identity verification process
3. **Setup Biometrics**: Enable fingerprint/Face ID on your device
4. **Open TrustChain SuperApp**: Launch the digital Euro application
5. **Complete Registration**: Link your EUDI identity with WebAuthn biometrics
6. **Start Transacting**: Send and receive digital Euros securely!
