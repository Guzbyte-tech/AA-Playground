Here’s your **complete AA flow documentation** converted into clean, formatted **Markdown**:

---

# 🧩 Complete Account Abstraction (AA) Flow

---

## ⚙️ PHASE 1: USER REGISTRATION

### **Frontend (Mobile/Web)**

1. User enters:

   * `username`, `email`, `password`
2. Device generates keypair (e.g., WebAuthn/biometric):

   ```js
   const keypair = await generateKeyPair();
   // privateKey → Stored in device secure enclave
   // publicKey → Sent to backend
   ```
3. **POST** `/api/auth/register`

   ```json
   {
     "username": "alice",
     "email": "alice@example.com",
     "password": "SecurePass123",
     "devicePublicKey": "0xABC123..."
   }
   ```

### **Backend**

1. Validate input
2. Hash password
3. Compute counterfactual account:

   ```solidity
   factory.getAddress(devicePublicKey, salt)
   ```
4. Store in database:

   * `username`, `email`, `passwordHash`
   * `smartAccountAddress`
   * `encryptedRecoveryData`
   * `isAccountDeployed: false`
5. Return:

   ```json
   {
     "smartAccountAddress": "0xDEF456...",
     "token": "eyJhbGci..."
   }
   ```

### **Frontend (After Registration)**

1. Store token in `localStorage`
2. Store private key in secure device storage
3. **Never send the private key to the backend!**

> 🔒 **Key Point:** Backend has **zero knowledge** of private keys.

---

## 💸 PHASE 2: SENDING TRANSACTION

### **Frontend**

1. User clicks **"Send 10 tokens to Bob"**
2. **POST** `/api/transactions/build`

   ```json
   {
     "to": "0xBobAddress",
     "amount": "10"
   }
   ```

---

### **Backend (Step 1 – Build UserOp)**

1. Fetch user from DB
2. Build **UserOperation**:

   ```json
   {
     "sender": "user.smartAccountAddress",
     "nonce": "getNonce()",
     "callData": "encode('execute(token, bob, 10)')",
     "callGasLimit": "100000",
     "verificationGasLimit": "300000",
     "preVerificationGas": "50000",
     "maxFeePerGas": "getGasPrice()",
     "maxPriorityFeePerGas": "2gwei",
     "paymasterAndData": "0x",
     "signature": "0x"
   }
   ```
3. Return unsigned `UserOp` to frontend

---

### **Frontend (Step 2 – Sign UserOp)**

1. Receive unsigned `UserOp`
2. Compute:

   ```js
   const userOpHash = hash(userOp + entryPoint + chainId);
   const signature = await deviceKey.sign(userOpHash);
   userOp.signature = signature;
   ```
3. **POST** `/api/transactions/submit`

   ```json
   { "userOp": signedUserOp }
   ```

---

### **Backend (Step 3 – Add Paymaster & Submit)**

1. Receive signed `UserOp`
2. Verify user signature
3. Add paymaster signature:

   ```js
   const paymasterData = signWithPaymasterKey(userOp);
   userOp.paymasterAndData = paymasterData;
   ```
4. Submit to bundler:

   ```bash
   POST https://bundler.stackup.sh/v1/eth_sendUserOperation
   ```
5. Save pending transaction in DB
6. Return `userOpHash` to frontend

---

### **Bundler (Stackup / Alchemy / Pimlico)**

1. Receive `UserOp`
2. Validate:

   * Signature validity
   * Paymaster verification
   * Gas limits and nonce
3. Add to mempool
4. Batch with others
5. Submit:

   ```solidity
   entryPoint.handleOps([userOps], beneficiary)
   ```

---

### **Blockchain (EntryPoint Contract)**

1. EntryPoint executes `handleOps()`
2. For each `UserOp`:

   * ✅ Verify paymaster signature
   * ✅ Validate user signature
   * ✅ Deploy account (if `initCode` exists)
   * ✅ Execute transaction (`execute()`)
   * ✅ Charge paymaster for gas
3. Emit `UserOperationEvent`
4. Confirm transaction on-chain

---

### **Backend (Step 4 – Monitor)**

1. Poll bundler:

   ```bash
   GET eth_getUserOperationReceipt(userOpHash)
   ```
2. When confirmed:

   * Update DB: `status = "confirmed"`
   * Store `txHash`, `blockNumber`
3. Optionally notify user (websocket/push)

---

> 🔑 **Summary**
>
> * Device signs transaction (user controls keys)
> * Backend adds paymaster signature (gas sponsorship)
> * Bundler submits to blockchain
> * EntryPoint executes transaction

---

## 🔁 PHASE 3: ACCOUNT RECOVERY

### **Scenario: User Loses Device**

#### **Frontend (New Device)**

1. Login with username/password
2. Backend verifies credentials
3. Backend returns `encryptedRecoveryData`
4. Frontend decrypts recovery data
5. Display `smartAccountAddress`
6. Generate new device keypair
7. **POST** `/api/recovery/rotate-key`

   ```json
   {
     "oldPublicKey": "0xLOST",
     "newPublicKey": "0xNEW"
   }
   ```

---

### **Backend**

1. Verify user identity (2FA, email, etc.)
2. Build `UserOp` calling:

   ```solidity
   smartAccount.transferOwnership(newPublicKey)
   ```
3. Submit to bundler
4. ✅ Ownership transferred → new device regains access

---

## 🔐 SECURITY MODEL

### **Who Holds What**

| Entity             | Holds                   | Description                                |
| ------------------ | ----------------------- | ------------------------------------------ |
| **Device**         | Private Key             | Stored in secure enclave, used for signing |
|                    | Biometric/PIN           | Unlocks private key                        |
| **Backend**        | Encrypted recovery data | For recovery flow                          |
|                    | Paymaster signer key    | Sponsors gas                               |
|                    | Password hash           | For login                                  |
| **Smart Contract** | Owner address           | Device public key                          |
|                    | Token balances          | Stored on-chain                            |
|                    | Execution logic         | Handles transactions                       |

---

### **Attack Scenarios**

| Scenario                     | Outcome                       |
| ---------------------------- | ----------------------------- |
| Backend hacked               | ❌ No private keys, funds safe |
| Device lost                  | ✅ Recover via backend         |
| Password stolen              | ❌ Still need device key       |
| Device + Backend compromised | ⚠️ Risk to funds              |

> 🛡 **Defense:** Add a **2-day timelock** for ownership changes.

---

## ⚖️ BUNDLER COMPARISON

| Bundler      | Pros                                                                | Cons                     | URL                                                     |
| ------------ | ------------------------------------------------------------------- | ------------------------ | ------------------------------------------------------- |
| **Stackup**  | ✅ Easiest integration<br>✅ Free tier<br>✅ Good docs                 | ✗ Fewer features         | `https://api.stackup.sh/v1/node/YOUR_KEY`               |
| **Alchemy**  | ✅ Reliable<br>✅ Best tooling<br>✅ Great analytics                   | ✗ More expensive         | `https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY`         |
| **Pimlico**  | ✅ Advanced features<br>✅ Custom gas logic<br>✅ Great for production | ✗ Steeper learning curve | `https://api.pimlico.io/v1/sepolia/rpc?apikey=YOUR_KEY` |
| **Biconomy** | ✅ Full AA stack<br>✅ Paymaster as a service<br>✅ SDK support        | ✗ Vendor lock-in         | (via SDK)                                               |

> 🧭 **Recommendation:**
> Start with **Stackup** (easy testing), migrate to **Alchemy** for production.

---

**End of Document**
✅ Secure
✅ Scalable
✅ Gas Sponsored
✅ User-Friendly


