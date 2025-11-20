import { ethers, AbiCoder, toBeHex } from "ethers";
import {
  BundlerService,
  UserOperation,
  AlchemyUserOperationV7,
  UserOperationV6,
  EstimateGasUserOperationV6,
  requestAlchemyUserOperationV6,
} from "./BundlerService";
import crypto from "crypto";

import FactoryABI from "../abis/FactoryABI.json";
import PayMasterABI from "../abis/PayMasterABI.json";
import { EntryPointABI } from "../abis/EntryPointABI";
import dotenv from "dotenv";

dotenv.config();

export class AAService {
  private provider: ethers.JsonRpcProvider;
  private bundler: BundlerService;
  private factoryAddress: string;
  private entryPointAddress: string;
  private paymasterAddress: string;
  private paymasterSigner: ethers.Wallet;
  private chainId: number | undefined;

  constructor() {
    this.provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL!);
    this.bundler = new BundlerService();
    this.factoryAddress = process.env.FACTORY_ADDRESS!;
    this.entryPointAddress = process.env.ENTRYPOINT_ADDRESS!;
    this.paymasterAddress = process.env.PAYMASTER_ADDRESS!;
    this.paymasterSigner = new ethers.Wallet(
      process.env.PAYMASTER_SIGNER_PRIVATE_KEY!,
      this.provider
    );
    this.init();
  }

  async init() {
    this.chainId = Number((await this.provider.getNetwork()).chainId);
    console.log("AA Service initialized");
    console.log("Chain ID:", this.chainId);
    console.log("EntryPoint:", this.entryPointAddress);
    console.log("Factory:", this.factoryAddress);
    console.log("Paymaster:", this.paymasterAddress);
  }

  /**
   * IMPORTANT: This creates the smart account address
   * But the DEVICE generates and holds the private key!
   * Backend only stores encrypted recovery data
   */
  async createSmartAccount(
    userId: string,
    ownerWalletAddress: string,
    decryptingKey: string
  ): Promise<{
    smartAccountAddress: string;
    encryptedRecoveryData: string;
    salt: any;
    salt_BigInt: string;
  }> {
    // Calculate counterfactual address
    const factory = new ethers.Contract(
      this.factoryAddress,
      FactoryABI,
      this.provider
    );

    const salt = "0x" + crypto.randomBytes(32).toString("hex");
    const salt_BigInt = BigInt(salt);
    const predictedAddress = await factory.getPredictedAddress(ownerWalletAddress, salt_BigInt); 
    const smartAccountAddress = predictedAddress;
    // Create recovery data (encrypted wallet address + salt)
    const recoveryData = JSON.stringify({
      predictedAddress,
      decryptingKey,
      salt: salt_BigInt.toString(),
      createdAt: Date.now(),
    });

    const encryptedRecoveryData = this.encryptRecoveryData(
      recoveryData,
      userId
    );

    console.log("✅ Smart account created (counterfactual)");
    console.log("   Address:", smartAccountAddress);
    console.log("   Owner (device):", decryptingKey);
    console.log("   Factory Address:", this.factoryAddress);
    
    return {
      smartAccountAddress,
      encryptedRecoveryData,
      salt,
      salt_BigInt: salt_BigInt.toString(),
    };
  }

  async buildTokenTransferUserOp(
    smartAccountAddress: string,
    ownerAddress: string,
    toAddress: string,
    amount: string,
    isDeployed: boolean,
    salt: string
  ): Promise<UserOperationV6> {
    if (!smartAccountAddress) {
      throw new Error("Smart account address is required");
    }
    console.log("Building UserOp (v0.6)...");

    // 1. Encode token transfer
    const tokenInterface = new ethers.Interface([
      "function transfer(address,uint256) returns (bool)",
    ]);
    const transferData = tokenInterface.encodeFunctionData("transfer", [
      toAddress,
      ethers.parseUnits(amount, 18),
    ]);

    // 2. Encode account.execute()
    const accountInterface = new ethers.Interface([
      "function execute(address,uint256,bytes)",
    ]);
    const callData = accountInterface.encodeFunctionData("execute", [
      process.env.UMC_TOKEN_ADDRESS!,
      0,
      transferData,
    ]);

    // 3. Prepare initCode
    let initCode = "0x";
    if (!isDeployed) {
      const factoryContract = new ethers.Contract(
        this.factoryAddress,
        FactoryABI,
        this.provider
      );

      const nSalt = BigInt(salt);
      const predictedAddress = await factoryContract["getPredictedAddress(address,uint256)"](
        ownerAddress,
        nSalt
      );

      if (predictedAddress.toLowerCase() !== smartAccountAddress.toLowerCase()) {
        throw new Error(
          `Address mismatch! Predicted: ${predictedAddress}, Expected: ${smartAccountAddress}`
        );
      }

      initCode = ethers.concat([
        this.factoryAddress,
        factoryContract.interface.encodeFunctionData("createAccount", [
          ownerAddress,
          nSalt,
        ]),
      ]);

      console.log("   Account not deployed, initCode created");
    }

    // 4. Get nonce
    const entryPoint = new ethers.Contract(
      this.entryPointAddress,
      EntryPointABI,
      this.provider
    );
    const nonce = await entryPoint.getNonce(smartAccountAddress, 0);

    // 5. Get gas info
    const gasFees = await this.bundler.getGasFees();

    // 6. Set preliminary gas values
    const callGasLimit = 200_000n;
    const verificationGasLimit = isDeployed ? 150_000n : 500_000n;
    const preVerificationGas = 50_000n;

    // 7. Build preliminary UserOp
    const dummySignature = "0x" + "00".repeat(65);

    // const preliminaryUserOp: UserOperationV6 = {
    //   sender: smartAccountAddress,
    //   nonce: ethers.toBeHex(nonce),
    //   initCode,
    //   callData,
    //   callGasLimit: ethers.toBeHex(callGasLimit),
    //   verificationGasLimit: ethers.toBeHex(verificationGasLimit),
    //   preVerificationGas: ethers.toBeHex(preVerificationGas),
    //   maxFeePerGas: gasFees.maxFeePerGas,
    //   maxPriorityFeePerGas: gasFees.maxPriorityFeePerGas,
    //   paymasterAndData: "0x",
    //   signature: dummySignature,
    // };


    const preliminaryUserOp: EstimateGasUserOperationV6 = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      initCode,
      callData,
      paymasterAndData: "0x",
      signature: dummySignature,
    };

    

    console.log("   Preliminary UserOp:");
    console.log(JSON.stringify(preliminaryUserOp, null, 2));

    // 8. Estimate gas
    let gasLimits;
    try {
      gasLimits = await this.bundler.estimateUserOperationGas(preliminaryUserOp);
      console.log("   Estimated Gas Limits:", gasLimits);
    } catch (error: any) {
      console.error("Gas estimation failed:", error);
      gasLimits = {
        callGasLimit: ethers.toBeHex(callGasLimit),
        verificationGasLimit: ethers.toBeHex(verificationGasLimit),
        preVerificationGas: ethers.toBeHex(preVerificationGas),
      };
    }

    // 9. Add 20% buffer to estimated gas
    const finalCallGas = (BigInt(gasLimits.callGasLimit) * 120n) / 100n;
    const finalVerificationGas = (BigInt(gasLimits.verificationGasLimit) * 120n) / 100n;
    const finalPreVerificationGas = (BigInt(gasLimits.preVerificationGas) * 120n) / 100n;

    let maxPFeePerGas = gasFees.maxPriorityFeePerGas;
    try {
      const { maxPriorityFeePerGas } = await this.bundler.getMaxPriorityFeePerGas();
      maxPFeePerGas = maxPriorityFeePerGas;
    } catch(error: any) {
      console.error("Gas est maxPriorityFeePerGas failed:", error);
    }

    // Add payMasterAndData so users can then sign
    const userOpPaymaster: UserOperationV6 = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      initCode,
      callData,
      callGasLimit: ethers.toBeHex(finalCallGas),
      verificationGasLimit: ethers.toBeHex(finalVerificationGas),
      preVerificationGas: ethers.toBeHex(finalPreVerificationGas),
      maxFeePerGas: gasFees.maxFeePerGas,
      maxPriorityFeePerGas: maxPFeePerGas,
      paymasterAndData: "0x",
      signature: "0x",
    };

    const userOpPaymasterAlchemy: requestAlchemyUserOperationV6 = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      initCode,
      callData,
      callGasLimit: ethers.toBeHex(finalCallGas),
      verificationGasLimit: ethers.toBeHex(finalVerificationGas),
      preVerificationGas: ethers.toBeHex(finalPreVerificationGas),
      maxFeePerGas: gasFees.maxFeePerGas,
      maxPriorityFeePerGas: maxPFeePerGas
    };


    const paymasterAndData = await this.addPaymasterSignature(userOpPaymaster);

    const paymasterAlchemyData = await this.getPayMasterAndData(userOpPaymasterAlchemy);

    console.log("   Paymaster and Data from Alchemy:", paymasterAlchemyData);

    // 10. Return final UserOp
    const userOp: UserOperationV6 = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      initCode,
      callData,
      callGasLimit: paymasterAlchemyData.callGasLimit,
      verificationGasLimit: paymasterAlchemyData.verificationGasLimit,
      preVerificationGas: paymasterAlchemyData.preVerificationGas,
      maxFeePerGas: paymasterAlchemyData.maxFeePerGas,
      maxPriorityFeePerGas: paymasterAlchemyData.maxPriorityFeePerGas,
      paymasterAndData: paymasterAlchemyData.paymasterAndData,
      signature: "0x",
    };

    console.log("   UserOp built successfully");
    return userOp;
  }

  async getPayMasterAndData(userOp: requestAlchemyUserOperationV6): Promise<any> {
      console.log("🔏 Adding paymaster data from alchemy (v0.6 format)...");

      const paymasterInfo = await this.bundler.requestGasAndPaymasterAndData(userOp);

      console.log("   Paymaster info:", paymasterInfo);
      return paymasterInfo;
    
  }

  async addPaymasterSignature(userOp: UserOperationV6): Promise<string> {
      console.log("🔏 Adding paymaster signature (v0.6 format)...");

      const validUntil = Math.floor(Date.now() / 1000) + 600; // 10 mins
      const validAfter = 0;

      console.log("Timing:");
      console.log("  ValidUntil:", validUntil);
      console.log("  ValidAfter:", validAfter);

      // 1. Compute userOpHash using EntryPoint contract
      const entryPoint = new ethers.Contract(
        this.entryPointAddress,
        EntryPointABI,
        this.provider
      );
      
      // 2. Compute paymaster hash according to ERC-4337 v0.6
      // CRITICAL: Compute hash EXACTLY as PayMaster.sol getHash() does
      // This MUST match your contract's getHash function!
      const abiCoder = ethers.AbiCoder.defaultAbiCoder();
      const encoded = abiCoder.encode(
      [
        "address", // userOp.sender
        "uint256", // userOp.nonce
        "uint256", // userOp.callGasLimit
        "uint256", // userOp.verificationGasLimit
        "uint256", // userOp.preVerificationGas
        "uint256", // userOp.maxFeePerGas
        "uint256", // userOp.maxPriorityFeePerGas
        "uint256", // block.chainid
        "address", // Paymaster address (address(this))
        "uint48",  // validUntil
        "uint48"   // validAfter
      ],
      [
        userOp.sender,
        userOp.nonce,
        userOp.callGasLimit,
        userOp.verificationGasLimit,
        userOp.preVerificationGas,
        userOp.maxFeePerGas,
        userOp.maxPriorityFeePerGas,
        this.chainId!,
        this.paymasterAddress!,
        validUntil,
        validAfter
      ]
    );
    const paymasterHash = ethers.keccak256(encoded);
    console.log("  Paymaster Hash:", paymasterHash);

    // 3. Sign with paymaster private key
    const signature = await this.paymasterSigner.signMessage(
      ethers.getBytes(paymasterHash)
    );

    console.log("  Signature:", signature);
    console.log("  Signer address:", await this.paymasterSigner.getAddress());

    // Verify signature locally
    const ethSignedHash = ethers.hashMessage(ethers.getBytes(paymasterHash));
    const recoveredAddress = ethers.recoverAddress(ethSignedHash, signature);
    console.log("  Recovered address:", recoveredAddress);
    console.log(
      "  Signature valid:",
      recoveredAddress.toLowerCase() ===
        (await this.paymasterSigner.getAddress()).toLowerCase()
        ? "✅ YES"
        : "❌ NO"
    );

    // 4. Pack paymasterAndData: [paymaster address (20 bytes)][validUntil (6 bytes)][validAfter (6 bytes)][signature (65 bytes)]
    const paymasterAndData = ethers.concat([
      this.paymasterAddress,
      abiCoder.encode(["uint48", "uint48"], [validUntil, validAfter]),
      signature,
    ]);
   

    console.log("✅ Paymaster signature added");
    console.log(" PaymasterAndData:", paymasterAndData);
    console.log("\n✅ PaymasterAndData created");
    console.log("   Length:", (paymasterAndData.length - 2) / 2, "bytes");

    return paymasterAndData;
  }

  /**
   * Verify user signature on UserOp
   */
  async verifyUserOpSignature(userOp: UserOperationV6, expectedOwner: string) {
    console.log("\n🔍 Verifying user signature...");

    // CRITICAL: User signed BEFORE paymaster was added
    // So we must calculate hash WITHOUT paymasterAndData
    // const userOpForHash = {
    //   ...userOp,
    //   paymasterAndData: "0x", // Remove paymaster for hash calculation
    // };


    const entryPoint = new ethers.Contract(
      this.entryPointAddress,
      EntryPointABI,
      this.provider
    );

    // Calculate hash
    const userOpHash = await entryPoint.getUserOpHash(userOp);
    console.log("  UserOpHash:", userOpHash);

    // Check if account is deployed
    const accountCode = await this.provider.getCode(userOp.sender);
    const isDeployed = accountCode !== "0x";
    console.log("  Account deployed:", isDeployed ? "YES ✅" : "NO (will deploy) ⏳");

    // Verify signature
    const ethSignedHash = ethers.hashMessage(ethers.getBytes(userOpHash));

    try {
      const recoveredAddress = ethers.recoverAddress(ethSignedHash, userOp.signature);

      console.log("  Recovered signer:", recoveredAddress);
      console.log("  Expected owner:", expectedOwner);

      let actualOwner = expectedOwner;

      if (isDeployed) {
        const account = new ethers.Contract(
          userOp.sender,
          ["function owner() view returns (address)"],
          this.provider
        );

        try {
          actualOwner = await account.owner();
          console.log("  Actual owner (on-chain):", actualOwner);
        } catch (error) {
          console.log("  ⚠️  Could not read owner from contract, using expected owner");
        }
      }

      const isValid = recoveredAddress.toLowerCase() === actualOwner.toLowerCase();
      console.log("  Signature valid:", isValid ? "✅ YES" : "❌ NO");

      if (!isValid) {
        throw new Error(
          `Invalid signature!\n` +
            `  Expected: ${actualOwner}\n` +
            `  Got: ${recoveredAddress}`
        );
      }

      return true;
    } catch (error: any) {
      console.error("❌ Signature recovery failed:", error.message);
      throw error;
    }
  }

  /**
   * Submit UserOperation to bundler
   */
  async submitUserOperation(userOp: UserOperationV6): Promise<string> {
    return await this.bundler.sendUserOperation(userOp);
  }

   /**
   * Check paymaster deposit
   */
  async checkPaymasterDeposit() {
    const entryPoint = new ethers.Contract(
      this.entryPointAddress,
      EntryPointABI,
      this.provider
    );

    const balance = await entryPoint.balanceOf(this.paymasterAddress);

    console.log("\n💰 Paymaster Deposit Check:");
    console.log("  Balance:", ethers.formatEther(balance), "ETH");

    return balance;
  }

  /**
   * Wait for transaction confirmation
   */
  async waitForConfirmation(userOpHash: string): Promise<any> {
    return await this.bundler.waitForUserOperationReceipt(userOpHash);
  }

  /**
   * Debug UserOp validation on-chain
   */
  async debugValidation(userOp: UserOperationV6) {
    const entryPoint = new ethers.Contract(
      this.entryPointAddress,
      EntryPointABI,
      this.provider
    );

    console.log("🔬 Simulating validation on-chain...");
    
    try {
      const result = await entryPoint.simulateValidation.staticCall(userOp);
      console.log("✅ Validation PASSED");
      return true;
    } catch (error: any) {
      // In v0.6, simulateValidation reverts with ValidationResult on SUCCESS
      if (error.revert && error.revert.name === "ValidationResult") {
        console.log("✅ Validation PASSED (ValidationResult)");
        
        try {
          // Decode the validation result manually from the error data
          // error.data format: 0xe0cff05f + encoded data
          const dataWithoutSelector = "0x" + error.data.slice(10);
          
          const abiCoder = ethers.AbiCoder.defaultAbiCoder();
          const decoded = abiCoder.decode(
            [
              "tuple(uint256 preOpGas, uint256 prefund, bool sigFailed, uint48 validAfter, uint48 validUntil, bytes paymasterContext)",
              "tuple(uint256 stake, uint256 unstakeDelay)",
              "tuple(uint256 stake, uint256 unstakeDelay)",
              "tuple(uint256 stake, uint256 unstakeDelay)"
            ],
            dataWithoutSelector
          );
          
          const [returnInfo, senderInfo, factoryInfo, paymasterInfo] = decoded;
          
          console.log("\n📊 Validation Result:");
          console.log("   Return Info:");
          console.log("     preOpGas:", returnInfo[0].toString());
          console.log("     prefund:", ethers.formatEther(returnInfo[1]), "ETH");
          console.log("     sigFailed:", returnInfo[2]);
          console.log("     validAfter:", returnInfo[3].toString());
          console.log("     validUntil:", returnInfo[4].toString());
          
          console.log("   Sender Info:");
          console.log("     stake:", ethers.formatEther(senderInfo[0]), "ETH");
          console.log("     unstakeDelay:", senderInfo[1].toString());
          
          console.log("   Factory Info:");
          console.log("     stake:", ethers.formatEther(factoryInfo[0]), "ETH");
          console.log("     unstakeDelay:", factoryInfo[1].toString());
          
          console.log("   Paymaster Info:");
          console.log("     stake:", ethers.formatEther(paymasterInfo[0]), "ETH");
          console.log("     unstakeDelay:", paymasterInfo[1].toString());
          
          // Check for signature failure
          if (returnInfo[2]) {
            console.log("\n❌ SIGNATURE FAILED!");
            throw new Error("Signature validation failed (sigFailed = true)");
          }
          
          console.log("\n✅ All validations passed!");
          return true;
        } catch (decodeError) {
          console.log("⚠️ Could not decode validation result");
        }
      } else {
        // Real error
        console.log("❌ Validation FAILED");
        console.log("Error:", error.message);
        
        // Check for common error codes
        if (error.message.includes("AA23")) {
          console.log("💡 AA23 = reverted (or OOG)");
        } else if (error.message.includes("AA24")) {
          console.log("💡 AA24 = signature error");
        } else if (error.message.includes("AA25")) {
          console.log("💡 AA25 = invalid account nonce");
        } else if (error.message.includes("AA31")) {
          console.log("💡 AA31 = paymaster deposit too low");
        } else if (error.message.includes("AA32")) {
          console.log("💡 AA32 = paymaster expired or not due");
        } else if (error.message.includes("AA33")) {
          console.log("💡 AA33 = reverted (or OOG)");
        } else if (error.message.includes("AA34")) {
          console.log("💡 AA34 = signature error");
        }
        
        throw error;
      }
    }
  }


  // Recovery helpers
  private encryptRecoveryData(data: string, userId: string): string {

    const masterKey = process.env.RECOVERY_ENCRYPTION_KEY!;
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(16);
    const key = crypto.scryptSync(masterKey, salt, 32);

    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
    let encrypted = cipher.update(data, "utf8", "hex");
    encrypted += cipher.final("hex");
    const authTag = cipher.getAuthTag();

    // Combine all parts (salt, iv, authTag, ciphertext)
    return [
      salt.toString("hex"),
      iv.toString("hex"),
      authTag.toString("hex"),
      encrypted,
    ].join(":");
  }

  decryptRecoveryData(encryptedData: string, userId: string): any {

    const parts = encryptedData.split(":");
    const salt = Buffer.from(parts[0], "hex");
    const iv = Buffer.from(parts[1], "hex");
    const authTag = Buffer.from(parts[2], "hex");
    const encrypted = parts[3];

    const masterKey = process.env.RECOVERY_ENCRYPTION_KEY!;
    const key = crypto.scryptSync(masterKey, salt, 32);

    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return JSON.parse(decrypted);
  }
}
