import { ethers } from "ethers";
import {
  BundlerService,
  UserOperationV7,
  UserOperationV7Unpacked,
  AlchemyUserOperationRequest,
} from "./BundlerService";
import crypto from "crypto";

import FactoryABI from "../abis/FactoryABI.json";
import dotenv from "dotenv";
import { EntryPointV07ABI } from "../abis/EntryPointV07ABI";

dotenv.config();

export class AAService {
  private provider: ethers.JsonRpcProvider;
  private bundler: BundlerService;
  private factoryAddress: string;
  private entryPointAddress: string;
  private chainId: number | undefined;

  constructor() {
    this.provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL!);
    this.bundler = new BundlerService();
    this.factoryAddress = process.env.FACTORY_ADDRESS!;
    this.entryPointAddress = process.env.ENTRYPOINT_V07_ADDRESS!; // NEW v0.7 entrypoint
    this.init();
  }

  async init() {
    this.chainId = Number((await this.provider.getNetwork()).chainId);
    console.log("AA Service initialized (v0.7)");
    console.log("Chain ID:", this.chainId);
    console.log("EntryPoint:", this.entryPointAddress);
    console.log("Factory:", this.factoryAddress);
  }

  /**
   * Create smart account (same as v0.6)
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
    const factory = new ethers.Contract(
      this.factoryAddress,
      FactoryABI,
      this.provider
    );

    const salt = "0x" + crypto.randomBytes(32).toString("hex");
    const salt_BigInt = BigInt(salt);
    const predictedAddress = await factory.getPredictedAddress(ownerWalletAddress, salt_BigInt);
    const smartAccountAddress = predictedAddress;

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

  /**
   * Build token transfer UserOp (v0.7 format)
   */
  async buildTokenTransferUserOp(
    smartAccountAddress: string,
    ownerAddress: string,
    toAddress: string,
    amount: string,
    isDeployed: boolean,
    salt: string
  ): Promise<UserOperationV7Unpacked> {
    if (!smartAccountAddress) {
      throw new Error("Smart account address is required");
    }
    console.log("Building UserOp (v0.7)...");

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

    // 3. Prepare factory and factoryData (replaces initCode in v0.7)
    let factory: string | undefined;
    let factoryData: string | undefined;

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

      factory = this.factoryAddress;
      factoryData = factoryContract.interface.encodeFunctionData("createAccount", [
        ownerAddress,
        nSalt,
      ]);

      console.log("   Account not deployed, factory & factoryData created");
    }

    // 4. Get nonce
    const entryPoint = new ethers.Contract(
      this.entryPointAddress,
      EntryPointV07ABI,
      this.provider
    );
    const nonce = await entryPoint.getNonce(smartAccountAddress, 0);

    // 5. Get gas info
    const gasFees = await this.bundler.getGasFees();

    // 6. Set preliminary gas values
    const callGasLimit = 200_000n;
    const verificationGasLimit = isDeployed ? 150_000n : 500_000n;
    const preVerificationGas = 50_000n;
    const dummySignature = "0x" + "00".repeat(65);

    // 7. Build request for Alchemy (clean format)
    const alchemyRequest: AlchemyUserOperationRequest = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      callData,
      callGasLimit: ethers.toBeHex(callGasLimit),
      verificationGasLimit: ethers.toBeHex(verificationGasLimit),
      preVerificationGas: ethers.toBeHex(preVerificationGas),
      maxFeePerGas: gasFees.maxFeePerGas,
      maxPriorityFeePerGas: gasFees.maxPriorityFeePerGas
    };

    // Only add factory if account needs deployment
    // if (factory && factory !== "0x" && factory !== ethers.ZeroAddress) {
    //   alchemyRequest.factory = factory;
    //   alchemyRequest.factoryData = factoryData;
    // }

    if (!isDeployed) {
      alchemyRequest.factory = factory;
      alchemyRequest.factoryData = factoryData;
    }

    console.log("Alchemy UserOp Request prepared:", alchemyRequest);
   

    console.log("   Requesting paymaster from Alchemy...");
    console.log("   Request:", JSON.stringify(alchemyRequest, null, 2))


    // 8. Get paymaster and gas estimates from Alchemy
    const paymasterData = await this.bundler.requestGasAndPaymasterAndData(alchemyRequest);

    // const gasDetails = await this.bundler.estimateUserOperationGas(alchemyRequest);

    console.log("   Gas estimated from Alchemy:", paymasterData);
    
    // console.log("   Paymaster data received:", paymasterData);

    // 9. Build final unpacked UserOp
    const userOp: UserOperationV7Unpacked = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      callData,
      callGasLimit: paymasterData.callGasLimit,
      verificationGasLimit: paymasterData.verificationGasLimit,
      preVerificationGas: paymasterData.preVerificationGas,
      maxFeePerGas: paymasterData.maxFeePerGas,
      maxPriorityFeePerGas: paymasterData.maxPriorityFeePerGas,
      signature: "0x",
    };

    // Add factory fields if account needs deployment
    if (factory) {
      userOp.factory = factory;
      userOp.factoryData = factoryData;
    }

    // Add paymaster fields if provided
    if (paymasterData.paymaster) {
      userOp.paymaster = paymasterData.paymaster;
      userOp.paymasterVerificationGasLimit = paymasterData.paymasterVerificationGasLimit;
      userOp.paymasterPostOpGasLimit = paymasterData.paymasterPostOpGasLimit;
      userOp.paymasterData = paymasterData.paymasterData;
    }

    console.log("   UserOp built successfully (v0.7)");
    return userOp;
  }

  /**
   * Verify user signature on UserOp (v0.7)
   */
  async verifyUserOpSignature(userOp: UserOperationV7, expectedOwner: string) {
    console.log("\n🔍 Verifying user signature (v0.7)...");

    const entryPoint = new ethers.Contract(
      this.entryPointAddress,
      EntryPointV07ABI,
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
  async submitUserOperation(userOp: UserOperationV7Unpacked): Promise<string> {
    return await this.bundler.sendUserOperation(userOp);
  }

  /**
   * Wait for transaction confirmation
   */
  async waitForConfirmation(userOpHash: string): Promise<any> {
    return await this.bundler.waitForUserOperationReceipt(userOpHash);
  }

  /**
   * Debug UserOp validation on-chain (v0.7)
   */
  async debugValidation(userOp: UserOperationV7) {
    const entryPoint = new ethers.Contract(
      this.entryPointAddress,
      EntryPointV07ABI,
      this.provider
    );

    console.log("🔬 Simulating validation on-chain (v0.7)...");

    try {
      const result = await entryPoint.simulateValidation.staticCall(userOp);
      console.log("✅ Validation PASSED");
      return true;
    } catch (error: any) {
      // In v0.7, simulateValidation also reverts with ValidationResult on SUCCESS
      if (error.revert && error.revert.name === "ValidationResult") {
        console.log("✅ Validation PASSED (ValidationResult)");
        return true;
      } else {
        console.log("❌ Validation FAILED");
        console.log("Error:", error.message);

        // Check for common error codes
        if (error.message.includes("AA23")) {
          console.log("💡 AA23 = reverted (or OOG)");
        } else if (error.message.includes("AA24")) {
          console.log("💡 AA24 = signature error");
        } else if (error.message.includes("AA25")) {
          console.log("💡 AA25 = invalid account nonce");
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