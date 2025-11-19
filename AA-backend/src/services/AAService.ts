import { ethers, AbiCoder, toBeHex } from "ethers";
import {
  BundlerService,
  UserOperation,
  AlchemyUserOperationV7,
} from "./BundlerService";
import crypto from "crypto";

import FactoryABI from "../abis/FactoryABI.json";
import PayMasterABI from "../abis/PayMasterABI.json";
import SmartAccountABI from "../abis/SmartAccountABI.json";

import { EntryPointABI } from "../abis/EntryPointABI";
import dotenv from "dotenv";
// import {  packAccountGasLimits, packGasFees } from '../utils/helpers';
import { max } from "class-validator";
import {
  packAccountGasLimits,
  packGasFees,
  predictSmartAccountAddress,
  unpackAccountGasLimits,
  unpackGasFees,
} from "../utils/helpers";
import { Signature } from "ethers";

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

  private packAccountGasLimits(
    verificationGasLimit: bigint,
    callGasLimit: bigint
  ): string {
    return ethers.toBeHex((verificationGasLimit << 128n) | callGasLimit, 32);
  }

  private packGasFees(
    maxPriorityFeePerGas: bigint,
    maxFeePerGas: bigint
  ): string {
    return ethers.toBeHex((maxPriorityFeePerGas << 128n) | maxFeePerGas, 32);
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

    const { predictedAddress, salt, salt_BigInt } =
      await predictSmartAccountAddress(
        this.provider,
        this.factoryAddress,
        ownerWalletAddress
      );

    // const smartAccountAddress = await (factory as any).getAddress(
    //   ownerWalletAddress,
    //   salt
    // );
    const smartAccountAddress = predictedAddress;
    // Create recovery data (encrypted wallet address + salt)
    const recoveryData = JSON.stringify({
      predictedAddress,
      decryptingKey,
      salt: salt.toString(),
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
      salt_BigInt,
    };
  }

  async buildTokenTransferUserOpAlchemyV7(
    smartAccountAddress: string,
    ownerAddress: string,
    toAddress: string,
    amount: string,
    isDeployed: boolean,
    salt: string
  ): Promise<{
    alchemyUserOp: Partial<AlchemyUserOperationV7>;
    entryPointPackedUserOp: UserOperation;
  }> {
    if (!smartAccountAddress) {
      throw new Error("Smart account address is required");
    }
    console.log("Building UserOp...");

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

    // 3. Prepare factory and factoryData (instead of initCode)
    let factory = "0x";
    let factoryData = "0x";
    let initCode = "0x";

    if (!isDeployed) {
      const factoryContract = new ethers.Contract(
        this.factoryAddress,
        FactoryABI,
        this.provider
      );

      const nSalt = BigInt(salt);
      const predictedAddress = await factoryContract[
        "getAddress(address,uint256)"
      ](ownerAddress, nSalt);

      if (
        predictedAddress.toLowerCase() !== smartAccountAddress.toLowerCase()
      ) {
        throw new Error(
          `Address mismatch! Predicted: ${predictedAddress}, Expected: ${smartAccountAddress}`
        );
      }

      // For Alchemy v0.7: separate factory and factoryData
      factory = this.factoryAddress;
      factoryData = factoryContract.interface.encodeFunctionData(
        "createAccount",
        [ownerAddress, nSalt]
      );
      initCode = ethers.concat([
        this.factoryAddress,
        factoryContract.interface.encodeFunctionData("createAccount", [
          ownerAddress,
          nSalt,
        ]),
      ]);

      console.log("   Account not deployed");
      console.log("   Factory:", factory);
      console.log("   FactoryData:", factoryData);
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
    // const { maxPriorityFeePerGas } =
    //   await this.bundler.getMaxPriorityFeePerGas_v2();

    // 6. Set preliminary gas values
    const callGasLimit = 200_000n;
    const verificationGasLimit = isDeployed ? 150_000n : 500_000n;
    const preVerificationGas = 50_000n;

    // 7. Build preliminary UserOp (UNPACKED FORMAT for Alchemy)
    const dummySignature = "0x" + "00".repeat(65);

    const preliminaryUserOp = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      callData,
      callGasLimit: ethers.toBeHex(callGasLimit),
      verificationGasLimit: ethers.toBeHex(verificationGasLimit),
      preVerificationGas: ethers.toBeHex(preVerificationGas),
      maxFeePerGas: gasFees.maxFeePerGas,
      // maxPriorityFeePerGas: ethers.toBeHex(maxPriorityFeePerGas),
      maxPriorityFeePerGas: gasFees.maxPriorityFeePerGas,
      signature: dummySignature,
      // Conditional fields for account deployment
      ...(isDeployed
        ? {}
        : {
            factory: factory,
            factoryData: factoryData,
          }),
      // No paymaster
      // paymaster, paymasterData, paymasterVerificationGasLimit, paymasterPostOpGasLimit omitted
    };

    console.log("   Preliminary UserOp:");
    console.log(JSON.stringify(preliminaryUserOp, null, 2));

    // 8. Estimate gas
    let gasLimits;
    try {
      gasLimits = await this.bundler.estimateUserOperationGas(
        preliminaryUserOp
      );
      console.log("   Estimated Gas Limits:", gasLimits);
    } catch (error: any) {
      console.error("Gas estimation failed:", error);
      // Fallback to preliminary values
      gasLimits = {
        callGasLimit: ethers.toBeHex(callGasLimit),
        verificationGasLimit: ethers.toBeHex(verificationGasLimit),
        preVerificationGas: ethers.toBeHex(preVerificationGas),
      };
    }

    // 9. Add 20% buffer to estimated gas
    const finalCallGas = (BigInt(gasLimits.callGasLimit) * 120n) / 100n;
    const finalVerificationGas =
      (BigInt(gasLimits.verificationGasLimit) * 120n) / 100n;
    const finalPreVerificationGas =
      (BigInt(gasLimits.preVerificationGas) * 120n) / 100n;

    // 10. Return final UserOp in BOTH format
    const alchemyUserOp = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      // initCode,
      callData,
      callGasLimit: ethers.toBeHex(finalCallGas),
      verificationGasLimit: ethers.toBeHex(finalVerificationGas),
      preVerificationGas: ethers.toBeHex(finalPreVerificationGas),
      maxFeePerGas: gasFees.maxFeePerGas,
      maxPriorityFeePerGas: gasFees.maxPriorityFeePerGas,
      signature: "0x", // Frontend will sign
      ...(isDeployed
        ? {}
        : {
            factory: factory,
            factoryData: factoryData,
          }),
    };

    // EntryPoint v0.7 format (packed)
    const entryPointPackedUserOp: UserOperation = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      initCode: initCode,
      callData: callData,
      accountGasLimits: this.packAccountGasLimits(
        finalVerificationGas,
        finalCallGas
      ),
      preVerificationGas: ethers.toBeHex(finalPreVerificationGas),
      gasFees: this.packGasFees(
        BigInt(gasFees.maxPriorityFeePerGas),
        BigInt(gasFees.maxFeePerGas)
      ),
      paymasterAndData: "0x", // No paymaster
      signature: "0x", // Frontend will sign
    };

    console.log("   UserOp built successfully");
    return { alchemyUserOp, entryPointPackedUserOp };
  }

  async addPaymasterSignature(userOp: UserOperation): Promise<string> {
    console.log("🔏 Adding paymaster signature (v0.7 format)...");

    const validUntil = Math.floor(Date.now() / 1000) + 600; // 10 mins
    const validAfter = 0;

    // 1. Compute userOpHash using EntryPoint contract
    const entryPoint = new ethers.Contract(
      this.entryPointAddress,
      EntryPointABI,
      this.provider
    );
    const userOpHash = await entryPoint.getUserOpHash(userOp);

    // 2. Compute paymaster hash according to ERC-4337 v0.7
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const paymasterHash = ethers.keccak256(
      abiCoder.encode(
        ["bytes32", "uint48", "uint48", "address"],
        [userOpHash, validUntil, validAfter, this.paymasterAddress]
      )
    );

    // 3. Sign it with your paymaster private key
    const signature = await this.paymasterSigner.signMessage(
      ethers.getBytes(paymasterHash)
    );

    // 4. Pack paymasterAndData (address + validity + signature)
    const paymasterAndData = ethers.concat([
      this.paymasterAddress,
      abiCoder.encode(["uint48", "uint48"], [validUntil, validAfter]),
      signature,
    ]);

    console.log("✅ Real paymaster signature added");
    return paymasterAndData;
  }

  // async addPaymasterSignatureV7(
  //   userOp: UserOperation // Must be PackedUserOperation format!
  // ): Promise<string> {
  //   console.log("🔏 Adding paymaster signature (v0.7 format)...");

  //   const validUntil = Math.floor(Date.now() / 1000) + 600; // 10 mins
  //   const validAfter = 0;

  //   // 1. Unpack gas limits and fees from the packed UserOp
  //   const { verificationGasLimit, callGasLimit } = unpackAccountGasLimits(
  //     userOp.accountGasLimits
  //   );
  //   const { maxPriorityFeePerGas, maxFeePerGas } = unpackGasFees(
  //     userOp.gasFees
  //   );

  //   // 2. Get chainId
  //   const network = await this.provider.getNetwork();
  //   const chainId = network.chainId;

  //   // 3. Create the SAME hash that the contract expects
  //   // This MUST match your contract's getHash() function exactly!
  //   const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  //   const paymasterHash = ethers.keccak256(
  //     abiCoder.encode(
  //       [
  //         "address", // sender
  //         "uint256", // nonce
  //         "uint256", // callGasLimit (unpacked)
  //         "uint256", // verificationGasLimit (unpacked)
  //         "uint256", // preVerificationGas
  //         "uint256", // maxFeePerGas (unpacked)
  //         "uint256", // maxPriorityFeePerGas (unpacked)
  //         "uint256", // chainId
  //         "address", // paymaster address
  //         "uint48", // validUntil
  //         "uint48", // validAfter
  //       ],
  //       [
  //         userOp.sender,
  //         userOp.nonce,
  //         callGasLimit,
  //         verificationGasLimit,
  //         userOp.preVerificationGas,
  //         maxFeePerGas,
  //         maxPriorityFeePerGas,
  //         chainId,
  //         this.paymasterAddress,
  //         validUntil,
  //         validAfter,
  //       ]
  //     )
  //   );

  //   console.log("   Paymaster Hash:", paymasterHash);
  //   console.log("   Parameters used:");
  //   console.log("     Sender:", userOp.sender);
  //   console.log("     Nonce:", userOp.nonce);
  //   console.log("     CallGasLimit:", callGasLimit.toString());
  //   console.log("     VerificationGasLimit:", verificationGasLimit.toString());
  //   console.log("     PreVerificationGas:", userOp.preVerificationGas);
  //   console.log("     MaxFeePerGas:", maxFeePerGas.toString());
  //   console.log("     MaxPriorityFeePerGas:", maxPriorityFeePerGas.toString());
  //   console.log("     ChainId:", chainId.toString());
  //   console.log("     Paymaster:", this.paymasterAddress);
  //   console.log("     ValidUntil:", validUntil);
  //   console.log("     ValidAfter:", validAfter);

  //   // 4. Sign with Ethereum signed message prefix
  //   const signature = await this.paymasterSigner.signMessage(
  //     ethers.getBytes(paymasterHash)
  //   );

  //   console.log("   Signature:", signature);

  //   // 5. Pack paymasterData (NOT including paymaster address)
  //   // Format: [64 bytes: validUntil + validAfter encoded][65 bytes: signature]
  //   const paymasterData = ethers.concat([
  //     abiCoder.encode(["uint48", "uint48"], [validUntil, validAfter]),
  //     signature,
  //   ]);

  //   console.log("✅ Paymaster data created");
  //   console.log("   Length:", (paymasterData.length - 2) / 2, "bytes");
  //   console.log("   PaymasterData:", paymasterData);

  //   return paymasterData;
  // }

  async addPaymasterSignatureV7(userOp: UserOperation): Promise<string> {
    console.log("\n🔏 Adding paymaster signature (v0.7 format)...");

    const validUntil = Math.floor(Date.now() / 1000) + 600; // 10 mins
    const validAfter = 0;

    console.log("Timing:");
    console.log("  ValidUntil:", validUntil);
    console.log("  ValidAfter:", validAfter);

    // CRITICAL: Calculate the ACTUAL UserOpHash from EntryPoint
    // This is the hash that includes ALL UserOp fields
    const entryPoint = new ethers.Contract(
        this.entryPointAddress,
        EntryPointABI,
        this.provider
    );
    
    const userOpHash = await entryPoint.getUserOpHash(userOp);
    console.log("  UserOpHash from EntryPoint:", userOpHash);

    // Now create the paymaster hash according to ERC-4337 v0.7
    // This should match what your paymaster contract expects
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    
    // The paymaster signs over: keccak256(abi.encode(userOpHash, validUntil, validAfter))
    const paymasterHash = ethers.keccak256(
        abiCoder.encode(
            ["bytes32", "uint48", "uint48"],
            [userOpHash, validUntil, validAfter]
        )
    );

    console.log("  Paymaster Hash:", paymasterHash);

    // Sign with Ethereum signed message prefix
    const signature = await this.paymasterSigner.signMessage(
        ethers.getBytes(paymasterHash)
    );

    console.log("  Signature:", signature);
    console.log("  Signer address:", await this.paymasterSigner.getAddress());

    // Verify signature locally
    const ethSignedHash = ethers.hashMessage(ethers.getBytes(paymasterHash));
    const recoveredAddress = ethers.recoverAddress(ethSignedHash, signature);
    console.log("  Recovered address:", recoveredAddress);
    console.log("  Signature valid:", recoveredAddress.toLowerCase() === (await this.paymasterSigner.getAddress()).toLowerCase() ? "✅ YES" : "❌ NO");

    // Pack paymasterData: [validUntil + validAfter (64 bytes)][signature (65 bytes)]
    const paymasterData = ethers.concat([
        abiCoder.encode(["uint48", "uint48"], [validUntil, validAfter]),
        signature,
    ]);

    console.log("\n✅ PaymasterData created");
    console.log("   Length:", (paymasterData.length - 2) / 2, "bytes");
    console.log("   Expected: 64 (encoded times) + 65 (signature) = 129 bytes");

    return paymasterData;
}

  async testPaymasterSignature(packedUserOp: UserOperation, paymasterData: string) {
    console.log("\n🧪 Testing Paymaster Signature On-Chain...");

    const paymaster = new ethers.Contract(
        this.paymasterAddress,
        PayMasterABI,
        this.provider
    );

    // Parse paymasterData
    const abiCoder = ethers.AbiCoder.defaultAbiCoder();
    const validUntil = Math.floor(Date.now() / 1000) + 600;
    const validAfter = 0;
    
    const paymasterDataHex = paymasterData.slice(2);
    const signature = "0x" + paymasterDataHex.slice(128); // Skip 64 bytes of encoded times

    console.log("Parsed:");
    console.log("  ValidUntil:", validUntil);
    console.log("  ValidAfter:", validAfter);
    console.log("  Signature:", signature);

    try {
        const [isValid, recoveredSigner] = await paymaster.testSignature(
            packedUserOp,
            validUntil,
            validAfter,
            signature
        );

        const expectedSigner = await paymaster.verifyingSigner();

        console.log("\nOn-Chain Test Results:");
        console.log("  Signature valid:", isValid ? "✅ YES" : "❌ NO");
        console.log("  Recovered signer:", recoveredSigner);
        console.log("  Expected signer:", expectedSigner);
        console.log("  Match:", recoveredSigner.toLowerCase() === expectedSigner.toLowerCase() ? "✅ YES" : "❌ NO");

        if (!isValid) {
            console.error("\n❌ SIGNATURE VERIFICATION FAILED ON-CHAIN!");
        }
    } catch (error: any) {
        console.error("\n❌ testSignature call failed:", error.message);
    }
  }

  async verifyUserOpHash(packedUserOp: UserOperation, expectedOwner: string) {
    // 🔍 DEBUG: Log what we're hashing on backend
    console.log("\n🔍 DEBUG - Backend UserOp for Hashing:");
    console.log("  Format check:");
    console.log("    Has accountGasLimits:", "accountGasLimits" in packedUserOp);
    console.log("    Has callGasLimit:", "callGasLimit" in packedUserOp);
    console.log("\n  Values:");
    console.log("    sender:", packedUserOp.sender);
    console.log("    nonce:", packedUserOp.nonce);
    console.log("    initCode:", packedUserOp.initCode);
    console.log("    callData:", packedUserOp.callData.slice(0, 50) + "...");
    console.log("    accountGasLimits:", packedUserOp.accountGasLimits);
    console.log("    preVerificationGas:", packedUserOp.preVerificationGas);
    console.log("    gasFees:", packedUserOp.gasFees);
    console.log("    paymasterAndData:", packedUserOp.paymasterAndData);

    
    const entryPoint = new ethers.Contract(
        this.entryPointAddress,
        EntryPointABI,
        this.provider
    );

    // Calculate hash on backend
    const backendHash = await entryPoint.getUserOpHash(packedUserOp);
    
    console.log("\n🔍 UserOpHash Verification:");
    console.log("  Backend calculated hash:", backendHash);
    
    // Check if account is deployed
    const accountCode = await this.provider.getCode(packedUserOp.sender);
    const isDeployed = accountCode !== "0x";
    
    console.log("  Account deployed:", isDeployed ? "YES ✅" : "NO (will deploy) ⏳");
    
    // Verify the signature
    const ethSignedHash = ethers.hashMessage(ethers.getBytes(backendHash));
    
    try {
        const recoveredAddress = ethers.recoverAddress(ethSignedHash, packedUserOp.signature);
        
        console.log("  Recovered signer:", recoveredAddress);
        console.log("  Expected owner:", expectedOwner);
        
        let actualOwner = expectedOwner;
        
        if (isDeployed) {
            // Account exists - verify owner on-chain
            const account = new ethers.Contract(
                packedUserOp.sender,
                ["function owner() view returns (address)"],
                this.provider
            );
            
            try {
                actualOwner = await account.owner();
                console.log("  Actual owner (on-chain):", actualOwner);
            } catch (error) {
                console.log("  ⚠️  Could not read owner from contract, using expected owner");
            }
        } else {
            console.log("  Expected owner (from DB):", expectedOwner);
            console.log("  ⏳ Account will be deployed with initCode");
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
  async submitUserOperation(userOp: AlchemyUserOperationV7): Promise<string> {
    return await this.bundler.sendUserOperation(userOp);
  }

  async checkPaymasterDepositDetailed() {
    const entryPoint = new ethers.Contract(
        this.entryPointAddress,
        ["function balanceOf(address) view returns (uint256)"],
        this.provider
    );

    const paymaster = new ethers.Contract(
        this.paymasterAddress,
        ["function paymasterDeposit() view returns (uint256)"],
        this.provider
    );

    const entryPointBalance = await entryPoint.balanceOf(this.paymasterAddress);
    const paymasterViewBalance = await paymaster.paymasterDeposit();

    console.log("\n💰 Paymaster Deposit Check:");
    console.log("  EntryPoint.balanceOf(paymaster):", ethers.formatEther(entryPointBalance), "ETH");
    console.log("  paymaster.paymasterDeposit():", ethers.formatEther(paymasterViewBalance), "ETH");
    console.log("  Match:", entryPointBalance === paymasterViewBalance ? "✅" : "❌");

    return entryPointBalance;
}

  /**
   * Wait for transaction confirmation
   */
  async waitForConfirmation(userOpHash: string): Promise<any> {
    return await this.bundler.waitForUserOperationReceipt(userOpHash);
  }

  // Recovery helpers
  private encryptRecoveryData(data: string, userId: string): string {
    // const key = crypto.scryptSync(process.env.RECOVERY_ENCRYPTION_KEY!, userId, 32);
    // const iv = crypto.randomBytes(16);
    // const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    // let encrypted = cipher.update(data, 'utf8', 'hex');
    // encrypted += cipher.final('hex');

    // const authTag = cipher.getAuthTag();

    // return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;

    const masterKey = process.env.RECOVERY_ENCRYPTION_KEY!;

    // Generate a random salt for this specific user’s encryption
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
    // const parts = encryptedData.split(':');
    // const iv = Buffer.from(parts[0], 'hex');
    // const authTag = Buffer.from(parts[1], 'hex');
    // const encrypted = parts[2];

    // const key = crypto.scryptSync(process.env.RECOVERY_ENCRYPTION_KEY!, userId, 32);
    // const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    // decipher.setAuthTag(authTag);

    // let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    // decrypted += decipher.final('utf8');

    // return JSON.parse(decrypted);

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


  // In your submitTransaction controller, after receiving the UserOp:




}
