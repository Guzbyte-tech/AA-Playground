import { ethers, AbiCoder, toBeHex } from "ethers";
import {
  BundlerService,
  UserOperation,
  AlchemyUserOperationV7,
} from "./BundlerService";
import crypto from "crypto";

import FactoryABI from "../abis/FactoryABI.json";

import { EntryPointABI } from "../abis/EntryPointABI";
import dotenv from "dotenv";
// import {  packAccountGasLimits, packGasFees } from '../utils/helpers';
import { max } from "class-validator";
import {
  packAccountGasLimits,
  packGasFees,
  predictSmartAccountAddress,
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
  ): Promise<Partial<UserOperation>> {
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
    const { maxPriorityFeePerGas } =
      await this.bundler.getMaxPriorityFeePerGas_v2();

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
      maxPriorityFeePerGas: ethers.toBeHex(maxPriorityFeePerGas),
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

    // 10. Return final UserOp in unpacked format
    const partialUserOp = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      callData,
      callGasLimit: ethers.toBeHex(finalCallGas),
      verificationGasLimit: ethers.toBeHex(finalVerificationGas),
      preVerificationGas: ethers.toBeHex(finalPreVerificationGas),
      maxFeePerGas: gasFees.maxFeePerGas,
      maxPriorityFeePerGas: ethers.toBeHex(maxPriorityFeePerGas),
      signature: "0x", // Frontend will sign
      ...(isDeployed
        ? {}
        : {
            factory: factory,
            factoryData: factoryData,
          }),
    };

    console.log("   UserOp built successfully");
    return partialUserOp;
  }

  async buildTokenTransferUserOp(
    smartAccountAddress: string,
    ownerAddress: string,
    toAddress: string,
    amount: string,
    isDeployed: boolean,
    salt: string
  ): Promise<Partial<UserOperation>> {
    if (!smartAccountAddress) {
      throw new Error("Smart account address is required");
    }
    console.log("Building UserOp...");

    // -------------------------------
    // 1. Encode token transfer
    // -------------------------------
    const tokenInterface = new ethers.Interface([
      "function transfer(address,uint256) returns (bool)",
    ]);
    const transferData = tokenInterface.encodeFunctionData("transfer", [
      toAddress,
      ethers.parseUnits(amount, 18),
    ]);

    // -------------------------------
    // 2. Encode account.execute()
    // -------------------------------
    const accountInterface = new ethers.Interface([
      "function execute(address,uint256,bytes)",
    ]);
    const callData = accountInterface.encodeFunctionData("execute", [
      process.env.UMC_TOKEN_ADDRESS!,
      0,
      transferData,
    ]);

    // -------------------------------
    // 3. Prepare initCode if account not deployed
    // -------------------------------
    let initCode = "0x";
    if (!isDeployed) {
      const factory = new ethers.Contract(
        this.factoryAddress,
        FactoryABI,
        this.provider
      );
      console.log("Factory Connected Address", await factory.getAddress());
      console.log("Predicting smart account address...");
      const nSalt: bigint = BigInt(salt);
      console.log(salt); // Output: 123456789012345678901234567890n
      console.log(typeof nSalt); // Output: bigint

      // Verify predicted address matches
      const predictedAddress = await factory["getAddress(address,uint256)"](
        ownerAddress,
        nSalt
      );

      console.log("Factory Address: ", this.factoryAddress);
      console.log("Salt:", nSalt);
      console.log("Predicted Address:", predictedAddress);
      console.log("Owner Address: ", ownerAddress);

      this.init();

      if (
        predictedAddress.toLowerCase() !== smartAccountAddress.toLowerCase()
      ) {
        throw new Error(
          `Address mismatch! Predicted: ${predictedAddress}, Expected: ${smartAccountAddress}`
        );
      }

      const createAccountCallData = (
        factory as any
      ).interface.encodeFunctionData("createAccount", [
        ownerAddress,
        ethers.toBigInt(salt),
      ]);

      // initCode = factory address (20 bytes) + createAccount calldata
      initCode = ethers.concat([this.factoryAddress, createAccountCallData]);

      // const initCode = this.factoryAddress + createAccountCallData.slice(2);

      console.log("   Account not deployed, initCode added");
      console.log("   Factory:", this.factoryAddress);
      console.log("   InitCode:", initCode);
    }

    // -------------------------------
    // 4. Get nonce from EntryPoint
    // -------------------------------
    const entryPoint = new ethers.Contract(
      this.entryPointAddress,
      EntryPointABI,
      this.provider
    );
    const nonce = await entryPoint.getNonce(smartAccountAddress, 0);

    // -------------------------------
    // 5. Get gas info from bundler
    // -------------------------------
    const gasFees = await this.bundler.getGasFees();
    const { maxPriorityFeePerGas } =
      await this.bundler.getMaxPriorityFeePerGas_v2();

    console.log("   Gas Fees:");
    console.log("   Max Fee Per Gas:", gasFees.maxFeePerGas);
    console.log(
      "   Max Priority Fee Per Gas:",
      maxPriorityFeePerGas.toString()
    );
    console.log("   Nonce:", nonce.toString());

    // -------------------------------
    // 6. Set preliminary gas values (INCREASED for estimation)
    // -------------------------------
    const callGasLimit = 2_000_000n;
    const verificationGasLimit = isDeployed ? 150_000n : 1_000_000n; // Higher if deploying
    const preVerificationGas = 100_000n;

    const accountGasLimits = this.packAccountGasLimits(
      verificationGasLimit,
      callGasLimit
    );
    const packedGasFees = this.packGasFees(
      ethers.toBigInt(maxPriorityFeePerGas),
      ethers.toBigInt(gasFees.maxFeePerGas)
    );

    // -------------------------------
    // 7. Build preliminary UserOp for gas estimation
    // -------------------------------
    // const dummySignature =
    //   "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c";
    const dummySignature = "0x" + "00".repeat(65);

    const preliminaryUserOp = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      initCode,
      callData,
      accountGasLimits,
      preVerificationGas: ethers.toBeHex(preVerificationGas),
      gasFees: packedGasFees,
      paymasterAndData: "0x", // Empty for estimation
      signature: dummySignature,
    };

    console.log("   Preliminary UserOp:");
    console.log(JSON.stringify(preliminaryUserOp, null, 2));

    // -------------------------------
    // 8. Estimate gas via bundler
    // -------------------------------
    let gasLimits;
    try {
      gasLimits = await this.bundler.estimateUserOperationGas(
        preliminaryUserOp
      );
      console.log("   Gas Limits:");
      console.log("   Call Gas:", gasLimits.callGasLimit);
      console.log("   Verification Gas:", gasLimits.verificationGasLimit);
      console.log("   PreVerification Gas:", gasLimits.preVerificationGas);
    } catch (error: any) {
      console.error("Gas estimation failed:", error);
      // If estimation fails, use fallback values
      gasLimits = {
        callGasLimit: ethers.toBeHex(callGasLimit),
        verificationGasLimit: ethers.toBeHex(verificationGasLimit),
        preVerificationGas: ethers.toBeHex(preVerificationGas),
      };
    }

    // Update accountGasLimits with actual estimated gas (add 20% buffer)
    const finalCallGas =
      (ethers.toBigInt(gasLimits.callGasLimit) * 120n) / 100n;
    const finalVerificationGas =
      (ethers.toBigInt(gasLimits.verificationGasLimit) * 120n) / 100n;
    const finalPreVerificationGas =
      (ethers.toBigInt(gasLimits.preVerificationGas) * 120n) / 100n;

    const finalAccountGasLimits = this.packAccountGasLimits(
      finalVerificationGas,
      finalCallGas
    );

    // -------------------------------
    // 9. Build partial UserOp for frontend to sign
    // -------------------------------
    const partialUserOp: Partial<UserOperation> = {
      sender: smartAccountAddress,
      nonce: ethers.toBeHex(nonce),
      initCode,
      callData,
      accountGasLimits: finalAccountGasLimits,
      preVerificationGas: ethers.toBeHex(finalPreVerificationGas),
      gasFees: packedGasFees,
      paymasterAndData: "0x", // backend adds paymaster signature on submit
      signature: "0x", // frontend signs
    };

    console.log("   UserOp built successfully");
    return partialUserOp;
  }

  /**
   * Build UserOperation for token transfer
   * Device will sign this UserOp
   */
  async buildTokenTransferUserOpOld(
    smartAccountAddress: string,
    ownerAddress: string,
    toAddress: string,
    amount: string,
    isDeployed: boolean,
    salt: any
  ): Promise<Partial<UserOperation>> {
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

    // Predicted Address
    const dummySignature =
      "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" +
      "1c";

    // 3. Get initCode if not deployed
    let initCode = "0x";
    if (!isDeployed) {
      // Will be filled by frontend with factory.createAccount()
      // console.log('   Account not deployed, will deploy on first tx');
      const factory = new ethers.Contract(
        this.factoryAddress,
        FactoryABI,
        this.provider
      );
      const predictedAddress = await (factory as any).getAddress(
        ownerAddress,
        salt
      );
      console.log("   Predicted Address:", predictedAddress);
      console.log("   SmartWallet:", smartAccountAddress);
      // const salt = 0; // default, or pass from frontend if needed
      initCode = ethers.concat([
        this.factoryAddress,
        (factory as any).interface.encodeFunctionData("createAccount", [
          ownerAddress,
          ethers.toBigInt(salt),
        ]),
      ]);
      console.log("   Account not deployed, initCode added for deployment");
    }

    // 4. Get nonce
    const entryPoint = new ethers.Contract(
      this.entryPointAddress,
      EntryPointABI,
      this.provider
    );
    const nonce =
      "0x" + (await entryPoint.getNonce(smartAccountAddress, 0)).toString(16);

    // 5. Get gas prices
    const gasFees = await this.bundler.getGasFees();
    // const {maxPriorityFeePerGas} = await this.bundler.getMaxPriorityFeePerGas();
    const { maxPriorityFeePerGas } =
      await this.bundler.getMaxPriorityFeePerGas_v2();

    console.log("   Gas Fees:");
    console.log("   Max Fee Per Gas:", gasFees.maxFeePerGas);
    console.log("   Max Priority Fee Per Gas:", maxPriorityFeePerGas);
    console.log("   Nonce", nonce);

    const callGasLimit = 1_000_000n;
    const verificationGasLimit = 100_000n;
    const preVerificationGas = 21_000n;

    const accountGasLimits = packAccountGasLimits(
      verificationGasLimit,
      callGasLimit
    );
    const pgasFees = packGasFees(
      maxPriorityFeePerGas,
      ethers.toBigInt(gasFees.maxFeePerGas)
    );

    // 6. Build preliminary UserOp (needed for gas estimation)
    const preliminaryUserOp = {
      sender: smartAccountAddress,
      nonce,
      initCode,
      callData,
      // callGasLimit: toBeHex(ethers.parseUnits("1000000", 0)),
      // verificationGasLimit: toBeHex(ethers.parseUnits("100000", 0)),
      accountGasLimits,
      preVerificationGas: toBeHex(ethers.parseUnits("21000", 0)),
      // maxFeePerGas: toBeHex(gasFees.maxFeePerGas),
      // // maxFeePerGas: '0x',
      // maxPriorityFeePerGas: toBeHex(maxPriorityFeePerGas),
      // // maxPriorityFeePerGas: '0x',
      // paymasterAndData: '0x',
      gasFees: pgasFees,
      // signature: '0x',
      signature: dummySignature,
    };

    console.log("   Preliminary UserOp:", preliminaryUserOp);

    // 7. Estimate gas via bundler
    const gasLimits = await this.bundler.estimateUserOperationGas(
      preliminaryUserOp
    );

    console.log("   Gas Limits:");
    console.log("   Call Gas Limit:", gasLimits.callGasLimit.toString());
    console.log(
      "   Verification Gas Limit:",
      gasLimits.verificationGasLimit.toString()
    );
    console.log(
      "   Pre-Verification Gas:",
      gasLimits.preVerificationGas.toString()
    );

    // 6. Build partial UserOp (device will complete and sign)
    const partialUserOp: Partial<UserOperation> = {
      ...preliminaryUserOp,
      accountGasLimits,
      preVerificationGas: gasLimits.preVerificationGas.toString(),
      gasFees: pgasFees,
      // sender: smartAccountAddress,
      // nonce,
      // initCode,
      // callData,
      // callGasLimit: gasLimits.callGasLimit.toString(),
      // verificationGasLimit: gasLimits.verificationGasLimit.toString(),
      // preVerificationGas: gasLimits.preVerificationGas.toString(),
      // maxFeePerGas: gasFees.maxFeePerGas,
      // maxPriorityFeePerGas: maxPriorityFeePerGas.toString(),
      // paymasterAndData: '0x', // backend adds paymaster signature on submit
      // signature: '0x' // frontend signs
    };

    console.log("   UserOp built successfully");
    return partialUserOp;
  }

  /**
   * Add paymaster signature to sponsor gas
   * This is what backend does - sponsors the transaction!
   */
  // async addPaymasterSignature(userOp: UserOperation): Promise<string> {
  //     console.log('🔏 Adding paymaster signature...');

  //     const validUntil = Math.floor(Date.now() / 1000) + 600; // 10 minutes
  //     const validAfter = 0;

  //     // Create hash to sign
  //     const abiCoder = AbiCoder.defaultAbiCoder();
  //     const hash = ethers.keccak256(
  //         abiCoder.encode(
  //             ['address', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'uint256', 'address', 'uint48', 'uint48'],
  //             [
  //                 userOp.sender,
  //                 userOp.nonce,
  //                 userOp.callGasLimit,
  //                 userOp.verificationGasLimit,
  //                 userOp.preVerificationGas,
  //                 userOp.maxFeePerGas,
  //                 userOp.maxPriorityFeePerGas,
  //                 this.chainId,
  //                 this.paymasterAddress,
  //                 validUntil,
  //                 validAfter
  //             ]
  //         )
  //     );

  //     // Sign with paymaster signer
  //     const signature = await this.paymasterSigner.signMessage(
  //         ethers.getBytes(hash)
  //     );
  //     // Pack paymasterAndData
  //     const paymasterAndData = ethers.concat([
  //         this.paymasterAddress,
  //         abiCoder.encode(['uint48', 'uint48'], [validUntil, validAfter]),
  //         signature
  //     ]);

  //     console.log('   ✅ Gas sponsored!');
  //     return paymasterAndData;
  // }

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

  /**
   * Submit UserOperation to bundler
   */
  async submitUserOperation(userOp: UserOperation): Promise<string> {
    return await this.bundler.sendUserOperation(userOp);
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
}
