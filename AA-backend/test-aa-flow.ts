import { EntryPointABI } from './src/abis/EntryPointABI';
import  FactoryABI  from "./src/abis/FactoryABI.json";
import { AbiCoder, ethers, HDNodeWallet, Wallet } from "ethers";
import axios from "axios";
import chalk from "chalk";
import dotenv from "dotenv";
import ERC1967ProxyBytecode from "./src/abis/ERC1967ProxyBytecode";
import crypto from "crypto";
import fs from 'fs';
import path from "path";


dotenv.config();

// Configuration
const config = {
  backendUrl: "http://localhost:4000",
  rpcUrl: process.env.SEPOLIA_RPC_URL!,
  entryPoint: process.env.ENTRYPOINT_ADDRESS!,
  factory: process.env.FACTORY_ADDRESS!,
  paymaster: process.env.PAYMASTER_ADDRESS!,
  token: process.env.UMC_TOKEN_ADDRESS!,
  chainId: 11155111, // Sepolia
  provider: new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL!),
};

interface PackedUserOperation {
  sender: string;
  nonce: string;
  initCode: string;
  callData: string;
  accountGasLimits: string; // bytes32
  preVerificationGas: string;
  gasFees: string; // bytes32
  paymasterAndData: string;
  signature: string;
}

export interface UserOperation {
    sender: string;
    nonce: string;
    initCode: string;
    callData: string;

    // Packed fields (bytes32)
    accountGasLimits: string; // = (verificationGasLimit << 128) | callGasLimit
    preVerificationGas: string;
    gasFees: string; // = (maxPriorityFeePerGas << 128) | maxFeePerGas

    paymasterAndData: string;
    signature: string;
}

export interface AlchemyUserOperationV7 {
  sender: string;
  nonce: string;
  initCode?: string;
  callData: string;
  callGasLimit: string;
  verificationGasLimit: string;
  preVerificationGas: string;
  maxFeePerGas: string;
  maxPriorityFeePerGas: string;
  signature: string;
  factory?: string; // Only if account needs deployment
  factoryData?: string; // Only if account needs deployment
  paymaster?: string; // Only if using paymaster
  paymasterData?: string;
  paymasterVerificationGasLimit?: string;
  paymasterPostOpGasLimit?: string;
}

// ============================================
// 1. DEVICE KEY SIMULATION (Simulates Mobile)
// ============================================

class DeviceKeyManager {
  // private wallet: ethers.Wallet;
  private wallet: Wallet | HDNodeWallet;
  private keystorePath: string;


  constructor(username?: string) {
    this.keystorePath = path.join(__dirname, '.keys', `${username || 'default'}.json`);


    // Try to load existing key
    if (fs.existsSync(this.keystorePath)) {
      console.log(chalk.blue("\n📱 Loading Existing Device Key"));
      const keyData = JSON.parse(fs.readFileSync(this.keystorePath, 'utf8'));
      this.wallet = new ethers.Wallet(keyData.privateKey);
      console.log("Public Key:", chalk.green(this.wallet.address));
    } else {
      // Generate new key
      console.log(chalk.blue("\n📱 Generating New Device Key"));
      this.wallet = Wallet.createRandom();
      console.log("Private Key:", chalk.gray(this.wallet.privateKey));
      console.log("Public Key:", chalk.green(this.wallet.address));
      
      // Save key
      this.saveKey();
    }

    // In real app, this is generated in device secure enclave
    // this.wallet = Wallet.createRandom();
    // console.log(chalk.blue("\n📱 Device Key Generated"));
    // console.log("Private Key:", chalk.gray(this.wallet.privateKey));
    // console.log("Public Key:", chalk.green(this.wallet.address));
  }

  private saveKey() {
    const keyData = {
      privateKey: this.wallet.privateKey,
      address: this.wallet.address
    };
    
    // Create .keys directory if it doesn't exist
    const dir = path.dirname(this.keystorePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(this.keystorePath, JSON.stringify(keyData, null, 2));
    console.log(chalk.gray("   Key saved to:", this.keystorePath));
  }

  // This is also the wallet Address
  getPublicKey(): string {
    return this.wallet.address;
  }

  async signUserOp(userOpHash: string): Promise<string> {
    const signature = await this.wallet.signMessage(
      ethers.getBytes(userOpHash)
    );
    
    console.log(chalk.blue("\n🔏 Signed UserOp"));
    console.log("   Signature:", chalk.gray(signature.slice(0, 20) + "..."));
    return signature;
  }

  // Return full wallet instance including private key
  getWallet(): Wallet | HDNodeWallet {
    return this.wallet;
  }
}

// ============================================
// 2. API CLIENT
// ============================================

class AAClient {
  private baseUrl: string;
  private token: string | null = null;
  private deviceKey: DeviceKeyManager | null = null;
  private username: string | null = null;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private async request(method: string, endpoint: string, data?: any) {
    try {
      const response = await axios({
        method,
        url: `${this.baseUrl}${endpoint}`,
        data,
        headers: {
          "Content-Type": "application/json",
          ...(this.token && { Authorization: `Bearer ${this.token}` }),
        },
      });
      return response.data;
    } catch (error: any) {
      console.error(error);
      console.error(
        chalk.red("❌ API Error:"),
        error.response?.data || error.message
      );
      throw error;
    }
  }

  // Register user
  async register(username: string, email: string, password: string) {
    try {
      console.log(chalk.yellow("\n📝 Registering User..."));
      console.log("   Username:", username);
      console.log("   Email:", email);

      // Device generates everything locally
      this.username = username;
      this.deviceKey = new DeviceKeyManager(username);
      const ownerWalletAddress = this.deviceKey.getPublicKey();
      // const salt = Math.floor(Math.random() * 1000000);
      // const { predictedAddress, salt, salt_BigInt } = await predictSmartAccountAddress(config.provider, config.factory, ownerWalletAddress);

      // Generate decrypting key (for recovery)
      const decryptingKey = ethers.Wallet.createRandom().privateKey;

      // console.log(chalk.blue("\n📱 Device Generated:"));
      // console.log("   Owner Wallet:", ownerWalletAddress);
      // console.log("   Salt Hex:", salt);
      // console.log("   Salt Decimal:", salt_BigInt);
      // console.log(
      //   "   Decrypting Key:",
      //   chalk.gray(decryptingKey.slice(0, 20) + "...")
      // );

      // // Calculate counterfactual address locally (optional verification)
      // // const factory = new Contract(
      // //   config.factory,
      // //   FactoryABI,
      // //   new ethers.JsonRpcProvider(config.rpcUrl)
      // // );

      // // const counterfactualAddress = await (factory as any).getAddress(
      // //   ownerWalletAddress,
      // //   ethers.toBigInt(salt)
      // // );
      // const counterfactualAddress = predictedAddress;
      // console.log("   Counterfactual Address:", counterfactualAddress);

      const response = await this.request("POST", "/api/auth/register", {
        username,
        email,
        password,
        ownerWalletAddress,
        decryptingKey,
      });

      this.token = response.data.token;
      console.log(chalk.green("✅ Registration Successful"));
      console.log("   Smart Account:", response.data.user.smartAccountAddress);
      console.log("   Deployed:", response.data.user.isAccountDeployed);

      return response.data;
    } catch (error: any) {
      console.error("Error registering user:", error);
    }
  }

  // Login user
  async login(username: string, password: string) {
    console.log(chalk.yellow("\n🔐 Logging In..."));

    this.username = username;
    this.deviceKey = new DeviceKeyManager(username);

    const response = await this.request("POST", "/api/auth/login", {
      username,
      password,
    });

    this.token = response.data.token;
    console.log(chalk.green("✅ Login Successful"));
    console.log("   Smart Account:", response.data.user.smartAccountAddress);

    return response.data;
  }

  // Get profile
  async getProfile() {
    console.log(chalk.yellow("\n👤 Fetching Profile..."));

    const response = await this.request("GET", "/api/auth/profile");

    console.log(chalk.green("✅ Profile Retrieved"));
    console.log("   Username:", response.data.user.username);
    console.log("   Smart Account:", response.data.user.smartAccountAddress);
    console.log("   Balance:", response.data.user.balance || "0");

    return response.data;
  }

  // Build UserOp for transaction
  async buildUserOp(to: string, amount: string): Promise<{
    packedUserOp: UserOperation;
    alchemyUserOp : AlchemyUserOperationV7;
  }> {
    console.log(chalk.yellow("\n🔨 Building UserOperation..."));
    console.log("   To:", to);
    console.log("   Amount:", amount);

    const response = await this.request("POST", "/api/transactions/build", {
      to,
      amount,
    });

    console.log(chalk.green("✅ UserOp Built"));
    console.log("BUILDD", response.data);
    return {
      packedUserOp: response.data.packedUserOp,    // Changed from response.data.userOp
      alchemyUserOp: response.data.alchemyUserOp 
    }
    // return response.data.userOp;
  }

  // Sign and submit transaction
 async sendTransaction(to: string, amount: string) {
    if (!this.deviceKey) {
        throw new Error("Device key not initialized. Please login first.");
    }
    console.log(chalk.yellow("\n💸 Sending Transaction..."));

    // Step 1: Build UserOp (backend adds paymaster)
    const { packedUserOp, alchemyUserOp } = await this.buildUserOp(to, amount);
    
    // Step 2: Calculate hash (includes paymaster now!)
    const userOpHash = await this.calculateUserOpHashFromContract(packedUserOp);
    console.log("   UserOp Hash:", chalk.gray(userOpHash));

    // Step 3: Sign
    const signature = await this.deviceKey.signUserOp(userOpHash);
    
    // Add signature to both
    packedUserOp.signature = signature;
    alchemyUserOp.signature = signature;

    // Step 4: Submit
    console.log(chalk.yellow("\n📤 Submitting to Backend..."));
    const response = await this.request("POST", "/api/transactions/submit", {
        packedUserOp: packedUserOp,
        alchemyUserOp: alchemyUserOp
    });

    console.log(chalk.green("✅ Transaction Submitted"));
    return response.data;
}

  // Sign and submit transaction
  async buildUserOperation(to: string, amount: string) {
    console.log(chalk.yellow("\n💸 Sending Transaction..."));

    // Step 1: Build UserOp
    const {packedUserOp, alchemyUserOp} = await this.buildUserOp(to, amount);

   

    return packedUserOp;
  }
  // Get transaction status
  async getTransactionStatus(userOpHash: string) {
    console.log(chalk.yellow("\n🔍 Checking Transaction Status..."));

    const response = await this.request(
      "GET",
      `/api/transactions/status/${userOpHash}`
    );

    const status = response.data.transaction.status;
    const color =
      status === "confirmed"
        ? chalk.green
        : status === "failed"
        ? chalk.red
        : chalk.yellow;

    console.log(color(`   Status: ${status.toUpperCase()}`));
    if (response.data.transaction.txHash) {
      console.log("   TxHash:", response.data.transaction.txHash);
    }

    return response.data;
  }

private async calculateUserOpHashFromContract(
    userOp: UserOperation
  ): Promise<string> {
    const entryPoint = new ethers.Contract(
      config.entryPoint,
      EntryPointABI,
      config.provider
    );

    const userOpHash = await entryPoint.getUserOpHash(userOp);
    return userOpHash;
}

  // Wait for transaction confirmation
  async waitForConfirmation(userOpHash: string, timeout: number = 60000) {
    console.log(chalk.yellow("\n⏳ Waiting for Confirmation..."));

    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      const response = await this.getTransactionStatus(userOpHash);
      const status = response.transaction.status;

      if (status === "confirmed") {
        console.log(chalk.green("\n🎉 Transaction Confirmed!"));
        return response;
      } else if (status === "failed") {
        console.log(chalk.red("\n❌ Transaction Failed!"));
        return response;
      }

      await new Promise((resolve) => setTimeout(resolve, 3000));
    }

    console.log(chalk.red("\n⏰ Transaction Timeout"));
    throw new Error("Transaction timeout");
  }
}

// ============================================
// 3. COMPLETE FLOW SIMULATION
// ============================================

async function runCompleteFlow() {
  console.log(
    chalk.bold.cyan("\n╔════════════════════════════════════════════╗")
  );
  console.log(chalk.bold.cyan("║   ACCOUNT ABSTRACTION FLOW SIMULATION     ║"));
  console.log(
    chalk.bold.cyan("╚════════════════════════════════════════════╝\n")
  );

  try {
    // Initialize client
    const client = new AAClient(config.backendUrl);

    // ═══════════════════════════════════════════
    // SCENARIO 1: NEW USER REGISTRATION
    // ═══════════════════════════════════════════
    console.log(chalk.bold.magenta("\n━━━ SCENARIO 1: User Registration ━━━"));

    const alice = await client.register(
      "alice_" + Date.now(),
      "alice@example.com",
      "SecurePassword123!"
    );

    console.log(chalk.bold.green("\n✓ Alice registered successfully!"));

    // ═══════════════════════════════════════════
    // SCENARIO 2: LOGIN
    // ═══════════════════════════════════════════
    console.log(chalk.bold.magenta("\n━━━ SCENARIO 2: User Login ━━━"));

    await client.login(alice.user.username, "SecurePassword123!");
    console.log(chalk.bold.green("\n✓ Alice logged in!"));

    // ═══════════════════════════════════════════
    // SCENARIO 3: GET PROFILE
    // ═══════════════════════════════════════════
    console.log(chalk.bold.magenta("\n━━━ SCENARIO 3: Get Profile ━━━"));

    await client.getProfile();
    console.log(chalk.bold.green("\n✓ Profile retrieved!"));

    // ═══════════════════════════════════════════
    // SCENARIO 4: SEND TRANSACTION
    // ═══════════════════════════════════════════
    console.log(chalk.bold.magenta("\n━━━ SCENARIO 4: Send Transaction ━━━"));

    const guzAddress = "0x06d97198756295a96c2158a23963306f507b2f69"; // Example
    const result = await client.sendTransaction(guzAddress, "10");

    console.log(chalk.bold.green("\n✓ Transaction submitted!"));

    // ═══════════════════════════════════════════
    // SCENARIO 5: WAIT FOR CONFIRMATION
    // ═══════════════════════════════════════════
    console.log(
      chalk.bold.magenta("\n━━━ SCENARIO 5: Wait for Confirmation ━━━")
    );

    await client.waitForConfirmation(result.userOpHash);

    console.log(chalk.bold.green("\n✓ Transaction confirmed!"));

    // ═══════════════════════════════════════════
    // FINAL SUMMARY
    // ═══════════════════════════════════════════
    console.log(
      chalk.bold.cyan("\n╔════════════════════════════════════════════╗")
    );
    console.log(
      chalk.bold.cyan("║          SIMULATION COMPLETED!             ║")
    );
    console.log(
      chalk.bold.cyan("╚════════════════════════════════════════════╝\n")
    );

    console.log(chalk.green("✅ All scenarios passed successfully!"));
    console.log(chalk.gray("\nWhat happened:"));
    console.log(
      chalk.gray("  1. Alice created account (device key generated)")
    );
    console.log(
      chalk.gray("  2. Smart account address created (counterfactual)")
    );
    console.log(chalk.gray("  3. Alice logged in"));
    console.log(chalk.gray("  4. Alice sent 10 tokens to Bob"));
    console.log(chalk.gray("  5. Backend sponsored gas (paymaster)"));
    console.log(chalk.gray("  6. Bundler submitted to blockchain"));
    console.log(
      chalk.gray("  7. Smart account deployed + transaction executed")
    );
    console.log(chalk.gray("  8. Transaction confirmed!"));
  } catch (error: any) {
    console.error(chalk.bold.red("\n\n❌ SIMULATION FAILED"));
    console.error(chalk.red(error.message));
    process.exit(1);
  }
}

// ============================================
// 4. INDIVIDUAL TEST SCENARIOS
// ============================================

async function testRegistration() {
  console.log(chalk.bold.cyan("\n🧪 Testing: Registration\n"));

  const client = new AAClient(config.backendUrl);
  await client.register(
    "test_" + Date.now(),
    "test@example.com",
    "TestPassword123!"
  );

  console.log(chalk.green("\n✅ Registration test passed!"));
}

async function testLogin() {
  console.log(chalk.bold.cyan("\n🧪 Testing: Login\n"));

  const client = new AAClient(config.backendUrl);

  // First register
  const user = await client.register(
    "test_" + Date.now(),
    "test@example.com",
    "TestPassword123!"
  );

  // Then login
  await client.login(user.user.username, "TestPassword123!");

  console.log(chalk.green("\n✅ Login test passed!"));
}

async function testTransaction() {
  console.log(chalk.bold.cyan("\n🧪 Testing: Transaction\n"));

  const client = new AAClient(config.backendUrl);

  // Register
//   await client.register(
//       'test_' + Date.now(),
//       'test@example.com',
//       'TestPassword123!'
//   );
  
    await client.login("test_1763417219003", "TestPassword123!");

  // Send transaction
  const result = await client.sendTransaction(
    // '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
    "0x06d97198756295a96c2158a23963306f507b2f69",
    "5"
  );

  // Wait for confirmation
  await client.waitForConfirmation(result.userOpHash);

  console.log(chalk.green("\n✅ Transaction test passed!"));
}

async function testBuildUserOperation() {
    console.log(chalk.bold.cyan("\n🧪 Testing: Building User Operation\n"));

    const client = new AAClient(config.backendUrl);
    // const user = await client.register(
    //     "test_" + Date.now(),
    //     "test@example.com",
    //     "TestPassword123!"
    // );
    await client.login("test_1763417219003", "TestPassword123!");

    const result = await client.buildUserOperation(
        // '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
        "0x06d97198756295a96c2158a23963306f507b2f69",
        "5"
    )
    console.log(result);
    console.log(chalk.green("\n✅ Successfully built User Operation!"));

    // await client.waitForConfirmation(result.userOpHash);
}

// ============================================
// 5. CLI INTERFACE
// ============================================

const args = process.argv.slice(2);
const command = args[0];

(async () => {
  try {
    switch (command) {
      case "full":
        await runCompleteFlow();
        break;
      case "register":
        await testRegistration();
        break;
      case "login":
        await testLogin();
        break;
      case "transaction":
        await testTransaction();
        break;
      case "buildUserOperation":
        await testBuildUserOperation();
        break;
      default:
        console.log(chalk.yellow("\nUsage:"));
        console.log(
          "  ts-node test-aa-flow.ts full         - Run complete flow"
        );
        console.log(
          "  ts-node test-aa-flow.ts register     - Test registration"
        );
        console.log("  ts-node test-aa-flow.ts login        - Test login");
        console.log(
          "  ts-node test-aa-flow.ts transaction  - Test transaction"
        );
        break;
    }
  } catch (error) {
    console.error(chalk.red("\n❌ Test failed:"), error);
    process.exit(1);
  }
})();


export async function predictSmartAccountAddress(
  provider: ethers.JsonRpcProvider,
  factoryAddress: string,
  owner: string,
  saltNumber?: number
): Promise<{ predictedAddress: string; salt: string, salt_BigInt: any }> {
  // 1️⃣ Connect to the factory contract (read-only)
  const factory = new ethers.Contract(factoryAddress, FactoryABI, provider);

  // 2️⃣ Get the account implementation contract
  const accountImpl: string = await factory.ACCOUNT_IMPLEMENTATION();

  // 3️⃣ Encode initialize calldata
  const iface = new ethers.Interface(["function initialize(address owner)"]);
  const proxyInitData = iface.encodeFunctionData("initialize", [owner]);

  // 5️⃣ Construct full CREATE2 init code
  const bytecode = ethers.concat([
    ethers.getBytes(ERC1967ProxyBytecode),
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "bytes"],
      [accountImpl, proxyInitData]
    ),
  ]);

  // 6️⃣ Generate salt
  let salt: string;
  if (saltNumber !== undefined) {
    // deterministic numeric salt
    salt = "0x" + BigInt(saltNumber).toString(16).padStart(64, "0");
  } else {
    // random 32-byte salt
    salt = "0x" + crypto.randomBytes(32).toString("hex");
  }

  // 7️⃣ Compute predicted CREATE2 address
  const predictedAddress = ethers.getCreate2Address(
    factoryAddress,
    salt,
    ethers.keccak256(bytecode)
  );

    const salt_BigInt = hexToBigInt(salt).toString();
  

  return { predictedAddress, salt, salt_BigInt};
}

export function hexToBigInt(hexString: string): BigInt {
  // The BigInt constructor handles the '0x' prefix automatically
  try {
    return BigInt(hexString);
  } catch (error) {
    console.error("Invalid hex string provided:", error);
    throw new Error("Failed to convert hex string to BigInt.");
  }
}