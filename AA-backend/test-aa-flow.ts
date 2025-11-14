import  FactoryABI  from "./src/abis/FactoryABI.json";
import { AbiCoder, Contract, ethers, HDNodeWallet, Wallet } from "ethers";
import axios from "axios";
import chalk from "chalk";
import dotenv from "dotenv";
import ERC1967ProxyBytecode from "./src/abis/ERC1967ProxyBytecode";
import crypto from "crypto";


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

// ============================================
// 1. DEVICE KEY SIMULATION (Simulates Mobile)
// ============================================

class DeviceKeyManager {
  // private wallet: ethers.Wallet;
  private wallet: HDNodeWallet;

  constructor() {
    // In real app, this is generated in device secure enclave
    this.wallet = Wallet.createRandom();
    console.log(chalk.blue("\n📱 Device Key Generated"));
    console.log("Private Key:", chalk.gray(this.wallet.privateKey));
    console.log("Public Key:", chalk.green(this.wallet.address));
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
  getWallet(): HDNodeWallet {
    return this.wallet;
  }
}

// ============================================
// 2. API CLIENT
// ============================================

class AAClient {
  private baseUrl: string;
  private token: string | null = null;
  private deviceKey: DeviceKeyManager;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
    this.deviceKey = new DeviceKeyManager();
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
  async buildUserOp(to: string, amount: string) {
    console.log(chalk.yellow("\n🔨 Building UserOperation..."));
    console.log("   To:", to);
    console.log("   Amount:", amount);

    const response = await this.request("POST", "/api/transactions/build", {
      to,
      amount,
    });

    console.log(chalk.green("✅ UserOp Built"));
    return response.data.userOp;
  }

  // Sign and submit transaction
  async sendTransaction(to: string, amount: string) {
    console.log(chalk.yellow("\n💸 Sending Transaction..."));

    // Step 1: Build UserOp
    const userOp = await this.buildUserOp(to, amount);

    // Step 2: Calculate UserOp hash
    const userOpHash = this.calculateUserOpHash(userOp);
    console.log("   UserOp Hash:", chalk.gray(userOpHash));

    // Step 3: Sign with device key
    const signature = await this.deviceKey.signUserOp(userOpHash);
    userOp.signature = signature;

    // Step 4: Submit to backend
    console.log(chalk.yellow("\n📤 Submitting to Backend..."));
    const response = await this.request("POST", "/api/transactions/submit", {
      userOp,
    });

    console.log(chalk.green("✅ Transaction Submitted"));
    console.log("   UserOpHash:", response.data.userOpHash);
    console.log("   Status:", response.data.status);

    return response.data;
  }

  // Sign and submit transaction
  async buildUserOperation(to: string, amount: string) {
    console.log(chalk.yellow("\n💸 Sending Transaction..."));

    // Step 1: Build UserOp
    const userOp = await this.buildUserOp(to, amount);

   

    return userOp;
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

  // Calculate UserOp hash (client-side)
  private calculateUserOpHash(userOp: any): string {
    const provider = new ethers.JsonRpcProvider(config.rpcUrl);

    const abiCoder = AbiCoder.defaultAbiCoder();

    const packed = ethers.keccak256(
      abiCoder.encode(
        [
          "address",
          "uint256",
          "bytes32",
          "bytes32",
          "uint256",
          "uint256",
          "uint256",
          "uint256",
          "uint256",
          "bytes32",
        ],
        [
          userOp.sender,
          userOp.nonce,
          ethers.keccak256(userOp.initCode),
          ethers.keccak256(userOp.callData),
          userOp.callGasLimit,
          userOp.verificationGasLimit,
          userOp.preVerificationGas,
          userOp.maxFeePerGas,
          userOp.maxPriorityFeePerGas,
          ethers.keccak256(userOp.paymasterAndData || "0x"),
        ]
      )
    );

    return ethers.keccak256(
      abiCoder.encode(
        ["bytes32", "address", "uint256"],
        [packed, config.entryPoint, config.chainId]
      )
    );
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
  
    await client.login("test_1763161258489", "TestPassword123!");

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
    await client.login("test_1763161258489", "TestPassword123!");

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

  // // 4️⃣ ERC1967Proxy bytecode (hardcoded or from compiled artifact)
  // const ERC1967ProxyBytecode =
  //   "0x608060405261029d8038038061001481610168565b92833981016040828203126101645781516001600160a01b03811692909190838303610164576020810151906001600160401b03821161016457019281601f8501121561016457835161006e610069826101a1565b610168565b9481865260208601936020838301011161016457815f926020809301865e86010152823b15610152577f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc80546001600160a01b031916821790557fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b5f80a282511561013a575f8091610122945190845af43d15610132573d91610113610069846101a1565b9283523d5f602085013e6101bc565b505b6040516082908161021b8239f35b6060916101bc565b50505034156101245763b398979f60e01b5f5260045ffd5b634c9c8ce360e01b5f5260045260245ffd5b5f80fd5b6040519190601f01601f191682016001600160401b0381118382101761018d57604052565b634e487b7160e01b5f52604160045260245ffd5b6001600160401b03811161018d57601f01601f191660200190565b906101e057508051156101d157805190602001fd5b63d6bda27560e01b5f5260045ffd5b81511580610211575b6101f1575090565b639996b31560e01b5f9081526001600160a01b0391909116600452602490fd5b50803b156101e956fe60806040527f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545f9081906001600160a01b0316368280378136915af43d5f803e156048573d5ff35b3d5ffdfea26469706673582212203d5f7c2fec6b8fd34ebd86e95761dd5d04b25456e0f1a87e2223212a86763f4364736f6c634300081c0033";

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