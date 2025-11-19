import { ValidationError } from "class-validator";
import { IValidationFormatResult } from "../interfaces/IValidateErrorFormat";
import { AlchemyUserOperationV7, UserOperation } from "../services/BundlerService";
import { ethers } from "ethers";
import { randomBytes } from "crypto";
import FactoryABI from "../abis/FactoryABI.json";
import crypto from "crypto";
import ERC1967ProxyBytecode from "../abis/ERC1967ProxyBytecode";

export function formatValidationErrors(errors: ValidationError[]): IValidationFormatResult {
    const fields: Record<string, string> = {};
    const message: string[] = [];

    for (const err of errors) {
        const constraints = err.constraints || {};
        const messages = Object.values(constraints);

        if (messages.length > 0) {
            fields[err.property] = messages[0]; // First message per field
            message.push(...messages);         // All messages for `message` array
        }
    }

    return {
        success: false,
        fields,
        message
    };
}

// export function serializeUserOp(userOp: Partial<UserOperation>) {
//     return {
//         ...userOp,
//         nonce: userOp.nonce != null && typeof userOp.nonce === 'bigint' ? String(userOp.nonce) : userOp.nonce,
//         callGasLimit: typeof userOp.callGasLimit === 'bigint' ? ethers.toBeHex(userOp.callGasLimit) : userOp.callGasLimit,
//         verificationGasLimit: typeof userOp.verificationGasLimit === 'bigint' ? ethers.toBeHex(userOp.verificationGasLimit) : userOp.verificationGasLimit,
//         preVerificationGas: typeof userOp.preVerificationGas === 'bigint' ? ethers.toBeHex(userOp.preVerificationGas) : userOp.preVerificationGas,
//         maxFeePerGas: typeof userOp.maxFeePerGas === 'bigint' ? ethers.toBeHex(userOp.maxFeePerGas) : userOp.maxFeePerGas,
//         maxPriorityFeePerGas: typeof userOp.maxPriorityFeePerGas === 'bigint' ? ethers.toBeHex(userOp.maxPriorityFeePerGas) : userOp.maxPriorityFeePerGas
//     };
// }

// export function serializePremilinaryUserOp(userOp: Partial<UserOperation>) {
//     return {
//         ...userOp,
//         nonce: userOp.nonce != null && typeof userOp.nonce === 'bigint' ? String(userOp.nonce) : userOp.nonce,
//         callGasLimit: typeof userOp.callGasLimit === 'bigint' ? ethers.toBeHex(userOp.callGasLimit) : userOp.callGasLimit,
//         verificationGasLimit: typeof userOp.verificationGasLimit === 'bigint' ? ethers.toBeHex(userOp.verificationGasLimit) : userOp.verificationGasLimit,
//         preVerificationGas: typeof userOp.preVerificationGas === 'bigint' ? ethers.toBeHex(userOp.preVerificationGas) : userOp.preVerificationGas,
//         maxFeePerGas: typeof userOp.maxFeePerGas === 'bigint' ? ethers.toBeHex(userOp.maxFeePerGas) : userOp.maxFeePerGas,
//         maxPriorityFeePerGas: typeof userOp.maxPriorityFeePerGas === 'bigint' ? ethers.toBeHex(userOp.maxPriorityFeePerGas) : userOp.maxPriorityFeePerGas
//     };
// }


export function packAccountGasLimits(
  verificationGasLimit: bigint,
  callGasLimit: bigint
): string {
  // Ensure we return a clean hex string with single 0x prefix
  const packed = (verificationGasLimit << 128n) | callGasLimit;
  return ethers.toBeHex(packed, 32);
}

export function packGasFees(
  maxPriorityFeePerGas: bigint,
  maxFeePerGas: bigint
): string {
  // Ensure we return a clean hex string with single 0x prefix
  const packed = (maxPriorityFeePerGas << 128n) | maxFeePerGas;
  return ethers.toBeHex(packed, 32);
}
export function generateRandomSalt(): { saltHex: string; saltBigInt: bigint } {
  const buf = randomBytes(32);        // 32 bytes = 256 bits
  const saltHex = "0x" + buf.toString("hex");
  const saltBigInt = BigInt("0x" + buf.toString("hex"));
  return { saltHex, saltBigInt };
} 


/**
 * Predicts a counterfactual smart account address
 * @param provider - ethers provider
 * @param factoryAddress - deployed AccountFactory address
 * @param owner - owner wallet address of the smart account
 * @param saltNumber - optional numeric salt; if omitted, generates a random one
 * @returns predicted smart account address and salt used
 */
export async function predictSmartAccountAddress(
  provider: ethers.JsonRpcProvider,
  factoryAddress: string,
  owner: string,
  saltNumber?: number
): Promise<{ predictedAddress: string; salt: string; salt_BigInt: string }> {
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

  return { predictedAddress, salt, salt_BigInt };
}


/**
 * Converts a hexadecimal string to a BigInt.
 * @param hexString The hexadecimal string (must start with '0x' or '0X').
 * @returns The value as a BigInt.
 */
export function hexToBigInt(hexString: string): BigInt {
  // The BigInt constructor handles the '0x' prefix automatically
  try {
    return BigInt(hexString);
  } catch (error) {
    console.error("Invalid hex string provided:", error);
    throw new Error("Failed to convert hex string to BigInt.");
  }
}

export function unpackAccountGasLimits(accountGasLimits: string): {
  verificationGasLimit: bigint;
  callGasLimit: bigint;
} {
  const hex = accountGasLimits.slice(2); // Remove 0x
  const verificationGasLimitHex = hex.slice(0, 32); // First 16 bytes
  const callGasLimitHex = hex.slice(32, 64); // Last 16 bytes

  return {
    verificationGasLimit: BigInt("0x" + verificationGasLimitHex),
    callGasLimit: BigInt("0x" + callGasLimitHex),
  };
}

export function unpackGasFees(gasFees: string): {
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
} {
  const hex = gasFees.slice(2); // Remove 0x
  const maxPriorityFeePerGasHex = hex.slice(0, 32); // First 16 bytes
  const maxFeePerGasHex = hex.slice(32, 64); // Last 16 bytes

  return {
    maxPriorityFeePerGas: BigInt("0x" + maxPriorityFeePerGasHex),
    maxFeePerGas: BigInt("0x" + maxFeePerGasHex),
  };
}

// ========================================
// BACKEND: Helper - Extract To Address
// ========================================

export function extractToAddress(callData: string): string {
    try {
        // callData format: execute(address dest, uint256 value, bytes data)
        const iface = new ethers.Interface([
            "function execute(address,uint256,bytes)"
        ]);
        const decoded = iface.decodeFunctionData("execute", callData);
        console.log("decoded: ", decoded);
        return decoded[0]; // dest address
    } catch {
        return "0x0000000000000000000000000000000000000000";
    }
}

// ========================================
// BACKEND: Helper - Extract Amount
// ========================================

export function extractAmount(callData: string): string {
    try {
        // Decode execute() to get the inner transfer() call
        const executeIface = new ethers.Interface([
            "function execute(address,uint256,bytes)"
        ]);
        const decoded = executeIface.decodeFunctionData("execute", callData);
        const innerCallData = decoded[2]; // bytes data
        
        // Decode transfer() from innerCallData
        const transferIface = new ethers.Interface([
            "function transfer(address,uint256)"
        ]);
        const transferDecoded = transferIface.decodeFunctionData("transfer", innerCallData);
        return ethers.formatUnits(transferDecoded[1], 18); // amount
    } catch {
        return "0";
    }
}


/**
 * Convert PackedUserOperation back to Alchemy v0.7 unpacked format
 * This is useful when you need to submit to Alchemy bundler after modifying packed format
 */
export function convertToAlchemy(packedUserOp: UserOperation): AlchemyUserOperationV7 {
    // Unpack accountGasLimits (32 bytes = 64 hex chars after 0x)
    // Format: [16 bytes verificationGasLimit][16 bytes callGasLimit]
    const accountGasLimitsHex = packedUserOp.accountGasLimits.slice(2); // Remove 0x
    
    // CRITICAL: Read ONLY 32 hex chars (16 bytes) for each value
    const verificationGasLimitHex = accountGasLimitsHex.slice(0, 32); // First 16 bytes
    const callGasLimitHex = accountGasLimitsHex.slice(32, 64);        // Last 16 bytes
    
    const verificationGasLimit = BigInt("0x" + verificationGasLimitHex);
    const callGasLimit = BigInt("0x" + callGasLimitHex);

    // Unpack gasFees (32 bytes = 64 hex chars after 0x)
    // Format: [16 bytes maxPriorityFeePerGas][16 bytes maxFeePerGas]
    const gasFeesHex = packedUserOp.gasFees.slice(2); // Remove 0x
    
    const maxPriorityFeePerGasHex = gasFeesHex.slice(0, 32); // First 16 bytes
    const maxFeePerGasHex = gasFeesHex.slice(32, 64);        // Last 16 bytes
    
    const maxPriorityFeePerGas = BigInt("0x" + maxPriorityFeePerGasHex);
    const maxFeePerGas = BigInt("0x" + maxFeePerGasHex);

    console.log("\n🔍 Unpacked Gas Values:");
    console.log("  Verification Gas Limit:", verificationGasLimit.toString(), "=", ethers.toBeHex(verificationGasLimit));
    console.log("  Call Gas Limit:", callGasLimit.toString(), "=", ethers.toBeHex(callGasLimit));
    console.log("  Max Priority Fee:", maxPriorityFeePerGas.toString(), "=", ethers.toBeHex(maxPriorityFeePerGas));
    console.log("  Max Fee Per Gas:", maxFeePerGas.toString(), "=", ethers.toBeHex(maxFeePerGas));

    // Unpack initCode
    let factory: string | undefined = undefined;
    let factoryData: string | undefined = undefined;
    if (packedUserOp.initCode && packedUserOp.initCode !== "0x") {
        factory = "0x" + packedUserOp.initCode.slice(2, 42); // 20 bytes = 40 hex chars
        factoryData = "0x" + packedUserOp.initCode.slice(42);
    }

    // Unpack paymasterAndData
    let paymaster: string | undefined = undefined;
    let paymasterVerificationGasLimit: string | undefined = undefined;
    let paymasterPostOpGasLimit: string | undefined = undefined;
    let paymasterData: string | undefined = undefined;

    if (packedUserOp.paymasterAndData && packedUserOp.paymasterAndData !== "0x") {
        const paymasterHex = packedUserOp.paymasterAndData.slice(2);
        
        // [20 bytes paymaster][16 bytes verGas][16 bytes postGas][rest]
        paymaster = "0x" + paymasterHex.slice(0, 40); // 20 bytes
        
        const pmVerGasHex = paymasterHex.slice(40, 72);  // 16 bytes = 32 hex chars
        const pmPostGasHex = paymasterHex.slice(72, 104); // 16 bytes = 32 hex chars
        
        paymasterVerificationGasLimit = ethers.toBeHex(BigInt("0x" + pmVerGasHex));
        paymasterPostOpGasLimit = ethers.toBeHex(BigInt("0x" + pmPostGasHex));
        
        if (paymasterHex.length > 104) {
            paymasterData = "0x" + paymasterHex.slice(104);
        }
    }

    // Build Alchemy UserOp
    const alchemyUserOp: any = {
        sender: packedUserOp.sender,
        nonce: packedUserOp.nonce,
        callData: packedUserOp.callData,
        callGasLimit: ethers.toBeHex(callGasLimit),
        verificationGasLimit: ethers.toBeHex(verificationGasLimit),
        preVerificationGas: packedUserOp.preVerificationGas,
        maxFeePerGas: ethers.toBeHex(maxFeePerGas),
        maxPriorityFeePerGas: ethers.toBeHex(maxPriorityFeePerGas),
        signature: packedUserOp.signature,
    };

    // Add optional fields
    if (factory && factory !== "0x") {
        alchemyUserOp.factory = factory;
        alchemyUserOp.factoryData = factoryData;
    }

    if (paymaster && paymaster !== "0x") {
        alchemyUserOp.paymaster = paymaster;
        alchemyUserOp.paymasterVerificationGasLimit = paymasterVerificationGasLimit;
        alchemyUserOp.paymasterPostOpGasLimit = paymasterPostOpGasLimit;
        alchemyUserOp.paymasterData = paymasterData;
    }

    return alchemyUserOp;
}