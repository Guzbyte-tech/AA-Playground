import { ValidationError } from "class-validator";
import { IValidationFormatResult } from "../interfaces/IValidateErrorFormat";
import { UserOperation } from "../services/BundlerService";
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