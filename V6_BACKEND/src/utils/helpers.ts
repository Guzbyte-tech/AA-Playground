import { ValidationError } from "class-validator";
import { IValidationFormatResult } from "../interfaces/IValidateErrorFormat";
import { ethers } from "ethers";
import { randomBytes } from "crypto";
import FactoryABI from "../abis/FactoryABI.json";
import crypto from "crypto";
import ERC1967ProxyBytecode from "../abis/ERC1967ProxyBytecode";

export function formatValidationErrors(
  errors: ValidationError[]
): IValidationFormatResult {
  const fields: Record<string, string> = {};
  const message: string[] = [];

  for (const err of errors) {
    const constraints = err.constraints || {};
    const messages = Object.values(constraints);

    if (messages.length > 0) {
      fields[err.property] = messages[0];
      message.push(...messages);
    }
  }

  return {
    success: false,
    fields,
    message,
  };
}

/**
 * Generate random salt for CREATE2
 */
export function generateRandomSalt(): { saltHex: string; saltBigInt: bigint } {
  const buf = randomBytes(32);
  const saltHex = "0x" + buf.toString("hex");
  const saltBigInt = BigInt("0x" + buf.toString("hex"));
  return { saltHex, saltBigInt };
}

/**
 * Predict counterfactual smart account address using CREATE2
 */
export async function predictSmartAccountAddress(
  provider: ethers.JsonRpcProvider,
  factoryAddress: string,
  owner: string,
  saltNumber?: number
): Promise<{ predictedAddress: string; salt: string; salt_BigInt: string }> {
  const factory = new ethers.Contract(factoryAddress, FactoryABI, provider);

  const accountImpl: string = await factory.ACCOUNT_IMPLEMENTATION();

  const iface = new ethers.Interface(["function initialize(address owner)"]);
  const proxyInitData = iface.encodeFunctionData("initialize", [owner]);

  const bytecode = ethers.concat([
    ethers.getBytes(ERC1967ProxyBytecode),
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["address", "bytes"],
      [accountImpl, proxyInitData]
    ),
  ]);

  let salt: string;
  if (saltNumber !== undefined) {
    salt = "0x" + BigInt(saltNumber).toString(16).padStart(64, "0");
  } else {
    salt = "0x" + crypto.randomBytes(32).toString("hex");
  }

  const predictedAddress = ethers.getCreate2Address(
    factoryAddress,
    salt,
    ethers.keccak256(bytecode)
  );

  const salt_BigInt = hexToBigInt(salt).toString();

  return { predictedAddress, salt, salt_BigInt };
}

/**
 * Convert hex string to BigInt
 */
export function hexToBigInt(hexString: string): BigInt {
  try {
    return BigInt(hexString);
  } catch (error) {
    console.error("Invalid hex string provided:", error);
    throw new Error("Failed to convert hex string to BigInt.");
  }
}

/**
 * Extract destination address from callData
 */
export function extractToAddress(callData: string): string {
  try {
    const iface = new ethers.Interface(["function execute(address,uint256,bytes)"]);
    const decoded = iface.decodeFunctionData("execute", callData);
    return decoded[0];
  } catch {
    return "0x0000000000000000000000000000000000000000";
  }
}

/**
 * Extract transfer amount from callData
 */
export function extractAmount(callData: string): string {
  try {
    const executeIface = new ethers.Interface([
      "function execute(address,uint256,bytes)",
    ]);
    const decoded = executeIface.decodeFunctionData("execute", callData);
    const innerCallData = decoded[2];

    const transferIface = new ethers.Interface([
      "function transfer(address,uint256)",
    ]);
    const transferDecoded = transferIface.decodeFunctionData(
      "transfer",
      innerCallData
    );
    return ethers.formatUnits(transferDecoded[1], 18);
  } catch {
    return "0";
  }
}