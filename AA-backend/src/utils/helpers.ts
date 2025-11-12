import { ValidationError } from "class-validator";
import { IValidationFormatResult } from "../interfaces/IValidateErrorFormat";
import { UserOperation } from "../services/BundlerService";
import { ethers } from "ethers";

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
  // high 128 bits: verificationGasLimit, low 128 bits: callGasLimit
  return ethers.toBeHex((verificationGasLimit << 128n) | callGasLimit, 32);
}

export function packGasFees(
  maxPriorityFeePerGas: bigint,
  maxFeePerGas: bigint
): string {
  // high 128 bits: maxPriorityFeePerGas, low 128 bits: maxFeePerGas
  return ethers.toBeHex((maxPriorityFeePerGas << 128n) | maxFeePerGas, 32);
}