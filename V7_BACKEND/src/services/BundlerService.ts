import { ethers } from 'ethers';
import axios from 'axios';

// v0.7 UserOperation format (PACKED)
export interface UserOperationV7 {
    sender: string;
    nonce: string;
    factory?: string;              // NEW: separate field
    factoryData?: string;          // NEW: separate field
    callData: string;
    accountGasLimits: string;      // NEW: packed (verificationGasLimit << 128 | callGasLimit)
    preVerificationGas: string;
    gasFees: string;               // NEW: packed (maxPriorityFeePerGas << 128 | maxFeePerGas)
    paymaster?: string;            // NEW: separate field
    paymasterVerificationGasLimit?: string; // NEW
    paymasterPostOpGasLimit?: string;       // NEW
    paymasterData?: string;        // NEW: separate field
    signature: string;
}

// Unpacked format for easier building
export interface UserOperationV7Unpacked {
    sender: string;
    nonce: string;
    factory?: string;
    factoryData?: string;
    callData: string;
    callGasLimit: string;
    verificationGasLimit: string;
    preVerificationGas: string;
    maxFeePerGas: string;
    maxPriorityFeePerGas: string;
    paymaster?: string;
    paymasterVerificationGasLimit?: string;
    paymasterPostOpGasLimit?: string;
    paymasterData?: string;
    signature: string;
}

// Alchemy request format for gas estimation
export interface AlchemyUserOperationRequest {
    sender: string;
    nonce: string;
    factory?: string;
    factoryData?: string;
    callData: string;
    callGasLimit?: string;
    verificationGasLimit?: string;
    preVerificationGas?: string;
    maxFeePerGas?: string;
    maxPriorityFeePerGas?: string;
    signature?: string;
    paymaster?: string;
    paymasterVerificationGasLimit?: string;
    paymasterPostOpGasLimit?: string;
    paymasterData?: string;
}

export class BundlerService {
    private bundlerUrl: string;
    private bundlerType: string;
    private entryPoint: string;
    private policyId: string;

    constructor() {
        this.bundlerUrl = process.env.BUNDLER_URL!;
        this.bundlerType = process.env.BUNDLER_TYPE || 'alchemy';
        this.entryPoint = process.env.ENTRYPOINT_V07_ADDRESS!; // NEW entrypoint address
        this.policyId = process.env.ALCHEMY_POLICY_ID!;
    }

    /**
     * Pack gas limits into single bytes32 value
     * Format: verificationGasLimit (128 bits) | callGasLimit (128 bits)
     */
    packAccountGasLimits(verificationGasLimit: string, callGasLimit: string): string {
        const vgl = BigInt(verificationGasLimit);
        const cgl = BigInt(callGasLimit);
        const packed = (vgl << 128n) | cgl;
        return ethers.toBeHex(packed, 32);
    }

    /**
     * Pack gas fees into single bytes32 value
     * Format: maxPriorityFeePerGas (128 bits) | maxFeePerGas (128 bits)
     */
    packGasFees(maxPriorityFeePerGas: string, maxFeePerGas: string): string {
        const priorityFee = BigInt(maxPriorityFeePerGas);
        const maxFee = BigInt(maxFeePerGas);
        const packed = (priorityFee << 128n) | maxFee;
        return ethers.toBeHex(packed, 32);
    }

    /**
     * Convert unpacked v0.7 UserOp to packed format
     */
    packUserOperation(unpacked: UserOperationV7Unpacked): UserOperationV7 {
        const packed: UserOperationV7 = {
            sender: unpacked.sender,
            nonce: unpacked.nonce,
            callData: unpacked.callData,
            accountGasLimits: this.packAccountGasLimits(
                unpacked.verificationGasLimit,
                unpacked.callGasLimit
            ),
            preVerificationGas: unpacked.preVerificationGas,
            gasFees: this.packGasFees(
                unpacked.maxPriorityFeePerGas,
                unpacked.maxFeePerGas
            ),
            signature: unpacked.signature,
        };

        // Add optional fields if present
        if (unpacked.factory) {
            packed.factory = unpacked.factory;
            packed.factoryData = unpacked.factoryData || '0x';
        }

        if (unpacked.paymaster) {
            packed.paymaster = unpacked.paymaster;
            packed.paymasterVerificationGasLimit = unpacked.paymasterVerificationGasLimit || '0x0';
            packed.paymasterPostOpGasLimit = unpacked.paymasterPostOpGasLimit || '0x0';
            packed.paymasterData = unpacked.paymasterData || '0x';
        }

        return packed;
    }

    /**
     * Request gas and paymaster data from Alchemy (v0.7)
     */
    async requestGasAndPaymasterAndData(userOp: AlchemyUserOperationRequest): Promise<{
        paymasterAndData?: string; // For backward compatibility
        paymaster?: string;
        paymasterData?: string;
        paymasterVerificationGasLimit?: string;
        paymasterPostOpGasLimit?: string;
        callGasLimit: string;
        verificationGasLimit: string;
        preVerificationGas: string;
        maxPriorityFeePerGas: string;
        maxFeePerGas: string;
    }> {
        try {
            console.log('\n🔍 Requesting Alchemy Paymaster (v0.7)...');

            // Build the user operation object - ONLY include fields that have values
            const userOperation: any = {
                sender: userOp.sender,
                nonce: userOp.nonce,
                callData: userOp.callData,
            };

            // Only add factory fields if account needs deployment
            if (userOp.factory && userOp.factory !== '0x' && userOp.factory !== ethers.ZeroAddress) {
                userOperation.factory = userOp.factory;
                userOperation.factoryData = userOp.factoryData || '0x';
            }

            // Add gas estimates if provided
            if (userOp.callGasLimit) {
                userOperation.callGasLimit = userOp.callGasLimit;
            }
            if (userOp.verificationGasLimit) {
                userOperation.verificationGasLimit = userOp.verificationGasLimit;
            }
            if (userOp.preVerificationGas) {
                userOperation.preVerificationGas = userOp.preVerificationGas;
            }
            if (userOp.maxFeePerGas) {
                userOperation.maxFeePerGas = userOp.maxFeePerGas;
            }
            if (userOp.maxPriorityFeePerGas) {
                userOperation.maxPriorityFeePerGas = userOp.maxPriorityFeePerGas;
            }

            console.log('   Sending to Alchemy:', JSON.stringify(userOperation, null, 2));

            const response = await axios.post(
                this.bundlerUrl,
                {
                    jsonrpc: "2.0",
                    method: "alchemy_requestGasAndPaymasterAndData",
                    params: [
                        {
                            webhookData: "example webhook data",
                            policyId: this.policyId,
                            entryPoint: this.entryPoint,
                            dummySignature: "0xfffffffffffffffffffffffffffffff0000000000000000000000000000000007aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c",
                            userOperation: userOperation
                        }
                    ],
                    id: 1
                },
                {
                    headers: {
                        "Content-Type": "application/json"
                    }
                }
            );

            if ((response.data as any).error) {
                console.error(
                    "Alchemy Paymaster Error:",
                    JSON.stringify((response.data as any).error, null, 2)
                );
                throw new Error(
                    `alchemy_requestGasAndPaymasterAndData failed: ${(response.data as any).error.message}`
                );
            }

            console.log('✅ Received Alchemy response');
            console.log('   Response:', JSON.stringify((response.data as any).result, null, 2));
            return (response.data as any).result;

        } catch (error: any) {
            if (error.response?.data) {
                console.error("Response error:", JSON.stringify(error.response.data, null, 2));
            }
            console.error("Full error:", error);
            throw error;
        }
    }

    /**
     * Estimate UserOperation gas (v0.7)
     */
    async estimateUserOperationGas(userOp: AlchemyUserOperationRequest): Promise<{
        preVerificationGas: string;
        verificationGasLimit: string;
        callGasLimit: string;
        paymasterVerificationGasLimit?: string;
        paymasterPostOpGasLimit?: string;
    }> {
        try {
            const response = await axios.post(
                this.bundlerUrl,
                {
                    jsonrpc: '2.0',
                    method: 'eth_estimateUserOperationGas',
                    params: [userOp, this.entryPoint],
                    id: 1,
                },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );

            if ((response.data as any).error) {
                console.error('Gas estimation error:', JSON.stringify((response.data as any).error, null, 2));
                throw new Error(`Gas estimation failed: ${(response.data as any).error.message}`);
            }

            return (response.data as any).result;
        } catch (error: any) {
            if (error.response?.data) {
                console.error('Response error:', JSON.stringify(error.response, null, 2));
            }
            throw error;
        }
    }

    /**
     * Send UserOperation to bundler (v0.7)
     */
    async sendUserOperation(userOp: UserOperationV7Unpacked): Promise<string> {
        console.log('\n📤 Sending UserOp to bundler (v0.7)...');
        console.log('   Sender:', userOp.sender);

        try {
            // const cleanedUserOp = this.cleanUserOpForAlchemy(userOp);

            console.log('\n   Full UserOp being sent:');
            // console.log(JSON.stringify(cleanedUserOp, null, 2));

            const response = await axios.post(
                this.bundlerUrl,
                {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_sendUserOperation',
                    params: [{
                        sender: userOp.sender,
                        nonce: userOp.nonce,
                        callData: userOp.callData,
                        callGasLimit: userOp.callGasLimit,
                        verificationGasLimit: userOp.verificationGasLimit,
                        maxFeePerGas: userOp.maxFeePerGas,
                        maxPriorityFeePerGas: userOp.maxPriorityFeePerGas,
                        paymaster: userOp.paymaster,
                        paymasterData: userOp.paymasterData,
                        paymasterVerificationGasLimit: userOp.paymasterVerificationGasLimit,
                        factory: userOp.factory,
                        factoryData: userOp.factoryData,
                        preVerificationGas: userOp.preVerificationGas,
                        paymasterPostOpGasLimit: userOp.paymasterPostOpGasLimit,
                        signature: userOp.signature,
                    }, this.entryPoint]
                },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );

            if ((response.data as any).error) {
                console.error('Bundler error:', JSON.stringify((response.data as any).error, null, 2));
                throw new Error(`Bundler error: ${(response.data as any).error.message}`);
            }

            const userOpHash = (response.data as any).result;
            console.log('✅ UserOp sent! Hash:', userOpHash);
            return userOpHash;
        } catch (error: any) {
            console.error('❌ Bundler error:', error.response?.data || error.message);
            throw new Error(`Failed to send UserOp: ${error.message}`);
        }
    }

    /**
     * Get UserOperation receipt
     */
    async getUserOperationReceipt(userOpHash: string): Promise<any> {
        try {
            const response = await axios.post(
                this.bundlerUrl,
                {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_getUserOperationReceipt',
                    params: [userOpHash]
                },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );

            return (response.data as any).result;
        } catch (error) {
            return null;
        }
    }

    /**
     * Wait for UserOperation to be mined
     */
    async waitForUserOperationReceipt(
        userOpHash: string,
        timeout: number = 60000
    ): Promise<any> {
        const startTime = Date.now();

        while (Date.now() - startTime < timeout) {
            const receipt = await this.getUserOperationReceipt(userOpHash);
            console.log("    Checking receipt...");
            
            if (receipt) {
                console.log('✅ UserOp confirmed!');
                const txHash = receipt.receipt?.transactionHash;
                const block = receipt.receipt?.blockNumber;

                console.log('   TxHash:', txHash);
                console.log('   Block:', block);
                return receipt;
            }

            await new Promise(resolve => setTimeout(resolve, 2000));
        }

        throw new Error('UserOperation timeout');
    }

    /**
     * Get gas prices
     */
    async getGasFees(): Promise<{
        maxFeePerGas: string;
        maxPriorityFeePerGas: string;
    }> {
        const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
        const feeData = await provider.getFeeData();

        const currentMaxFeePerGas = feeData.maxFeePerGas || 0n;
        const currentMaxPriorityFee = feeData.maxPriorityFeePerGas || 0n;

        const MIN_MAX_FEE_PER_GAS = 100_000_000_000n; // 100 gwei
        const MIN_PRIORITY_FEE = 1_000_000_000n;      // 1 gwei

        const bufferedMaxFee = (currentMaxFeePerGas * 120n) / 100n;
        const bufferedPriorityFee = (currentMaxPriorityFee * 120n) / 100n;

        const finalMaxFeePerGas = bufferedMaxFee > MIN_MAX_FEE_PER_GAS 
            ? bufferedMaxFee 
            : MIN_MAX_FEE_PER_GAS;
        
        const finalMaxPriorityFee = bufferedPriorityFee > MIN_PRIORITY_FEE
            ? bufferedPriorityFee
            : MIN_PRIORITY_FEE;

        console.log("Gas Fee Calculation:");
        console.log("  Network maxFeePerGas:", ethers.formatUnits(currentMaxFeePerGas, "gwei"), "gwei");
        console.log("  Final maxFeePerGas:", ethers.formatUnits(finalMaxFeePerGas, "gwei"), "gwei");
        console.log("  Final maxPriorityFee:", ethers.formatUnits(finalMaxPriorityFee, "gwei"), "gwei");

        return {
            maxFeePerGas: ethers.toBeHex(finalMaxFeePerGas),
            maxPriorityFeePerGas: ethers.toBeHex(finalMaxPriorityFee)
        };
    }

    /**
     * Clean UserOp for Alchemy (v0.7)
     */
    private cleanUserOpForAlchemy(userOp: UserOperationV7): UserOperationV7 {
        const cleaned: UserOperationV7 = {
            sender: this.cleanHex(userOp.sender),
            nonce: this.cleanHexNumber(userOp.nonce),
            callData: this.cleanHex(userOp.callData),
            accountGasLimits: this.cleanHex(userOp.accountGasLimits),
            preVerificationGas: this.cleanHexNumber(userOp.preVerificationGas),
            gasFees: this.cleanHex(userOp.gasFees),
            signature: this.cleanHex(userOp.signature),
        };

        if (userOp.factory) {
            cleaned.factory = this.cleanHex(userOp.factory);
            cleaned.factoryData = this.cleanHex(userOp.factoryData || '0x');
        }

        if (userOp.paymaster) {
            cleaned.paymaster = this.cleanHex(userOp.paymaster);
            cleaned.paymasterVerificationGasLimit = this.cleanHexNumber(userOp.paymasterVerificationGasLimit || '0x0');
            cleaned.paymasterPostOpGasLimit = this.cleanHexNumber(userOp.paymasterPostOpGasLimit || '0x0');
            cleaned.paymasterData = this.cleanHex(userOp.paymasterData || '0x');
        }

        return cleaned;
    }

    private cleanHex(value: string): string {
        if (!value || value === "0x") return "0x";
        return "0x" + value.slice(2);
    }

    private cleanHexNumber(value: string): string {
        if (!value || value === "0x" || value === "0x0" || value === "0x00") {
            return "0x0";
        }
        
        let hex = value.slice(2);
        hex = hex.replace(/^0+/, "");
        
        if (hex === "") return "0x0";
        
        return "0x" + hex;
    }
}
