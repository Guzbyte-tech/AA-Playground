import { ethers } from 'ethers';
import axios from 'axios';

export interface UserOperationV6 {
    sender: string;
    nonce: string;
    initCode: string;
    callData: string;
    callGasLimit: string;
    verificationGasLimit: string;
    preVerificationGas: string;
    maxFeePerGas: string;
    maxPriorityFeePerGas: string;
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


export class BundlerService {
    private bundlerUrl: string;
    private bundlerType: string;
    private entryPoint: string;

    constructor() {
        this.bundlerUrl = process.env.BUNDLER_URL!;
        this.bundlerType = process.env.BUNDLER_TYPE || 'alchemy';
        this.entryPoint = process.env.ENTRYPOINT_ADDRESS!;
    }

    /**
     * Send UserOperation to bundler
     */
    async sendUserOperation(userOp: UserOperationV6): Promise<string> {
        console.log('Sending UserOp to bundler...');
        console.log('Bundler:', this.bundlerType);
        console.log('Sender:', userOp.sender);

        try {
            const cleanedUserOp = this.cleanUserOpForAlchemy(userOp);

            console.log("\n📤 Sending to Alchemy:");
            console.log("   Original nonce:", userOp.nonce);
            console.log("   Cleaned nonce:", cleanedUserOp.nonce);
            console.log("   Original signature length:", userOp.signature.length);
            console.log("   Cleaned signature length:", cleanedUserOp.signature.length);
            console.log("   PaymasterAndData length:", (cleanedUserOp.paymasterAndData.length - 2) / 2, "bytes");
            console.log("\n   Full UserOp being sent:");
            console.log(JSON.stringify(cleanedUserOp, null, 2));
            const response = await axios.post(
                this.bundlerUrl,
                {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_sendUserOperation',
                    params: [cleanedUserOp, this.entryPoint]
                },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );

            if (((response.data as any) as any).error) {
                // Log the complete error object
                console.error('Full bundler error for send Operation:', JSON.stringify((response.data as any).error, null, 2));

                // The error.data field often contains the revert reason
                if ((response.data as any).error.data) {
                    console.error('Error data:', (response.data as any).error.data);
                }
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
     * Get UserOperation receipt (wait for confirmation)
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

            if (receipt) {
                console.log('✅ UserOp confirmed!');
                console.log('   TxHash:', receipt.transactionHash);
                console.log('   Block:', receipt.blockNumber);
                return receipt;
            }

            await new Promise(resolve => setTimeout(resolve, 2000));
        }

        throw new Error('UserOperation timeout');
    }

    /**
     * Estimate UserOperation gas
     */
    async estimateUserOperationGasOld(userOp: any): Promise<{
        preVerificationGas: string;
        verificationGasLimit: string;
        callGasLimit: string;
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
                throw new Error(`Gas estimation failed: ${(response.data as any).error.message}`);
            }
            console.log((response.data as any).result);
            return (response.data as any).result;
        } catch (error: any) {
            console.error('Gas estimation error:', error.response?.data || error.message);
            throw error;
        }
    }

    async estimateUserOperationGas(userOp: any): Promise<{
        preVerificationGas: string;
        verificationGasLimit: string;
        callGasLimit: string;
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
            // Log the complete error object
            console.error('Full bundler error:', JSON.stringify((response.data as any).error, null, 2));
            
            // The error.data field often contains the revert reason
            if ((response.data as any).error.data) {
                console.error('Error data:', (response.data as any).error.data);
            }
            
            throw new Error(`Gas estimation failed: ${(response.data as any).error.message}`);
        }
        
        return (response.data as any).result;
    } catch (error: any) {
        // Log everything we can get
        if (error.response?.data) {
            console.error('Response error data:', JSON.stringify(error.response.data, null, 2));
        }
        console.error('Full error object:', error);
        throw error;
    }
    }

    async getMaxPriorityFeePerGas(): Promise<{
        maxPriorityFeePerGas: string;
    }> {
        try {
            const response = await axios.post(
                this.bundlerUrl,
                {
                    jsonrpc: '2.0',
                    method: 'rundler_maxPriorityFeePerGas',
                    params: [],
                    id: 1,
                },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );

            if ((response.data as any).error) {
                throw new Error(`maxPriorityFeePerGas failed: ${(response.data as any).error.message}`);
            }
            console.log((response.data as any).result);
            return {
                maxPriorityFeePerGas: (response.data as any).result
            }
        } catch (error: any) {
            console.error('maxPriorityFeePerGas error:', error.response?.data || error.message);
            throw error;
        }
    }

     async getMaxPriorityFeePerGas_v2(): Promise<{
        maxPriorityFeePerGas: bigint;
    }> {
        try {
            const response = await axios.post(
                this.bundlerUrl,
                {
                    jsonrpc: '2.0',
                    method: 'rundler_maxPriorityFeePerGas',
                    params: [],
                    id: 1,
                },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );

            if ((response.data as any).error) {
                throw new Error(`maxPriorityFeePerGas failed: ${(response.data as any).error.message}`);
            }
            console.log((response.data as any).result);
            // return (response.data as any).result;
            return {
                maxPriorityFeePerGas: (response.data as any).result
            }
        } catch (error: any) {
            console.error('maxPriorityFeePerGas error:', error.response?.data || error.message);
            throw error;
        }
    }

    /**
     * Get gas prices from bundler
     */
    // async getGasFees(): Promise<{
    //     maxFeePerGas: string;
    //     maxPriorityFeePerGas: string;
    // }> {
    //     const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
    //     const feeData = await provider.getFeeData();

    //     return {
    //         maxFeePerGas: '0x' + feeData.maxFeePerGas?.toString(16) || '0x0',
    //         maxPriorityFeePerGas: '0x' + feeData.maxPriorityFeePerGas?.toString(16) || '0x0'
    //     };
    // }

    async getGasFees(): Promise<{
    maxFeePerGas: string;
    maxPriorityFeePerGas: string;
}> {
    const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
    const feeData = await provider.getFeeData();

    // Get current network fees
    const currentMaxFeePerGas = feeData.maxFeePerGas || 0n;
    const currentMaxPriorityFee = feeData.maxPriorityFeePerGas || 0n;

    // IMPORTANT: Add buffer and ensure minimum for bundler
    // Bundlers often require higher fees than the network minimum
    const MIN_MAX_FEE_PER_GAS = 100_000_000_000n; // 100 gwei minimum
    const MIN_PRIORITY_FEE = 1_000_000_000n;      // 1 gwei minimum

    // Add 20% buffer to network fees
    const bufferedMaxFee = (currentMaxFeePerGas * 120n) / 100n;
    const bufferedPriorityFee = (currentMaxPriorityFee * 120n) / 100n;

    // Use the higher of: (buffered network fee) or (minimum required)
    const finalMaxFeePerGas = bufferedMaxFee > MIN_MAX_FEE_PER_GAS 
        ? bufferedMaxFee 
        : MIN_MAX_FEE_PER_GAS;
    
    const finalMaxPriorityFee = bufferedPriorityFee > MIN_PRIORITY_FEE
        ? bufferedPriorityFee
        : MIN_PRIORITY_FEE;

    console.log("Gas Fee Calculation:");
    console.log("  Network maxFeePerGas:", ethers.formatUnits(currentMaxFeePerGas, "gwei"), "gwei");
    console.log("  Network maxPriorityFee:", ethers.formatUnits(currentMaxPriorityFee, "gwei"), "gwei");
    console.log("  Final maxFeePerGas:", ethers.formatUnits(finalMaxFeePerGas, "gwei"), "gwei");
    console.log("  Final maxPriorityFee:", ethers.formatUnits(finalMaxPriorityFee, "gwei"), "gwei");

    return {
        maxFeePerGas: ethers.toBeHex(finalMaxFeePerGas),
        maxPriorityFeePerGas: ethers.toBeHex(finalMaxPriorityFee)
    };
}


  /**
   * Clean UserOp for Alchemy
   * Alchemy is VERY strict about hex formatting
   */
  private cleanUserOpForAlchemy(userOp: UserOperationV6): UserOperationV6 {
    return {
      sender: this.cleanHex(userOp.sender),
      nonce: this.cleanHexNumber(userOp.nonce),
      initCode: this.cleanHex(userOp.initCode),
      callData: this.cleanHex(userOp.callData),
      callGasLimit: this.cleanHexNumber(userOp.callGasLimit),
      verificationGasLimit: this.cleanHexNumber(userOp.verificationGasLimit),
      preVerificationGas: this.cleanHexNumber(userOp.preVerificationGas),
      maxFeePerGas: this.cleanHexNumber(userOp.maxFeePerGas),
      maxPriorityFeePerGas: this.cleanHexNumber(userOp.maxPriorityFeePerGas),
      paymasterAndData: this.cleanHex(userOp.paymasterAndData),
      signature: this.cleanHex(userOp.signature),
    };
  }

  /**
   * Clean hex address/bytes (keep leading zeros)
   */
  private cleanHex(value: string): string {
    if (!value || value === "0x") return "0x";
    // Remove 0x, then add it back
    return "0x" + value.slice(2);
  }

  /**
   * Clean hex number (remove leading zeros, except for 0x0)
   */
  private cleanHexNumber(value: string): string {
    if (!value || value === "0x" || value === "0x0" || value === "0x00") {
      return "0x0";
    }
    
    // Remove 0x prefix
    let hex = value.slice(2);
    
    // Remove leading zeros
    hex = hex.replace(/^0+/, "");
    
    // If empty, return 0x0
    if (hex === "") return "0x0";
    
    return "0x" + hex;
  }



}