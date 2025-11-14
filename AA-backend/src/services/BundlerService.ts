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
    async sendUserOperation(userOp: UserOperation): Promise<string> {
        console.log('Sending UserOp to bundler...');
        console.log('Bundler:', this.bundlerType);
        console.log('Sender:', userOp.sender);

        try {
            const response = await axios.post(
                this.bundlerUrl,
                {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_sendUserOperation',
                    params: [userOp, this.entryPoint]
                },
                {
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );

            if (((response.data as any) as any).error) {
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
            // return (response.data as any).result;
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
    async getGasFees(): Promise<{
        maxFeePerGas: string;
        maxPriorityFeePerGas: string;
    }> {
        const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
        const feeData = await provider.getFeeData();

        return {
            maxFeePerGas: '0x' + feeData.maxFeePerGas?.toString(16) || '0x0',
            maxPriorityFeePerGas: '0x' + feeData.maxPriorityFeePerGas?.toString(16) || '0x0'
        };
    }
}