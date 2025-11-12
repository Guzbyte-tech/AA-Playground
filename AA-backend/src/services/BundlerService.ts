import { ethers } from 'ethers';
import axios from 'axios';

export interface UserOperation {
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
    async estimateUserOperationGas(userOp: UserOperation): Promise<{
        preVerificationGas: string;
        verificationGasLimit: string;
        callGasLimit: string;
    }> {
        try {
            const response = await axios.post(
                this.bundlerUrl,
                {
                    jsonrpc: '2.0',
                    id: 1,
                    method: 'eth_estimateUserOperationGas',
                    params: [userOp, this.entryPoint]
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

            return (response.data as any).result;
        } catch (error: any) {
            console.error('Gas estimation error:', error.response?.data || error.message);
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
        const provider = new ethers.JsonRpcProvider(process.env.RPC_URL);
        const feeData = await provider.getFeeData();

        return {
            maxFeePerGas: feeData.maxFeePerGas?.toString() || '0x0',
            maxPriorityFeePerGas: feeData.maxPriorityFeePerGas?.toString() || '0x0'
        };
    }
}