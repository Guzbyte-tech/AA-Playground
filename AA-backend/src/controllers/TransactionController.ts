import { Response } from 'express';
import { User } from '../entities/User';
import { Transaction, TxStatus } from '../entities/Transaction';
import { AAService } from '../services/AAService';
import { AuthRequest } from '../middlewares/auth.middleware';
import AppDataSource from '../config/db';

export class TransactionController {
    private aaService: AAService;

    constructor() {
        this.aaService = new AAService();
    }

    async init() {
        await this.aaService.init();
    }

    /**
     * Step 1: Frontend requests UserOp template
     * Backend builds it and adds paymaster signature
     */
    buildUserOp = async (req: AuthRequest, res: Response) => {
        try {
            const { to, amount } = req.body;
            const user = req.user!;

            console.log('Building UserOp for transfer');
            console.log('From:', user.smartAccountAddress);
            console.log('To:', to);
            console.log('Amount:', amount);

            // Build UserOp (unsigned)
            const partialUserOp = await this.aaService.buildTokenTransferUserOp(
                user.smartAccountAddress,
                to,
                amount,
                user.isAccountDeployed
            );
            res.json({
                success: true,
                data: {
                    userOp: partialUserOp,
                    message: 'Sign this UserOp on your device and send back'
                }
            });
        } catch (error: any) {
            console.error('Build UserOp error:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to build UserOp',
                details: error.message
            });
        }
    };

    /**
     * Step 2: Frontend signs UserOp and sends back
     * Backend adds paymaster signature and submits to bundler
     */
    submitTransaction = async (req: AuthRequest, res: Response) => {
        try {
            const { userOp } = req.body;
            const user = req.user!;

            console.log('\n Submitting transaction');
            console.log('From:', user.smartAccountAddress);
            console.log('Nonce:', userOp.nonce);

            // Verify userOp sender matches user
            if (userOp.sender.toLowerCase() !== user.smartAccountAddress.toLowerCase()) {
                return res.status(400).json({
                    success: false,
                    error: 'UserOp sender mismatch'
                });
            }

            // Add paymaster signature (backend sponsors gas!)
            const paymasterAndData = await this.aaService.addPaymasterSignature(userOp);
            userOp.paymasterAndData = paymasterAndData;

            console.log('Gas sponsored by paymaster');

            // Submit to bundler
            const userOpHash = await this.aaService.submitUserOperation(userOp);

            console.log('Submitted to bundler');
            console.log('UserOpHash:', userOpHash);

            // Save transaction
            const txRepo = AppDataSource.getRepository(Transaction);
            const transaction = txRepo.create({
                userOpHash,
                fromAddress: user.smartAccountAddress,
                toAddress: userOp.callData, // Parse actual recipient from callData
                amount: '0', // Parse from callData
                status: TxStatus.PENDING,
                user
            });

            await txRepo.save(transaction);

            // Update deployment status if first transaction
            if (!user.isAccountDeployed) {
                const userRepo = AppDataSource.getRepository(User);
                user.isAccountDeployed = true;
                await userRepo.save(user);
                console.log('   🎉 Account deployed!');
            }

            // Monitor transaction in background
            this.monitorTransaction(userOpHash);

            res.json({
                success: true,
                data: {
                    userOpHash,
                    status: 'pending',
                    message: 'Transaction submitted to bundler'
                }
            });
        } catch (error: any) {
            console.error('Submit transaction error:', error);
            res.status(500).json({
                success: false,
                error: 'Failed to submit transaction',
                details: error.message
            });
        }
    };

    /**
     * Get transaction status
     */
    getTransactionStatus = async (req: AuthRequest, res: Response) => {
        try {
            const { userOpHash } = req.params;

            const txRepo = AppDataSource.getRepository(Transaction);
            const transaction = await txRepo.findOne({
                where: { userOpHash }
            });

            if (!transaction) {
                return res.status(404).json({
                    success: false,
                    error: 'Transaction not found'
                });
            }

            res.json({
                success: true,
                data: { transaction }
            });
        } catch (error: any) {
            res.status(500).json({
                success: false,
                error: 'Failed to get transaction status'
            });
        }
    };

    /**
     * Monitor transaction confirmation
     */
    private async monitorTransaction(userOpHash: string) {
        try {
            console.log('\n⏳ Monitoring transaction:', userOpHash);

            const receipt = await this.aaService.waitForConfirmation(userOpHash);

            const txRepo = AppDataSource.getRepository(Transaction);
            const transaction = await txRepo.findOne({
                where: { userOpHash }
            });

            if (transaction) {
                transaction.status = receipt.success ? TxStatus.CONFIRMED : TxStatus.FAILED;
                transaction.txHash = receipt.transactionHash;
                transaction.blockNumber = parseInt(receipt.blockNumber);
                await txRepo.save(transaction);

                console.log('Transaction confirmed!');
                console.log('TxHash:', receipt.transactionHash);
                console.log('Block:', receipt.blockNumber);
            }
        } catch (error) {
            console.error('❌ Transaction monitoring failed:', error);
        }
    }
}