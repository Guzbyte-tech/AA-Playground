import { ethers } from "ethers";
import { Response } from "express";
import { User } from "../entities/User";
import { Transaction, TxStatus } from "../entities/Transaction";
import { AAService } from "../services/AAService";
import { BundlerService } from "../services/BundlerService";
import { AuthRequest } from "../middlewares/auth.middleware";
import AppDataSource from "../config/db";

import { EntryPointV07ABI } from "../abis/EntryPointV07ABI";
import FactoryABI from "../abis/FactoryABI.json";
import { extractAmount, extractToAddress } from "../utils/helpers";

export class TransactionController {
  private aaService: AAService;
  private bundler: BundlerService;
  private provider: ethers.JsonRpcProvider;
  private entryPointAddress: string;

  constructor() {
    this.aaService = new AAService();
    this.bundler = new BundlerService();
    this.provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL!);
    this.entryPointAddress = process.env.ENTRYPOINT_V07_ADDRESS!;
  }

  async init() {
    await this.aaService.init();
  }

  /**
   * Step 1: Build UserOp template (v0.7 unpacked format)
   */
  buildUserOp = async (req: AuthRequest, res: Response) => {
    try {
      const { to, amount } = req.body;
      const user = req.user!;

      console.log("Building UserOp for transfer (v0.7)");

      // Build UserOp (unsigned, with paymaster from Alchemy)
      const userOp = await this.aaService.buildTokenTransferUserOp(
        user.smartAccountAddress,
        user.ownerAddress,
        to,
        amount,
        user.isAccountDeployed,
        user.saltDecimal
      );

      console.log("✅ UserOp built (v0.7 with paymaster)");

      res.json({
        success: true,
        data: {
          userOp,
          message: "Sign this UserOp on your device and send back",
        },
      });
    } catch (error: any) {
      console.error("Build UserOp error:", error);
      res.status(500).json({
        success: false,
        error: "Failed to build UserOp",
        details: error.message,
      });
    }
  };

  /**
   * Step 2: Submit signed UserOp
   */
  submitTransaction = async (req: AuthRequest, res: Response) => {
    try {
      const { userOp } = req.body;
      const user = req.user!;

      console.log("\n📝 Submitting transaction (v0.7)");

      // Verify sender matches
      if (userOp.sender.toLowerCase() !== user.smartAccountAddress.toLowerCase()) {
        return res.status(400).json({
          success: false,
          error: "UserOp sender mismatch",
        });
      }

      // Pack the UserOp for submission (v0.7 uses packed format)
      const packedUserOp = this.bundler.packUserOperation(userOp);

      console.log("\n📦 UserOp packed for submission");
      console.log("   accountGasLimits:", packedUserOp.accountGasLimits);
      console.log("   gasFees:", packedUserOp.gasFees);

      // Submit to bundler
      console.log("\n📤 Submitting to bundler...");
      // const userOpHash = await this.aaService.submitUserOperation(packedUserOp);
      // console.log("Packed UserOp to submit:", packedUserOp);
      console.log("UserOp to submit:", userOp);
      const userOpHash = await this.aaService.submitUserOperation(userOp);

      console.log("✅ Submitted to bundler");
      console.log("UserOpHash:", userOpHash);

      // Save transaction
      const txRepo = AppDataSource.getRepository(Transaction);
      const transaction = txRepo.create({
        userOpHash,
        fromAddress: user.smartAccountAddress,
        toAddress: extractToAddress(userOp.callData),
        amount: extractAmount(userOp.callData),
        status: TxStatus.PENDING,
        user,
      });

      await txRepo.save(transaction);

      // Mark account as deployed if this is first transaction
      if (!user.isAccountDeployed && userOp.factory) {
        const userRepo = AppDataSource.getRepository(User);
        user.isAccountDeployed = true;
        await userRepo.save(user);
        console.log("🎉 Account deployed!");
      }

      // Monitor transaction
      const trx = await this.monitorTransaction(userOpHash);

      res.json({
        success: true,
        data: {
          userOpHash,
          status: trx?.status,
          transaction: trx,
          message: "Transaction submitted to bundler",
        },
      });

    } catch (error: any) {
      console.error("❌ Submit transaction error:", error);
      res.status(500).json({
        success: false,
        error: "Failed to submit transaction",
        details: error.message,
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
        where: { userOpHash },
      });

      if (!transaction) {
        return res.status(404).json({
          success: false,
          error: "Transaction not found",
        });
      }

      res.json({
        success: true,
        data: { transaction },
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: "Failed to get transaction status",
      });
    }
  };

  /**
   * Monitor transaction confirmation
   */
  private async monitorTransaction(userOpHash: string) {
    try {
      console.log("\n⏳ Monitoring transaction:", userOpHash);

      const receipt = await this.aaService.waitForConfirmation(userOpHash);

      const txRepo = AppDataSource.getRepository(Transaction);
      const transaction = await txRepo.findOne({
        where: { userOpHash },
      });

      if (transaction) {
        transaction.status = receipt.success
          ? TxStatus.CONFIRMED
          : TxStatus.FAILED;
        transaction.txHash = receipt.receipt?.transactionHash;
        const blockNumber =
          receipt.receipt?.blockNumber !== null && receipt.receipt?.blockNumber !== undefined
            ? Number(receipt.receipt?.blockNumber).toString()
            : null;
        transaction.blockNumber = blockNumber;
        await txRepo.save(transaction);

        console.log("Transaction confirmed!");
        console.log("TxHash:", receipt.receipt?.transactionHash);
        console.log("Block:", receipt.receipt?.blockNumber);

        return transaction;
      }
    } catch (error) {
      console.error("❌ Transaction monitoring failed:", error);
    }
  }
}
