import { max } from "class-validator";
import { ethers } from "ethers";
import { Response } from "express";
import { User } from "../entities/User";
import { Transaction, TxStatus } from "../entities/Transaction";
import { AAService } from "../services/AAService";
import { AuthRequest } from "../middlewares/auth.middleware";
import AppDataSource from "../config/db";
import { BundlerService } from "../services/BundlerService";

import { EntryPointABI } from "../abis/EntryPointABI";
import FactoryABI from "../abis/FactoryABI.json";
import { extractAmount, extractToAddress, testPaymasterHashMatching } from "../utils/helpers";

export class TransactionController {
  private aaService: AAService;
  private bundler: BundlerService;
  private paymasterAddress: string;
  private provider: ethers.JsonRpcProvider;
  private entryPointAddress: string;

  constructor() {
    this.aaService = new AAService();
    this.bundler = new BundlerService();
    this.paymasterAddress = process.env.PAYMASTER_ADDRESS!;
    this.provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL!);
    this.entryPointAddress = process.env.ENTRYPOINT_ADDRESS!;
  }

  async init() {
    await this.aaService.init();
  }

  /**
   * Step 1: Build UserOp template (v0.6 unpacked format)
   */
  buildUserOp = async (req: AuthRequest, res: Response) => {
    try {
      const { to, amount } = req.body;
      const user = req.user!;

      console.log("Building UserOp for transfer");

      // Build UserOp (unsigned, no paymaster yet)
      const userOp = await this.aaService.buildTokenTransferUserOp(
        user.smartAccountAddress,
        user.ownerAddress,
        to,
        amount,
        user.isAccountDeployed,
        user.saltDecimal
      );

      console.log("✅ UserOp built (no paymaster yet)");

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
   * Step 2: Submit signed UserOp with paymaster signature
   */
  submitTransaction = async (req: AuthRequest, res: Response) => {
    try {
      const { userOp } = req.body;
      const user = req.user!;

      console.log("\n📝 Submitting transaction");

      // Verify sender matches
      if (userOp.sender.toLowerCase() !== user.smartAccountAddress.toLowerCase()) {
        return res.status(400).json({
          success: false,
          error: "UserOp sender mismatch",
        });
      }

      // Verify user signature (without paymaster)
      // await this.aaService.verifyUserOpSignature(userOp, user.ownerAddress);
      // console.log("✅ User signature verified");

      // Add paymaster signature
      // console.log("\n🔏 Adding paymaster signature...");
      // const paymasterAndData = await this.aaService.addPaymasterSignature(userOp);
      // userOp.paymasterAndData = paymasterAndData;
      // console.log("✅ Paymaster signature added");

      // Check paymaster deposit
      // const paymasterDeposit = await this.aaService.checkPaymasterDeposit();
      // const estimatedGas =
      //   BigInt(userOp.verificationGasLimit) +
      //   BigInt(userOp.callGasLimit) +
      //   BigInt(userOp.preVerificationGas);

      // const maxFeePerGas = BigInt(userOp.maxFeePerGas);
      // const estimatedCost = estimatedGas * maxFeePerGas;

      // if (paymasterDeposit < estimatedCost) {
      //   throw new Error("Insufficient paymaster deposit");
      // }

       // Debug validation before submitting
      // console.log("\n🔬 Testing validation on-chain...");
      // await this.aaService.debugValidation(userOp);
      // await testPaymasterHashMatching(userOp, userOp.paymasterAndData);

      // Submit to bundler
      console.log("\n📤 Submitting to bundler...");
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
      if (!user.isAccountDeployed && userOp.initCode !== "0x") {
        const userRepo = AppDataSource.getRepository(User);
        user.isAccountDeployed = true;
        await userRepo.save(user);
        console.log("🎉 Account deployed!");
      }
      
      // this.monitorTransaction(userOpHash);
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
