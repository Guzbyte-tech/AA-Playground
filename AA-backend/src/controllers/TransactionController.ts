import { max } from "class-validator";
import { ethers } from "ethers";
import { Response } from "express";
import { User } from "../entities/User";
import { Transaction, TxStatus } from "../entities/Transaction";
import { AAService } from "../services/AAService";
import { AuthRequest } from "../middlewares/auth.middleware";
import AppDataSource from "../config/db";
import { BundlerService } from "../services/BundlerService";
import {
  convertToAlchemy,
  extractAmount,
  extractToAddress,
} from "../utils/helpers";
import { EntryPointABI } from "../abis/EntryPointABI";
import FactoryABI from "../abis/FactoryABI.json";

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
   * Step 1: Frontend requests UserOp template
   * Backend builds it and adds paymaster signature
   */

  buildUserOp = async (req: AuthRequest, res: Response) => {
    try {
      const { to, amount } = req.body;
      const user = req.user!;

      console.log("Building UserOp for transfer");

      // Build UserOp (unsigned, NO paymaster yet)
      const { alchemyUserOp, entryPointPackedUserOp } =
        await this.aaService.buildTokenTransferUserOpAlchemyV7(
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
          packedUserOp: entryPointPackedUserOp, // No paymaster
          alchemyUserOp: alchemyUserOp, // No paymaster
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

  // 2. TransactionController.ts - submitTransaction
  // Add paymaster AFTER client has signed
  submitTransaction = async (req: AuthRequest, res: Response) => {
    try {
      const { packedUserOp, alchemyUserOp } = req.body;
      const user = req.user!;

      console.log("\n📝 Submitting transaction");

      // Verify sender matches
      if (
        packedUserOp.sender.toLowerCase() !==
        user.smartAccountAddress.toLowerCase()
      ) {
        return res.status(400).json({
          success: false,
          error: "UserOp sender mismatch",
        });
      }

      // ✅ Verify user signature (without paymaster)
      await this.aaService.verifyUserOpHash(packedUserOp, user.ownerAddress);
      console.log("✅ User signature verified");

      // ✅ NOW add paymaster signature (after user has signed)
      console.log("\n🔏 Adding paymaster signature...");
      const paymasterData = await this.aaService.addPaymasterSignatureV7(
        packedUserOp
      );

      const fullPaymasterAndData = ethers.concat([
        this.paymasterAddress,
        paymasterData,
      ]);

      // Update BOTH formats with paymaster
      packedUserOp.paymasterAndData = fullPaymasterAndData;

      const paymasterVerificationGasLimit = 150_000n;
      const paymasterPostOpGasLimit = 100_000n;

      alchemyUserOp.paymaster = this.paymasterAddress;
      alchemyUserOp.paymasterVerificationGasLimit = ethers.toBeHex(
        paymasterVerificationGasLimit
      );
      alchemyUserOp.paymasterPostOpGasLimit = ethers.toBeHex(
        paymasterPostOpGasLimit
      );
      alchemyUserOp.paymasterData = paymasterData;

      console.log("✅ Paymaster signature added");

      // Check deposits
      const paymasterDeposit =
        await this.aaService.checkPaymasterDepositDetailed();
      const estimatedGas =
        BigInt(alchemyUserOp.verificationGasLimit) +
        BigInt(alchemyUserOp.callGasLimit) +
        BigInt(alchemyUserOp.preVerificationGas) +
        BigInt(alchemyUserOp.paymasterVerificationGasLimit || 0) +
        BigInt(alchemyUserOp.paymasterPostOpGasLimit || 0);

      const maxFeePerGas = BigInt(alchemyUserOp.maxFeePerGas);
      const estimatedCost = estimatedGas * maxFeePerGas;

      if (paymasterDeposit < estimatedCost) {
        throw new Error("Insufficient paymaster deposit");
      }

      // Submit to bundler (UserOp now has both signatures)
      console.log("\n📤 Submitting to bundler...");
      const userOpHash = await this.aaService.submitUserOperation(
        alchemyUserOp
      );

      console.log("✅ Submitted to bundler");
      console.log("UserOpHash:", userOpHash);

      // Save transaction
      const txRepo = AppDataSource.getRepository(Transaction);
      const transaction = txRepo.create({
        userOpHash,
        fromAddress: user.smartAccountAddress,
        toAddress: extractToAddress(packedUserOp.callData),
        amount: extractAmount(packedUserOp.callData),
        status: TxStatus.PENDING,
        user,
      });

      await txRepo.save(transaction);

      if (!user.isAccountDeployed && packedUserOp.initCode !== "0x") {
        const userRepo = AppDataSource.getRepository(User);
        user.isAccountDeployed = true;
        await userRepo.save(user);
        console.log("🎉 Account deployed!");
      }

      this.monitorTransaction(userOpHash);

      res.json({
        success: true,
        data: {
          userOpHash,
          status: "pending",
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
   * TEST NOT IMPORTANT: Frontend signs UserOp and sends back
   * Backend adds paymaster signature and submits to bundler
   */
  calculatePaymasterData = async (req: AuthRequest, res: Response) => {
    try {
      const { userOp } = req.body;
      const user = req.user!;

      console.log("UserOperation Loggg: ", userOp);

      console.log("\n Submitting transaction 2222");
      console.log("From:", user.smartAccountAddress);
      console.log("Nonce:", userOp.nonce);

      // Verify userOp sender matches user
      if (
        userOp.sender.toLowerCase() !== user.smartAccountAddress.toLowerCase()
      ) {
        return res.status(400).json({
          success: false,
          error: "UserOp sender mismatch",
        });
      }

      // return res.json({
      //     success: true,
      //     data: {
      //         userOp,
      //         status: 'pending',
      //         message: 'Transaction With PaymasterData .....'
      //     }
      // });
      // Add paymaster signature (backend sponsors gas!)
      // const paymasterAndData = await this.aaService.addPaymasterSignature(userOp);
      const paymasterAndData = await this.aaService.addPaymasterSignature(
        userOp
      );
      userOp.paymasterAndData = paymasterAndData;

      console.log("Gas sponsored by paymaster");

      console.log("UserOp:", userOp);

      res.json({
        success: true,
        data: {
          userOp,
          status: "pending",
          message: "Transaction With PaymasterData",
        },
      });
    } catch (error: any) {
      console.error("Submit transaction error:", error);
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
        transaction.txHash = receipt.transactionHash;
        transaction.blockNumber = parseInt(receipt.blockNumber);
        await txRepo.save(transaction);

        console.log("Transaction confirmed!");
        console.log("TxHash:", receipt.transactionHash);
        console.log("Block:", receipt.blockNumber);
      }
    } catch (error) {
      console.error("❌ Transaction monitoring failed:", error);
    }
  }
}
