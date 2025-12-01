import { ethers } from "ethers";
import dotenv from "dotenv";

dotenv.config();

/**
 * Script to stake your Factory contract in the EntryPoint
 * Required for Alchemy bundler to accept UserOps with initCode
 */
async function stakeFactory() {
  console.log("\n💰 STAKING FACTORY CONTRACT");
  console.log("=".repeat(60));

  // Setup
  const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL!);
  const deployer = new ethers.Wallet(
    process.env.DEPLOYER_PRIVATE_KEY!, // Your deployer wallet
    provider
  );

  const entryPointAddress = process.env.ENTRYPOINT_ADDRESS!;
  const factoryAddress = process.env.FACTORY_ADDRESS!;

  console.log("\n📋 Configuration:");
  console.log("  EntryPoint:", entryPointAddress);
  console.log("  Factory:", factoryAddress);
  console.log("  Deployer:", deployer.address);

  // EntryPoint ABI for staking
  const entryPointABI = [
    "function addStake(uint32 unstakeDelaySec) payable",
    "function getDepositInfo(address account) view returns (tuple(uint256 deposit, bool staked, uint112 stake, uint32 unstakeDelaySec, uint48 withdrawTime))",
  ];

  const entryPoint = new ethers.Contract(
    entryPointAddress,
    entryPointABI,
    deployer
  );

  // Check current stake
  console.log("\n1️⃣ Checking current stake...");
  try {
    const depositInfo = await entryPoint.getDepositInfo(factoryAddress);
    console.log("  Current deposit:", ethers.formatEther(depositInfo.deposit), "ETH");
    console.log("  Is staked:", depositInfo.staked);
    console.log("  Stake amount:", ethers.formatEther(depositInfo.stake), "ETH");
    console.log("  Unstake delay:", depositInfo.unstakeDelaySec.toString(), "seconds");

    if (depositInfo.staked) {
      console.log("\n✅ Factory is already staked!");
      console.log("   If you need to increase stake, you'll need to unstake first and wait.");
      return;
    }
  } catch (error) {
    console.log("  ⚠️  Could not check current stake");
  }

  // Alchemy requirements
  const requiredStake = ethers.parseEther("0.1"); // 0.1 ETH
  const requiredUnstakeDelay = 86400; // 1 day in seconds

  console.log("\n2️⃣ Alchemy Requirements:");
  console.log("  Minimum stake:", ethers.formatEther(requiredStake), "ETH");
  console.log("  Minimum unstake delay:", requiredUnstakeDelay, "seconds (1 day)");

  // Check deployer balance
  const balance = await provider.getBalance(deployer.address);
  console.log("\n3️⃣ Deployer Balance:", ethers.formatEther(balance), "ETH");

  if (balance < requiredStake) {
    console.error("\n❌ Insufficient balance to stake!");
    console.error("   Need:", ethers.formatEther(requiredStake), "ETH");
    console.error("   Have:", ethers.formatEther(balance), "ETH");
    return;
  }

  // Add stake
  console.log("\n4️⃣ Adding stake to factory...");
  console.log("  Amount:", ethers.formatEther(requiredStake), "ETH");
  console.log("  Unstake delay:", requiredUnstakeDelay, "seconds");

  try {
    const tx = await entryPoint.addStake(requiredUnstakeDelay, {
      value: requiredStake,
    });

    console.log("\n📤 Transaction sent:", tx.hash);
    console.log("   Waiting for confirmation...");

    const receipt = await tx.wait();
    console.log("✅ Transaction confirmed!");
    console.log("   Block:", receipt.blockNumber);
    console.log("   Gas used:", receipt.gasUsed.toString());

    // Verify stake
    console.log("\n5️⃣ Verifying stake...");
    const newDepositInfo = await entryPoint.getDepositInfo(factoryAddress);
    console.log("  New deposit:", ethers.formatEther(newDepositInfo.deposit), "ETH");
    console.log("  Is staked:", newDepositInfo.staked ? "✅ YES" : "❌ NO");
    console.log("  Stake amount:", ethers.formatEther(newDepositInfo.stake), "ETH");
    console.log("  Unstake delay:", newDepositInfo.unstakeDelaySec.toString(), "seconds");

    console.log("\n" + "=".repeat(60));
    console.log("🎉 FACTORY SUCCESSFULLY STAKED!");
    console.log("You can now deploy accounts using this factory!");
    console.log("=".repeat(60));
  } catch (error: any) {
    console.error("\n❌ Staking failed:", error.message);
  }
}

// Run the script
stakeFactory().catch(console.error);
