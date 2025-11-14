import { Contract, ethers } from "ethers";
import  FactoryABI  from "./src/abis/FactoryABI.json";
import dotenv from "dotenv";
dotenv.config();

const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
const factoryAddress = process.env.FACTORY_ADDRESS!;
const owner = "0x1111111111111111111111111111111111111111"; // use same owner as in your test
const salt = BigInt(12345); // or use the one you used

(async () => {
  const factory = new Contract(factoryAddress, FactoryABI, provider);

  console.log("Factory address (env):", factoryAddress);

  try {
    // If your factory exposes ACCOUNT_IMPLEMENTATION
    const impl = await factory.ACCOUNT_IMPLEMENTATION().catch(e => null);
    console.log("Factory.ACCOUNT_IMPLEMENTATION():", impl);

    const predicted = await (factory as any).getAddress(owner, 1);
    console.log("Predicted address from factory.getAddress():", predicted);

    const factoryCode = await provider.getCode(factoryAddress);
    const predictedCode = await provider.getCode(predicted);
    console.log("on-chain code at factoryAddress length:", factoryCode.length);
    console.log("on-chain code at predicted addr length:", predictedCode.length);

  } catch (err) {
    console.error("Error calling factory:", err);
  }
})();
