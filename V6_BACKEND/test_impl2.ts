import { ethers } from "ethers";
import FactoryABI from "./src/abis/FactoryABI.json";
import dotenv from "dotenv";
dotenv.config();

const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
const factoryAddress = process.env.FACTORY_ADDRESS!;
const owner = "0xaC58684c421B753180F0Ef8Bb88bDE7A71226522";
const salt = 246059n; // same salt as used in Solidity

(async () => {
  const factory = new ethers.Contract(factoryAddress, FactoryABI, provider);

  try {
    // 1. Get the deployed implementation from the factory
    const accountImpl: string = await factory.ACCOUNT_IMPLEMENTATION();
    console.log("Account Implementation:", accountImpl);

    // 2. Encode the initialize calldata
    const iface = new ethers.Interface([
      "function initialize(address owner)"
    ]);
    const proxyInitData = iface.encodeFunctionData("initialize", [owner]);

    // 3. Get the ERC1967Proxy bytecode
    // This assumes you have ERC1967Proxy compiled locally
    // Alternatively, you can hardcode its creationCode if needed
    const ERC1967ProxyBytecode = "0x608060405261029d8038038061001481610168565b92833981016040828203126101645781516001600160a01b03811692909190838303610164576020810151906001600160401b03821161016457019281601f8501121561016457835161006e610069826101a1565b610168565b9481865260208601936020838301011161016457815f926020809301865e86010152823b15610152577f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc80546001600160a01b031916821790557fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b5f80a282511561013a575f8091610122945190845af43d15610132573d91610113610069846101a1565b9283523d5f602085013e6101bc565b505b6040516082908161021b8239f35b6060916101bc565b50505034156101245763b398979f60e01b5f5260045ffd5b634c9c8ce360e01b5f5260045260245ffd5b5f80fd5b6040519190601f01601f191682016001600160401b0381118382101761018d57604052565b634e487b7160e01b5f52604160045260245ffd5b6001600160401b03811161018d57601f01601f191660200190565b906101e057508051156101d157805190602001fd5b63d6bda27560e01b5f5260045ffd5b81511580610211575b6101f1575090565b639996b31560e01b5f9081526001600160a01b0391909116600452602490fd5b50803b156101e956fe60806040527f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545f9081906001600160a01b0316368280378136915af43d5f803e156048573d5ff35b3d5ffdfea26469706673582212203d5f7c2fec6b8fd34ebd86e95761dd5d04b25456e0f1a87e2223212a86763f4364736f6c634300081c0033"; // REPLACE with ERC1967Proxy creationCode

     // 4. Construct the full bytecode for CREATE2
    const bytecode = ethers.concat([
      ethers.getBytes(ERC1967ProxyBytecode),
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["address", "bytes"],
        [accountImpl, proxyInitData]
      ),
    ]);

    // 5. Convert salt to 32-byte hex
    // convert bigint salt to 32-byte hex string
    const saltBytes = "0x" + salt.toString(16).padStart(64, "0");


     // 5. Compute CREATE2 address
    const create2Address = ethers.getCreate2Address(
      factoryAddress,
      saltBytes,
      ethers.keccak256(bytecode)
    );

    console.log("Predicted Account Address:", create2Address);

    console.log("Factory address (env):", factoryAddress);

    // 6. Check if it exists on-chain
    const codeAtAddress = await provider.getCode(create2Address);
    console.log(
      "Code at predicted address length:",
      codeAtAddress.length
    );
  } catch (err) {
    console.error(err);
  }
})();
