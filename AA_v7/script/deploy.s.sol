//SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import "forge-std/console2.sol";
import {Vm} from "forge-std/Vm.sol";

import { AccountFactory } from "../src/AccountFactory.sol";
import { SmartUserAccount } from "../src/SmartUserAccount.sol";
// import { PayMaster } from "../src/PayMaster.sol";
import { PayMaster } from "../src/PayMaster.sol";

import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";

contract DeployScript is Script {

    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(privateKey);

        address entryPoint = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

        address feeAddress = address(0x0059351e2b3f85534a2e1bf92a2424f37e180919d9);


        console2.log("Deployer: ", deployer);
        
        vm.startBroadcast(privateKey);
        console2.log("\n=== Starting Deployment ===");
        
        // Deploy account factory
        AccountFactory factory = new AccountFactory(IEntryPoint(entryPoint), feeAddress);
        console2.log("AccountFactory: ", address(factory));

        // Deploy paymaster
        uint256 maxGasPerOperation = 2_000_000;
        PayMaster paymaster = new PayMaster(IEntryPoint(entryPoint), address(deployer), maxGasPerOperation);
        console2.log("PayMaster: ", address(paymaster));

        // Deploy SmartUserAccount
        SmartUserAccount userAccount = new SmartUserAccount(IEntryPoint(entryPoint), feeAddress);
        console2.log("SmartUserAccount: ", address(userAccount));

        console2.log("\n=== Finished Deployment ===");
        vm.stopBroadcast();
    }
}
