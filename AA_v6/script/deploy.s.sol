//SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import "forge-std/console2.sol";
import {Vm} from "forge-std/Vm.sol";

import { AccountFactory } from "../src/AccountFactory.sol";
import { SmartUserAccount } from "../src/SmartUserAccount.sol";
// import { PayMaster } from "../src/PayMaster.sol";
import { PayMaster } from "../src/Paymaster.sol";
import { PayMasterV2 } from "../src/PayMasterV2.sol";

import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";

contract DeployScript is Script {

    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(privateKey);

        address entryPoint = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

        console2.log("Deployer: ", deployer);
        
        vm.startBroadcast(privateKey);
        console2.log("\n=== Starting Deployment ===");
        
        // Deploy account factory
        // AccountFactory factory = new AccountFactory(IEntryPoint(entryPoint));
        // console2.log("AccountFactory: ", address(factory));

        // Deploy paymaster
        // PayMaster paymaster = new PayMaster(IEntryPoint(entryPoint), address(deployer));
        // console2.log("PayMaster: ", address(paymaster));

        PayMasterV2 paymaster = new PayMasterV2(IEntryPoint(entryPoint), address(deployer));
        console2.log("PayMasterV2: ", address(paymaster));

        // Deploy SmartUserAccount
        // SmartUserAccount userAccount = new SmartUserAccount(IEntryPoint(entryPoint));
        // console2.log("SmartUserAccount: ", address(userAccount));

        console2.log("\n=== Finished Deployment ===");
        vm.stopBroadcast();

    }
}
