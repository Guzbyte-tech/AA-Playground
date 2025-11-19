//SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import "forge-std/console2.sol";
import {Vm} from "forge-std/Vm.sol";

import { GTT } from "../src/GTT.sol";

contract DeployTokenScript is Script {

    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.addr(privateKey);


        console2.log("Deployer: ", deployer);
        
        vm.startBroadcast(privateKey);
        console2.log("\n=== Starting Token Deployment ===");
        // Deploy token

        GTT token = new GTT();


        console2.log("\n=== Token Deployed ===");
        console2.log("Token address: ", address(token));
        

        console2.log("\n=== Finished Deployment ===");
        vm.stopBroadcast();

    }
}
