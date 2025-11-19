//SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/PayMaster.sol";
import {EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { TestHelpers } from "./utils/Helpers.t.sol";
import { ErrorLib } from "../src/library/ErrorLib.sol";
import "../src/SmartUserAccount.sol";
import "../src/AccountFactory.sol";

contract EdgeCasesTest is Test {
    EntryPoint public entryPoint;
    AccountFactory public factory;
    PayMaster public paymaster;
    
    address public owner;
    uint256 public ownerKey;
    address public paymasterSigner;
    uint256 public paymasterSignerKey;

    function setUp() public {
        ownerKey = 0xA11CE;
        owner = vm.addr(ownerKey);
        paymasterSignerKey = 0xABCD;
        paymasterSigner = vm.addr(paymasterSignerKey);
        
        entryPoint = new EntryPoint();
        factory = new AccountFactory(IEntryPoint(address(entryPoint)));
        paymaster = new PayMaster(IEntryPoint(address(entryPoint)), paymasterSigner);
    }

     // Test empty callData execution
    function test_EmptyCallData() public {
        SmartUserAccount account = factory.createAccount(owner, 0);
        vm.deal(address(account), 10 ether);
        
        address recipient = address(0x888);
        
        // Execute with empty callData (just ETH transfer)
        vm.prank(owner);
        account.execute(recipient, 1 ether, "");
        
        assertEq(recipient.balance, 1 ether, "ETH transfer with empty callData failed");
    }

    // Test executeBatch with empty arrays
    function test_ExecuteBatchEmpty() public {
        SmartUserAccount account = factory.createAccount(owner, 0);
        
        address[] memory targets = new address[](0);
        uint256[] memory values = new uint256[](0);
        bytes[] memory calls = new bytes[](0);
        
        // Should not revert with empty arrays
        vm.prank(owner);
        account.executeBatch(targets, values, calls);
    }

    // Test nonce management
    function test_NonceIncrement() public {
        SmartUserAccount account = factory.createAccount(owner, 0);
        
        // Initial nonce should be 0
        uint256 nonce = entryPoint.getNonce(address(account), 0);
        assertEq(nonce, 0, "Initial nonce should be 0");
    }

    // Test receive function
    function test_ReceiveETH() public {
        SmartUserAccount account = factory.createAccount(owner, 0);
        
        // Send ETH to account
        vm.deal(address(this), 10 ether);
        (bool success,) = address(account).call{value: 5 ether}("");
        
        assertTrue(success, "ETH transfer failed");
        assertEq(address(account).balance, 5 ether, "Account balance mismatch");
    }

    function testFuzz_CreateMultipleAccounts(uint256 salt) public {
        vm.assume(salt < type(uint256).max - 10);
        
        SmartUserAccount account1 = factory.createAccount(owner, salt);
        SmartUserAccount account2 = factory.createAccount(owner, salt + 1);
        
        assertTrue(address(account1) != address(account2), "Accounts should be unique");
    }
}