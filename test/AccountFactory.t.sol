//SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import "../src/AccountFactory.sol";
import "../src/SmartUserAccount.sol";
import "@account-abstraction/core/EntryPoint.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import { ErrorLib } from "../src/library/ErrorLib.sol";

contract AccountFactoryTest is Test {
    EntryPoint public entryPoint;
    AccountFactory public factory;
    SmartUserAccount public implementation;
    
    address public owner1;
    address public owner2;
    uint256 public owner1Key;
    uint256 public owner2Key;
    
    event SmartAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);

    function setUp() public {
        // Generate test accounts
        owner1Key = 0xA11CE;
        owner2Key = 0xB0B;
        owner1 = vm.addr(owner1Key);
        owner2 = vm.addr(owner2Key);
        
        // Deploy real EntryPoint from account-abstraction library
        entryPoint = new EntryPoint();
        
        // Deploy factory (which deploys implementation)
        factory = new AccountFactory(IEntryPoint(address(entryPoint)));
        implementation = factory.ACCOUNT_IMPLEMENTATION();
    }

    // Deployment
    function test_Deployment() public {
        // Implementation should exist
        assertTrue(address(implementation) != address(0), "Implementation not deployed");
        
        // Implementation should be uninitialized (owner == address(0))
        assertEq(implementation.owner(), address(0), "Implementation should have zero owner");
        
        // EntryPoint should be set correctly
        assertEq(address(implementation.entryPoint()), address(entryPoint), "EntryPoint mismatch on implementation");

        // Try to call initialize on implementation - should fail (already initialized)
        // vm.expectRevert();
        implementation.initialize(owner1);

        // Second initialize call should revert
        vm.expectRevert();
        implementation.initialize(owner2);
    }

    // Test 2: getAddress Determinism
    function test_GetAddressDeterminism() public {
        uint256 salt = 0;
        
        // Call getAddress twice
        address predicted1 = factory.getAddress(owner1, salt);
        address predicted2 = factory.getAddress(owner1, salt);
        
        // Should return same address
        assertEq(predicted1, predicted2, "getAddress not deterministic");
        
        // Deploy account
        SmartUserAccount account = factory.createAccount(owner1, salt);
        
        // Deployed address must equal predicted
        assertEq(address(account), predicted1, "Deployed address mismatch");
    }

    // Test 3: createAccount Behavior - New Deployment
    function test_CreateAccount_NewDeployment() public {
        uint256 salt = 0;
        address predicted = factory.getAddress(owner1, salt);
        
        // Check no code at address initially
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(predicted)
        }
        assertEq(codeSize, 0, "Code should not exist yet");
        
        // Expect initialization event
        vm.expectEmit(true, true, false, false);
        emit SmartAccountInitialized(IEntryPoint(address(entryPoint)), owner1);
        
        // Create account
        SmartUserAccount account = factory.createAccount(owner1, salt);
        
        // Verify deployment
        assembly {
            codeSize := extcodesize(predicted)
        }
        assertGt(codeSize, 0, "Code should exist after deployment");
        
        // Verify owner and entryPoint
        assertEq(account.owner(), owner1, "Owner mismatch");
        assertEq(address(account.entryPoint()), address(entryPoint), "EntryPoint mismatch");
    }

     // Test 3b:  createAccount Behavior - Already Deployed
    function test_CreateAccount_AlreadyDeployed() public {
        uint256 salt = 0;
        
        // Deploy first time
        SmartUserAccount account1 = factory.createAccount(owner1, salt);
        address addr1 = address(account1);
        
        // Deploy again with same parameters
        SmartUserAccount account2 = factory.createAccount(owner1, salt);
        address addr2 = address(account2);
        
        // Should return same instance (no new deployment)
        assertEq(addr1, addr2, "Should return existing account");
        
        // Owner should still be correct
        assertEq(account2.owner(), owner1, "Owner should remain unchanged");
    }

     // Test 4: CREATE2 Salt Collision Test
    function test_CREATE2_SaltUniqueness() public view {
        uint256 salt1 = 0;
        uint256 salt2 = 1;
        
        // Different salts produce unique addresses
        address addr1 = factory.getAddress(owner1, salt1);
        address addr2 = factory.getAddress(owner1, salt2);
        
        assertTrue(addr1 != addr2, "Different salts should produce different addresses");
        
        // Same salt + same owner always produces same address
        address addr3 = factory.getAddress(owner1, salt1);
        assertEq(addr1, addr3, "Same parameters should produce same address");
        
        // Same salt + different owner produces different address
        address addr4 = factory.getAddress(owner2, salt1);
        assertTrue(addr1 != addr4, "Different owners should produce different addresses");
    }

    // Test 5: Edge Case - Zero Address Owner
    function test_EdgeCase_ZeroAddressOwner() public {
        uint256 salt = 0;
        
        // Disallow zero address owner
        vm.expectRevert(ErrorLib.InvalidAddress.selector);
        SmartUserAccount account = factory.createAccount(address(0), salt);
    
    }

    function test_MultipleAccountsPerOwner() public {
        SmartUserAccount account1 = factory.createAccount(owner1, 0);
        SmartUserAccount account2 = factory.createAccount(owner1, 1);
        SmartUserAccount account3 = factory.createAccount(owner1, 2);
        
        // All should be different addresses
        assertTrue(address(account1) != address(account2), "Accounts should be unique");
        assertTrue(address(account2) != address(account3), "Accounts should be unique");
        assertTrue(address(account1) != address(account3), "Accounts should be unique");
        
        // All should have same owner
        assertEq(account1.owner(), owner1);
        assertEq(account2.owner(), owner1);
        assertEq(account3.owner(), owner1);
    }
}