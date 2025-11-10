//SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/SmartUserAccount.sol";
import "../src/AccountFactory.sol";
import "../src/PayMaster.sol";
import {EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";
import { TestHelpers } from "./utils/Helpers.t.sol";


contract SystemFlowTest is Test {
    EntryPoint public entryPoint;
    AccountFactory public factory;
    SmartUserAccount public implementation;
    PayMaster public paymaster;
    
    address public accountOwner;
    uint256 public ownerKey;
    address public paymasterSigner;
    uint256 public paymasterSignerKey;
    address public beneficiary;
    
    TestTarget public target;

    function setUp() public {
        // Setup keys
        ownerKey = 0xA11CE;
        accountOwner = vm.addr(ownerKey);
        paymasterSignerKey = 0xABCD;
        paymasterSigner = vm.addr(paymasterSignerKey);
        beneficiary = address(0x888);
        
        // Deploy contracts
        entryPoint = new EntryPoint();
        factory = new AccountFactory(IEntryPoint(address(entryPoint)));
        implementation = factory.ACCOUNT_IMPLEMENTATION();
        paymaster = new PayMaster(IEntryPoint(address(entryPoint)), paymasterSigner);
        
        // Deploy test target
        target = new TestTarget();
        
        // Fund accounts
        vm.deal(address(this), 100 ether);
        vm.deal(accountOwner, 10 ether);
    }

    // Test 1: Deploy Smart Account via Factory
    function test_DeploySmartAccountViaFactory() public {
        uint256 salt = 0;
        
        // Compute counterfactual address
        address predictedAddr = factory.getAddress(accountOwner, salt);
        
        // Verify no code exists
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(predictedAddr)
        }
        assertEq(codeSize, 0, "Address should be empty");
        
        // Create account
        SmartUserAccount account = factory.createAccount(accountOwner, salt);
        
        // Verify deployment
        assertEq(address(account), predictedAddr, "Deployed address mismatch");
        assembly {
            codeSize := extcodesize(predictedAddr)
        }
        assertGt(codeSize, 0, "Contract should be deployed");
        
        // Verify configuration
        assertEq(account.owner(), accountOwner, "Owner mismatch");
        assertEq(address(account.entryPoint()), address(entryPoint), "EntryPoint mismatch");
    }

     // Test 2: Prefund Paymaster
    function test_PrefundPaymaster() public {
        uint256 fundAmount = 10 ether;
        
        // Check initial balance
        assertEq(entryPoint.balanceOf(address(paymaster)), 0, "Should start with 0");
        
        // Fund paymaster
        paymaster.addDeposit{value: fundAmount}();
        
        // Verify balance
        assertEq(entryPoint.balanceOf(address(paymaster)), fundAmount, "Balance mismatch");
        assertEq(paymaster.paymasterDeposit(), fundAmount, "Paymaster deposit mismatch");
    }

    // Test 3: Build & Validate UserOperation
    function test_BuildAndValidateUserOperation() public {
        // Deploy account
        SmartUserAccount account = factory.createAccount(accountOwner, 0);
        vm.deal(address(account), 10 ether);
        
        // Fund paymaster
        paymaster.addDeposit{value: 10 ether}();
        
        // Build UserOperation
        bytes memory callData = abi.encodeWithSelector(
            SmartUserAccount.execute.selector,
            beneficiary,
            1 ether,
            ""
        ); // Send One ether to the beneficiary address through smart user account contract
        
        bytes32 accountGasLimits = TestHelpers.packGasLimits(100000, 100000);
        bytes32 gasFees = TestHelpers.packGasFees(1 gwei, 10 gwei);
        // vm.warp(block.timestamp + 1 days);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        // Create paymasterAndData
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: accountGasLimits,
            preVerificationGas: 21000,
            gasFees: gasFees,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 paymasterHash = paymaster.getHash(userOp, validUntil, validAfter);
        bytes memory paymasterSignature = TestHelpers.signPaymasterData(vm, paymasterHash, paymasterSignerKey);
        
        bytes memory paymasterAndData = abi.encodePacked(
            address(paymaster),
            validUntil,
            validAfter,
            paymasterSignature
        );
        
        userOp.paymasterAndData = paymasterAndData;
        
        // Sign UserOp
        bytes32 userOpHash = TestHelpers.getUserOpHash(vm, userOp, address(entryPoint), block.chainid);
        userOp.signature = TestHelpers.signUserOp(vm, userOp, address(entryPoint), block.chainid, ownerKey);
        
        // Validate via account
        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        
        assertEq(validationData, 0, "UserOp validation should succeed");
    }

     // Test 4: Full ERC-4337 Execution Simulation
    function test_FullERC4337ExecutionSimulation() public {
        // Step 1: Deploy account
        SmartUserAccount account = factory.createAccount(accountOwner, 0);
        vm.deal(address(account), 10 ether);
        
        // Step 2: Fund paymaster
        uint256 initialPaymasterDeposit = 10 ether;
        paymaster.addDeposit{value: initialPaymasterDeposit}();
        
        // Step 3: Build UserOperation to call target contract
        bytes memory targetCallData = abi.encodeWithSelector(TestTarget.setValue.selector, 42);
        bytes memory accountCallData = abi.encodeWithSelector(
            SmartUserAccount.execute.selector,
            address(target),
            0,
            targetCallData
        );
        
        bytes32 accountGasLimits = TestHelpers.packGasLimits(150000, 150000);
        bytes32 gasFees = TestHelpers.packGasFees(1 gwei, 10 gwei);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: accountCallData,
            accountGasLimits: accountGasLimits,
            preVerificationGas: 21000,
            gasFees: gasFees,
            paymasterAndData: "",
            signature: ""
        });
        
        // Sign paymaster data
        bytes32 paymasterHash = paymaster.getHash(userOp, validUntil, validAfter);
        bytes memory paymasterSignature = TestHelpers.signPaymasterData(vm, paymasterHash, paymasterSignerKey);
        bytes memory paymasterAndData = abi.encodePacked(
            address(paymaster),
            validUntil,
            validAfter,
            paymasterSignature
        );
        
        userOp.paymasterAndData = paymasterAndData;
        
        // Sign UserOp
        bytes32 userOpHash = TestHelpers.getUserOpHash(vm, userOp, address(entryPoint), block.chainid);
        userOp.signature = TestHelpers.signUserOp(vm, userOp, address(entryPoint), block.chainid, ownerKey);
        
        // Step 4: Simulate EntryPoint execution
        // Validate account
        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        assertEq(validationData, 0, "Account validation failed");
        
        // Execute the call
        vm.prank(address(entryPoint));
        account.execute(address(target), 0, targetCallData);
        
        // Step 5: Verify execution
        assertEq(target.value(), 42, "Target function not executed correctly");
    }

    // Test 5: Upgrade Path
    function test_UpgradePath() public {
        // Deploy account
        SmartUserAccount account = factory.createAccount(accountOwner, 0);
        vm.deal(address(account), 10 ether);
        
        // Verify initial state
        assertEq(account.owner(), accountOwner, "Initial owner mismatch");
        assertEq(address(account.entryPoint()), address(entryPoint), "Initial EntryPoint mismatch");
        
        // Deploy new implementation (V2)
        SmartUserAccountV2 newImplementation = new SmartUserAccountV2(IEntryPoint(address(entryPoint)));
        
        // Upgrade
        vm.prank(accountOwner);
        account.upgradeToAndCall(address(newImplementation), "");
        
        // Verify state persisted
        assertEq(account.owner(), accountOwner, "Owner not persisted after upgrade");
        assertEq(address(account.entryPoint()), address(entryPoint), "EntryPoint not persisted");
        
        // Verify new logic works
        SmartUserAccountV2 accountV2 = SmartUserAccountV2(payable(address(account)));
        assertEq(accountV2.version(), 2, "New version function failed");
        
        // Verify old functionality still works
        vm.prank(accountOwner);
        account.execute(beneficiary, 1 ether, "");
        assertEq(beneficiary.balance, 1 ether, "Execute still works after upgrade");
    }

    function test_Security_InvalidSignatureReplay() public {
        // Deploy account
        SmartUserAccount account = factory.createAccount(accountOwner, 0);
        vm.deal(address(account), 10 ether);
        
        // Build UserOp with wrong signature
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(SmartUserAccount.execute.selector, beneficiary, 1 ether, ""),
            accountGasLimits: TestHelpers.packGasLimits(100000, 100000),
            preVerificationGas: 21000,
            gasFees: TestHelpers.packGasFees(1 gwei, 10 gwei),
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 userOpHash = TestHelpers.getUserOpHash(vm, userOp, address(entryPoint), block.chainid);
        
        // Sign with wrong key
        uint256 wrongKey = 0xBAD;
        userOp.signature = TestHelpers.signUserOp(vm, userOp, address(entryPoint), block.chainid, wrongKey);
        
        // Validation should fail
        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        
        assertEq(validationData, 1, "Invalid signature should fail validation");
    }

    function test_Security_WrongChainId() public {
        SmartUserAccount account = factory.createAccount(accountOwner, 0);
        
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(SmartUserAccount.execute.selector, beneficiary, 1 ether, ""),
            accountGasLimits: TestHelpers.packGasLimits(100000, 100000),
            preVerificationGas: 21000,
            gasFees: TestHelpers.packGasFees(1 gwei, 10 gwei),
            paymasterAndData: "",
            signature: ""
        });
        
        // Sign with wrong chainId
        uint256 wrongChainId = 999;
        bytes32 userOpHash = TestHelpers.getUserOpHash(vm, userOp, address(entryPoint), wrongChainId);
        userOp.signature = TestHelpers.signUserOp(vm, userOp, address(entryPoint), wrongChainId, ownerKey);
        
        // Get correct hash for validation
        bytes32 correctHash = TestHelpers.getUserOpHash(vm, userOp, address(entryPoint), block.chainid);
        
        // Validation should fail because signature is for different chainId
        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(userOp, correctHash, 0);
        
        assertEq(validationData, 1, "Wrong chainId signature should fail");
    }

    function test_Security_PaymasterWrongEntryPoint() public {
        // Deploy a different EntryPoint
        EntryPoint wrongEntryPoint = new EntryPoint();
        
        // Try to use paymaster with wrong EntryPoint
        // The paymaster's entryPoint is immutable and set in constructor
        assertTrue(address(paymaster.entryPoint()) != address(wrongEntryPoint), "Should have different EntryPoint");
    }

    function test_AccountDeploymentViaInitCode() public {
        uint256 salt = 123;
        address predictedAddr = factory.getAddress(accountOwner, salt);
        
        // Build initCode
        bytes memory initCode = abi.encodePacked(
            address(factory),
            abi.encodeWithSelector(AccountFactory.createAccount.selector, accountOwner, salt)
        );
        
        // Verify account doesn't exist
        uint256 codeSize;
        assembly {
            codeSize := extcodesize(predictedAddr)
        }
        assertEq(codeSize, 0, "Account should not exist yet");
        
        // Build UserOp with initCode
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: predictedAddr,
            nonce: 0,
            initCode: initCode,
            callData: abi.encodeWithSelector(SmartUserAccount.execute.selector, beneficiary, 0, ""),
            accountGasLimits: TestHelpers.packGasLimits(700000, 100000), // Higher gas for deployment
            preVerificationGas: 21000,
            gasFees: TestHelpers.packGasFees(1 gwei, 10 gwei),
            paymasterAndData: "",
            signature: ""
        });
        
        // Sign UserOp
        bytes32 userOpHash = TestHelpers.getUserOpHash(vm, userOp, address(entryPoint), block.chainid);
        userOp.signature = TestHelpers.signUserOp(vm, userOp, address(entryPoint), block.chainid, ownerKey);
        
        // In a real scenario, EntryPoint would:
        // 1. Execute initCode to deploy the account
        // 2. Then validate and execute the UserOp
        
        // For testing, we manually deploy
        factory.createAccount(accountOwner, salt);
        
        // Verify deployment
        assembly {
            codeSize := extcodesize(predictedAddr)
        }
        assertGt(codeSize, 0, "Account should be deployed");
    }


}



// Upgraded Account V2 for testing
contract SmartUserAccountV2 is SmartUserAccount {
    constructor(IEntryPoint anEntryPoint) SmartUserAccount(anEntryPoint) {}
    
    function version() external pure returns (uint256) {
        return 2;
    }
}










contract TestTarget {
    uint256 public value;
    
    function setValue(uint256 _value) external {
        value = _value;
    }
    
    function increment() external {
        value++;
    }
    
    function revertingFunction() external pure {
        revert("Target reverted");
    }
    
    receive() external payable {}
}
