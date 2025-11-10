//SPDX-Licence-Identifier: MIT
pragma solidity ^0.8.28;

import { Test, console } from "forge-std/Test.sol";
import "../src/AccountFactory.sol";
import "../src/SmartUserAccount.sol";
import "@account-abstraction/core/EntryPoint.sol";
import "@account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";
import { TestHelpers } from "./utils/Helpers.t.sol";

import { ErrorLib } from "../src/library/ErrorLib.sol"; 


contract SmartUserAccountTest is Test {
    EntryPoint public entryPoint;
    AccountFactory public factory;
    SmartUserAccount public account;
    SmartUserAccount public implementation;
    
    address public owner;
    uint256 public ownerKey;
    address public randomUser;
    address public beneficiary;
    
    // Target contract for testing execute
    TestTarget public target;
    
    event SimpleAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        // Setup accounts
        ownerKey = 0xA11CE;
        owner = vm.addr(ownerKey);
        randomUser = address(0x999);
        beneficiary = address(0x888);
        
        // Deploy contracts
        entryPoint = new EntryPoint();
        factory = new AccountFactory(IEntryPoint(address(entryPoint)));
        implementation = factory.ACCOUNT_IMPLEMENTATION();
        
        // Create smart account for owner
        account = factory.createAccount(owner, 0);
        
        // Deploy test target
        target = new TestTarget();
        
        // Fund the smart account
        vm.deal(address(account), 10 ether);
    }

     // Test 1: Initialization
    function test_Initialization() public {
        // Check entryPoint
        assertEq(address(account.entryPoint()), address(entryPoint), "EntryPoint mismatch");
        
        // Check owner
        assertEq(account.owner(), owner, "Owner mismatch");
        
        // Try to initialize again - should revert
        vm.expectRevert();
        account.initialize(randomUser);
    }

    // Test 2: execute() Behavior - Owner Call
    function test_Execute_OwnerCall() public {
        uint256 sendAmount = 1 ether;
        
        // Owner calls execute to send ETH
        vm.prank(owner);
        account.execute(beneficiary, sendAmount, "");
        
        // Verify ETH was sent
        assertEq(beneficiary.balance, sendAmount, "ETH not transferred");
    }

    // Test 2b: execute() Behavior - EntryPoint Call
    function test_Execute_EntryPointCall() public {
        uint256 sendAmount = 1 ether;
        
        // EntryPoint calls execute
        vm.prank(address(entryPoint));
        account.execute(beneficiary, sendAmount, "");
        
        // Verify ETH was sent
        assertEq(beneficiary.balance, sendAmount, "ETH not transferred");
    }

    // Test 2c: execute() Behavior - Random Address Reverts
    function test_Execute_RandomAddressReverts() public {
        // Random user tries to call execute
        vm.prank(randomUser);
        vm.expectRevert(ErrorLib.NotOwnerOrEntryPoint.selector);
        account.execute(beneficiary, 1 ether, "");
    }

    // Test 2d: execute() with calldata
    function test_Execute_WithCalldata() public {
        // Execute call to target contract
        bytes memory callData = abi.encodeWithSelector(TestTarget.setValue.selector, 42);
        
        vm.prank(owner);
        account.execute(address(target), 0, callData);
        
        // Verify target state changed
        assertEq(target.value(), 42, "Target function not executed");
    }

    // Test 3: executeBatch()
    function test_ExecuteBatch_Success() public {
        address[] memory targets = new address[](3);
        uint256[] memory values = new uint256[](3);
        bytes[] memory calls = new bytes[](3);
        
        // Prepare batch calls
        targets[0] = address(target);
        values[0] = 0;
        calls[0] = abi.encodeWithSelector(TestTarget.setValue.selector, 10);
        
        targets[1] = address(target);
        values[1] = 0;
        calls[1] = abi.encodeWithSelector(TestTarget.increment.selector);
        
        targets[2] = beneficiary;
        values[2] = 1 ether;
        calls[2] = "";
        
        // Execute batch
        vm.prank(owner);
        account.executeBatch(targets, values, calls);
        
        // Verify all executed
        assertEq(target.value(), 11, "Batch execution failed"); // 10 + 1
        assertEq(beneficiary.balance, 1 ether, "ETH transfer in batch failed");
    }

    // Test 3b: executeBatch() - Array Length Mismatch
    function test_ExecuteBatch_ArrayLengthMismatch() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](3); // Wrong length
        bytes[] memory calls = new bytes[](2);
        
        vm.prank(owner);
        vm.expectRevert(ErrorLib.WrongArrayLengths.selector);
        account.executeBatch(targets, values, calls);
    }

    // Test 4: validateUserOp() - Correct Signature
    function test_ValidateUserOp_CorrectSignature() public {
        // Build UserOp (User Operation)
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(SmartUserAccount.execute.selector, beneficiary, 1 ether, ""),
            accountGasLimits: TestHelpers.packGasLimits(100000, 100000),
            preVerificationGas: 21000,
            gasFees: TestHelpers.packGasFees(1 gwei, 2 gwei),
            paymasterAndData: "",
            signature: ""
        });

        
        // Get hash and sign
        bytes32 userOpHash = TestHelpers.getUserOpHash(vm, userOp, address(entryPoint), block.chainid);
        userOp.signature = TestHelpers.signUserOp(vm, userOp, address(entryPoint), block.chainid, ownerKey);
        
        // Call validateUserOp (only EntryPoint can call)
        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        
        // Should return 0 (success)
        assertEq(validationData, 0, "Validation should succeed");
    }

    // Test 4b:  validateUserOp() - Wrong Signature
    function test_ValidateUserOp_WrongSignature() public {
        // Build UserOp
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(SmartUserAccount.execute.selector, beneficiary, 1 ether, ""),
            accountGasLimits: TestHelpers.packGasLimits(100000, 100000),
            preVerificationGas: 21000,
            gasFees: TestHelpers.packGasFees(1 gwei, 2 gwei),
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 userOpHash = TestHelpers.getUserOpHash(vm, userOp, address(entryPoint), block.chainid);
        
        // Sign with wrong key
        uint256 wrongKey = 0xBAD;
        userOp.signature = TestHelpers.signUserOp(vm, userOp, address(entryPoint), block.chainid, wrongKey);
        
        // Call validateUserOp
        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        
        // Should return 1 (SIG_VALIDATION_FAILED)
        assertEq(validationData, 1, "Validation should fail");
    }

    // Test 4c: validateUserOp() - Non-EntryPoint Call
    function test_ValidateUserOp_NonEntryPointReverts() public {
        PackedUserOperation memory userOp;
        bytes32 userOpHash = bytes32(0);
        
        // Random user tries to call
        vm.prank(randomUser);
        vm.expectRevert(ErrorLib.NotEntryPoint.selector);
        account.validateUserOp(userOp, userOpHash, 0);
    }

     // Test 5:  UUPS Upgrade - Owner Can Upgrade
    function test_UUPS_OwnerCanUpgrade() public {
        // Deploy new implementation (V2)
        SmartUserAccountV2 newImplementation = new SmartUserAccountV2(IEntryPoint(address(entryPoint)));
        
        // Owner upgrades
        vm.prank(owner);
        account.upgradeToAndCall(address(newImplementation), "");
        
        // Verify state persisted
        assertEq(account.owner(), owner, "Owner should persist after upgrade");
        assertEq(address(account.entryPoint()), address(entryPoint), "EntryPoint should persist");
        
        // Test new functionality
        SmartUserAccountV2 accountV2 = SmartUserAccountV2(payable(address(account)));
        assertEq(accountV2.version(), 2, "New version function should work");
    }

     // Test 5b: UUPS Upgrade - Non-Owner Cannot Upgrade
    function test_UUPS_NonOwnerCannotUpgrade() public {
        SmartUserAccountV2 newImplementation = new SmartUserAccountV2(IEntryPoint(address(entryPoint)));
        
        // Random user tries to upgrade
        vm.prank(randomUser);
        vm.expectRevert();
        account.upgradeToAndCall(address(newImplementation), "");
    }

     // Test 6: Deposits - Add Deposit
    function test_Deposits_AddDeposit() public {
        uint256 depositAmount = 5 ether;
        vm.deal(owner, depositAmount);
        
        // Add deposit
        vm.prank(owner);
        account.addDeposit{value: depositAmount}();
        
        // Check balance in EntryPoint
        uint256 deposit = account.getDeposit();
        assertEq(deposit, depositAmount, "Deposit not reflected in EntryPoint");
    }

    // Test 6b:  Deposits - Withdraw Deposit
    function test_Deposits_WithdrawDeposit() public {
        // First add deposit
        uint256 depositAmount = 5 ether;
        vm.deal(owner, depositAmount);
        vm.prank(owner);
        account.addDeposit{value: depositAmount}();
        
        // Withdraw
        uint256 withdrawAmount = 2 ether;
        uint256 beneficiaryBalanceBefore = beneficiary.balance;
        
        vm.prank(owner);
        account.withdrawDepositTo(payable(beneficiary), withdrawAmount);
        
        // Check balances
        assertEq(account.getDeposit(), depositAmount - withdrawAmount, "Deposit not decreased");
        assertEq(beneficiary.balance, beneficiaryBalanceBefore + withdrawAmount, "Withdraw failed");
    }

    // Test 7: Reentrancy / Malicious Call
    function test_Execute_RevertBubblesUp() public {
        // Call target that reverts
        bytes memory callData = abi.encodeWithSelector(TestTarget.revertingFunction.selector);
        
        vm.prank(owner);
        vm.expectRevert("Target reverted");
        account.execute(address(target), 0, callData);
    }

    // Test ownership transfer
    function test_TransferOwnership() public {
        address newOwner = address(0x777);
        
        // Transfer ownership
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, newOwner);
        account.transferOwnership(newOwner);
        
        // Verify new owner
        assertEq(account.owner(), newOwner, "Ownership not transferred");
        
        // Old owner can't execute anymore
        vm.prank(owner);
        vm.expectRevert(ErrorLib.NotOwnerOrEntryPoint.selector);
        account.execute(beneficiary, 1 ether, "");
        
        // New owner can execute
        vm.prank(newOwner);
        account.execute(beneficiary, 1 ether, "");
    }

    // Test zero address ownership transfer fails
    function test_TransferOwnership_ZeroAddressReverts() public {
        vm.prank(owner);
        vm.expectRevert("new owner is zero address");
        account.transferOwnership(address(0));
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


// Upgraded Account V2 for testing
contract SmartUserAccountV2 is SmartUserAccount {
    constructor(IEntryPoint anEntryPoint) SmartUserAccount(anEntryPoint) {}
    
    function version() external pure returns (uint256) {
        return 2;
    }
}