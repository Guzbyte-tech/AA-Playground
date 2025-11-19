//SPDX-Licence-Identifier: MIT
pragma solidity ^0.8.12;

import { Test, console } from "forge-std/Test.sol";
import "../src/AccountFactory.sol";
import "../src/SmartUserAccount.sol";
import "../lib/account-abstraction/contracts/core/EntryPoint.sol";
import "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "../lib/account-abstraction/contracts/interfaces/UserOperation.sol";
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
    
    TestTarget public target;
    
    event SimpleAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        ownerKey = 0xA11CE;
        owner = vm.addr(ownerKey);
        randomUser = address(0x999);
        beneficiary = address(0x888);
        
        entryPoint = new EntryPoint();
        factory = new AccountFactory(IEntryPoint(address(entryPoint)));
        implementation = factory.ACCOUNT_IMPLEMENTATION();
        
        account = factory.createAccount(owner, 0);
        
        target = new TestTarget();
        
        vm.deal(address(account), 10 ether);
    }

    function test_Initialization() public {
        assertEq(address(account.entryPoint()), address(entryPoint), "EntryPoint mismatch");
        assertEq(account.owner(), owner, "Owner mismatch");
        
        vm.expectRevert();
        account.initialize(randomUser);
    }

    function test_Execute_OwnerCall() public {
        uint256 sendAmount = 1 ether;
        
        vm.prank(owner);
        account.execute(beneficiary, sendAmount, "");
        
        assertEq(beneficiary.balance, sendAmount, "ETH not transferred");
    }

    function test_Execute_EntryPointCall() public {
        uint256 sendAmount = 1 ether;
        
        vm.prank(address(entryPoint));
        account.execute(beneficiary, sendAmount, "");
        
        assertEq(beneficiary.balance, sendAmount, "ETH not transferred");
    }

    function test_Execute_RandomAddressReverts() public {
        vm.prank(randomUser);
        vm.expectRevert(ErrorLib.NotOwnerOrEntryPoint.selector);
        account.execute(beneficiary, 1 ether, "");
    }

    function test_Execute_WithCalldata() public {
        bytes memory callData = abi.encodeWithSelector(TestTarget.setValue.selector, 42);
        
        vm.prank(owner);
        account.execute(address(target), 0, callData);
        
        assertEq(target.value(), 42, "Target function not executed");
    }

    function test_ExecuteBatch_Success() public {
        address[] memory targets = new address[](3);
        uint256[] memory values = new uint256[](3);
        bytes[] memory calls = new bytes[](3);
        
        targets[0] = address(target);
        values[0] = 0;
        calls[0] = abi.encodeWithSelector(TestTarget.setValue.selector, 10);
        
        targets[1] = address(target);
        values[1] = 0;
        calls[1] = abi.encodeWithSelector(TestTarget.increment.selector);
        
        targets[2] = beneficiary;
        values[2] = 1 ether;
        calls[2] = "";
        
        vm.prank(owner);
        account.executeBatch(targets, values, calls);
        
        assertEq(target.value(), 11, "Batch execution failed");
        assertEq(beneficiary.balance, 1 ether, "ETH transfer in batch failed");
    }

    function test_ExecuteBatch_ArrayLengthMismatch() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](3);
        bytes[] memory calls = new bytes[](2);
        
        vm.prank(owner);
        vm.expectRevert(ErrorLib.WrongArrayLengths.selector);
        account.executeBatch(targets, values, calls);
    }

    function test_ValidateUserOp_CorrectSignature() public {
        UserOperation memory userOp = UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(SmartUserAccount.execute.selector, beneficiary, 1 ether, ""),
            callGasLimit: 100000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 2 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 userOpHash = TestHelpers.getUserOpHash(vm, userOp, address(entryPoint), block.chainid);
        userOp.signature = TestHelpers.signUserOp(vm, userOp, address(entryPoint), block.chainid, ownerKey);
        
        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        
        assertEq(validationData, 0, "Validation should succeed");
    }

    function test_ValidateUserOp_WrongSignature() public {
        UserOperation memory userOp = UserOperation({
            sender: address(account),
            nonce: 0,
            initCode: "",
            callData: abi.encodeWithSelector(SmartUserAccount.execute.selector, beneficiary, 1 ether, ""),
            callGasLimit: 100000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 2 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 userOpHash = TestHelpers.getUserOpHash(vm, userOp, address(entryPoint), block.chainid);
        
        uint256 wrongKey = 0xBAD;
        userOp.signature = TestHelpers.signUserOp(vm, userOp, address(entryPoint), block.chainid, wrongKey);
        
        vm.prank(address(entryPoint));
        uint256 validationData = account.validateUserOp(userOp, userOpHash, 0);
        
        assertEq(validationData, 1, "Validation should fail");
    }

    function test_ValidateUserOp_NonEntryPointReverts() public {
        UserOperation memory userOp;
        bytes32 userOpHash = bytes32(0);
        
        vm.prank(randomUser);
        vm.expectRevert(ErrorLib.NotEntryPoint.selector);
        account.validateUserOp(userOp, userOpHash, 0);
    }

    function test_UUPS_OwnerCanUpgrade() public {
        SmartUserAccountV2 newImplementation = new SmartUserAccountV2(IEntryPoint(address(entryPoint)));
        
        vm.prank(owner);
        account.upgradeToAndCall(address(newImplementation), "");
        
        assertEq(account.owner(), owner, "Owner should persist after upgrade");
        assertEq(address(account.entryPoint()), address(entryPoint), "EntryPoint should persist");
        
        SmartUserAccountV2 accountV2 = SmartUserAccountV2(payable(address(account)));
        assertEq(accountV2.version(), 2, "New version function should work");
    }

    function test_UUPS_NonOwnerCannotUpgrade() public {
        SmartUserAccountV2 newImplementation = new SmartUserAccountV2(IEntryPoint(address(entryPoint)));
        
        vm.prank(randomUser);
        vm.expectRevert();
        account.upgradeToAndCall(address(newImplementation), "");
    }

    function test_Deposits_AddDeposit() public {
        uint256 depositAmount = 5 ether;
        vm.deal(owner, depositAmount);
        
        vm.prank(owner);
        account.addDeposit{value: depositAmount}();
        
        uint256 deposit = account.getDeposit();
        assertEq(deposit, depositAmount, "Deposit not reflected in EntryPoint");
    }

    function test_Deposits_WithdrawDeposit() public {
        uint256 depositAmount = 5 ether;
        vm.deal(owner, depositAmount);
        vm.prank(owner);
        account.addDeposit{value: depositAmount}();
        
        uint256 withdrawAmount = 2 ether;
        uint256 beneficiaryBalanceBefore = beneficiary.balance;
        
        vm.prank(owner);
        account.withdrawDepositTo(payable(beneficiary), withdrawAmount);
        
        assertEq(account.getDeposit(), depositAmount - withdrawAmount, "Deposit not decreased");
        assertEq(beneficiary.balance, beneficiaryBalanceBefore + withdrawAmount, "Withdraw failed");
    }

    function test_Execute_RevertBubblesUp() public {
        bytes memory callData = abi.encodeWithSelector(TestTarget.revertingFunction.selector);
        
        vm.prank(owner);
        vm.expectRevert("Target reverted");
        account.execute(address(target), 0, callData);
    }

    function test_TransferOwnership() public {
        address newOwner = address(0x777);
        
        vm.prank(owner);
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, newOwner);
        account.transferOwnership(newOwner);
        
        assertEq(account.owner(), newOwner, "Ownership not transferred");
        
        vm.prank(owner);
        vm.expectRevert(ErrorLib.NotOwnerOrEntryPoint.selector);
        account.execute(beneficiary, 1 ether, "");
        
        vm.prank(newOwner);
        account.execute(beneficiary, 1 ether, "");
    }

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

contract SmartUserAccountV2 is SmartUserAccount {
    constructor(IEntryPoint anEntryPoint) SmartUserAccount(anEntryPoint) {}
    
    function version() external pure returns (uint256) {
        return 2;
    }
}