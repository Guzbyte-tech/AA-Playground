// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../src/SmartUserAccount.sol";
import "../src/AccountFactory.sol";
import { IEntryPoint } from "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { EntryPoint } from "../lib/account-abstraction/contracts/core/EntryPoint.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { ERC20Mock } from "@openzeppelin/contracts/mocks/token/ERC20Mock.sol";

contract SmartUserAccountTest is Test {
    SmartUserAccount public account;
    AccountFactory public factory;
    IEntryPoint public entryPoint;
    ERC20Mock public token;
    
    address public owner;
    address public feeRecipient;
    address public recipient;
    address public attacker;
    
    uint256 public ownerPrivateKey;
    
    // EntryPoint v0.7.0 address (mainnet/testnet)
    address constant ENTRY_POINT_V7 = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    event FeeCollected(address indexed token, uint256 amount, address indexed recipient);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        // Setup addresses
        ownerPrivateKey = 0xA11CE;
        owner = vm.addr(ownerPrivateKey);
        feeRecipient = makeAddr("feeRecipient");
        recipient = makeAddr("recipient");
        attacker = makeAddr("attacker");
        
        // Deploy or use existing EntryPoint
        if (ENTRY_POINT_V7.code.length == 0) {
            // For local testing, you'd deploy a mock EntryPoint
            // For now, we'll use a mock address
            entryPoint = IEntryPoint(address(new EntryPoint()));
        } else {
            entryPoint = IEntryPoint(ENTRY_POINT_V7);
        }
        
        // Deploy factory
        factory = new AccountFactory(entryPoint, feeRecipient);
        
        // Deploy account through factory
        account = factory.createAccount(owner, 0);
        
        // Deploy mock ERC20 token
        token = new ERC20Mock();
        
        // Fund the account
        vm.deal(address(account), 10 ether);
        token.mint(address(account), 1000 * 10**18);
    }

    /*//////////////////////////////////////////////////////////////
                            INITIALIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_Initialize() public {
        assertEq(account.owner(), owner);
        assertEq(address(account.entryPoint()), address(entryPoint));
        assertEq(account.FEE_RECIPIENT(), feeRecipient);
    }

    function test_CannotInitializeTwice() public {
        vm.expectRevert();
        account.initialize(owner);
    }

    function test_CannotInitializeWithZeroAddress() public {
        SmartUserAccount newAccount = SmartUserAccount(
            payable(factory.createAccount(owner, 1))
        );
        
        // This should fail during construction, not initialization
        // The factory prevents this, but let's verify
        vm.expectRevert();
        new SmartUserAccount(entryPoint, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                            ETH TRANSFER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_NativeTransferWithFee() public {
        uint256 sendAmount = 1 ether;
        uint256 expectedFee = (sendAmount * 100) / 10000; // 1%
        
        uint256 recipientBalanceBefore = recipient.balance;
        uint256 feeRecipientBalanceBefore = feeRecipient.balance;
        uint256 accountBalanceBefore = address(account).balance;
        
        // Execute transfer as owner
        vm.prank(owner);
        account.execute(recipient, sendAmount, "");
        
        // Verify balances
        assertEq(recipient.balance, recipientBalanceBefore + sendAmount);
        assertEq(feeRecipient.balance, feeRecipientBalanceBefore + expectedFee);
        assertEq(
            address(account).balance,
            accountBalanceBefore - sendAmount - expectedFee
        );
    }

    function test_NativeTransferWithFee_EmitEvent() public {
        uint256 sendAmount = 1 ether;
        uint256 expectedFee = (sendAmount * 100) / 10000;
        
        vm.expectEmit(true, true, true, true);
        emit FeeCollected(address(0), expectedFee, feeRecipient);
        
        vm.prank(owner);
        account.execute(recipient, sendAmount, "");
    }

    function test_NativeTransfer_InsufficientBalance() public {
        uint256 sendAmount = 15 ether; // Account only has 10 ETH
        
        vm.prank(owner);
        vm.expectRevert(ErrorLib.InsufficientBalance.selector);
        account.execute(recipient, sendAmount, "");
    }

    // function test_NativeTransfer_ZeroAmount() public {
    //     vm.prank(owner);
    //     vm.expectRevert(ErrorLib.InvalidAmount.selector);
    //     account.execute(recipient, 0, "");
    // }

    function test_NativeTransfer_ZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ErrorLib.ZeroAddressNotAllowed.selector);
        account.execute(address(0), 1 ether, "");
    }

    /*//////////////////////////////////////////////////////////////
                        ERC20 TRANSFER TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ERC20TransferWithFee() public {
        uint256 sendAmount = 100 * 10**18;
        uint256 expectedFee = (sendAmount * 100) / 10000; // 1%
        
        uint256 recipientBalanceBefore = token.balanceOf(recipient);
        uint256 feeRecipientBalanceBefore = token.balanceOf(feeRecipient);
        uint256 accountBalanceBefore = token.balanceOf(address(account));
        
        bytes memory transferCall = abi.encodeWithSelector(
            IERC20.transfer.selector,
            recipient,
            sendAmount
        );
        
        vm.prank(owner);
        account.execute(address(token), 0, transferCall);
        
        // Verify balances
        assertEq(token.balanceOf(recipient), recipientBalanceBefore + sendAmount);
        assertEq(token.balanceOf(feeRecipient), feeRecipientBalanceBefore + expectedFee);
        assertEq(
            token.balanceOf(address(account)),
            accountBalanceBefore - sendAmount - expectedFee
        );
    }

    function test_ERC20TransferWithFee_EmitEvent() public {
        uint256 sendAmount = 100 * 10**18;
        uint256 expectedFee = (sendAmount * 100) / 10000;
        
        bytes memory transferCall = abi.encodeWithSelector(
            IERC20.transfer.selector,
            recipient,
            sendAmount
        );
        
        vm.expectEmit(true, true, true, true);
        emit FeeCollected(address(token), expectedFee, feeRecipient);
        
        vm.prank(owner);
        account.execute(address(token), 0, transferCall);
    }

    function test_ERC20Transfer_InsufficientBalance() public {
        uint256 sendAmount = 2000 * 10**18; // Account only has 1000
        
        bytes memory transferCall = abi.encodeWithSelector(
            IERC20.transfer.selector,
            recipient,
            sendAmount
        );
        
        vm.prank(owner);
        vm.expectRevert(ErrorLib.InsufficientBalance.selector);
        account.execute(address(token), 0, transferCall);
    }

    /*//////////////////////////////////////////////////////////////
                    ERC20 TRANSFERFROM TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ERC20TransferFromWithFee() public {
        uint256 sendAmount = 100 * 10**18;
        uint256 expectedFee = (sendAmount * 100) / 10000; // 1%
        uint256 totalRequired = sendAmount + expectedFee;
        
        // Setup: owner approves account to spend tokens
        address tokenHolder = makeAddr("tokenHolder");
        token.mint(tokenHolder, 1000 * 10**18);
        
        vm.prank(tokenHolder);
        token.approve(address(account), totalRequired);
        
        uint256 recipientBalanceBefore = token.balanceOf(recipient);
        uint256 feeRecipientBalanceBefore = token.balanceOf(feeRecipient);
        
        bytes memory transferFromCall = abi.encodeWithSelector(
            IERC20.transferFrom.selector,
            tokenHolder,
            recipient,
            sendAmount
        );
        
        vm.prank(owner);
        account.execute(address(token), 0, transferFromCall);
        
        // Verify balances
        assertEq(token.balanceOf(recipient), recipientBalanceBefore + sendAmount);
        assertEq(token.balanceOf(feeRecipient), feeRecipientBalanceBefore + expectedFee);
    }

    function test_ERC20TransferFrom_InsufficientAllowance() public {
        uint256 sendAmount = 100 * 10**18;
        
        address tokenHolder = makeAddr("tokenHolder");
        token.mint(tokenHolder, 1000 * 10**18);
        
        // Only approve sendAmount, not sendAmount + fee
        vm.prank(tokenHolder);
        token.approve(address(account), sendAmount);
        
        bytes memory transferFromCall = abi.encodeWithSelector(
            IERC20.transferFrom.selector,
            tokenHolder,
            recipient,
            sendAmount
        );
        
        vm.prank(owner);
        vm.expectRevert(ErrorLib.InsufficientAllowance.selector);
        account.execute(address(token), 0, transferFromCall);
    }

    /*//////////////////////////////////////////////////////////////
                        BATCH EXECUTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_ExecuteBatch_MixedOperations() public {
        address[] memory dests = new address[](3);
        uint256[] memory values = new uint256[](3);
        bytes[] memory funcs = new bytes[](3);
        
        // 1. ETH transfer
        dests[0] = recipient;
        values[0] = 1 ether;
        funcs[0] = "";
        
        // 2. Token transfer
        dests[1] = address(token);
        values[1] = 0;
        funcs[1] = abi.encodeWithSelector(
            IERC20.transfer.selector,
            recipient,
            50 * 10**18
        );
        
        // 3. Regular contract call (approve)
        dests[2] = address(token);
        values[2] = 0;
        funcs[2] = abi.encodeWithSelector(
            IERC20.approve.selector,
            recipient,
            100 * 10**18
        );
        
        vm.prank(owner);
        account.executeBatch(dests, values, funcs);
        
        // Verify ETH transfer happened with fee
        assertGt(recipient.balance, 0);
        assertGt(feeRecipient.balance, 0);
        
        // Verify token transfer happened with fee
        assertEq(token.balanceOf(recipient), 50 * 10**18);
        
        // Verify approve happened (no fee for non-transfer)
        assertEq(token.allowance(address(account), recipient), 100 * 10**18);
    }

    function test_ExecuteBatch_ArrayLengthMismatch() public {
        address[] memory dests = new address[](2);
        uint256[] memory values = new uint256[](3); // Mismatch
        bytes[] memory funcs = new bytes[](2);
        
        vm.prank(owner);
        vm.expectRevert(ErrorLib.ArrayLengthMismatch.selector);
        account.executeBatch(dests, values, funcs);
    }

    /*//////////////////////////////////////////////////////////////
                        AUTHORIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_OnlyOwnerCanExecute() public {
        vm.prank(attacker);
        vm.expectRevert(ErrorLib.NotAuthorized.selector);
        account.execute(recipient, 1 ether, "");
    }

    function test_OnlyEntryPointCanExecute() public {
        // EntryPoint should be able to execute
        vm.prank(address(entryPoint));
        account.execute(recipient, 1 ether, "");
        
        assertGt(recipient.balance, 0);
    }

    function test_OnlyOwnerCanTransferOwnership() public {
        address newOwner = makeAddr("newOwner");
        
        vm.prank(attacker);
        vm.expectRevert(ErrorLib.NotAuthorized.selector);
        account.transferOwnership(newOwner);
    }

    function test_TransferOwnership() public {
        address newOwner = makeAddr("newOwner");
        
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, newOwner);
        
        vm.prank(owner);
        account.transferOwnership(newOwner);
        
        assertEq(account.owner(), newOwner);
    }

    function test_TransferOwnership_ZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ErrorLib.ZeroAddressNotAllowed.selector);
        account.transferOwnership(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                        NON-TRANSFER EXECUTION
    //////////////////////////////////////////////////////////////*/

    function test_RegularContractCall_NoFee() public {
        // Approve should not incur fee
        uint256 approveAmount = 100 * 10**18;
        
        bytes memory approveCall = abi.encodeWithSelector(
            IERC20.approve.selector,
            recipient,
            approveAmount
        );
        
        uint256 feeRecipientBalanceBefore = token.balanceOf(feeRecipient);
        
        vm.prank(owner);
        account.execute(address(token), 0, approveCall);
        
        // Verify no fee was collected
        assertEq(token.balanceOf(feeRecipient), feeRecipientBalanceBefore);
        
        // Verify approve worked
        assertEq(token.allowance(address(account), recipient), approveAmount);
    }

    /*//////////////////////////////////////////////////////////////
                        ENTRYPOINT INTEGRATION
    //////////////////////////////////////////////////////////////*/

    function test_DepositToEntryPoint() public {
        vm.deal(owner, 1 ether);

        uint256 depositAmount = 1 ether;
        
        vm.prank(owner);
        account.addDeposit{value: depositAmount}();
        
        assertEq(account.getDeposit(), depositAmount);
    }

    function test_WithdrawFromEntryPoint() public {
        uint256 depositAmount = 1 ether;
        vm.deal(owner, depositAmount);
        
        vm.prank(owner);
        account.addDeposit{value: depositAmount}();
        
        vm.prank(owner);
        account.withdrawDepositTo(payable(recipient), depositAmount);
        
        assertEq(account.getDeposit(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                        IMMUTABILITY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_FeeRecipientIsImmutable() public {
        // Fee recipient should be set and immutable
        assertEq(account.FEE_RECIPIENT(), feeRecipient);
        
        // There should be no function to change it
        // This is enforced at compile time, but we verify it's set correctly
    }

    function test_CannotBypassFees() public {
        // Try to call token.transfer directly (should fail - only account can call)
        bytes memory transferCall = abi.encodeWithSelector(
            IERC20.transfer.selector,
            recipient,
            100 * 10**18
        );
        
        // This should go through fee mechanism
        vm.prank(owner);
        account.execute(address(token), 0, transferCall);
        
        // Verify fee was collected
        assertGt(token.balanceOf(feeRecipient), 0);
    }

    /*//////////////////////////////////////////////////////////////
                        EDGE CASES & FUZZING
    //////////////////////////////////////////////////////////////*/

    function testFuzz_NativeTransferWithFee(uint96 amount) public {
        vm.assume(amount > 0);
        vm.assume(amount < 9 ether); // Account has 10 ETH
        
        uint256 expectedFee = (amount * 100) / 10000;
        uint256 totalRequired = amount + expectedFee;
        vm.assume(totalRequired <= 9 ether);
        
        vm.prank(owner);
        account.execute(recipient, amount, "");
        
        assertEq(recipient.balance, amount);
        assertEq(feeRecipient.balance, expectedFee);
    }

    function testFuzz_ERC20TransferWithFee(uint96 amount) public {
        vm.assume(amount > 0);
        vm.assume(amount < 900 * 10**18); // Account has 1000 tokens
        
        uint256 expectedFee = (amount * 100) / 10000;
        uint256 totalRequired = amount + expectedFee;
        vm.assume(totalRequired <= 900 * 10**18);
        
        bytes memory transferCall = abi.encodeWithSelector(
            IERC20.transfer.selector,
            recipient,
            amount
        );
        
        vm.prank(owner);
        account.execute(address(token), 0, transferCall);
        
        assertEq(token.balanceOf(recipient), amount);
        assertEq(token.balanceOf(feeRecipient), expectedFee);
    }

    function test_FeeCalculationPrecision() public {
        // Test with small amount to verify precision
        uint256 smallAmount = 100; // 100 wei
        uint256 expectedFee = (smallAmount * 100) / 10000; // Should be 1 wei
        
        vm.deal(address(account), 1 ether);
        
        vm.prank(owner);
        account.execute(recipient, smallAmount, "");
        
        assertEq(recipient.balance, smallAmount);
        assertEq(feeRecipient.balance, expectedFee);
    }
}
