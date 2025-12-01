// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../src/AccountFactory.sol";
import "../src/SmartUserAccount.sol";
import { IEntryPoint } from "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { EntryPoint } from "../lib/account-abstraction/contracts/core/EntryPoint.sol";

contract AccountFactoryTest is Test {
    AccountFactory public factory;
    IEntryPoint public entryPoint;
    
    address public feeRecipient;
    address public owner;
    address public user1;
    address public user2;
    
    event AccountCreated(address indexed account, address indexed owner, uint256 salt);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    function setUp() public {
        feeRecipient = makeAddr("feeRecipient");
        owner = makeAddr("owner");
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        
        // Deploy mock EntryPoint
        entryPoint = IEntryPoint(address(new EntryPoint()));
        
        // Deploy factory
        vm.prank(owner);
        factory = new AccountFactory(entryPoint, feeRecipient);
    }

    /*//////////////////////////////////////////////////////////////
                        DEPLOYMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_FactoryDeployment() public {
        assertEq(address(factory.entryPoint()), address(entryPoint));
        assertEq(factory.PROTOCOL_FEE_RECIPIENT(), feeRecipient);
        assertEq(factory.owner(), owner);
        assertNotEq(address(factory.ACCOUNT_IMPLEMENTATION()), address(0));
    }

    function test_CannotDeployWithZeroEntryPoint() public {
        vm.expectRevert(ErrorLib.ZeroAddressNotAllowed.selector);
        new AccountFactory(IEntryPoint(address(0)), feeRecipient);
    }

    function test_CannotDeployWithZeroFeeRecipient() public {
        vm.expectRevert(ErrorLib.ZeroAddressNotAllowed.selector);
        new AccountFactory(entryPoint, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                        ACCOUNT CREATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CreateAccount() public {
        uint256 salt = 0;
        
        vm.expectEmit(false, true, false, true);
        emit AccountCreated(address(0), user1, salt);
        
        SmartUserAccount account = factory.createAccount(user1, salt);
        
        // Verify account properties
        assertEq(account.owner(), user1);
        assertEq(address(account.entryPoint()), address(entryPoint));
        assertEq(account.FEE_RECIPIENT(), feeRecipient);
    }

    function test_CreateAccount_DeterministicAddress() public {
        uint256 salt = 123;
        
        // Get predicted address
        address predictedAddress = factory.getPredictedAddress(user1, salt);
        
        // Create account
        SmartUserAccount account = factory.createAccount(user1, salt);
        
        // Verify address matches prediction
        assertEq(address(account), predictedAddress);
    }

    function test_CreateAccount_SameSaltReturnsSameAccount() public {
        uint256 salt = 456;
        
        // Create account first time
        SmartUserAccount account1 = factory.createAccount(user1, salt);
        
        // Try creating with same salt
        SmartUserAccount account2 = factory.createAccount(user1, salt);
        
        // Should return same account
        assertEq(address(account1), address(account2));
    }

    function test_CreateAccount_DifferentSaltsDifferentAddresses() public {
        uint256 salt1 = 100;
        uint256 salt2 = 200;
        
        SmartUserAccount account1 = factory.createAccount(user1, salt1);
        SmartUserAccount account2 = factory.createAccount(user1, salt2);
        
        // Different salts should produce different addresses
        assertTrue(address(account1) != address(account2));
    }

    function test_CreateAccount_DifferentOwnersDifferentAddresses() public {
        uint256 salt = 300;
        
        SmartUserAccount account1 = factory.createAccount(user1, salt);
        SmartUserAccount account2 = factory.createAccount(user2, salt);
        
        // Different owners with same salt should produce different addresses
        assertTrue(address(account1) != address(account2));
    }

    function test_CreateAccount_CannotUseZeroAddress() public {
        vm.expectRevert(ErrorLib.InvalidAddress.selector);
        factory.createAccount(address(0), 0);
    }

    function test_CreateMultipleAccounts() public {
        SmartUserAccount[] memory accounts = new SmartUserAccount[](5);
        
        for (uint256 i = 0; i < 5; i++) {
            accounts[i] = factory.createAccount(user1, i);
        }
        
        // Verify all accounts are different
        for (uint256 i = 0; i < 5; i++) {
            for (uint256 j = i + 1; j < 5; j++) {
                assertTrue(address(accounts[i]) != address(accounts[j]));
            }
        }
        
        // Verify smart accounts array
        assertEq(factory.smartAccounts(0), address(accounts[0]));
        assertEq(factory.smartAccounts(4), address(accounts[4]));
    }

    /*//////////////////////////////////////////////////////////////
                        PREDICTED ADDRESS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetPredictedAddress() public {
        uint256 salt = 999;
        
        address predicted = factory.getPredictedAddress(user1, salt);
        
        // Predicted address should not be zero
        assertNotEq(predicted, address(0));
        
        // Creating account should match prediction
        SmartUserAccount account = factory.createAccount(user1, salt);
        assertEq(address(account), predicted);
    }

    function testFuzz_PredictedAddressMatchesCreated(address accountOwner, uint256 salt) public {
        vm.assume(accountOwner != address(0));
        
        address predicted = factory.getPredictedAddress(accountOwner, salt);
        SmartUserAccount account = factory.createAccount(accountOwner, salt);
        
        assertEq(address(account), predicted);
    }

    /*//////////////////////////////////////////////////////////////
                        OWNERSHIP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_TransferFactoryOwnership() public {
        address newOwner = makeAddr("newOwner");
        
        vm.expectEmit(true, true, false, false);
        emit OwnershipTransferred(owner, newOwner);
        
        vm.prank(owner);
        factory.transferOwnership(newOwner);
        
        assertEq(factory.owner(), newOwner);
    }

    function test_TransferOwnership_OnlyOwner() public {
        address newOwner = makeAddr("newOwner");
        
        vm.prank(user1);
        vm.expectRevert(ErrorLib.NotAuthorized.selector);
        factory.transferOwnership(newOwner);
    }

    function test_TransferOwnership_CannotUseZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(ErrorLib.ZeroAddressNotAllowed.selector);
        factory.transferOwnership(address(0));
    }

    /*//////////////////////////////////////////////////////////////
                        STAKING TESTS
    //////////////////////////////////////////////////////////////*/

    function test_StakeFactory() public {
        uint32 unstakeDelay = 86400; // 1 day
        uint256 stakeAmount = 1 ether;
        
        vm.deal(owner, 10 ether);
        
        vm.prank(owner);
        factory.stakeFactory{value: stakeAmount}(unstakeDelay);
        
        // Verify stake was added to EntryPoint
        // (This would check EntryPoint state in a real test)
    }

    function test_StakeFactory_OnlyOwner() public {
        uint32 unstakeDelay = 86400;
        
        vm.deal(user1, 1 ether);
        vm.prank(user1);
        vm.expectRevert(ErrorLib.NotAuthorized.selector);
        factory.stakeFactory{value: 1 ether}(unstakeDelay);
    }

    function test_UnlockStake() public {
        vm.deal(owner, 10 ether);

        vm.prank(owner);
        factory.stakeFactory{value: 1 ether}(86400); // 1 day

        vm.prank(owner);
        factory.unlockStake();

        
        vm.warp(86400 + 1); // Move time forward to allow unstaking
        

        
        // Should not revert
    }

    function test_UnlockStake_OnlyOwner() public {
        vm.prank(user1);
        vm.expectRevert(ErrorLib.NotAuthorized.selector);
        factory.unlockStake();
    }

    function test_WithdrawStake() public {
            address payable withdrawAddress = payable(makeAddr("withdrawAddress"));

            vm.deal(owner, 10 ether);

            // Step 1: Stake for 1 day
            vm.prank(owner);
            factory.stakeFactory{value: 1 ether}(86400);

            // Step 2: Unlock stake (starts countdown)
            vm.prank(owner);
            factory.unlockStake();

            // Step 3: Warp PAST unlock timestamp
            vm.warp(block.timestamp + 86400 + 1);

            // Step 4: Withdraw
            vm.prank(owner);
            factory.withdrawStake(withdrawAddress);

            // Should not revert
    }


    function test_WithdrawStake_OnlyOwner() public {
        address payable withdrawAddress = payable(makeAddr("withdrawAddress"));
        
        vm.prank(user1);
        vm.expectRevert(ErrorLib.NotAuthorized.selector);
        factory.withdrawStake(withdrawAddress);
    }

    /*//////////////////////////////////////////////////////////////
                        INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CreatedAccountsHaveCorrectFeeRecipient() public {
        SmartUserAccount account1 = factory.createAccount(user1, 0);
        SmartUserAccount account2 = factory.createAccount(user2, 0);
        
        // Both accounts should have same fee recipient
        assertEq(account1.FEE_RECIPIENT(), feeRecipient);
        assertEq(account2.FEE_RECIPIENT(), feeRecipient);
        assertEq(account1.FEE_RECIPIENT(), account2.FEE_RECIPIENT());
    }

    function test_CreatedAccountsAreInitialized() public {
        SmartUserAccount account = factory.createAccount(user1, 0);
        
        // Account should be initialized
        assertEq(account.owner(), user1);
        
        // Should not be able to initialize again
        vm.expectRevert();
        account.initialize(user2);
    }

    function test_CreatedAccountUsesCorrectImplementation() public {
        SmartUserAccount account = factory.createAccount(user1, 0);
        
        // Get implementation address (from ERC1967 storage slot)
        bytes32 implementationSlot = bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        address implementation = address(uint160(uint256(vm.load(address(account), implementationSlot))));
        
        assertEq(implementation, address(factory.ACCOUNT_IMPLEMENTATION()));
    }

    /*//////////////////////////////////////////////////////////////
                        GAS OPTIMIZATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_CreateAccountGasCost() public {
        uint256 gasBefore = gasleft();
        factory.createAccount(user1, 0);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Log gas usage for monitoring
        console.log("Gas used for createAccount:", gasUsed);
        
        // Should be reasonable (less than 500k gas)
        assertLt(gasUsed, 500000);
    }

    function test_SecondCallToSameAccountCheaper() public {
        uint256 salt = 12345;
        
        uint256 gasBefore1 = gasleft();
        factory.createAccount(user1, salt);
        uint256 gasUsed1 = gasBefore1 - gasleft();
        
        uint256 gasBefore2 = gasleft();
        factory.createAccount(user1, salt);
        uint256 gasUsed2 = gasBefore2 - gasleft();
        
        // Second call should be much cheaper (just returns existing)
        assertLt(gasUsed2, gasUsed1 / 2);
    }

    /*//////////////////////////////////////////////////////////////
                        EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_CreateAccountWithMaxSalt() public {
        uint256 maxSalt = type(uint256).max;
        
        SmartUserAccount account = factory.createAccount(user1, maxSalt);
        
        assertEq(account.owner(), user1);
    }

    function test_MultipleUsersCanHaveSameSalt() public {
        uint256 salt = 777;
        
        SmartUserAccount account1 = factory.createAccount(user1, salt);
        SmartUserAccount account2 = factory.createAccount(user2, salt);
        
        // Different users with same salt should create different accounts
        assertTrue(address(account1) != address(account2));
        assertEq(account1.owner(), user1);
        assertEq(account2.owner(), user2);
    }
}

