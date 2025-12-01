// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "../src/PayMaster.sol";
import { IEntryPoint } from "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { EntryPoint } from "../lib/account-abstraction/contracts/core/EntryPoint.sol";
import { PackedUserOperation } from "../lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract PaymasterTest is Test {
    using MessageHashUtils for bytes32;
    using ECDSA for bytes32;

    PayMaster public paymaster;
    IEntryPoint public entryPoint;
    
    address public owner;
    address public verifyingSigner;
    address public user1;
    address public user2;
    address public bundler;
    
    uint256 public verifyingSignerPrivateKey;
    uint256 public maxGasPerOperation = 1 ether;

    event UserWhitelisted(address indexed user, bool status);
    event GasLimitSet(address indexed user, uint256 limit);
    event GasSponsored(address indexed user, uint256 actualGasCost);
    event WhitelistModeChanged(bool enabled);

    function setUp() public {
        owner = makeAddr("owner");
        verifyingSignerPrivateKey = 0xB0B;
        verifyingSigner = vm.addr(verifyingSignerPrivateKey);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        bundler = makeAddr("bundler");
        
        // Deploy mock EntryPoint
        entryPoint = IEntryPoint(address(new EntryPoint()));
        
        // Deploy paymaster
        vm.prank(owner);
        paymaster = new PayMaster(entryPoint, verifyingSigner, maxGasPerOperation);
        
        // Fund Owner
        vm.deal(owner, 10 ether);

        
        // Fund paymaster
        vm.deal(address(paymaster), 10 ether);
        vm.prank(owner);
        paymaster.deposit{value: 5 ether}();
    }

    /*//////////////////////////////////////////////////////////////
                        DEPLOYMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_PaymasterDeployment() public {
        assertEq(address(paymaster.entryPoint()), address(entryPoint));
        assertEq(paymaster.verifyingSigner(), verifyingSigner);
        assertEq(paymaster.maxGasPerOperation(), maxGasPerOperation);
        assertEq(paymaster.whitelistEnabled(), false);
        assertEq(paymaster.owner(), owner);
    }

    function test_CannotDeployWithZeroSigner() public {
        vm.expectRevert(PayMaster.ZeroAddressNotAllowed.selector);
        new PayMaster(entryPoint, address(0), maxGasPerOperation);
    }

    /*//////////////////////////////////////////////////////////////
                        WHITELIST MODE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_EnableWhitelistMode() public {
        vm.expectEmit(false, false, false, true);
        emit WhitelistModeChanged(true);
        
        vm.prank(owner);
        paymaster.setWhitelistMode(true);
        
        assertTrue(paymaster.whitelistEnabled());
    }

    function test_AddToWhitelist() public {
        vm.expectEmit(true, false, false, true);
        emit UserWhitelisted(user1, true);
        
        vm.prank(owner);
        paymaster.setWhitelist(user1, true);
        
        assertTrue(paymaster.whitelist(user1));
    }

    function test_RemoveFromWhitelist() public {
        vm.prank(owner);
        paymaster.setWhitelist(user1, true);
        
        vm.expectEmit(true, false, false, true);
        emit UserWhitelisted(user1, false);
        
        vm.prank(owner);
        paymaster.setWhitelist(user1, false);
        
        assertFalse(paymaster.whitelist(user1));
    }

    function test_BatchWhitelist() public {
        address[] memory users = new address[](3);
        users[0] = user1;
        users[1] = user2;
        users[2] = makeAddr("user3");
        
        vm.prank(owner);
        paymaster.batchSetWhitelist(users, true);
        
        assertTrue(paymaster.whitelist(user1));
        assertTrue(paymaster.whitelist(user2));
        assertTrue(paymaster.whitelist(users[2]));
    }

    function test_WhitelistMode_OnlyOwner() public {
        vm.prank(user1);
        vm.expectRevert();
        paymaster.setWhitelist(user2, true);
    }

    function test_WhitelistMode_CannotAddZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert(PayMaster.ZeroAddressNotAllowed.selector);
        paymaster.setWhitelist(address(0), true);
    }

    /*//////////////////////////////////////////////////////////////
                        GAS LIMIT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetGasLimit() public {
        uint256 limit = 0.5 ether;
        
        vm.expectEmit(true, false, false, true);
        emit GasLimitSet(user1, limit);
        
        vm.prank(owner);
        paymaster.setGasLimit(user1, limit);
        
        assertEq(paymaster.gasLimits(user1), limit);
    }

    function test_BatchSetGasLimits() public {
        address[] memory users = new address[](2);
        users[0] = user1;
        users[1] = user2;
        
        uint256[] memory limits = new uint256[](2);
        limits[0] = 0.5 ether;
        limits[1] = 1 ether;
        
        vm.prank(owner);
        paymaster.batchSetGasLimits(users, limits);
        
        assertEq(paymaster.gasLimits(user1), 0.5 ether);
        assertEq(paymaster.gasLimits(user2), 1 ether);
    }

    function test_GetRemainingGasAllowance_Unlimited() public {
        // User with no limit should have unlimited allowance
        uint256 remaining = paymaster.getRemainingGasAllowance(user1);
        assertEq(remaining, type(uint256).max);
    }

    function test_GetRemainingGasAllowance_WithLimit() public {
        uint256 limit = 1 ether;
        
        vm.prank(owner);
        paymaster.setGasLimit(user1, limit);
        
        uint256 remaining = paymaster.getRemainingGasAllowance(user1);
        assertEq(remaining, limit);
    }

    function test_ResetGasSpent() public {
        vm.prank(owner);
        paymaster.setGasLimit(user1, 1 ether);
        
        // Simulate some gas spent (we'll set it directly for testing)
        vm.store(
            address(paymaster),
            keccak256(abi.encode(user1, 3)), // gasSpent mapping slot
            bytes32(uint256(0.5 ether))
        );
        
        vm.prank(owner);
        paymaster.resetGasSpent(user1);
        
        assertEq(paymaster.gasSpent(user1), 0);
    }

    function test_BatchResetGasSpent() public {
        address[] memory users = new address[](2);
        users[0] = user1;
        users[1] = user2;
        
        vm.prank(owner);
        paymaster.batchResetGasSpent(users);
        
        assertEq(paymaster.gasSpent(user1), 0);
        assertEq(paymaster.gasSpent(user2), 0);
    }

    /*//////////////////////////////////////////////////////////////
                    SIGNATURE GENERATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_GetHash() public view {
        PackedUserOperation memory userOp = _createMockUserOp(user1);
        uint48 validUntil = uint48(block.timestamp + 3600);
        uint48 validAfter = uint48(block.timestamp);
        
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        
        // Hash should not be zero
        assertNotEq(hash, bytes32(0));
    }

    function test_SignatureGeneration() public {
        PackedUserOperation memory userOp = _createMockUserOp(user1);
        uint48 validUntil = uint48(block.timestamp + 3600);
        uint48 validAfter = uint48(block.timestamp);
        
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifyingSignerPrivateKey, ethSignedHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        // Verify signature recovers to verifying signer
        address recovered = ethSignedHash.recover(signature);
        assertEq(recovered, verifyingSigner);
    }

    /*//////////////////////////////////////////////////////////////
                    VALIDATION TESTS (SIGNATURE MODE)
    //////////////////////////////////////////////////////////////*/

    function test_ValidatePaymasterUserOp_ValidSignature() public {
        // Set to signature mode
        vm.prank(owner);
        paymaster.setWhitelistMode(false);
        
        PackedUserOperation memory userOp = _createMockUserOp(user1);
        uint48 validUntil = uint48(block.timestamp + 3600);
        uint48 validAfter = uint48(block.timestamp);
        
        // Generate signature
        bytes memory signature = _generateSignature(userOp, validUntil, validAfter);
        
        // Construct paymasterAndData
        userOp.paymasterAndData = _constructPaymasterAndData(validUntil, validAfter, signature);
        
        bytes32 userOpHash = keccak256("userOpHash");
        uint256 maxCost = 0.1 ether;
        
        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            userOpHash,
            maxCost
        );
        
        // Should return success (validationData low bits should be 0)
        assertEq(validationData & 1, 0);
        assertGt(context.length, 0);
    }

    function test_ValidatePaymasterUserOp_InvalidSignature() public {
        vm.prank(owner);
        paymaster.setWhitelistMode(false);
        
        PackedUserOperation memory userOp = _createMockUserOp(user1);
        uint48 validUntil = uint48(block.timestamp + 3600);
        uint48 validAfter = uint48(block.timestamp);
        
        // Generate invalid signature (use different private key)
        uint256 wrongPrivateKey = 0xBAD;
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongPrivateKey, ethSignedHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        
        userOp.paymasterAndData = _constructPaymasterAndData(validUntil, validAfter, signature);
        
        bytes32 userOpHash = keccak256("userOpHash");
        uint256 maxCost = 0.1 ether;
        
        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            userOpHash,
            maxCost
        );
        
        // Should return failure (validationData low bit should be 1)
        assertEq(validationData & 1, 1);
        assertEq(context.length, 0);
    }

    function test_ValidatePaymasterUserOp_ExceedsMaxGas() public {
        PackedUserOperation memory userOp = _createMockUserOp(user1);
        uint48 validUntil = uint48(block.timestamp + 3600);
        uint48 validAfter = uint48(block.timestamp);
        
        bytes memory signature = _generateSignature(userOp, validUntil, validAfter);
        userOp.paymasterAndData = _constructPaymasterAndData(validUntil, validAfter, signature);
        
        bytes32 userOpHash = keccak256("userOpHash");
        uint256 maxCost = maxGasPerOperation + 1; // Exceeds limit
        
        vm.prank(address(entryPoint));
        vm.expectRevert(PayMaster.GasCostTooHigh.selector);
        paymaster.validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    /*//////////////////////////////////////////////////////////////
                    VALIDATION TESTS (WHITELIST MODE)
    //////////////////////////////////////////////////////////////*/

    function test_ValidatePaymasterUserOp_WhitelistMode_Success() public {
        // Enable whitelist mode and add user
        vm.startPrank(owner);
        paymaster.setWhitelistMode(true);
        paymaster.setWhitelist(user1, true);
        vm.stopPrank();
        
        PackedUserOperation memory userOp = _createMockUserOp(user1);
        bytes32 userOpHash = keccak256("userOpHash");
        uint256 maxCost = 0.1 ether;
        
        vm.prank(address(entryPoint));
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            userOpHash,
            maxCost
        );
        
        // Should succeed
        assertEq(validationData, 0);
        assertGt(context.length, 0);
    }

    function test_ValidatePaymasterUserOp_WhitelistMode_NotWhitelisted() public {
        vm.prank(owner);
        paymaster.setWhitelistMode(true);
        // Don't add user1 to whitelist
        
        PackedUserOperation memory userOp = _createMockUserOp(user1);
        bytes32 userOpHash = keccak256("userOpHash");
        uint256 maxCost = 0.1 ether;
        
        vm.prank(address(entryPoint));
        vm.expectRevert(PayMaster.UserNotWhitelisted.selector);
        paymaster.validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    function test_ValidatePaymasterUserOp_WhitelistMode_GasLimitExceeded() public {
        // Setup whitelist with gas limit
        vm.startPrank(owner);
        paymaster.setWhitelistMode(true);
        paymaster.setWhitelist(user1, true);
        paymaster.setGasLimit(user1, 0.2 ether);
        vm.stopPrank();
        
        // Set gas already spent
        vm.store(
            address(paymaster),
            keccak256(abi.encode(user1, 3)),
            bytes32(uint256(0.15 ether))
        );
        
        PackedUserOperation memory userOp = _createMockUserOp(user1);
        bytes32 userOpHash = keccak256("userOpHash");
        uint256 maxCost = 0.7 ether; // 0.15 + 0.1 = 0.25 > 0.2 limit
        
        vm.prank(address(entryPoint));
        vm.expectRevert(PayMaster.GasLimitExceeded.selector);
        paymaster.validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    /*//////////////////////////////////////////////////////////////
                        POSTOP TESTS
    //////////////////////////////////////////////////////////////*/

    function test_PostOp_TracksGasSpent() public {
        // Setup
        vm.startPrank(owner);
        paymaster.setWhitelistMode(true);
        paymaster.setWhitelist(user1, true);
        paymaster.setGasLimit(user1, 1 ether);
        vm.stopPrank();
        
        uint256 maxCost = 0.1 ether;
        bytes memory context = abi.encode(user1, maxCost, true);
        uint256 actualGasCost = 0.05 ether;
        
        vm.expectEmit(true, false, false, true);
        emit GasSponsored(user1, actualGasCost);
        
        vm.prank(address(entryPoint));
        paymaster.postOp(
            IPaymaster.PostOpMode.opSucceeded,
            context,
            actualGasCost,
            1 gwei
        );
        
        assertEq(paymaster.gasSpent(user1), actualGasCost);
    }

    function test_PostOp_OnlyEntryPoint() public {
        bytes memory context = abi.encode(user1, 0.1 ether, true);
        
        vm.prank(user1);
        vm.expectRevert(PayMaster.NotFromEntryPoint.selector);
        paymaster.postOp(
            IPaymaster.PostOpMode.opSucceeded,
            context,
            0.05 ether,
            1 gwei
        );
    }

    /*//////////////////////////////////////////////////////////////
                        ADMIN FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_SetVerifyingSigner() public {
        address newSigner = makeAddr("newSigner");
        
        vm.prank(owner);
        paymaster.setVerifyingSigner(newSigner);
        
        assertEq(paymaster.verifyingSigner(), newSigner);
    }

    function test_SetVerifyingSigner_OnlyOwner() public {
        address newSigner = makeAddr("newSigner");
        
        vm.prank(user1);
        vm.expectRevert();
        paymaster.setVerifyingSigner(newSigner);
    }

    function test_SetMaxGasPerOperation() public {
        uint256 newMax = 2 ether;
        
        vm.prank(owner);
        paymaster.setMaxGasPerOperation(newMax);
        
        assertEq(paymaster.maxGasPerOperation(), newMax);
    }

    function test_Deposit() public {
        uint256 depositAmount = 1 ether;
        // uint256 balanceBefore = paymaster.getDeposit();
        uint256 balanceBefore = entryPoint.balanceOf(address(paymaster));
        
        vm.deal(user1, depositAmount);
        vm.prank(user1);
        paymaster.deposit{value: depositAmount}();

        uint256 balanceAfter = entryPoint.balanceOf(address(paymaster));
        assertEq(balanceAfter, balanceBefore + depositAmount);


        
        // Note: getDeposit returns EntryPoint balance
        // For testing, we just verify the function doesn't revert
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _createMockUserOp(address sender) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(uint256(150000) << 128 | uint256(150000)),
            preVerificationGas: 100000,
            gasFees: bytes32(uint256(1 gwei) << 128 | uint256(2 gwei)),
            paymasterAndData: "",
            signature: ""
        });
    }

    function _generateSignature(
        PackedUserOperation memory userOp,
        uint48 validUntil,
        uint48 validAfter
    ) internal view returns (bytes memory) {
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(verifyingSignerPrivateKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    function _constructPaymasterAndData(
        uint48 validUntil,
        uint48 validAfter,
        bytes memory signature
    ) internal view returns (bytes memory) {
        return abi.encodePacked(
            address(paymaster),           // 20 bytes
            uint128(100000),              // validationGasLimit: 16 bytes
            uint128(50000),               // postOpGasLimit: 16 bytes
            validUntil,                   // 6 bytes
            validAfter,                   // 6 bytes
            signature                     // 65 bytes
        );
    }
}
