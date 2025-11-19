//SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "../src/PayMaster.sol";
import "../lib/account-abstraction/contracts/core/EntryPoint.sol";
import "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import "../lib/account-abstraction/contracts/interfaces/UserOperation.sol";
import { TestHelpers } from "./utils/Helpers.t.sol";

contract PaymasterTest is Test {
    PayMaster public paymaster;
    EntryPoint public entryPoint;
    
    address public verifyingSigner;
    uint256 public signerKey;
    address public randomUser;

    function setUp() public {
        signerKey = 0xABCD;
        verifyingSigner = vm.addr(signerKey);
        randomUser = address(0x999);
        
        entryPoint = new EntryPoint();
        paymaster = new PayMaster(IEntryPoint(address(entryPoint)), verifyingSigner);
        
        vm.deal(address(this), 100 ether);
    }

    function test_Deployment() public {
        assertEq(paymaster.verifyingSigner(), verifyingSigner, "VerifyingSigner mismatch");
        assertEq(address(paymaster.entryPoint()), address(entryPoint), "EntryPoint mismatch");
        assertEq(paymaster.getDeposit(), 0, "Initial deposit should be 0");
    }

    function test_DepositManagement_AddDeposit() public {
        uint256 depositAmount = 10 ether;
        
        paymaster.deposit{value: depositAmount}();
        
        uint256 balance = entryPoint.balanceOf(address(paymaster));
        assertEq(balance, depositAmount, "Balance in EntryPoint mismatch");
        assertEq(paymaster.getDeposit(), depositAmount, "getDeposit() mismatch");
    }

    function test_DepositManagement_MultipleDeposits() public {
        paymaster.deposit{value: 5 ether}();
        paymaster.deposit{value: 3 ether}();
        paymaster.deposit{value: 2 ether}();
        
        assertEq(paymaster.getDeposit(), 10 ether, "Multiple deposits not accumulated");
    }

    function test_GetHashLogic() public {
        UserOperation memory userOp = UserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            callGasLimit: 200000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 10 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });
        
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        bytes32 contractHash = paymaster.getHash(userOp, validUntil, validAfter);
        
        assertTrue(contractHash != bytes32(0), "Hash should not be zero");
    }

    function test_GetHash_DifferentParamsProduceDifferentHash() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        UserOperation memory userOp1 = UserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            callGasLimit: 200000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 10 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 hash1 = paymaster.getHash(userOp1, validUntil, validAfter);
        
        UserOperation memory userOp2 = userOp1;
        userOp2.nonce = 6;
        bytes32 hash2 = paymaster.getHash(userOp2, validUntil, validAfter);
        
        assertTrue(hash1 != hash2, "Different nonce should produce different hash");
        
        UserOperation memory userOp3 = userOp1;
        userOp3.sender = address(0x456);
        bytes32 hash3 = paymaster.getHash(userOp3, validUntil, validAfter);
        
        assertTrue(hash1 != hash3, "Different sender should produce different hash");
    }

    function test_SignatureValidation_CorrectSignature() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        UserOperation memory userOp = UserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            callGasLimit: 200000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 10 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        bytes memory signature = TestHelpers.signPaymasterData(vm, hash, signerKey);
        
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        address recovered = ECDSA.recover(ethSignedHash, signature);
        
        assertEq(recovered, verifyingSigner, "Recovered signer should match verifyingSigner");
    }

    function test_SignatureValidation_WrongSigner() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        UserOperation memory userOp = UserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            callGasLimit: 200000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 10 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        
        uint256 wrongKey = 0xBAD;
        bytes memory signature = TestHelpers.signPaymasterData(vm, hash, wrongKey);
        
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        address recovered = ECDSA.recover(ethSignedHash, signature);
        
        assertTrue(recovered != verifyingSigner, "Wrong signer should not match");
    }

    function test_SignatureValidation_ExpiredSignature() public {
        vm.warp(block.timestamp + 1 days);
        uint48 validUntil = uint48(block.timestamp - 1 hours);
        uint48 validAfter = uint48(block.timestamp - 2 hours);
        
        UserOperation memory userOp = UserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            callGasLimit: 200000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 10 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        bytes memory signature = TestHelpers.signPaymasterData(vm, hash, signerKey);
        
        bytes memory paymasterAndData = abi.encodePacked(
            address(paymaster),
            validUntil,
            validAfter,
            signature
        );
        
        userOp.paymasterAndData = paymasterAndData;
        
        paymaster.deposit{value: 10 ether}();
        
        assertTrue(block.timestamp > validUntil, "Should be expired");
    }

    function test_SignatureValidation_NotYetValid() public {
        vm.warp(block.timestamp + 1 days);
        uint48 validUntil = uint48(block.timestamp + 2 hours);
        uint48 validAfter = uint48(block.timestamp + 1 hours);
        
        assertTrue(block.timestamp < validAfter, "Should not be valid yet");
    }

    function test_InsufficientDeposit() public {
        assertEq(paymaster.getDeposit(), 0, "Should have no deposit");
    }

    function test_ReplayProtection() public {
        vm.warp(block.timestamp + 1 days);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        UserOperation memory userOp = UserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            callGasLimit: 200000,
            verificationGasLimit: 100000,
            preVerificationGas: 21000,
            maxFeePerGas: 10 gwei,
            maxPriorityFeePerGas: 1 gwei,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        bytes memory signature = TestHelpers.signPaymasterData(vm, hash, signerKey);
        
        vm.warp(block.timestamp + 2 hours);
        
        assertTrue(block.timestamp > validUntil, "Signature should be expired");
    }
}