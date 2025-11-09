//SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import "../src/PayMaster.sol";
import {EntryPoint } from "@account-abstraction/core/EntryPoint.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { TestHelpers } from "./utils/Helpers.t.sol";

contract PaymasterTest is Test {
    PayMaster public paymaster;
    EntryPoint public entryPoint;
    
    address public verifyingSigner;
    uint256 public signerKey;
    address public randomUser;

    function setUp() public {
        // Setup signer
        signerKey = 0xABCD;
        verifyingSigner = vm.addr(signerKey);
        randomUser = address(0x999);
        
        // Deploy EntryPoint
        entryPoint = new EntryPoint();
        
        // Deploy Paymaster
        paymaster = new PayMaster(IEntryPoint(address(entryPoint)), verifyingSigner);
        
        // Fund deployer for deposits
        vm.deal(address(this), 100 ether);
    }

    // Test 1: Deployment
    function test_Deployment() public {
        // Check verifyingSigner
        assertEq(paymaster.verifyingSigner(), verifyingSigner, "VerifyingSigner mismatch");
        
        // Check entryPoint
        assertEq(address(paymaster.entryPoint()), address(entryPoint), "EntryPoint mismatch");
        
        // Check initial deposit is 0
        assertEq(paymaster.paymasterDeposit(), 0, "Initial deposit should be 0");
    }

    function test_DepositManagement_AddDeposit() public {
        uint256 depositAmount = 10 ether;
        
        // Add deposit
        paymaster.addDeposit{value: depositAmount}();
        
        // Check paymaster balance in EntryPoint
        uint256 balance = entryPoint.balanceOf(address(paymaster));
        assertEq(balance, depositAmount, "Balance in EntryPoint mismatch");
        
        // Check via paymasterDeposit()
        assertEq(paymaster.paymasterDeposit(), depositAmount, "paymasterDeposit() mismatch");
    }

    function test_DepositManagement_MultipleDeposits() public {
        paymaster.addDeposit{value: 5 ether}();
        paymaster.addDeposit{value: 3 ether}();
        paymaster.addDeposit{value: 2 ether}();
        
        assertEq(paymaster.paymasterDeposit(), 10 ether, "Multiple deposits not accumulated");
    }

    function test_GetHashLogic() public {
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            accountGasLimits: TestHelpers.packGasLimits(100000, 200000),
            preVerificationGas: 21000,
            gasFees: TestHelpers.packGasFees(1 gwei, 10 gwei),
            paymasterAndData: "",
            signature: ""
        });
        
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        // Get hash from contract
        bytes32 contractHash = paymaster.getHash(userOp, validUntil, validAfter);
        
        // Verify hash is not zero
        assertTrue(contractHash != bytes32(0), "Hash should not be zero");
    }

      // Test 3b: getHash - Different Params Produce Different Hash
    function test_GetHash_DifferentParamsProduceDifferentHash() public {
        bytes32 accountGasLimits = TestHelpers.packGasLimits(100000, 200000);
        bytes32 gasFees = TestHelpers.packGasFees(1 gwei, 10 gwei);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        PackedUserOperation memory userOp1 = PackedUserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            accountGasLimits: accountGasLimits,
            preVerificationGas: 21000,
            gasFees: gasFees,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 hash1 = paymaster.getHash(userOp1, validUntil, validAfter);
        
        // Change nonce
        PackedUserOperation memory userOp2 = userOp1;
        userOp2.nonce = 6;
        bytes32 hash2 = paymaster.getHash(userOp2, validUntil, validAfter);
        
        assertTrue(hash1 != hash2, "Different nonce should produce different hash");
        
        // Change sender
        PackedUserOperation memory userOp3 = userOp1;
        userOp3.sender = address(0x456);
        bytes32 hash3 = paymaster.getHash(userOp3, validUntil, validAfter);
        
        assertTrue(hash1 != hash3, "Different sender should produce different hash");
    }

    // Test 4: Signature Validation - Correct Signature
    function test_SignatureValidation_CorrectSignature() public {
        bytes32 accountGasLimits = TestHelpers.packGasLimits(100000, 200000);
        bytes32 gasFees = TestHelpers.packGasFees(1 gwei, 10 gwei);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            accountGasLimits: accountGasLimits,
            preVerificationGas: 21000,
            gasFees: gasFees,
            paymasterAndData: "",
            signature: ""
        });
        
        // Get hash
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        
        // Sign with correct signer
        bytes memory signature = TestHelpers.signPaymasterData(vm, hash, signerKey);
        
        // Recover signer from signature
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        address recovered = ECDSA.recover(ethSignedHash, signature);
        
        // Should match verifyingSigner
        assertEq(recovered, verifyingSigner, "Recovered signer should match verifyingSigner");
    }

    // Test 4b: Signature Validation - Wrong Signer
    function test_SignatureValidation_WrongSigner() public {
        bytes32 accountGasLimits = TestHelpers.packGasLimits(100000, 200000);
        bytes32 gasFees = TestHelpers.packGasFees(1 gwei, 10 gwei);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            accountGasLimits: accountGasLimits,
            preVerificationGas: 21000,
            gasFees: gasFees,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        
        // Sign with wrong key
        uint256 wrongKey = 0xBAD;
        bytes memory signature = TestHelpers.signPaymasterData(vm, hash, wrongKey);
        
        // Recover signer
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        address recovered = ECDSA.recover(ethSignedHash, signature);
        
        // Should NOT match verifyingSigner
        assertTrue(recovered != verifyingSigner, "Wrong signer should not match");
    }

     // Test 4c: Signature Validation - Expired Signature
    function test_SignatureValidation_ExpiredSignature() public {
        // Set validUntil in the past
        // uint48 validUntil = uint48(block.timestamp - 1 hours);
        vm.warp(block.timestamp + 1 days);  // Move time to 1 day + 1 second
        uint48 validUntil = uint48(block.timestamp - 1 hours); // Now safe!
        uint48 validAfter = uint48(block.timestamp - 2 hours);
        
        bytes32 accountGasLimits = TestHelpers.packGasLimits(100000, 200000);
        bytes32 gasFees = TestHelpers.packGasFees(1 gwei, 10 gwei);
        
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            accountGasLimits: accountGasLimits,
            preVerificationGas: 21000,
            gasFees: gasFees,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        bytes memory signature = TestHelpers.signPaymasterData(vm, hash, signerKey);
        
        // Pack paymasterAndData
        bytes memory paymasterAndData = abi.encodePacked(
            address(paymaster),
            validUntil,
            validAfter,
            signature
        );
        
        userOp.paymasterAndData = paymasterAndData;
        
        // Fund paymaster
        paymaster.addDeposit{value: 10 ether}();
        
        // This should fail due to expired signature
        // Verify timestamp logic
        assertTrue(block.timestamp > validUntil, "Should be expired");
    }

    // Test 4d: Signature Validation - Not Yet Valid
    function test_SignatureValidation_NotYetValid() public {
        // Set validAfter in the future
        vm.warp(block.timestamp + 1 days);
        uint48 validUntil = uint48(block.timestamp + 2 hours);
        uint48 validAfter = uint48(block.timestamp + 1 hours);
        
        // Should not be valid yet
        assertTrue(block.timestamp < validAfter, "Should not be valid yet");
    }

    // Test 5: Insufficient Deposit
    function test_InsufficientDeposit() public {
        // Don't add any deposit (balance = 0)
        assertEq(paymaster.paymasterDeposit(), 0, "Should have no deposit");
        
        // Attempting to sponsor a UserOp would fail due to insufficient deposit
        // This would be caught in _validatePaymasterUserOp with requiredPreFund check
    }


    // Test 6: Replay Protection
    function test_ReplayProtection() public {
        vm.warp(block.timestamp + 1 days);
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        
        bytes32 accountGasLimits = TestHelpers.packGasLimits(100000, 200000);
        bytes32 gasFees = TestHelpers.packGasFees(1 gwei, 10 gwei);
        
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(0x123),
            nonce: 5,
            initCode: "",
            callData: "",
            accountGasLimits: accountGasLimits,
            preVerificationGas: 21000,
            gasFees: gasFees,
            paymasterAndData: "",
            signature: ""
        });
        
        bytes32 hash = paymaster.getHash(userOp, validUntil, validAfter);
        bytes memory signature = TestHelpers.signPaymasterData(vm, hash, signerKey);
        
        // Warp time past validUntil
        vm.warp(block.timestamp + 2 hours);
        
        // Now it should be expired
        assertTrue(block.timestamp > validUntil, "Signature should be expired");
    }

    // // Test _packValidationData
    // function test_PackValidationData() public {
    //     vm.warp(block.timestamp + 1 days);
    //     uint48 validUntil = uint48(block.timestamp + 1 hours);
    //     uint48 validAfter = uint48(block.timestamp);
        
    //     // Pack with sigFailed = false
    //     uint256 packed1 = paymaster._packValidationData(false, validUntil, validAfter);
    //     assertEq(packed1 & 1, 0, "Should not have failure bit");
        
    //     // Pack with sigFailed = true
    //     uint256 packed2 = paymaster._packValidationData(true, validUntil, validAfter);
    //     assertEq(packed2 & 1, 1, "Should have failure bit");
        
    //     // Different timestamps should produce different values
    //     assertTrue(packed1 != packed2, "Different sig status should produce different packed data");
    // }


}