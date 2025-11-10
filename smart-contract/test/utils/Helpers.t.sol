// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";

import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";


// struct PackedUserOperation {
//     address sender;
//     uint256 nonce;
//     bytes initCode;
//     bytes callData;
//     bytes32 accountGasLimits;
//     uint256 preVerificationGas;
//     bytes32 gasFees;
//     bytes paymasterAndData;
//     bytes signature;
// }

library TestHelpers {
    using stdJson for string;

    function getUserOpHash(
        Vm vm,
        PackedUserOperation memory userOp,
        address entryPoint,
        uint256 chainId
    ) internal pure returns (bytes32) {
        bytes32 packed = keccak256(
            abi.encode(
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode), // hash of initCode if any
                keccak256(userOp.callData),
                userOp.accountGasLimits,
                userOp.preVerificationGas,
                userOp.gasFees,
                keccak256(userOp.paymasterAndData)
            )
        );

        return keccak256(abi.encode(packed, entryPoint, chainId));
    }

    function signUserOp(
        Vm vm,
        PackedUserOperation memory userOp,
        address entryPoint,
        uint256 chainId,
        uint256 privateKey
    ) internal returns (bytes memory) {
        bytes32 hash = getUserOpHash(vm, userOp, entryPoint, chainId);
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    function getPaymasterHash(
        Vm vm,
        address sender,
        uint256 nonce,
        bytes32 accountGasLimits,
        uint256 preVerificationGas,
        bytes32 gasFees,
        uint256 chainId,
        address paymaster,
        uint48 validUntil,
        uint48 validAfter
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                sender,
                nonce,
                accountGasLimits,
                preVerificationGas,
                gasFees,
                chainId,
                paymaster,
                validUntil,
                validAfter
            )
        );
    }

    function signPaymasterData(
        Vm vm,
        bytes32 hash,
        uint256 privateKey
    ) internal returns (bytes memory) {
        bytes32 ethSignedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, ethSignedHash);
        return abi.encodePacked(r, s, v);
    }

    function packGasLimits(uint128 verificationGasLimit, uint128 callGasLimit) internal pure returns (bytes32) {
        return bytes32(uint256(verificationGasLimit) << 128 | uint256(callGasLimit));
    }

    function packGasFees(uint128 maxPriorityFeePerGas, uint128 maxFeePerGas) internal pure returns (bytes32) {
        return bytes32(uint256(maxPriorityFeePerGas) << 128 | uint256(maxFeePerGas));
    }
}
