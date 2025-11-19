// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "forge-std/Test.sol";
import "../../lib/account-abstraction/contracts/interfaces/UserOperation.sol";

library TestHelpers {
    using stdJson for string;

    function getUserOpHash(
        Vm vm,
        UserOperation memory userOp,
        address entryPoint,
        uint256 chainId
    ) internal pure returns (bytes32) {
        bytes32 packed = keccak256(
            abi.encode(
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.callGasLimit,
                userOp.verificationGasLimit,
                userOp.preVerificationGas,
                userOp.maxFeePerGas,
                userOp.maxPriorityFeePerGas,
                keccak256(userOp.paymasterAndData)
            )
        );

        return keccak256(abi.encode(packed, entryPoint, chainId));
    }

    function signUserOp(
        Vm vm,
        UserOperation memory userOp,
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
        uint256 callGasLimit,
        uint256 verificationGasLimit,
        uint256 preVerificationGas,
        uint256 maxFeePerGas,
        uint256 maxPriorityFeePerGas,
        uint256 chainId,
        address paymaster,
        uint48 validUntil,
        uint48 validAfter
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                sender,
                nonce,
                callGasLimit,
                verificationGasLimit,
                preVerificationGas,
                maxFeePerGas,
                maxPriorityFeePerGas,
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
}