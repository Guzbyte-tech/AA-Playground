// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { BasePaymaster } from "@account-abstraction/core/BasePaymaster.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { UserOperationLib, PackedUserOperation } from "@account-abstraction/core/UserOperationLib.sol";



contract PayMaster is BasePaymaster {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;
    using UserOperationLib for PackedUserOperation;


    address public immutable verifyingSigner;
    uint256 private constant VALID_TIMESTAMP_OFFSET = 20;
    uint256 private constant SIGNATURE_OFFSET = 84;

    constructor(IEntryPoint _entryPoint, address _verifyingSigner) BasePaymaster(_entryPoint) {
        verifyingSigner = _verifyingSigner;
    }

    /**
     * @notice Return the hash we're going to sign off-chain (and validate on-chain)
     */
    function getHash(
        PackedUserOperation calldata userOp,
        uint48 validUntil,
        uint48 validAfter
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
                userOp.sender,
                userOp.nonce,
                userOp.unpackCallGasLimit(),
                userOp.unpackVerificationGasLimit(),
                userOp.preVerificationGas,
                userOp.unpackMaxFeePerGas(),
                userOp.unpackMaxPriorityFeePerGas(),
                block.chainid,
                address(this),
                validUntil,
                validAfter
            )
        );
    }

    /**
     * @notice Parse paymasterAndData: it should be the paymaster address, signature offset, and signature
     */
    function _parsePaymasterAndData(bytes calldata paymasterAndData)
        internal
        pure
        returns (uint48 validUntil, uint48 validAfter, bytes calldata signature)
    {
        (validUntil, validAfter) = abi.decode(
                paymasterAndData[VALID_TIMESTAMP_OFFSET:SIGNATURE_OFFSET],
                (uint48, uint48)
            );
        signature = paymasterAndData[SIGNATURE_OFFSET:];
    }

    /**
     * @notice Verify our external signer signed this request and decode paymasterData
     * paymasterData contains the following:
     * - validUntil and validAfter timestamps
     * - signature over the entire request
     */
    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /*userOpHash*/,
        uint256 requiredPreFund
    ) internal view override returns (bytes memory context, uint256 validationData) {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = _parsePaymasterAndData(userOp.paymasterAndData);
        
        // Verify signature
        bytes32 hash = getHash(userOp, validUntil, validAfter).toEthSignedMessageHash();
        
        if (verifyingSigner != hash.recover(signature)) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }

        // Check paymaster has enough deposit
        require(paymasterDeposit() >= requiredPreFund, "Paymaster: insufficient deposit");

        return (abi.encode(userOp.sender), _packValidationData(false, validUntil, validAfter));
    }

    /**
     * @notice Get current paymaster deposit on EntryPoint
     */
    function paymasterDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /**
     * @notice Add deposit for this paymaster
     */
    function addDeposit() public payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice Pack validation data
     */
    function _packValidationData(bool sigFailed, uint48 validUntil, uint48 validAfter) internal pure returns (uint256) {
        return (sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
    }
}
