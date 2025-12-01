// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { IEntryPoint } from "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { UserOperation } from "../lib/account-abstraction/contracts/interfaces/UserOperation.sol";
import { IPaymaster } from "../lib/account-abstraction/contracts/interfaces/IPaymaster.sol";

contract PayMasterV2 is IPaymaster {
    using ECDSA for bytes32;

    IEntryPoint public immutable entryPoint;
    address public immutable verifyingSigner;

    uint256 private constant VALID_TIMESTAMP_OFFSET = 20;
    uint256 private constant SIGNATURE_OFFSET = 84;


    constructor(IEntryPoint _entryPoint, address _verifyingSigner) {
        entryPoint = _entryPoint;
        verifyingSigner = _verifyingSigner;
    }

    /**
     * @notice Return the hash we're going to sign off-chain (and validate on-chain)
     */
    function getHash(
        UserOperation calldata userOp,
        uint48 validUntil,
        uint48 validAfter
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
                userOp.sender,
                userOp.nonce,
                userOp.callGasLimit,
                userOp.verificationGasLimit,
                userOp.preVerificationGas,
                userOp.maxFeePerGas,
                userOp.maxPriorityFeePerGas,
                block.chainid, // Adds chainID to prevent Cross Chain Attack
                address(this), //Prevent signature reuse across paymasters
                validUntil,
                validAfter
            )
        );
    }

    function validatePaymasterUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
    external view returns  (bytes memory context, uint256 validationData) {
         _requireFromEntryPoint();
        return _validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost) external {
        _requireFromEntryPoint();

        (mode,context,actualGasCost); // unused params
        
    }

    /**
     * @notice Verify our external signer signed this request and decode paymasterData
     * paymasterData contains the following:
     * - validUntil and validAfter timestamps
     * - signature over the entire request
     */
    function _validatePaymasterUserOp(
        UserOperation calldata userOp,
        bytes32 /*userOpHash*/,
        uint256 
    ) internal view returns (bytes memory context, uint256 validationData) {
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = _parsePaymasterAndData(userOp.paymasterAndData);
        
        // Verify signature
        bytes32 hash = ECDSA.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter));
        
        (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(hash, signature);
   
        if (error != ECDSA.RecoverError.NoError || recovered != verifyingSigner) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }

        // return (abi.encode(userOp.sender), _packValidationData(false, validUntil, validAfter));
        
        return ("", _packValidationData(false, validUntil, validAfter));
    }

    /**
     * @notice Parse paymasterAndData
     * paymasterAndData structure: 
     * [paymaster address (20 bytes)]
     * [abi.encoded(validUntil, validAfter) (64 bytes)]
     * [signature (65 bytes)]
     * Total: 149 bytes
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

    /// validate the call is made from a valid entrypoint
    function _requireFromEntryPoint() internal view {
        require(msg.sender == address(entryPoint), "Sender not EntryPoint");
    }

    function _packValidationData(bool sigFailed, uint48 validUntil, uint48 validAfter) internal pure returns (uint256) {
        return (sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
    }

}
