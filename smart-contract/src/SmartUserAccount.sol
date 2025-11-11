// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { BaseAccount } from "@account-abstraction/core/BaseAccount.sol";
import { IEntryPoint } from "@account-abstraction/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "@account-abstraction/interfaces/PackedUserOperation.sol";
import { ErrorLib } from "./library/ErrorLib.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "@account-abstraction/core/Helpers.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/**
 * @title SmartUserAccount
 * @notice Minimal ERC-4337 smart contract wallet implementation
 * @dev Inherits from BaseAccount and allows users to leverage account abstraction features
 * @author Guzbyte
 */
contract SmartUserAccount is BaseAccount, Initializable, UUPSUpgradeable{
    using ECDSA for bytes32;

    /// @notice The owner of this smart user account.
    address public owner;
    IEntryPoint private immutable ENTRY_POINT;

    event SmartAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Constructor for SmartUserAccount
    /// @param ePoint The entry point contract for account abstraction
    constructor(IEntryPoint ePoint) {
        ENTRY_POINT = ePoint;
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.To upgrade EntryPoint,
     * a new implementation of SmartUserAccount must be deployed with the new EntryPoint address, then upgrading
     * the implementation by calling `upgradeTo()`
    */
    function initialize(address anOwner) public virtual initializer {
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        owner = anOwner;
        emit SmartAccountInitialized(ENTRY_POINT, owner);
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

    function execute(address dest, uint256 value, bytes calldata data) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, data);
    }

    function executeBatch(address[] calldata dest, uint256[] calldata value, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        if (dest.length != func.length || dest.length != value.length) {
            revert ErrorLib.WrongArrayLengths();
        }
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], value[i], func[i]);
        }
    }

     /**
     * @notice Validate user's signature and nonce
     * @dev the entryPoint will make the call to the recipient only if this validation call returns successfully.
     * signature failure should be reported by returning SIG_VALIDATION_FAILED (1).
     * This allows making a "simulation call" without a valid signature
     * Other failures (e.g. nonce mismatch, or invalid signature format) should still revert to signal failure.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual override returns (uint256 validationData) {
        _requireFromEntryPoint();
        validationData = _validateSignature(userOp, userOpHash);
        _validateNonce(userOp.nonce);
        _payPrefund(missingAccountFunds);
    }

    /**
     * @notice Check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * @notice Deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }


    /**
     * @notice Withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }
    

    /**
     * @notice Transfer ownership of the account
     */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "new owner is zero address");
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    function _authorizeUpgrade(address newImplementation) internal view override onlyOwner {
        (newImplementation);
    }

    /// @notice Only owner modifier to restrict access to certain functions
    function _onlyOwner() internal view {
        if (msg.sender != owner) {
            revert ErrorLib.NotAuthorized();
        }
    }

    /**
     * @notice Ensure the function is called by the EntryPoint or the owner
     */
    function _requireFromEntryPointOrOwner() internal view {
        if (msg.sender != address(entryPoint()) && msg.sender != owner) {
            revert ErrorLib.NotOwnerOrEntryPoint();
        }
    }

    /**
     * @notice Ensure the function is only called by the EntryPoint
     */
    function _requireFromEntryPoint() internal override view {
        if (msg.sender != address(entryPoint())) {
            revert ErrorLib.NotEntryPoint();
        }
    }


    /// @notice Internal function to perform a call to a target address
    /// @dev Uses low-level call and reverts on failure
    /// @param dest The target address to call
    /// @param value The amount of ETH to send with the call
    /// @param data The calldata for the function to call on the target
    function _call(address dest, uint256 value, bytes calldata data) internal {
        (bool success, bytes memory result) = dest.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }


    /**
     * @notice Validate the signature is valid for this message
     * @param userOp validate the userOp.signature field
     * @param userOpHash convenient field: the hash of the request, to check the signature against
     * @return validationData signature and time-range of this operation
     *      <20-byte> sigAuthorizer - 0 for valid signature, 1 to mark signature failure,
     *         otherwise, an address of an "authorizer" contract.
     *      <6-byte> validUntil - last timestamp this operation is valid. 0 for "indefinite"
     *      <6-byte> validAfter - first timestamp this operation is valid
     *      If an account doesn't use time-range, it is enough to return SIG_VALIDATION_FAILED value (1) for signature failure.
     *      Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override view returns (uint256 validationData) {
        // bytes32 hash = userOpHash.toEthSignedMessageHash();
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        if (owner != hash.recover(userOp.signature)) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    /**
     * @notice Pay prefund for this UserOperation
     */
    function _payPrefund(uint256 missingAccountFunds) internal override {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
            //ignore failure (its EntryPoint's job to verify, not account.)
        }
    }

    receive() external payable {}

    uint256[50] private __gap;
}
