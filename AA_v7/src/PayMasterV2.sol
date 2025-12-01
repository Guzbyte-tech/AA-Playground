// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import { IEntryPoint } from "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "../lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { IPaymaster } from "../lib/account-abstraction/contracts/interfaces/IPaymaster.sol";
import { UserOperationLib } from "../lib/account-abstraction/contracts/core/UserOperationLib.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";


/**
 * @title Paymaster
 * @notice Paymaster for EntryPoint v0.7.0 with signature verification, whitelist, and gas tracking
 * @dev Upgraded from v0.6.0 to support PackedUserOperation format
 */
contract PayMasterV2 is IPaymaster, Ownable {
    using ECDSA for bytes32;
    using UserOperationLib for PackedUserOperation;

    IEntryPoint public immutable entryPoint;
    address public verifyingSigner;

    /// @notice Whitelist of addresses that get free sponsorship
    mapping(address => bool) public whitelist;

    /// @notice Per-user gas spending limits (0 = unlimited)
    mapping(address => uint256) public gasLimits;

    /// @notice Track gas spent by each user
    mapping(address => uint256) public gasSpent;

    /// @notice Maximum gas cost per operation (prevents griefing)
    uint256 public maxGasPerOperation;

    /// @notice Enable/disable whitelist mode globally
    bool public whitelistEnabled;

    // Offsets for parsing paymasterAndData in v0.7.0
    uint256 private constant PAYMASTER_VALIDATION_GAS_OFFSET = UserOperationLib.PAYMASTER_VALIDATION_GAS_OFFSET;
    uint256 private constant PAYMASTER_POSTOP_GAS_OFFSET = UserOperationLib.PAYMASTER_POSTOP_GAS_OFFSET;
    uint256 private constant PAYMASTER_DATA_OFFSET = UserOperationLib.PAYMASTER_DATA_OFFSET;

    event UserWhitelisted(address indexed user, bool status);
    event GasLimitSet(address indexed user, uint256 limit);
    event GasSponsored(address indexed user, uint256 actualGasCost);
    event VerifyingSignerChanged(address indexed oldSigner, address indexed newSigner);
    event MaxGasPerOperationChanged(uint256 oldMax, uint256 newMax);
    event WhitelistModeChanged(bool enabled);

    error UserNotWhitelisted();
    error InvalidSignature();
    error GasLimitExceeded();
    error GasCostTooHigh();
    error ZeroAddressNotAllowed();
    error NotFromEntryPoint();

    constructor(
        IEntryPoint _entryPoint,
        address _verifyingSigner,
        uint256 _maxGasPerOperation
    ) Ownable(msg.sender) {
        if (_verifyingSigner == address(0)) revert ZeroAddressNotAllowed();
        entryPoint = _entryPoint;
        verifyingSigner = _verifyingSigner;
        maxGasPerOperation = _maxGasPerOperation;
        whitelistEnabled = false; // Default to signature mode
    }

    /**
     * @notice Return the hash we're going to sign off-chain (and validate on-chain)
     * @dev Updated for v0.7.0 PackedUserOperation format
     */
    function getHash(
        PackedUserOperation calldata userOp,
        uint48 validUntil,
        uint48 validAfter
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            userOp.sender,
            userOp.nonce,
            userOp.accountGasLimits,
            userOp.preVerificationGas,
            userOp.gasFees,
            block.chainid,
            address(this),
            validUntil,
            validAfter
        ));
    }

    /**
     * @notice Validate paymaster user operation
     * @param userOp The packed user operation (v0.7.0 format)
     * @param userOpHash The hash of the user operation
     * @param maxCost The maximum cost of this operation
     */
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external view returns (bytes memory context, uint256 validationData) {
        _requireFromEntryPoint();
        return _validatePaymasterUserOp(userOp, userOpHash, maxCost);
    }

    /**
     * @notice Post operation handler
     * @param mode Operation mode (success/revert)
     * @param context Context from validation
     * @param actualGasCost Actual gas cost
     * @param actualUserOpFeePerGas Actual fee per gas
     */
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external {
        _requireFromEntryPoint();
        _postOp(mode, context, actualGasCost, actualUserOpFeePerGas);
    }

    /**
     * @notice Internal validation logic with whitelist and signature verification
     */
    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /*userOpHash*/,
        uint256 maxCost
    ) internal view returns (bytes memory context, uint256 validationData) {
        // Check max gas cost
        if (maxCost > maxGasPerOperation) revert GasCostTooHigh();

        address sender = userOp.sender;

        // Whitelist mode: Check if user is whitelisted
        if (whitelistEnabled) {
            if (!whitelist[sender]) revert UserNotWhitelisted();

            // Check gas limit
            if (gasLimits[sender] > 0) {
                if (gasSpent[sender] + maxCost > gasLimits[sender]) {
                    revert GasLimitExceeded();
                }
            }

            // Return context for postOp
            context = abi.encode(sender, maxCost, whitelistEnabled);
            return (context, 0);
        }

        // Signature mode: Verify off-chain signature
        (uint48 validUntil, uint48 validAfter, bytes calldata signature) = 
            _parsePaymasterAndData(userOp.paymasterAndData);

        // Verify signature
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(getHash(userOp, validUntil, validAfter));
        
        (address recovered, ECDSA.RecoverError error, ) = ECDSA.tryRecover(hash, signature);

        if (error != ECDSA.RecoverError.NoError || recovered != verifyingSigner) {
            return ("", _packValidationData(true, validUntil, validAfter));
        }

        context = abi.encode(sender, maxCost, whitelistEnabled);
        validationData = _packValidationData(false, validUntil, validAfter);
        
        return (context, validationData);
    }

    /**
     * @notice Post operation handler - tracks gas usage
     */
    function _postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) internal {
        if (context.length == 0) return;

        (address sender, uint256 maxCost, bool wasWhitelistMode) = 
            abi.decode(context, (address, uint256, bool));

        // Track gas spent if whitelist mode with limits
        if (wasWhitelistMode && gasLimits[sender] > 0) {
            gasSpent[sender] += actualGasCost;
        }

        emit GasSponsored(sender, actualGasCost);

        // Prevent unused variable warnings
        (mode, actualUserOpFeePerGas, maxCost);
    }

    /**
     * @notice Parse paymasterAndData for v0.7.0
     * Format: [paymaster (20)][validationGasLimit (16)][postOpGasLimit (16)][validUntil (6)][validAfter (6)][signature (65)]
     */
    function _parsePaymasterAndData(bytes calldata paymasterAndData)
        internal
        pure
        returns (uint48 validUntil, uint48 validAfter, bytes calldata signature)
    {
        // paymasterAndData structure in v0.7.0:
        // [0:20] paymaster address
        // [20:36] validationGasLimit (uint128)
        // [36:52] postOpGasLimit (uint128)
        // [52:58] validUntil (uint48)
        // [58:64] validAfter (uint48)
        // [64:129] signature (65 bytes)

        validUntil = uint48(bytes6(paymasterAndData[52:58]));
        validAfter = uint48(bytes6(paymasterAndData[58:64]));
        signature = paymasterAndData[64:];
    }

    /**
     * @notice Add or remove addresses from whitelist
     */
    function setWhitelist(address user, bool status) external onlyOwner {
        if (user == address(0)) revert ZeroAddressNotAllowed();
        whitelist[user] = status;
        emit UserWhitelisted(user, status);
    }

    /**
     * @notice Batch whitelist users
     */
    function batchSetWhitelist(address[] calldata users, bool status) external onlyOwner {
        for (uint256 i = 0; i < users.length; i++) {
            if (users[i] == address(0)) revert ZeroAddressNotAllowed();
            whitelist[users[i]] = status;
            emit UserWhitelisted(users[i], status);
        }
    }

    /**
     * @notice Set gas spending limit for a user
     */
    function setGasLimit(address user, uint256 limit) external onlyOwner {
        if (user == address(0)) revert ZeroAddressNotAllowed();
        gasLimits[user] = limit;
        emit GasLimitSet(user, limit);
    }

    /**
     * @notice Batch set gas limits
     */
    function batchSetGasLimits(
        address[] calldata users,
        uint256[] calldata limits
    ) external onlyOwner {
        require(users.length == limits.length, "Length mismatch");
        for (uint256 i = 0; i < users.length; i++) {
            if (users[i] == address(0)) revert ZeroAddressNotAllowed();
            gasLimits[users[i]] = limits[i];
            emit GasLimitSet(users[i], limits[i]);
        }
    }

    /**
     * @notice Reset gas spent counter for a user
     */
    function resetGasSpent(address user) external onlyOwner {
        gasSpent[user] = 0;
    }

    /**
     * @notice Batch reset gas spent
     */
    function batchResetGasSpent(address[] calldata users) external onlyOwner {
        for (uint256 i = 0; i < users.length; i++) {
            gasSpent[users[i]] = 0;
        }
    }

    /**
     * @notice Update the verifying signer
     */
    function setVerifyingSigner(address newSigner) external onlyOwner {
        if (newSigner == address(0)) revert ZeroAddressNotAllowed();
        address oldSigner = verifyingSigner;
        verifyingSigner = newSigner;
        emit VerifyingSignerChanged(oldSigner, newSigner);
    }

    /**
     * @notice Update maximum gas per operation
     */
    function setMaxGasPerOperation(uint256 newMax) external onlyOwner {
        uint256 oldMax = maxGasPerOperation;
        maxGasPerOperation = newMax;
        emit MaxGasPerOperationChanged(oldMax, newMax);
    }

    /**
     * @notice Enable or disable whitelist mode
     */
    function setWhitelistMode(bool enabled) external onlyOwner {
        whitelistEnabled = enabled;
        emit WhitelistModeChanged(enabled);
    }

    /**
     * @notice Check if a user is whitelisted
     */
    function isWhitelisted(address user) external view returns (bool) {
        return whitelist[user];
    }

    /**
     * @notice Get remaining gas allowance for a user
     */
    function getRemainingGasAllowance(address user) external view returns (uint256) {
        uint256 limit = gasLimits[user];
        if (limit == 0) return type(uint256).max;
        
        uint256 spent = gasSpent[user];
        if (spent >= limit) return 0;
        
        return limit - spent;
    }

    /**
     * @notice Deposit funds to EntryPoint for sponsoring operations
     */
    function deposit() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice Withdraw funds from EntryPoint
     */
    function withdrawTo(address payable withdrawAddress, uint256 amount) external onlyOwner {
        entryPoint.withdrawTo(withdrawAddress, amount);
    }

    /**
     * @notice Add stake to EntryPoint
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        entryPoint.addStake{value: msg.value}(unstakeDelaySec);
    }

    /**
     * @notice Get deposit balance in EntryPoint
     */
    function getDeposit() external view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /**
     * @notice Unlock stake
     */
    function unlockStake() external onlyOwner {
        entryPoint.unlockStake();
    }

    /**
     * @notice Withdraw stake
     */
    function withdrawStake(address payable withdrawAddress) external onlyOwner {
        entryPoint.withdrawStake(withdrawAddress);
    }

    /**
     * @notice Validate the call is made from a valid entrypoint
     */
    function _requireFromEntryPoint() internal view {
        if (msg.sender != address(entryPoint)) revert NotFromEntryPoint();
    }

    /**
     * @notice Pack validation data
     */
    function _packValidationData(
        bool sigFailed,
        uint48 validUntil,
        uint48 validAfter
    ) internal pure returns (uint256) {
        return (sigFailed ? 1 : 0) | 
               (uint256(validUntil) << 160) | 
               (uint256(validAfter) << (160 + 48));
    }

    /**
     * @notice Allow contract to receive ETH
     */
    receive() external payable {}
}
