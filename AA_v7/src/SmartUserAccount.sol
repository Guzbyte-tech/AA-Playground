// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ErrorLib } from "./library/ErrorLib.sol";
import { BaseAccount } from "../lib/account-abstraction/contracts/core/BaseAccount.sol";
import { IEntryPoint } from "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { PackedUserOperation } from "../lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import { SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS } from "../lib/account-abstraction/contracts/core/Helpers.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";


/**
 * @title SmartUserAccount
 * @notice Minimal ERC-4337 smart contract wallet implementation using Entry Point v0.7.0
 * @dev Inherits from BaseAccount and allows users to leverage account abstraction features
 * @author Guzbyte
 */
contract SmartUserAccount is BaseAccount, Initializable, UUPSUpgradeable {

    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /// @notice The owner of this smart user account.
    address public owner;
    
    /// @notice The immutable entry point contract
    IEntryPoint private immutable ENTRY_POINT;
    
    /// @notice The immutable wallet that receives transaction fees (1%)
    /// @dev Set during deployment, cannot be changed by account owner
    address public immutable FEE_RECIPIENT;
    
    /// @notice The fee percentage in basis points (100 = 1%)
    uint256 public constant FEE_BASIS_POINTS = 100;
    uint256 public constant BASIS_POINTS_DIVISOR = 10000;

    /// @notice Function selectors for ERC20 transfer functions
    bytes4 private constant TRANSFER_SELECTOR = bytes4(keccak256("transfer(address,uint256)"));
    bytes4 private constant TRANSFER_FROM_SELECTOR = bytes4(keccak256("transferFrom(address,address,uint256)"));

    event SmartAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event FeeCollected(address indexed token, uint256 amount, address indexed recipient);


    /// @notice Constructor for SmartUserAccount
    /// @param ePoint The entry point contract for account abstraction
    /// @param _feeRecipient The address that will receive all transaction fees
    constructor(IEntryPoint ePoint, address _feeRecipient) {
        if (_feeRecipient == address(0)) revert ErrorLib.ZeroAddressNotAllowed();
        ENTRY_POINT = ePoint;
        FEE_RECIPIENT = _feeRecipient;
        _disableInitializers();
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

     /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption. To upgrade EntryPoint,
     * a new implementation of SmartUserAccount must be deployed with the new EntryPoint address, then upgrading
     * the implementation by calling `upgradeTo()`
     */
    function initialize(address anOwner) public virtual initializer {
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        if (anOwner == address(0)) revert ErrorLib.ZeroAddressNotAllowed();
        owner = anOwner;
        emit SmartAccountInitialized(ENTRY_POINT, owner);
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view override returns (IEntryPoint) {
        return ENTRY_POINT;
    }

     /**
     * @notice Validate the signature of a user operation
     * @param userOp The user operation to validate
     * @param userOpHash The hash of the user operation
     * @return validationData 0 for valid signature, SIG_VALIDATION_FAILED otherwise
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override view returns (uint256 validationData) {
        bytes32 hash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        
        // tryRecover returns (address recovered, RecoverError error, bytes32 errorArg)
        // It will NOT revert on invalid signatures, making gas estimation work
        (address recovered, ECDSA.RecoverError error, ) = ECDSA.tryRecover(hash, userOp.signature);

        if (error != ECDSA.RecoverError.NoError || recovered != owner) {
            return SIG_VALIDATION_FAILED;
        }
       
       return SIG_VALIDATION_SUCCESS;
    }

     /**
     * @notice Execute a transaction from this account with automatic fee handling
     * @param dest The destination address
     * @param value The amount of ETH to send
     * @param func The calldata to execute
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        
        // Check if this is a native ETH transfer (empty calldata and value > 0)
        if (func.length == 0 && value > 0) {
            _handleNativeTransferWithFee(dest, value);
            return;
        }
        
        // Check if this is an ERC20 transfer or transferFrom call
        if (func.length >= 4) {
            bytes4 selector = bytes4(func[:4]);
            
            if (selector == TRANSFER_SELECTOR) {
                _handleTransferWithFee(dest, func);
                return;
            } else if (selector == TRANSFER_FROM_SELECTOR) {
                _handleTransferFromWithFee(dest, func);
                return;
            }
        }
        
        // For non-transfer calls, execute normally
        _call(dest, value, func);
    }

     /**
     * @notice Execute a batch of transactions with automatic fee handling
     * @param dest Array of destination addresses
     * @param value Array of ETH amounts to send
     * @param func Array of calldata to execute
     */
    function executeBatch(
        address[] calldata dest,
        uint256[] calldata value,
        bytes[] calldata func
    ) external {
        _requireFromEntryPointOrOwner();
        if (dest.length != func.length || dest.length != value.length) {
            revert ErrorLib.ArrayLengthMismatch();
        }
        
        for (uint256 i = 0; i < dest.length; i++) {
            // Check if this is a native ETH transfer (empty calldata and value > 0)
            if (func[i].length == 0 && value[i] > 0) {
                _handleNativeTransferWithFee(dest[i], value[i]);
                continue;
            }
            
            // Check if this is an ERC20 transfer or transferFrom call
            if (func[i].length >= 4) {
                bytes4 selector = bytes4(func[i][:4]);
                
                if (selector == TRANSFER_SELECTOR) {
                    _handleTransferWithFee(dest[i], func[i]);
                    continue;
                } else if (selector == TRANSFER_FROM_SELECTOR) {
                    _handleTransferFromWithFee(dest[i], func[i]);
                    continue;
                }
            }
            
            // For non-transfer calls, execute normally
            _call(dest[i], value[i], func[i]);
        }


    }

    /**
     * @notice Handle native ETH transfer with fee (user sends amount + 1% fee)
     * @param recipient The recipient address
     * @param amount The amount of ETH to send (not including fee)
     */
    function _handleNativeTransferWithFee(address recipient, uint256 amount) internal {
        if (recipient == address(0)) revert ErrorLib.ZeroAddressNotAllowed();
        if (amount == 0) revert ErrorLib.InvalidAmount();
        
        // Calculate 1% fee
        uint256 fee = (amount * FEE_BASIS_POINTS) / BASIS_POINTS_DIVISOR;
        uint256 totalRequired = amount + fee;
        
        // Check if smart account has enough balance
        if (address(this).balance < totalRequired) revert ErrorLib.InsufficientBalance();
        
        // Transfer the requested amount to recipient
        (bool success, ) = payable(recipient).call{value: amount}("");
        if (!success) revert ErrorLib.TransferFailed();
        
        // Transfer the fee to fee recipient
        if (fee > 0) {
            (bool feeSuccess, ) = payable(FEE_RECIPIENT).call{value: fee}("");
            if (!feeSuccess) revert ErrorLib.TransferFailed();
            emit FeeCollected(address(0), fee, FEE_RECIPIENT); // address(0) represents ETH
        }
    }

    /**
     * @notice Handle ERC20 transfer with fee (user sends amount + 1% fee)
     * @param token The token contract address
     * @param data The calldata containing transfer(address,uint256)
     */
    function _handleTransferWithFee(address token, bytes calldata data) internal {
        // Decode the transfer parameters
        (address recipient, uint256 amount) = abi.decode(data[4:], (address, uint256));
        
        if (recipient == address(0)) revert ErrorLib.ZeroAddressNotAllowed();
        if (amount == 0) revert ErrorLib.InvalidAmount();
        
        // Calculate 1% fee
        uint256 fee = (amount * FEE_BASIS_POINTS) / BASIS_POINTS_DIVISOR;
        
        // Check if user has enough balance (amount + fee)
        uint256 totalRequired = amount + fee;
        uint256 balance = IERC20(token).balanceOf(address(this));
        if (balance < totalRequired) revert ErrorLib.InsufficientBalance();
        
        // Transfer the requested amount to recipient
        bool success = IERC20(token).transfer(recipient, amount);
        if (!success) revert ErrorLib.TransferFailed();
        
        // Transfer the fee to fee recipient
        if (fee > 0) {
            bool feeSuccess = IERC20(token).transfer(FEE_RECIPIENT, fee);
            if (!feeSuccess) revert ErrorLib.TransferFailed();
            emit FeeCollected(token, fee, FEE_RECIPIENT);
        }
    }

    /**
     * @notice Handle ERC20 transferFrom with fee (sender approves amount + 1% fee)
     * @param token The token contract address
     * @param data The calldata containing transferFrom(address,address,uint256)
     */
    function _handleTransferFromWithFee(address token, bytes calldata data) internal {
        // Decode the transferFrom parameters
        (address from, address to, uint256 amount) = abi.decode(data[4:], (address, address, uint256));
        
        if (from == address(0) || to == address(0)) revert ErrorLib.ZeroAddressNotAllowed();
        if (amount == 0) revert ErrorLib.InvalidAmount();
        
        // Calculate 1% fee
        uint256 fee = (amount * FEE_BASIS_POINTS) / BASIS_POINTS_DIVISOR;
        uint256 totalRequired = amount + fee;
        
        // Check allowance
        uint256 allowance = IERC20(token).allowance(from, address(this));
        if (allowance < totalRequired) revert ErrorLib.InsufficientAllowance();
        
        // Transfer the requested amount to recipient
        bool success = IERC20(token).transferFrom(from, to, amount);
        if (!success) revert ErrorLib.TransferFailed();
        
        // Transfer the fee from sender to fee recipient
        if (fee > 0) {
            bool feeSuccess = IERC20(token).transferFrom(from, FEE_RECIPIENT, fee);
            if (!feeSuccess) revert ErrorLib.TransferFailed();
            emit FeeCollected(token, fee, FEE_RECIPIENT);
        }
    }

    /**
     * @notice Transfer ownership of the account
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ErrorLib.ZeroAddressNotAllowed();
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /**
     * @notice Internal function to execute calls
     * @param target The target address
     * @param value The ETH value to send
     * @param data The calldata
     */
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

     /**
     * @notice Ensure the caller is either the EntryPoint or the owner
     */
    function _requireFromEntryPointOrOwner() internal view {
        if (msg.sender != address(ENTRY_POINT) && msg.sender != owner) {
            revert ErrorLib.NotAuthorized();
        }
    }

    /**
     * @notice Ensure the caller is the owner
     */
    function _onlyOwner() internal view {
        if (msg.sender != owner) {
            revert ErrorLib.NotAuthorized();
        }
    }


    /**
     * @notice Check if an address is authorized to upgrade the contract
     * @param newImplementation The new implementation address
     */
    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation); // silence unused variable warning
        _onlyOwner();
    }

    /**
     * @notice Deposit ETH to the EntryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice Withdraw ETH from the EntryPoint
     * @param withdrawAddress The address to withdraw to
     * @param amount The amount to withdraw
     */
    function withdrawDepositTo(
        address payable withdrawAddress,
        uint256 amount
    ) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /**
     * @notice Get the deposit balance in the EntryPoint
     * @return The deposit balance
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /// @notice Receive function to accept ETH
    receive() external payable {}

     uint256[50] private __gap;
}
