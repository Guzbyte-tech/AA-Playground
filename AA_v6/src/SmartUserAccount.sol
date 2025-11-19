// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import { IEntryPoint, UserOperation } from "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { BaseAccount } from "../lib/account-abstraction/contracts/core/BaseAccount.sol";
import { ErrorLib } from "./library/ErrorLib.sol";
import { Initializable } from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title SmartUserAccount
 * @notice Minimal ERC-4337 smart contract wallet implementation
 * @dev Inherits from BaseAccount and allows users to leverage account abstraction features
 * @author Guzbyte
 */
contract SmartUserAccount is BaseAccount, Initializable, UUPSUpgradeable {

     using ECDSA for bytes32;

    address public owner;
    IEntryPoint private immutable ENTRY_POINT;

    event SmartAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(IEntryPoint ePoint) {
        ENTRY_POINT = ePoint;
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function initialize(address anOwner) public virtual initializer {
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        owner = anOwner;
        emit SmartAccountInitialized(ENTRY_POINT, owner);
    }

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

    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual override returns (uint256 validationData) {
        _requireFromEntryPoint();
        validationData = _validateSignature(userOp, userOpHash);
        _payPrefund(missingAccountFunds);
    }

    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "new owner is zero address");
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    function _authorizeUpgrade(address newImplementation) internal view override onlyOwner {
        (newImplementation);
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) {
            revert ErrorLib.NotAuthorized();
        }
    }

    function _requireFromEntryPointOrOwner() internal view {
        if (msg.sender != address(entryPoint()) && msg.sender != owner) {
            revert ErrorLib.NotOwnerOrEntryPoint();
        }
    }

    function _requireFromEntryPoint() internal view override {
        if (msg.sender != address(entryPoint())) {
            revert ErrorLib.NotEntryPoint();
        }
    }

    function _call(address dest, uint256 value, bytes calldata data) internal {
        (bool success, bytes memory result) = dest.call{value: value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function _validateSignature(
       UserOperation calldata userOp,
       bytes32 userOpHash
   ) internal view override returns (uint256 validationData) {
       bytes32 hash = ECDSA.toEthSignedMessageHash(userOpHash);
       
       // Use tryRecover to avoid reverts
       (address recovered, ECDSA.RecoverError error) = ECDSA.tryRecover(hash, userOp.signature);
       
       if (error != ECDSA.RecoverError.NoError || recovered != owner) {
           return 1; // SIG_VALIDATION_FAILED
       }
       
       return 0; // SIG_VALIDATION_SUCCESS
   }

    function _payPrefund(uint256 missingAccountFunds) internal override {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
        }
    }

    receive() external payable {}

    uint256[50] private __gap;
}
