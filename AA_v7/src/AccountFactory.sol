//SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {SmartUserAccount} from "./SmartUserAccount.sol";
import { IEntryPoint } from "../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import { Create2 } from "@openzeppelin/contracts/utils/Create2.sol";
import { ErrorLib } from "./library/ErrorLib.sol";

contract AccountFactory {
    SmartUserAccount public immutable ACCOUNT_IMPLEMENTATION;
    IEntryPoint public immutable entryPoint;
    address public owner;

    /// @notice The protocol fee recipient (controlled by protocol, not users)
    address public immutable PROTOCOL_FEE_RECIPIENT;

    event AccountCreated(address indexed account, address indexed owner, uint256 salt);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);


    address[] public smartAccounts;

    modifier onlyOwner() {
        if (msg.sender != owner) revert ErrorLib.NotAuthorized();
        _;
    }

    constructor(IEntryPoint _entryPoint, address _protocolFeeRecipient) {
        if (address(_entryPoint) == address(0) || _protocolFeeRecipient == address(0)) {
            revert ErrorLib.ZeroAddressNotAllowed();
        }
        PROTOCOL_FEE_RECIPIENT = _protocolFeeRecipient;
        entryPoint = _entryPoint;
        owner = msg.sender;

        // Deploy the implementation contract once
        ACCOUNT_IMPLEMENTATION = new SmartUserAccount(_entryPoint, _protocolFeeRecipient);
        
    }

    /**
     * @notice Create an account, and return its address
     * @dev returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
    */
    function createAccount(address accountOwner, uint256 salt) public returns (SmartUserAccount ret) {
        if (accountOwner == address(0)) revert ErrorLib.InvalidAddress();

        address addr = getPredictedAddress(accountOwner, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return SmartUserAccount(payable(addr));
        }
        ret = SmartUserAccount(
            payable(
                new ERC1967Proxy{salt: bytes32(salt)}(
                    address(ACCOUNT_IMPLEMENTATION),
                    abi.encodeCall(SmartUserAccount.initialize, (accountOwner))
                )
            )
        );
    
        smartAccounts.push(address(ret));
        emit AccountCreated(address(ret), accountOwner, salt);

    }

    /**
     * @notice Calculate the counterfactual address of this account as it would be returned by createAccount()
     * @param accountOwner The owner of the smart account
     * @param salt The salt used for CREATE2
     * @return The computed address
    */
    function getPredictedAddress(address accountOwner, uint256 salt) public view returns (address) {
        return Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(
                    type(ERC1967Proxy).creationCode,
                    abi.encode(
                        address(ACCOUNT_IMPLEMENTATION),
                        abi.encodeCall(SmartUserAccount.initialize, (accountOwner))    
                    )
                )
            ),
            address(this)
        );
    }

    /**
     * @notice Transfer factory ownership (for governance/multisig control)
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ErrorLib.ZeroAddressNotAllowed();
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    function stakeFactory(uint32 unstakeDelaySec) external payable onlyOwner {
        IEntryPoint(entryPoint).addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockStake() external onlyOwner {
        IEntryPoint(entryPoint).unlockStake();
    }

    function withdrawStake(address payable to) external onlyOwner {
        IEntryPoint(entryPoint).withdrawStake(to);
    }
}
