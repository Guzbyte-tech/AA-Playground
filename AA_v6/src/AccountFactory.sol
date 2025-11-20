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
    address public immutable owner;


    address[] public smartAccounts;

    constructor(IEntryPoint _entryPoint) {
        ACCOUNT_IMPLEMENTATION = new SmartUserAccount(_entryPoint);
        entryPoint = _entryPoint;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not factory owner");
        _;
    }

    /**
     * @notice Create an account, and return its address
     * @dev returns the address even if the account is already deployed.
     * Note that during UserOperation execution, this method is called only if the account is not deployed.
     * This method returns an existing account address so that entryPoint.getSenderAddress() would work even after account creation
    */
    function createAccount(address owner, uint256 salt) public returns (SmartUserAccount ret) {
        if (owner == address(0)) revert ErrorLib.InvalidAddress();

        address addr = getPredictedAddress(owner, salt);
        uint256 codeSize = addr.code.length;
        if (codeSize > 0) {
            return SmartUserAccount(payable(addr));
        }
        ret = SmartUserAccount(
            payable(
                new ERC1967Proxy{salt: bytes32(salt)}(
                    address(ACCOUNT_IMPLEMENTATION),
                    abi.encodeCall(SmartUserAccount.initialize, (owner))
                )
            )
        );

        smartAccounts.push(address(ret));
    }

    /**
     * @notice Calculate the counterfactual address of this account as it would be returned by createAccount()
    */
    function getPredictedAddress(address owner, uint256 salt) public view returns (address) {
        return Create2.computeAddress(
            bytes32(salt),
            keccak256(
                abi.encodePacked(
                    type(ERC1967Proxy).creationCode,
                    abi.encode(
                        address(ACCOUNT_IMPLEMENTATION),
                        abi.encodeCall(SmartUserAccount.initialize, (owner))    
                    )
                )
            ),
            address(this)
        );
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
