// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library ErrorLib {
    error InvalidSignature();
    error NotAuthorized();
    error NotOwnerOrEntryPoint();
    error NotEntryPoint();
    error WrongArrayLengths();
    error InvalidAddress();
    error ZeroAddressNotAllowed();
    error ArrayLengthMismatch();
    error InsufficientBalance();
    error UpgradeNotAuthorized();
    error InvalidAmount();
    error TransferFailed();
    error InsufficientAllowance();

}