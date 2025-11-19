// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

library ErrorLib {
    error InvalidSignature();
    error NotAuthorized();
    error NotOwnerOrEntryPoint();
    error NotEntryPoint();
    error WrongArrayLengths();
    error InvalidAddress();
}