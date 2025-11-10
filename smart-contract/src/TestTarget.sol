// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract TestTarget {
    uint256 public value;
    
    function setValue(uint256 _value) external {
        value = _value;
    }
    
    function increment() external {
        value++;
    }
    
    function revertingFunction() external pure {
        revert("Target reverted");
    }
    
    receive() external payable {}
}