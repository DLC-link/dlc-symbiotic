// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

contract SelfDestruct {
    constructor() payable {
        selfdestruct(payable(address(this)));
    }
}
