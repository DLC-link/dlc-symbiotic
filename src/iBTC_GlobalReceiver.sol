// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract iBTC_GlobalReceiver is OwnableUpgradeable {
    using SafeERC20 for IERC20;

    address public collateral;

    uint256[50] __gap;

    event TokensRedistribution(address indexed token, address indexed to, uint256 amount);

    error ZeroToAddress();
    error ZeroAmount();
    error InsufficientBalance();

    constructor() {
        _disableInitializers();
    }

    function initialize(address iBTC, address initialOwner) public initializer {
        require(iBTC != address(0), "Invalid iBTC address");
        require(initialOwner != address(0), "Invalid owner address");

        __Ownable_init(initialOwner);
        collateral = iBTC;
    }

    function redistributeTokens(address to, uint256 amount) external onlyOwner {
        if (to == address(0)) {
            revert ZeroToAddress();
        }
        if (amount == 0) {
            revert ZeroAmount();
        }
        if (IERC20(collateral).balanceOf(address(this)) < amount) {
            revert InsufficientBalance();
        }

        IERC20(collateral).safeTransfer(to, amount);

        emit TokensRedistribution(collateral, to, amount);
    }
}
