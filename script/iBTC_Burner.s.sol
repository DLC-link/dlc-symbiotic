// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Script} from "forge-std/Script.sol";
import {iBTC_Treasury} from "../src/iBTC_Treasury.sol";
import {iBTC_Burner} from "../src/iBTC_Burner.sol";

contract DeployiBTC_Burner is Script {
    // Define deployment parameters
    address constant COLLATERAL_ADDRESS = 0xeb762Ed11a09E4A394C9c8101f8aeeaf5382ED74; // eth sepolia
    uint256 constant MAX_WITHDRAW_AMOUNT = 1e9; // 10 iBTC
    uint256 constant MIN_WITHDRAW_AMOUNT = 1e4;

    function run() external {
        // Fetch the private key to deploy contracts
        uint256 deployerPrivateKey = uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80);

        // Start broadcasting transactions from the deployer account
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the iBTC_Treasury contract
        iBTC_Treasury treasury = new iBTC_Treasury(COLLATERAL_ADDRESS, MAX_WITHDRAW_AMOUNT, MIN_WITHDRAW_AMOUNT);

        // Deploy the iBTC_Burner contract
        iBTC_Burner burner = new iBTC_Burner(COLLATERAL_ADDRESS, address(treasury));

        // Stop broadcasting transactions
        vm.stopBroadcast();
    }
}
