// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {SimpleMiddleware} from "src/SimpleMiddleware.sol";

contract SetupNetworkMiddleware is Script {
    // Using anvil's default addresses
    address constant NETWORK = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266; // first address
    address constant OWNER = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // second address
    uint48 constant EPOCH_DURATION = 7 days;
    uint48 constant SLASHING_WINDOW = 8 days;

    // Registry addresses (Sepolia)
    address constant OPERATOR_REGISTRY = 0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548;
    address constant NETWORK_REGISTRY = 0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9;
    address constant NETWORK_OPTIN = 0x58973d16FFA900D11fC22e5e2B6840d9f7e13401;

    // Initial operators and their keys (if any)
    address[] operators;
    bytes32[] keys;

    // Initial vaults (if any)
    address[] vaults;

    function setUp() public {
        // Add any initial operators and their keys
        // operators.push(address(0));
        // keys.push(bytes32(0));

        // Add any initial vaults
        // vaults.push(address(0));
    }

    function run() external {
        require(operators.length == keys.length, "inconsistent length");
        require(NETWORK != address(0), "set network address");
        require(OWNER != address(0), "set owner address");

        vm.startBroadcast();

        SimpleMiddleware middleware = new SimpleMiddleware(
            NETWORK, OPERATOR_REGISTRY, NETWORK_REGISTRY, NETWORK_OPTIN, OWNER, EPOCH_DURATION, SLASHING_WINDOW
        );

        for (uint256 i = 0; i < vaults.length; ++i) {
            middleware.registerVault(vaults[i]);
        }

        for (uint256 i = 0; i < operators.length; ++i) {
            middleware.registerOperator(operators[i], keys[i]);
        }

        vm.stopBroadcast();
    }
}
