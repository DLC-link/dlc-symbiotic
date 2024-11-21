// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";

contract DeployFactories is Script {
    address constant OWNER = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

    function run() external {
        uint256 deployerPrivateKey = uint256(0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80);
        vm.startBroadcast(deployerPrivateKey);

        DelegatorFactory delegatorFactory = new DelegatorFactory(OWNER);
        console2.log("DelegatorFactory deployed at:", address(delegatorFactory));

        SlasherFactory slasherFactory = new SlasherFactory(OWNER);
        console2.log("SlasherFactory deployed at:", address(slasherFactory));

        VaultFactory vaultFactory = new VaultFactory(OWNER);
        console2.log("VaultFactory deployed at:", address(vaultFactory));

        vm.stopBroadcast();
    }
}
