// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {VaultConfigurator} from "core/src/contracts/VaultConfigurator.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {ReadFile} from "./libs/ReadFile.sol";

contract DeployVaultConfigurator is Script {
    address VAULT_FACTORY;
    address DELEGATOR_FACTORY;
    address SLASHER_FACTORY;

    function run(
        uint256 _chainId
    ) external {
        vm.startBroadcast();
        ReadFile readFile = new ReadFile();
        VAULT_FACTORY = readFile.readInput(_chainId, "symbiotic", "VAULT_FACTORY");
        DELEGATOR_FACTORY = readFile.readInput(_chainId, "symbiotic", "DELEGATOR_FACTORY");
        SLASHER_FACTORY = readFile.readInput(_chainId, "symbiotic", "SLASHER_FACTORY");

        // Deploy the VaultConfigurator contract
        VaultConfigurator vaultConfigurator = new VaultConfigurator(VAULT_FACTORY, DELEGATOR_FACTORY, SLASHER_FACTORY);

        // Log the deployed address
        console2.log("VaultConfigurator deployed at:", address(vaultConfigurator));

        vm.stopBroadcast();
    }
}
