// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {VaultConfigurator} from "core/src/contracts/VaultConfigurator.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";

contract DeployVaultConfigurator is Script {
    address constant VAULT_FACTORY = 0x407A039D94948484D356eFB765b3c74382A050B4;
    address constant DELEGATOR_FACTORY = 0x890CA3f95E0f40a79885B7400926544B2214B03f;
    address constant SLASHER_FACTORY = 0xbf34bf75bb779c383267736c53a4ae86ac7bB299;

    function run() external {
        vm.startBroadcast();

        // Deploy the VaultConfigurator contract
        VaultConfigurator vaultConfigurator = new VaultConfigurator(VAULT_FACTORY, DELEGATOR_FACTORY, SLASHER_FACTORY);

        // Log the deployed address
        console2.log("VaultConfigurator deployed at:", address(vaultConfigurator));

        vm.stopBroadcast();
    }
}
