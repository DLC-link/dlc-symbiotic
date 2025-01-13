pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {OptInService} from "core/src/contracts/service/OptInService.sol";

contract OptInVault is Script {
    // sepolia
    address constant VAULT_OPTIN_SERVICE = 0x95CC0a052ae33941877c9619835A233D21D57351;

    function run(
        address vault
    ) public {
        vm.startBroadcast();
        OptInService(VAULT_OPTIN_SERVICE).optIn(vault);
        vm.stopBroadcast();
    }
}
