pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {OptInService} from "core/src/contracts/service/OptInService.sol";

contract OptInOperator is Script {
    // sepolia
    address constant NEWTORK_OPTIN_SERVICE = 0x58973d16FFA900D11fC22e5e2B6840d9f7e13401;

    function run(
        address network
    ) public {
        vm.startBroadcast();
        OptInService(NEWTORK_OPTIN_SERVICE).optIn(network);
        vm.stopBroadcast();
    }
}
