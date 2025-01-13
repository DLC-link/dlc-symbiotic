pragma solidity 0.8.25;

import {Script} from "forge-std/Script.sol";
import {OperatorRegistry} from "core/src/contracts/OperatorRegistry.sol";

contract RegisterOperator is Script {
    address constant OPERATOR_REGISTRY = 0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548; // sepolia

    function run() public {
        vm.startBroadcast();
        OperatorRegistry(OPERATOR_REGISTRY).registerOperator();
        vm.stopBroadcast();
    }
}
