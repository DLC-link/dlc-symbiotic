pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {NetworkMiddleware} from "../src/iBTC_NetworkMiddleware.sol";

contract DeployNetworkMiddleware is Script {
    address constant OPERATOR_REGISTRY = 0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548;
    address constant NETWORK_REGISTRY = 0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9;
    address constant NEWTORK_OPTIN_SERVICE = 0x58973d16FFA900D11fC22e5e2B6840d9f7e13401;
    address constant VAULT_FACTORY = 0x407A039D94948484D356eFB765b3c74382A050B4;
    address constant OWNER = 0x8Ae0F53A071F5036910509FE48eBB8b3558fa9fD; //NOTE: Rayer's testing account

    /*
    Rules:
    1. Vault Epoch Duration should be significantly greater than validatorSetCaptureDelay + Network Epoch + Slashing Window.
    2. Veto Duration should not be too close to Vault Epoch Duration to prevent delays or high gas costs from hindering slashing execution.
    3. Provide sufficient buffer time to ensure slashing requests can be executed safely.
    */
    uint48 constant VAULT_EPOCH_DURATION = 14 days; // Vault Epoch Duration: Ensures ample time for slashing execution and avoids conflicts.
    uint48 constant NETWORK_EPOCH = 4 days; // Network Epoch: Defines how frequently the network processes updates or slashing events.
    uint48 constant SLASHING_WINDOW = 6 days; // Slashing Window: The duration within which slashing requests can be executed.
    uint48 constant validatorSetCaptureDelay = 15 minutes; // Validator Set Capture Delay: Time to wait for block finality (e.g., on Ethereum).
    uint48 constant maxSlashRequestDelay = 2 days; // Max Slash Request Delay: Maximum allowed delay for executing a slashing request.
    uint48 constant vetoDuration = 1 days; // Veto Duration: Time allocated for vetoing a slashing request.
    uint16 constant threshold = 2; // for test case
    uint16 constant minimumThreshold = 2;

    function run(address NETWORK, address STAKER_REWARDS, address OPERATOR_REWARDS, address REWARD_TOKEN) external {
        vm.startBroadcast();
        NetworkMiddleware iBTC_networkMiddleware = new NetworkMiddleware(
            NETWORK,
            OPERATOR_REGISTRY,
            VAULT_FACTORY,
            NEWTORK_OPTIN_SERVICE,
            OWNER,
            STAKER_REWARDS,
            OPERATOR_REWARDS,
            REWARD_TOKEN,
            NETWORK_EPOCH,
            SLASHING_WINDOW,
            threshold,
            minimumThreshold
        );
        console2.log("NetworkMiddleware deployed at:", address(iBTC_networkMiddleware));
        vm.stopBroadcast();
    }
}
