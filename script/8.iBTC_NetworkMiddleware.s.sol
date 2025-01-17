pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {NetworkMiddleware} from "../src/iBTC_NetworkMiddleware.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Vm} from "forge-std/Vm.sol";

contract DeployNetworkMiddleware is Script {
    address constant OPERATOR_REGISTRY = 0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548;
    address constant NETWORK_REGISTRY = 0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9;
    address constant NEWTORK_OPTIN_SERVICE = 0x58973d16FFA900D11fC22e5e2B6840d9f7e13401;
    address constant VAULT_FACTORY = 0x407A039D94948484D356eFB765b3c74382A050B4;
    address constant OWNER = 0x8Ae0F53A071F5036910509FE48eBB8b3558fa9fD; //NOTE: Rayer's testing account

    /*
    Notes:
    1. SLASHING_WINDOW is derived from EPOCH_DURATION and maxSlashRequestDelay.
    2. SLASHING_WINDOW + vetoDuration must always be less than VAULT_EPOCH_DURATION.
    3. This configuration allows for a buffer of 7 days (maxSlashExecutionDelay) for off-chain slashing execution.
    4. The setup can accommodate vaults with shorter epoch durations or higher veto durations by adjusting SLASHING_WINDOW.
    */
    // Vault parameters
    uint48 constant VAULT_EPOCH_DURATION = 14 days; // Total duration of the vault's epoch.
    uint48 constant vetoDuration = 1 days; // Time allocated for vetoing a slashing request.

    // Middleware parameters
    uint48 constant validatorSetCaptureDelay = 15 minutes; // Time delay before capturing the validator set.
    uint48 constant NETWORK_EPOCH = 4 days; // Duration of a network epoch for processing updates or slashing events.
    uint48 constant maxSlashRequestDelay = 2 days; // Maximum delay allowed for initiating a slashing request.
    uint48 constant SLASHING_WINDOW = 6 days; // Total time allocated for slashing in a network epoch (EPOCH_DURATION + maxSlashRequestDelay).

    // Derived values (off-chain consideration)
    uint48 maxSlashExecutionDelay = VAULT_EPOCH_DURATION - SLASHING_WINDOW - vetoDuration;
    // maxSlashExecutionDelay = 14 days - 6 days - 1 day = 7 days

    uint16 constant threshold = 2; // for test case
    uint16 constant minimumThreshold = 2;

    ProxyAdmin private proxyAdmin;
    TransparentUpgradeableProxy private proxy;
    NetworkMiddleware private iBTC_networkMiddleware;

    function run(address NETWORK, address STAKER_REWARDS, address OPERATOR_REWARDS, address REWARD_TOKEN) external {
        vm.startBroadcast();
        NetworkMiddleware implementation = new NetworkMiddleware();
        proxy = new TransparentUpgradeableProxy(
            address(implementation),
            OWNER,
            abi.encodeWithSelector(
                NetworkMiddleware.initialize.selector,
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
            )
        );
        proxyAdmin = ProxyAdmin(_getAdminAddress(address(proxy)));
        iBTC_networkMiddleware = NetworkMiddleware(address(proxy));

        console2.log("NetworkMiddleware deployed at:", address(iBTC_networkMiddleware));
        console2.log("ProxyAdmin deployed at:", address(proxyAdmin));
        vm.stopBroadcast();
    }

    function _getAdminAddress(
        address proxy_
    ) internal view returns (address) {
        address CHEATCODE_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
        Vm vm = Vm(CHEATCODE_ADDRESS);

        bytes32 adminSlot = vm.load(proxy_, ERC1967Utils.ADMIN_SLOT);
        return address(uint160(uint256(adminSlot)));
    }
}
