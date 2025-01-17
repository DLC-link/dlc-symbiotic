// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";

import {IMigratablesFactory} from "@symbiotic/interfaces/common/IMigratablesFactory.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "@symbiotic/interfaces/delegator/IFullRestakeDelegator.sol";
import {IOperatorSpecificDelegator} from "@symbiotic/interfaces/delegator/IOperatorSpecificDelegator.sol";
import {IBaseSlasher} from "@symbiotic/interfaces/slasher/IBaseSlasher.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {ReadFile} from "./libs/ReadFile.sol";

contract VaultScript is Script {
    // ------------------------------- contracts on sepolia -------------------------------
    address NETWORK_MIDDLEWARE_SERVICE;
    address NETWORK_REGISTRY;
    address OPERATOR_REGISTRY;
    address COLLATERAL;
    address VAULT_FACTORY;
    address DELEGATOR_FACTORY;
    address SLASHER_FACTORY;
    address NEWTORK_OPTIN_SERVICE;
    address VAULT_OPTIN_SERVICE;
    address DEFAULT_STAKER_REWARDS_FACTORY;
    address DEFAULT_OPERATOR_REWARDS_FACTORY;
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

    function run(uint256 _chainId, address vaultConfigurator, address burner) public {
        ReadFile readFile = new ReadFile();
        COLLATERAL = readFile.readInput(_chainId, "iBTC", "COLLATERAL");
        VAULT_FACTORY = readFile.readInput(_chainId, "symbiotic", "VAULT_FACTORY");
        DELEGATOR_FACTORY = readFile.readInput(_chainId, "symbiotic", "DELEGATOR_FACTORY");
        SLASHER_FACTORY = readFile.readInput(_chainId, "symbiotic", "SLASHER_FACTORY");
        NETWORK_MIDDLEWARE_SERVICE = readFile.readInput(_chainId, "symbiotic", "NETWORK_MIDDLEWARE_SERVICE");
        NETWORK_REGISTRY = readFile.readInput(_chainId, "symbiotic", "NETWORK_REGISTRY");
        OPERATOR_REGISTRY = readFile.readInput(_chainId, "symbiotic", "OPERATOR_REGISTRY");
        NEWTORK_OPTIN_SERVICE = readFile.readInput(_chainId, "symbiotic", "NEWTORK_OPTIN_SERVICE");
        VAULT_OPTIN_SERVICE = readFile.readInput(_chainId, "symbiotic", "VAULT_OPTIN_SERVICE");
        DEFAULT_STAKER_REWARDS_FACTORY = readFile.readInput(_chainId, "symbiotic", "DEFAULT_STAKER_REWARDS_FACTORY");
        DEFAULT_OPERATOR_REWARDS_FACTORY = readFile.readInput(_chainId, "symbiotic", "DEFAULT_OPERATOR_REWARDS_FACTORY");

        uint256 depositLimit = 1e10;
        address hook = 0x0000000000000000000000000000000000000000;
        uint64 delegatorIndex = 0;
        uint64 slasherIndex = 1;
        bool withSlasher = true;
        vm.startBroadcast();
        (,, address deployer) = vm.readCallers();

        bool depositWhitelist = false;

        bytes memory vaultParams = abi.encode(
            IVault.InitParams({
                collateral: COLLATERAL,
                burner: address(burner),
                epochDuration: VAULT_EPOCH_DURATION,
                depositWhitelist: depositWhitelist,
                isDepositLimit: depositLimit != 0,
                depositLimit: depositLimit,
                defaultAdminRoleHolder: depositWhitelist ? deployer : OWNER,
                depositWhitelistSetRoleHolder: OWNER,
                depositorWhitelistRoleHolder: OWNER,
                isDepositLimitSetRoleHolder: OWNER,
                depositLimitSetRoleHolder: OWNER
            })
        );
        uint256 roleHolders = 1;
        if (hook != address(0) && hook != OWNER) {
            roleHolders = 2;
        }
        address[] memory networkLimitSetRoleHolders = new address[](roleHolders);
        address[] memory operatorNetworkLimitSetRoleHolders = new address[](roleHolders);
        address[] memory operatorNetworkSharesSetRoleHolders = new address[](roleHolders);
        networkLimitSetRoleHolders[0] = OWNER;
        operatorNetworkLimitSetRoleHolders[0] = OWNER;
        operatorNetworkSharesSetRoleHolders[0] = OWNER;
        if (roleHolders > 1) {
            networkLimitSetRoleHolders[1] = hook;
            operatorNetworkLimitSetRoleHolders[1] = hook;
            operatorNetworkSharesSetRoleHolders[1] = hook;
        }

        bytes memory delegatorParams;
        if (delegatorIndex == 0) {
            delegatorParams = abi.encode(
                INetworkRestakeDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: OWNER,
                        hook: hook,
                        hookSetRoleHolder: OWNER
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
                })
            );
        } else if (delegatorIndex == 1) {
            delegatorParams = abi.encode(
                IFullRestakeDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: OWNER,
                        hook: hook,
                        hookSetRoleHolder: OWNER
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operatorNetworkLimitSetRoleHolders: operatorNetworkLimitSetRoleHolders
                })
            );
        } else if (delegatorIndex == 2) {
            delegatorParams = abi.encode(
                IOperatorSpecificDelegator.InitParams({
                    baseParams: IBaseDelegator.BaseParams({
                        defaultAdminRoleHolder: OWNER,
                        hook: hook,
                        hookSetRoleHolder: OWNER
                    }),
                    networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                    operator: OWNER
                })
            );
        }

        bytes memory slasherParams;
        if (slasherIndex == 0) {
            slasherParams = abi.encode(
                ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: burner != address(0)})})
            );
        } else if (slasherIndex == 1) {
            slasherParams = abi.encode(
                IVetoSlasher.InitParams({
                    baseParams: IBaseSlasher.BaseParams({isBurnerHook: burner != address(0)}),
                    vetoDuration: vetoDuration,
                    resolverSetEpochsDelay: 3
                })
            );
        }

        (address vault_, address delegator_, address slasher_) = IVaultConfigurator(vaultConfigurator).create(
            IVaultConfigurator.InitParams({
                version: 1,
                owner: OWNER,
                vaultParams: vaultParams,
                delegatorIndex: delegatorIndex,
                delegatorParams: delegatorParams,
                withSlasher: withSlasher,
                slasherIndex: slasherIndex,
                slasherParams: slasherParams
            })
        );

        console2.log("Vault: ", vault_);
        console2.log("Delegator: ", delegator_);
        console2.log("Slasher: ", slasher_);

        vm.stopBroadcast();
    }
}
