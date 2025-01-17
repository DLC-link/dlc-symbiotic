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

contract VaultScript is Script {
    // ------------------------------- contracts on sepolia -------------------------------
    address constant NETWORK_MIDDLEWARE_SERVICE = 0x62a1ddfD86b4c1636759d9286D3A0EC722D086e3;
    address constant NETWORK_REGISTRY = 0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9;
    address constant OPERATOR_REGISTRY = 0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548;
    address constant COLLATERAL = 0xeb762Ed11a09E4A394C9c8101f8aeeaf5382ED74;
    address constant VAULT_FACTORY = 0x407A039D94948484D356eFB765b3c74382A050B4;
    address constant DELEGATOR_FACTORY = 0x890CA3f95E0f40a79885B7400926544B2214B03f;
    address constant SLASHER_FACTORY = 0xbf34bf75bb779c383267736c53a4ae86ac7bB299;
    address constant NEWTORK_OPTIN_SERVICE = 0x58973d16FFA900D11fC22e5e2B6840d9f7e13401;
    address constant VAULT_OPTIN_SERVICE = 0x95CC0a052ae33941877c9619835A233D21D57351;
    address constant OWNER = 0x8Ae0F53A071F5036910509FE48eBB8b3558fa9fD; //NOTE: Rayer's testing account
    address constant DEFAULT_STAKER_REWARDS_FACTORY = 0x70C618a13D1A57f7234c0b893b9e28C5cA8E7f37;
    address constant DEFAULT_OPERATOR_REWARDS_FACTORY = 0x8D6C873cb7ffa6BE615cE1D55801a9417Ed55f9B;
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

    function run(address vaultConfigurator, address burner) public {
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
