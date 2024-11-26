// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.25;

import {BaseSlasher} from "@symbiotic/contracts/slasher/BaseSlasher.sol";
import {DelegatorFactory} from "@symbiotic/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "@symbiotic/contracts/SlasherFactory.sol";
import {VaultFactory} from "@symbiotic/contracts/VaultFactory.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IVault} from "core/src/interfaces/vault/IVault.sol";
import {iBTC_Vault} from "./iBTC_Vault.sol";

contract VaultConfigurator is IVaultConfigurator {
    /**
     * @inheritdoc IVaultConfigurator
     */
    address public immutable VAULT_FACTORY;

    /**
     * @inheritdoc IVaultConfigurator
     */
    address public immutable DELEGATOR_FACTORY;

    /**
     * @inheritdoc IVaultConfigurator
     */
    address public immutable SLASHER_FACTORY;

    constructor(address vaultFactory, address delegatorFactory, address slasherFactory) {
        VAULT_FACTORY = vaultFactory;
        DELEGATOR_FACTORY = delegatorFactory;
        SLASHER_FACTORY = slasherFactory;
    }

    /**
     * @inheritdoc IVaultConfigurator
     */
    function create(InitParams memory params) public returns (address vault, address delegator, address slasher) {
        vault = VaultFactory(VAULT_FACTORY).create(params.version, params.owner, params.vaultParams);

        delegator =
            DelegatorFactory(DELEGATOR_FACTORY).create(params.delegatorIndex, abi.encode(vault, params.delegatorParams));

        if (params.withSlasher) {
            slasher =
                SlasherFactory(SLASHER_FACTORY).create(params.slasherIndex, abi.encode(vault, params.slasherParams));
        }

        iBTC_Vault(vault).setDelegator(delegator);
        iBTC_Vault(vault).setSlasher(slasher);
    }
}
