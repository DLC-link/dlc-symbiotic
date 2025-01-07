pragma solidity ^0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {NetworkMiddlewareService} from "core/src/contracts/service/NetworkMiddlewareService.sol";
import {NetworkRegistry} from "core/src/contracts/NetworkRegistry.sol";
import {OperatorRegistry} from "core/src/contracts/OperatorRegistry.sol";
import {NetworkMiddleware} from "../src/iBTC_NetworkMiddleware.sol";
import {NetworkRestakeDelegator} from "core/src/contracts/delegator/NetworkRestakeDelegator.sol";
import {OptInService} from "core/src/contracts/service/OptInService.sol";
import {VaultConfigurator} from "src/iBTC_VaultConfigurator.sol";
import {BurnerRouter} from "burners/src/contracts/router/BurnerRouter.sol";
import {BurnerRouterFactory} from "burners/src/contracts/router/BurnerRouterFactory.sol";
import {VetoSlasher} from "core/src/contracts/slasher/VetoSlasher.sol";
import {iBTC_GlobalReceiver} from "src/iBTC_GlobalReceiver.sol";
import {NetworkMock} from "../test/mocks/NetworkMock.sol";
import {DefaultStakerRewards} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewards.sol";
import {DefaultOperatorRewards} from "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewards.sol";
import {RewardTokenMock} from "../test/mocks/RewardTokenMock.sol";
import {NetworkMiddlewareService} from "core/src/contracts/service/NetworkMiddlewareService.sol";
import {iBTC_Vault} from "src/iBTC_Vault.sol";

import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {INetworkRestakeDelegator} from "@symbiotic/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IBaseSlasher} from "@symbiotic/interfaces/slasher/IBaseSlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {IBurnerRouter} from "burners/src/interfaces/router/IBurnerRouter.sol";
import {IDefaultStakerRewardsFactory} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewardsFactory.sol";
import {IDefaultOperatorRewardsFactory} from
    "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewardsFactory.sol";
import {IDefaultStakerRewards} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewards.sol";
import {IDefaultOperatorRewards} from "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewards.sol";

contract DeployAll is Script {
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
    address NETWORK;
    address STAKER_REWARDS;
    address OPERATOR_REWARDS;
    address REWARD_TOKEN;
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

    OptInService network_optIn_service;
    OptInService vault_optIn_service;
    NetworkMiddleware public iBTC_networkMiddleware;
    BurnerRouter public burner;
    VaultConfigurator public vaultConfigurator;
    NetworkRegistry networkRegistry;
    OperatorRegistry operatorRegistry;
    NetworkRestakeDelegator iBTC_delegator;
    NetworkMiddlewareService networkMiddlewareService;
    NetworkMiddleware networkmiddleware;
    VetoSlasher iBTC_slasher;
    iBTC_Vault public iBTC_vault;
    iBTC_GlobalReceiver iBTC_globalReceiver;
    NetworkMock public network;
    DefaultStakerRewards public defaultStakerRewards;
    DefaultOperatorRewards public defaultOperatorRewards;
    RewardTokenMock public rewardToken;

    function run() external {
        uint256 depositLimit = 1e10;
        address hook = 0x0000000000000000000000000000000000000000;
        uint64 delegatorIndex = 0;
        uint64 slasherIndex = 1;
        bool withSlasher = true;
        uint16 threshold = 2; // for test case
        uint16 minimumThreshold = 2;
        vm.startBroadcast();

        //  ---------------------------------- Start Vault Deployment ----------------------------------

        // ------------------------------- Start Global Receiver Deployment -------------------------------
        iBTC_globalReceiver = new iBTC_GlobalReceiver();
        iBTC_globalReceiver.initialize(COLLATERAL, OWNER);
        // ------------------------------- End Global Receiver Deployment -------------------------------

        // ------------------------------- Start Vault Configurator Deployment -------------------------------
        vaultConfigurator = new VaultConfigurator(VAULT_FACTORY, DELEGATOR_FACTORY, SLASHER_FACTORY);
        // ------------------------------- End   Vault Configurator Deployment -------------------------------

        // ------------------------------- Start Burner Deployment -------------------------------
        // burner setup
        IBurnerRouter.InitParams memory params = IBurnerRouter.InitParams({
            owner: OWNER,
            collateral: COLLATERAL,
            delay: 0,
            globalReceiver: address(iBTC_globalReceiver),
            networkReceivers: new IBurnerRouter.NetworkReceiver[](0),
            operatorNetworkReceivers: new IBurnerRouter.OperatorNetworkReceiver[](0)
        });
        BurnerRouter burnerTemplate = new BurnerRouter();
        BurnerRouterFactory burnerRouterFactory = new BurnerRouterFactory(address(burnerTemplate));
        address burnerAddress = address(burnerRouterFactory.create(params));
        burner = BurnerRouter(burnerAddress);

        // Vault setup
        bytes memory vaultParams = abi.encode(
            IVault.InitParams({
                collateral: COLLATERAL,
                burner: address(burner),
                epochDuration: VAULT_EPOCH_DURATION,
                depositWhitelist: false,
                isDepositLimit: depositLimit != 0,
                depositLimit: depositLimit,
                defaultAdminRoleHolder: OWNER,
                depositWhitelistSetRoleHolder: OWNER,
                depositorWhitelistRoleHolder: OWNER,
                isDepositLimitSetRoleHolder: OWNER,
                depositLimitSetRoleHolder: OWNER
            })
        );

        // Role holders setup
        uint256 roleHolders = 1;
        address[] memory networkLimitSetRoleHolders = new address[](roleHolders);
        address[] memory operatorNetworkLimitSetRoleHolders = new address[](roleHolders);
        address[] memory operatorNetworkSharesSetRoleHolders = new address[](roleHolders);
        networkLimitSetRoleHolders[0] = OWNER;
        operatorNetworkLimitSetRoleHolders[0] = OWNER;
        operatorNetworkSharesSetRoleHolders[0] = OWNER;

        // Delegator params
        bytes memory delegatorParams;
        delegatorParams = abi.encode(
            INetworkRestakeDelegator.InitParams({
                baseParams: IBaseDelegator.BaseParams({defaultAdminRoleHolder: OWNER, hook: hook, hookSetRoleHolder: OWNER}),
                networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
            })
        );
        bytes memory slasherParams;
        slasherParams = abi.encode(
            IVetoSlasher.InitParams({
                baseParams: IBaseSlasher.BaseParams({isBurnerHook: address(burner) != address(0)}),
                vetoDuration: vetoDuration,
                resolverSetEpochsDelay: 3
            })
        );
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

        // we don't need to set deposit whitelist for now
        // if (depositWhitelist) {
        //     iBTC_Vault(vault_).grantRole(iBTC_Vault(vault_).DEFAULT_ADMIN_ROLE(), OWNER);
        //     iBTC_Vault(vault_).grantRole(iBTC_Vault(vault_).DEPOSITOR_WHITELIST_ROLE(), deployer);

        //     for (uint256 i; i < whitelistedDepositors.length; ++i) {
        //         iBTC_Vault(vault_).setDepositorWhitelistStatus(whitelistedDepositors[i], true);
        //     }

        //     iBTC_Vault(vault_).renounceRole(iBTC_Vault(vault_).DEPOSITOR_WHITELIST_ROLE(), deployer);
        //     iBTC_Vault(vault_).renounceRole(iBTC_Vault(vault_).DEFAULT_ADMIN_ROLE(), deployer);
        // }

        iBTC_vault = iBTC_Vault(vault_);

        // ---------------------------------- End Vault Deployment ----------------------------------

        // --------------------------- Start NetworkMiddleware Deployment ---------------------------
        NetworkMock networkMock = new NetworkMock();
        NETWORK = address(networkMock);
        address defaultStakerRewards_ = IDefaultStakerRewardsFactory(DEFAULT_STAKER_REWARDS_FACTORY).create(
            IDefaultStakerRewards.InitParams({
                vault: address(iBTC_vault),
                adminFee: 1000, // admin fee percent to get from all the rewards distributions (10% = 1_000 | 100% = 10_000)
                defaultAdminRoleHolder: OWNER, // address of the main admin (can manage all roles)
                adminFeeClaimRoleHolder: OWNER, // address of the admin fee claimer
                adminFeeSetRoleHolder: OWNER // address of the admin fee setter
            })
        );
        address defaultOperatorRewards_ = IDefaultOperatorRewardsFactory(DEFAULT_OPERATOR_REWARDS_FACTORY).create();
        rewardToken = new RewardTokenMock("reward", "REWARD", 100e18);

        STAKER_REWARDS = address(defaultStakerRewards_);
        OPERATOR_REWARDS = address(defaultOperatorRewards_);
        REWARD_TOKEN = address(rewardToken);
        defaultStakerRewards = DefaultStakerRewards(STAKER_REWARDS);
        defaultOperatorRewards = DefaultOperatorRewards(OPERATOR_REWARDS);

        iBTC_networkMiddleware = new NetworkMiddleware(
            NETWORK,
            OPERATOR_REGISTRY,
            NETWORK_REGISTRY,
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
        // --------------------------- End NetworkMiddleware Deployment ---------------------------

        console2.log("Vault: ", vault_);
        console2.log("Delegator: ", delegator_);
        console2.log("Slasher: ", slasher_);
        console2.log("iBTC_GlobalReceiver: ", address(iBTC_globalReceiver));
        console2.log("NETWORK: ", NETWORK);
        console2.log("DefaultStakerRewards: ", STAKER_REWARDS);
        console2.log("DefaultOperatorRewards: ", OPERATOR_REWARDS);
        console2.log("RewardToken: ", REWARD_TOKEN);
        console2.log("NetworkMiddleware: ", address(iBTC_networkMiddleware));
        // _registerNetworkMiddleware(address(iBTC_networkMiddleware));

        // ------------------------ End NetworkMiddleware Deployment -------------------------

        vm.stopBroadcast();
    }

    // function _registerNetworkMiddleware(
    //     address middleware
    // ) internal {
    //     NetworkMock(NETWORK).registerInRegistry(NETWORK_REGISTRY);

    //     NetworkMock(NETWORK).setMiddleware(NETWORK_MIDDLEWARE_SERVICE, middleware);
    // }
}
