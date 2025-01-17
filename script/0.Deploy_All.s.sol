pragma solidity ^0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {NetworkMiddlewareService} from "core/src/contracts/service/NetworkMiddlewareService.sol";
import {NetworkRegistry} from "core/src/contracts/NetworkRegistry.sol";
import {OperatorRegistry} from "core/src/contracts/OperatorRegistry.sol";
import {NetworkMiddleware} from "../src/iBTC_NetworkMiddleware.sol";
import {NetworkRestakeDelegator} from "core/src/contracts/delegator/NetworkRestakeDelegator.sol";
import {OptInService} from "core/src/contracts/service/OptInService.sol";
import {BurnerRouter} from "burners/src/contracts/router/BurnerRouter.sol";
import {BurnerRouterFactory} from "burners/src/contracts/router/BurnerRouterFactory.sol";
import {VetoSlasher} from "core/src/contracts/slasher/VetoSlasher.sol";
import {iBTC_GlobalReceiver} from "src/iBTC_GlobalReceiver.sol";
import {NetworkMock} from "../test/mocks/NetworkMock.sol";
import {DefaultStakerRewards} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewards.sol";
import {DefaultOperatorRewards} from "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewards.sol";
import {RewardTokenMock} from "../test/mocks/RewardTokenMock.sol";
import {NetworkMiddlewareService} from "core/src/contracts/service/NetworkMiddlewareService.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Vm} from "forge-std/Vm.sol";
import {ReadFile} from "./libs/ReadFile.sol";

import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IVaultConfigurator} from "@symbiotic/interfaces/IVaultConfigurator.sol";
import {VaultConfigurator} from "core/src/contracts/VaultConfigurator.sol";
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

//NOTICE: This script for some reason doesn't work for now
contract DeployAll is Script {
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

    address NETWORK;
    address STAKER_REWARDS;
    address OPERATOR_REWARDS;
    address REWARD_TOKEN;
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
    iBTC_GlobalReceiver iBTC_globalReceiver;
    NetworkMock public network;
    DefaultStakerRewards public defaultStakerRewards;
    DefaultOperatorRewards public defaultOperatorRewards;
    RewardTokenMock public rewardToken;

    ProxyAdmin public proxyAdmin;
    TransparentUpgradeableProxy public proxy;

    function run(
        uint256 _chainId
    ) external {
        ReadFile readFile = new ReadFile();
        NETWORK_MIDDLEWARE_SERVICE = readFile.readInput(_chainId, "symbiotic", "NETWORK_MIDDLEWARE_SERVICE");
        NETWORK_REGISTRY = readFile.readInput(_chainId, "symbiotic", "NETWORK_REGISTRY");
        OPERATOR_REGISTRY = readFile.readInput(_chainId, "symbiotic", "OPERATOR_REGISTRY");
        COLLATERAL = readFile.readInput(_chainId, "symbiotic", "COLLATERAL");
        VAULT_FACTORY = readFile.readInput(_chainId, "symbiotic", "VAULT_FACTORY");
        DELEGATOR_FACTORY = readFile.readInput(_chainId, "symbiotic", "DELEGATOR_FACTORY");
        SLASHER_FACTORY = readFile.readInput(_chainId, "symbiotic", "SLASHER_FACTORY");
        NEWTORK_OPTIN_SERVICE = readFile.readInput(_chainId, "symbiotic", "NEWTORK_OPTIN_SERVICE");
        VAULT_OPTIN_SERVICE = readFile.readInput(_chainId, "symbiotic", "VAULT_OPTIN_SERVICE");
        DEFAULT_STAKER_REWARDS_FACTORY = readFile.readInput(_chainId, "symbiotic", "DEFAULT_STAKER_REWARDS_FACTORY");
        DEFAULT_OPERATOR_REWARDS_FACTORY = readFile.readInput(_chainId, "symbiotic", "DEFAULT_OPERATOR_REWARDS_FACTORY");
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

        // ---------------------------------- End Vault Deployment ----------------------------------

        // --------------------------- Start NetworkMiddleware Deployment ---------------------------
        NetworkMock networkMock = new NetworkMock();
        NETWORK = address(networkMock);
        address defaultStakerRewards_ = IDefaultStakerRewardsFactory(DEFAULT_STAKER_REWARDS_FACTORY).create(
            IDefaultStakerRewards.InitParams({
                vault: vault_,
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

    function _registerNetworkMiddleware(
        address middleware
    ) internal {
        NetworkMock(NETWORK).registerInRegistry(NETWORK_REGISTRY);

        NetworkMock(NETWORK).setMiddleware(NETWORK_MIDDLEWARE_SERVICE, middleware);
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
