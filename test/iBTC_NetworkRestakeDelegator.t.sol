// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {NetworkMiddlewareService} from "core/src/contracts/service/NetworkMiddlewareService.sol";
import {NetworkRegistry} from "core/src/contracts/NetworkRegistry.sol";
import {OperatorRegistry} from "core/src/contracts/OperatorRegistry.sol";
import {NetworkMiddleware} from "src/iBTC_NetworkMiddleware.sol";
import {NetworkRestakeDelegator} from "core/src/contracts/delegator/NetworkRestakeDelegator.sol";
import {OptInService} from "core/src/contracts/service/OptInService.sol";
import {iBTC_Vault} from "src/iBTC_Vault.sol";
import {Subnetwork} from "core/src/contracts/libraries/Subnetwork.sol";
import {VaultConfigurator} from "src/iBTC_VaultConfigurator.sol";
import {BurnerRouter} from "burners/src/contracts/router/BurnerRouter.sol";
import {BurnerRouterFactory} from "burners/src/contracts/router/BurnerRouterFactory.sol";
import {MetadataService} from "core/test/service/MetadataService.t.sol";
import {BaseDelegatorHints} from "lib/burners/lib/core/src/contracts/hints/DelegatorHints.sol";
import {VetoSlasher} from "core/src/contracts/slasher/VetoSlasher.sol";
import {iBTC_GlobalReceiver} from "src/iBTC_GlobalReceiver.sol";
import {NetworkMock} from "./mocks/NetworkMock.sol";
import {DefaultStakerRewards} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewards.sol";
import {DefaultOperatorRewards} from "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewards.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {MapWithTimeData} from "../src/libraries/MapWithTimeData.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {IVault} from "core/src/interfaces/vault/IVault.sol";
import {IBurnerRouter} from "burners/src/interfaces/router/IBurnerRouter.sol";
import {INetworkRestakeDelegator} from "core/src/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IBaseDelegator} from "core/src/interfaces/delegator/IBaseDelegator.sol";
import {IVetoSlasher} from "core/src/interfaces/slasher/IVetoSlasher.sol";
import {IBaseSlasher} from "core/src/interfaces/slasher/IBaseSlasher.sol";
import {IVaultConfigurator} from "core/src/interfaces/IVaultConfigurator.sol";
import {IRegistry} from "core/src/interfaces/common/IRegistry.sol";
import {IBTC} from "test/mocks/iBTCMock.sol";
import {RewardTokenMock} from "test/mocks/RewardTokenMock.sol";
import {IDefaultStakerRewardsFactory} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewardsFactory.sol";
import {IDefaultStakerRewards} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewards.sol";
import {IDefaultOperatorRewardsFactory} from
    "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewardsFactory.sol";
import {IDefaultOperatorRewards} from "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewards.sol";

contract iBTC_NetworkRestakeDelegatorTest is Test {
    using Math for uint256;
    using Subnetwork for bytes32;
    using Subnetwork for address;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;

    uint256 sepoliaFork;
    string SEPOLIA_RPC_URL = vm.envString("SEPOLIA_RPC_URL");

    // sepolia
    address constant NETWORK_MIDDLEWARE_SERVICE = 0x62a1ddfD86b4c1636759d9286D3A0EC722D086e3;
    address constant NETWORK_REGISTRY = 0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9;
    address constant OPERATOR_REGISTRY = 0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548;
    address constant COLLATERAL = 0xeb762Ed11a09E4A394C9c8101f8aeeaf5382ED74;
    address constant VAULT_FACTORY = 0x407A039D94948484D356eFB765b3c74382A050B4;
    address constant DELEGATOR_FACTORY = 0x890CA3f95E0f40a79885B7400926544B2214B03f;
    address constant SLASHER_FACTORY = 0xbf34bf75bb779c383267736c53a4ae86ac7bB299;
    address constant NEWTORK_OPTIN_SERVICE = 0x58973d16FFA900D11fC22e5e2B6840d9f7e13401;
    address constant VAULT_OPTIN_SERVICE = 0x95CC0a052ae33941877c9619835A233D21D57351;
    address constant OPERATOR_METADATA_SERVICE = 0x0999048aB8eeAfa053bF8581D4Aa451ab45755c9;
    address constant NETWORK_METADATA_SERVICE = 0x0F7E58Cc4eA615E8B8BEB080dF8B8FDB63C21496;
    address constant DEFAULT_STAKER_REWARDS_FACTORY = 0x70C618a13D1A57f7234c0b893b9e28C5cA8E7f37;
    address constant DEFAULT_OPERATOR_REWARDS_FACTORY = 0x8D6C873cb7ffa6BE615cE1D55801a9417Ed55f9B;
    uint256 constant MAX_WITHDRAW_AMOUNT = 1e9;
    uint256 constant MIN_WITHDRAW_AMOUNT = 1e4;
    uint256 constant ADMIN_FEE_BASE = 1e4;

    bytes32 public constant APPROVED_SIGNER = keccak256("APPROVED_SIGNER");
    bytes32 public constant NETWORK_LIMIT_SET_ROLE = keccak256("NETWORK_LIMIT_SET_ROLE");
    bytes32 public constant OPERATOR_NETWORK_SHARES_SET_ROLE = keccak256("OPERATOR_NETWORK_SHARES_SET_ROLE");
    bytes32 public constant ADMIN_FEE_SET_ROLE = keccak256("ADMIN_FEE_SET_ROLE");
    bytes32 public constant ADMIN_FEE_CLAIM_ROLE = keccak256("ADMIN_FEE_CLAIM_ROLE");
    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    address constant OWNER = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // second address
    address NETWORK; // address network should be a multisig contract
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

    EnumerableMap.AddressToUintMap operators;

    bytes32[] keys;

    address[] vaults;
    address alice;
    uint256 alicePrivateKey;
    address bob;
    uint256 bobPrivateKey;

    address approvedSigner1;
    uint256 approvedSigner1Key;
    address approvedSigner2;
    uint256 approvedSigner2Key;

    OptInService network_optIn_service;
    OptInService vault_optIn_service;
    NetworkMiddleware public iBTC_networkMiddleware;
    BurnerRouter public burner;
    VaultConfigurator public vaultConfigurator;
    iBTC_Vault public iBTC_vault;
    NetworkRegistry networkRegistry;
    OperatorRegistry operatorRegistry;
    NetworkRestakeDelegator iBTC_delegator;
    NetworkMiddlewareService networkMiddlewareService;
    MetadataService operatorMetadataService;
    MetadataService networkMetadataService;
    BaseDelegatorHints baseDelegatorHints;
    NetworkMiddleware networkmiddleware;
    IBTC iBTC;
    VetoSlasher iBTC_slasher;
    iBTC_GlobalReceiver iBTC_globalReceiver;
    NetworkMock public network;
    DefaultStakerRewards public defaultStakerRewards;
    DefaultOperatorRewards public defaultOperatorRewards;
    RewardTokenMock public rewardToken;

    event VetoSlash(uint256 indexed slashIndex, address indexed resolver);
    event StakerRewardsDistributed(uint48 indexed epoch, uint256 rewardAmount, uint256 totalStake, uint256 timestamp);
    event OperatorRewardsDistributed(uint48 indexed epoch, uint256 rewardAmount, uint256 timestamp);

    // staker rewards
    event ClaimRewards(
        address indexed token,
        address indexed network,
        address indexed claimer,
        address recipient,
        uint256 firstRewardIndex,
        uint256 numRewards,
        uint256 amount
    );

    // operator rewards
    event ClaimRewards(
        address recipient, address indexed network, address indexed token, address indexed claimer, uint256 amount
    );

    ProxyAdmin private proxyAdmin;
    TransparentUpgradeableProxy private proxy;

    function setUp() public {
        sepoliaFork = vm.createSelectFork(SEPOLIA_RPC_URL);
        (alice, alicePrivateKey) = makeAddrAndKey("alice");
        (bob, bobPrivateKey) = makeAddrAndKey("bob");
        (approvedSigner1, approvedSigner1Key) = makeAddrAndKey("approvedSigner1");
        (approvedSigner2, approvedSigner2Key) = makeAddrAndKey("approvedSigner2");
        network = new NetworkMock();
        NETWORK = address(network);
        network.registerSubnetwork(0);
        networkRegistry = NetworkRegistry(NETWORK_REGISTRY);
        networkMiddlewareService = NetworkMiddlewareService(NETWORK_MIDDLEWARE_SERVICE);
        operatorRegistry = OperatorRegistry(OPERATOR_REGISTRY);
        iBTC = IBTC(COLLATERAL);
        operatorMetadataService = new MetadataService(OPERATOR_METADATA_SERVICE);
        networkMetadataService = new MetadataService(NETWORK_METADATA_SERVICE);
        address[] memory whitelistedDepositors;

        uint256 depositLimit = 1e10;
        address hook = 0x0000000000000000000000000000000000000000;
        uint64 delegatorIndex = 0;
        uint64 slasherIndex = 1;
        bool withSlasher = true;
        uint16 threshold = 2; // for test case
        uint16 minimumThreshold = 2;
        vm.startPrank(OWNER);

        vaultConfigurator = new VaultConfigurator(VAULT_FACTORY, DELEGATOR_FACTORY, SLASHER_FACTORY);
        //  create Global Receiver
        iBTC_globalReceiver = new iBTC_GlobalReceiver();
        iBTC_globalReceiver.initialize(COLLATERAL, OWNER);

        // create Burner Router
        IBurnerRouter.NetworkReceiver[] memory networkReceiver;
        IBurnerRouter.OperatorNetworkReceiver[] memory operatorNetworkReceiver;
        IBurnerRouter.InitParams memory params = IBurnerRouter.InitParams({
            owner: OWNER,
            collateral: COLLATERAL,
            delay: 0, //NOTE we can set a delay
            globalReceiver: address(iBTC_globalReceiver),
            networkReceivers: networkReceiver,
            operatorNetworkReceivers: operatorNetworkReceiver
        });
        BurnerRouter burnerTemplate = new BurnerRouter();
        BurnerRouterFactory burnerRouterFactory = new BurnerRouterFactory(address(burnerTemplate));
        address burnerAddress = address(burnerRouterFactory.create(params));
        burner = BurnerRouter(burnerAddress);
        assertEq(burner.collateral(), COLLATERAL, "Burner Router should be setting correctly");
        (,, address deployer) = vm.readCallers();

        bool depositWhitelist = whitelistedDepositors.length != 0;

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
        address[] memory networkLimitSetRoleHolders = new address[](roleHolders);
        address[] memory operatorNetworkLimitSetRoleHolders = new address[](roleHolders);
        address[] memory operatorNetworkSharesSetRoleHolders = new address[](roleHolders);
        networkLimitSetRoleHolders[0] = OWNER;
        operatorNetworkLimitSetRoleHolders[0] = OWNER;
        operatorNetworkSharesSetRoleHolders[0] = OWNER;
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

        if (depositWhitelist) {
            iBTC_Vault(vault_).grantRole(iBTC_Vault(vault_).DEFAULT_ADMIN_ROLE(), OWNER);
            iBTC_Vault(vault_).grantRole(iBTC_Vault(vault_).DEPOSITOR_WHITELIST_ROLE(), deployer);

            for (uint256 i; i < whitelistedDepositors.length; ++i) {
                iBTC_Vault(vault_).setDepositorWhitelistStatus(whitelistedDepositors[i], true);
            }

            iBTC_Vault(vault_).renounceRole(iBTC_Vault(vault_).DEPOSITOR_WHITELIST_ROLE(), deployer);
            iBTC_Vault(vault_).renounceRole(iBTC_Vault(vault_).DEFAULT_ADMIN_ROLE(), deployer);
        }
        vm.stopPrank();
        // ------------ End Vault Deployment ------------------
        iBTC_vault = iBTC_Vault(vault_);

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

        iBTC_delegator = NetworkRestakeDelegator(delegator_);
        network_optIn_service = OptInService(NEWTORK_OPTIN_SERVICE);
        vault_optIn_service = OptInService(VAULT_OPTIN_SERVICE);

        vaults.push(vault_);
        vm.startPrank(OWNER);
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
        console.log(Time.timestamp(), "Start Time");

        vm.stopPrank();
        _registerNetwork(NETWORK, address(iBTC_networkMiddleware));

        console.log("Vault: ", vault_);
        console.log("Delegator: ", delegator_);
        console.log("Slasher: ", slasher_);
        assertEq(IVault(vault_).slasher(), slasher_);
        iBTC_slasher = VetoSlasher(slasher_);
        vm.startPrank(address(iBTC_networkMiddleware));
        NetworkRegistry(NETWORK_REGISTRY).registerNetwork();
        NetworkMiddlewareService(NETWORK_MIDDLEWARE_SERVICE).setMiddleware(address(iBTC_networkMiddleware));
        vm.stopPrank();
    }

    function test_SetNetworkLimit() public {
        uint256 amount1 = 1e10;
        uint256 amount2 = 1e9;
        uint256 amount3 = 5e9;
        uint256 amount4 = 8e9;

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        _setMaxNetworkLimit(NETWORK, 0, type(uint256).max);
        _grantRole(OWNER, alice, keccak256("NETWORK_LIMIT_SET_ROLE"));
        _setNetworkLimit(alice, NETWORK, amount1);

        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp), ""), amount1);
        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp + 1), ""), amount1);
        assertEq(iBTC_delegator.networkLimit(NETWORK.subnetwork(0)), amount1);

        _setNetworkLimit(alice, NETWORK, amount2);

        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp), ""), amount2);
        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp + 1), ""), amount2);
        assertEq(iBTC_delegator.networkLimit(NETWORK.subnetwork(0)), amount2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _setNetworkLimit(alice, NETWORK, amount3);

        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp - 1), ""), amount2);
        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp), ""), amount3);
        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp + 1), ""), amount3);
        assertEq(iBTC_delegator.networkLimit(NETWORK.subnetwork(0)), amount3);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _setNetworkLimit(alice, NETWORK, amount4);

        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp - 2), ""), amount2);
        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp - 1), ""), amount3);
        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp), ""), amount4);
        assertEq(iBTC_delegator.networkLimitAt(NETWORK.subnetwork(0), uint48(blockTimestamp + 1), ""), amount4);
        assertEq(iBTC_delegator.networkLimit(NETWORK.subnetwork(0)), amount4);
    }

    function test_Stakes() public {
        uint256 depositAmount = 1e10;
        uint256 withdrawAmount = 5e9;
        uint256 networkLimit = 1e10;
        uint256 operatorNetworkShares1 = 1e10;
        uint256 operatorNetworkShares2 = 5e9;
        uint256 operatorNetworkShares3 = 1e9;
        vm.assume(withdrawAmount <= depositAmount);

        vm.assume(operatorNetworkShares2 - 1 != operatorNetworkShares3);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        _setMaxNetworkLimit(NETWORK, 0, type(uint256).max);

        _registerOperator(alice);
        _registerOperator(bob);

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);
        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), bob), 0);

        _optInOperatorVault(alice);
        _optInOperatorVault(bob);

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);
        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), bob), 0);

        _optInOperatorNetwork(alice, NETWORK);
        _optInOperatorNetwork(bob, NETWORK);

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);
        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), bob), 0);

        _deposit(alice, depositAmount);
        _withdraw(alice, withdrawAmount);

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);
        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), bob), 0);

        _grantRole(OWNER, alice, keccak256("NETWORK_LIMIT_SET_ROLE"));
        _setNetworkLimit(alice, NETWORK, networkLimit);

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);
        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), bob), 0);

        _grantRole(OWNER, alice, keccak256("OPERATOR_NETWORK_SHARES_SET_ROLE"));
        _setOperatorNetworkShares(alice, NETWORK, alice, operatorNetworkShares1);

        assertEq(
            iBTC_delegator.stake(NETWORK.subnetwork(0), alice),
            operatorNetworkShares1.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit), operatorNetworkShares1
            )
        );
        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), bob), 0);

        _setOperatorNetworkShares(alice, NETWORK, bob, operatorNetworkShares2);

        assertEq(
            iBTC_delegator.stake(NETWORK.subnetwork(0), alice),
            operatorNetworkShares1.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit), operatorNetworkShares1 + operatorNetworkShares2
            )
        );
        assertEq(
            iBTC_delegator.stake(NETWORK.subnetwork(0), bob),
            operatorNetworkShares2.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit), operatorNetworkShares1 + operatorNetworkShares2
            )
        );

        _setOperatorNetworkShares(alice, NETWORK, bob, operatorNetworkShares2 - 1);

        assertEq(
            iBTC_delegator.stake(NETWORK.subnetwork(0), alice),
            operatorNetworkShares1.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit),
                operatorNetworkShares1 + operatorNetworkShares2 - 1
            )
        );
        assertEq(
            iBTC_delegator.stakeAt(NETWORK.subnetwork(0), alice, uint48(blockTimestamp), ""),
            operatorNetworkShares1.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit),
                operatorNetworkShares1 + operatorNetworkShares2 - 1
            )
        );
        assertEq(
            iBTC_delegator.stake(NETWORK.subnetwork(0), alice),
            operatorNetworkShares1.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit),
                operatorNetworkShares1 + operatorNetworkShares2 - 1
            )
        );
        assertEq(
            iBTC_delegator.stakeAt(NETWORK.subnetwork(0), bob, uint48(blockTimestamp), ""),
            (operatorNetworkShares2 - 1).mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit),
                operatorNetworkShares1 + operatorNetworkShares2 - 1
            )
        );
        assertEq(
            iBTC_delegator.stake(NETWORK.subnetwork(0), bob),
            (operatorNetworkShares2 - 1).mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit),
                operatorNetworkShares1 + operatorNetworkShares2 - 1
            )
        );

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _setOperatorNetworkShares(alice, NETWORK, bob, operatorNetworkShares3);

        assertEq(
            iBTC_delegator.stakeAt(NETWORK.subnetwork(0), alice, uint48(blockTimestamp - 1), ""),
            operatorNetworkShares1.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit),
                operatorNetworkShares1 + operatorNetworkShares2 - 1
            )
        );
        assertEq(
            iBTC_delegator.stakeAt(NETWORK.subnetwork(0), alice, uint48(blockTimestamp), ""),
            operatorNetworkShares1.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit), operatorNetworkShares1 + operatorNetworkShares3
            )
        );
        assertEq(
            iBTC_delegator.stake(NETWORK.subnetwork(0), alice),
            operatorNetworkShares1.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit), operatorNetworkShares1 + operatorNetworkShares3
            )
        );
        assertEq(
            iBTC_delegator.stakeAt(NETWORK.subnetwork(0), bob, uint48(blockTimestamp - 1), ""),
            (operatorNetworkShares2 - 1).mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit),
                operatorNetworkShares1 + operatorNetworkShares2 - 1
            )
        );
        assertEq(
            iBTC_delegator.stakeAt(NETWORK.subnetwork(0), bob, uint48(blockTimestamp), ""),
            operatorNetworkShares3.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit), operatorNetworkShares1 + operatorNetworkShares3
            )
        );
        assertEq(
            iBTC_delegator.stake(NETWORK.subnetwork(0), bob),
            operatorNetworkShares3.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit), operatorNetworkShares1 + operatorNetworkShares3
            )
        );

        bytes memory hints = abi.encode(
            INetworkRestakeDelegator.StakeHints({
                baseHints: "",
                activeStakeHint: abi.encode(0),
                networkLimitHint: abi.encode(0),
                operatorNetworkSharesHint: abi.encode(0),
                totalOperatorNetworkSharesHint: abi.encode(0)
            })
        );
        uint256 gasLeft = gasleft();
        assertEq(
            iBTC_delegator.stakeAt(NETWORK.subnetwork(0), bob, uint48(blockTimestamp), hints),
            operatorNetworkShares3.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit), operatorNetworkShares1 + operatorNetworkShares3
            )
        );
        uint256 gasSpent = gasLeft - gasleft();
        hints = abi.encode(
            INetworkRestakeDelegator.StakeHints({
                baseHints: "",
                activeStakeHint: abi.encode(0),
                networkLimitHint: abi.encode(0),
                operatorNetworkSharesHint: abi.encode(1),
                totalOperatorNetworkSharesHint: abi.encode(1)
            })
        );
        gasLeft = gasleft();
        assertEq(
            iBTC_delegator.stakeAt(NETWORK.subnetwork(0), bob, uint48(blockTimestamp), hints),
            operatorNetworkShares3.mulDiv(
                Math.min(depositAmount - withdrawAmount, networkLimit), operatorNetworkShares1 + operatorNetworkShares3
            )
        );
        assertGt(gasSpent, gasLeft - gasleft());
    }

    function test_SlashBase() public {
        uint256 depositAmount = 1e10;
        uint256 networkLimit = 1e10;
        uint256 operatorNetworkShares1 = 1e10;
        uint256 operatorNetworkShares2 = 5e9;
        uint256 slashAmount1 = 1e10;

        uint256 blockTimestamp = block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        // address network = alice;
        _setMaxNetworkLimit(NETWORK, 0, type(uint256).max);

        _registerOperator(alice);
        _registerOperator(bob);

        _optInOperatorVault(alice);
        _optInOperatorVault(bob);

        _optInOperatorNetwork(alice, NETWORK);
        _optInOperatorNetwork(bob, NETWORK);

        _deposit(alice, depositAmount);

        _grantRole(OWNER, alice, keccak256("OPERATOR_NETWORK_SHARES_SET_ROLE"));
        _setOperatorNetworkShares(alice, NETWORK, alice, operatorNetworkShares1);
        _setOperatorNetworkShares(alice, NETWORK, bob, operatorNetworkShares2);

        blockTimestamp = blockTimestamp + 2 * iBTC_vault.epochDuration();
        vm.warp(blockTimestamp);

        _grantRole(OWNER, alice, keccak256("NETWORK_LIMIT_SET_ROLE"));
        _setNetworkLimit(alice, NETWORK, networkLimit);

        assertEq(
            iBTC_delegator.networkLimitAt(
                NETWORK.subnetwork(0), uint48(blockTimestamp + 2 * iBTC_vault.epochDuration()), ""
            ),
            networkLimit
        );
        assertEq(iBTC_delegator.networkLimit(NETWORK.subnetwork(0)), networkLimit);
        assertEq(
            iBTC_delegator.totalOperatorNetworkSharesAt(
                NETWORK.subnetwork(0), uint48(blockTimestamp + 2 * iBTC_vault.epochDuration()), ""
            ),
            operatorNetworkShares1 + operatorNetworkShares2
        );
        assertEq(
            iBTC_delegator.totalOperatorNetworkShares(NETWORK.subnetwork(0)),
            operatorNetworkShares1 + operatorNetworkShares2
        );
        assertEq(
            iBTC_delegator.operatorNetworkSharesAt(
                NETWORK.subnetwork(0), alice, uint48(blockTimestamp + 2 * iBTC_vault.epochDuration()), ""
            ),
            operatorNetworkShares1
        );
        assertEq(iBTC_delegator.operatorNetworkShares(NETWORK.subnetwork(0), alice), operatorNetworkShares1);
        assertEq(
            iBTC_delegator.operatorNetworkSharesAt(
                NETWORK.subnetwork(0), bob, uint48(blockTimestamp + 2 * iBTC_vault.epochDuration()), ""
            ),
            operatorNetworkShares2
        );
        assertEq(iBTC_delegator.operatorNetworkShares(NETWORK.subnetwork(0), bob), operatorNetworkShares2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        uint256 operatorNetworkStake1 = operatorNetworkShares1.mulDiv(
            Math.min(networkLimit, depositAmount), operatorNetworkShares1 + operatorNetworkShares2
        );
        vm.assume(operatorNetworkStake1 > 0);
        uint256 slashAmount1Real = Math.min(slashAmount1, operatorNetworkStake1);
        assertEq(
            _slash(address(iBTC_networkMiddleware), NETWORK, alice, slashAmount1, uint48(blockTimestamp - 1), ""),
            slashAmount1Real
        );
        assertEq(
            iBTC_delegator.networkLimitAt(
                NETWORK.subnetwork(0), uint48(blockTimestamp + 2 * iBTC_vault.epochDuration()), ""
            ),
            networkLimit
        );
        assertEq(iBTC_delegator.networkLimit(NETWORK.subnetwork(0)), networkLimit);
        assertEq(
            iBTC_delegator.totalOperatorNetworkSharesAt(
                NETWORK.subnetwork(0), uint48(blockTimestamp + 2 * iBTC_vault.epochDuration()), ""
            ),
            operatorNetworkShares1 + operatorNetworkShares2
        );
        assertEq(
            iBTC_delegator.totalOperatorNetworkShares(NETWORK.subnetwork(0)),
            operatorNetworkShares1 + operatorNetworkShares2
        );
        assertEq(
            iBTC_delegator.operatorNetworkSharesAt(
                NETWORK.subnetwork(0), alice, uint48(blockTimestamp + 2 * iBTC_vault.epochDuration()), ""
            ),
            operatorNetworkShares1
        );
        assertEq(iBTC_delegator.operatorNetworkShares(NETWORK.subnetwork(0), alice), operatorNetworkShares1);
        assertEq(
            iBTC_delegator.operatorNetworkSharesAt(
                NETWORK.subnetwork(0), bob, uint48(blockTimestamp + 2 * iBTC_vault.epochDuration()), ""
            ),
            operatorNetworkShares2
        );
        assertEq(iBTC_delegator.operatorNetworkShares(NETWORK.subnetwork(0), bob), operatorNetworkShares2);
    }

    function _setMaxNetworkLimit(address user, uint96 identifier, uint256 amount) internal {
        vm.startPrank(user);
        iBTC_delegator.setMaxNetworkLimit(identifier, amount);
        vm.stopPrank();
    }

    function _grantRole(address owner, address user, bytes32 role) internal {
        vm.prank(owner);
        iBTC_delegator.grantRole(role, user);
    }

    function _registerNetwork(address user, address middleware) internal {
        vm.startPrank(user);
        networkRegistry.registerNetwork();
        networkMiddlewareService.setMiddleware(middleware);
        vm.stopPrank();
    }

    function _registerOperator(
        address user
    ) internal {
        vm.startPrank(user);
        operatorRegistry.registerOperator();
        vm.stopPrank();
    }

    function _optInOperatorVault(
        address user
    ) internal {
        vm.startPrank(user);
        vault_optIn_service.optIn(address(iBTC_vault));
        vm.stopPrank();
    }

    function _optInOperatorNetwork(address user, address network_) internal {
        vm.startPrank(user);
        network_optIn_service.optIn(network_);
        vm.stopPrank();
    }

    function _setResolver(uint96 identifier, address resolver) internal {
        vm.prank(NETWORK);
        iBTC_slasher.setResolver(identifier, resolver, "");
    }

    function _deposit(address user, uint256 amount) internal returns (uint256 depositedAmount, uint256 mintedShares) {
        vm.prank(iBTC.owner());
        iBTC.setMinter(address(this));
        iBTC.mint(user, amount);
        uint256 operatorBalance = iBTC.balanceOf(user);
        assertEq(operatorBalance, amount, "Operator should have minted tokens");
        vm.startPrank(user);
        iBTC.approve(address(iBTC_vault), amount);
        (depositedAmount, mintedShares) = iBTC_vault.deposit(user, amount);
        vm.stopPrank();
    }

    function _withdraw(address user, uint256 amount) internal returns (uint256 burnedShares, uint256 mintedShares) {
        vm.startPrank(user);
        (burnedShares, mintedShares) = iBTC_vault.withdraw(user, amount);
        vm.stopPrank();
    }

    function _setNetworkLimit(address user, address network_, uint256 amount) internal {
        vm.startPrank(user);
        iBTC_delegator.setNetworkLimit(network_.subnetwork(0), amount);
        vm.stopPrank();
    }

    function _setOperatorNetworkShares(address user, address network_, address operator, uint256 shares) internal {
        vm.startPrank(user);
        iBTC_delegator.setOperatorNetworkShares(network_.subnetwork(0), operator, shares);
        vm.stopPrank();
    }

    function _slash(
        address networkMiddleware,
        address network_,
        address operator,
        uint256 amount,
        uint48 captureTimestamp,
        bytes memory hints
    ) internal returns (uint256 slashAmount) {
        vm.startPrank(networkMiddleware);
        uint256 slashIndex =
            iBTC_slasher.requestSlash(network_.subnetwork(0), operator, amount, captureTimestamp, hints);
        vm.warp(captureTimestamp + 3 days);
        slashAmount = iBTC_slasher.executeSlash(slashIndex, "");
        vm.stopPrank();
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
