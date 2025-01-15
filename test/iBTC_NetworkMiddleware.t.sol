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
import {Vault} from "core/src/contracts/vault/Vault.sol";
import {Subnetwork} from "core/src/contracts/libraries/Subnetwork.sol";
import {VaultConfigurator} from "core/src/contracts/VaultConfigurator.sol";
import {BurnerRouter} from "burners/src/contracts/router/BurnerRouter.sol";
import {BurnerRouterFactory} from "burners/src/contracts/router/BurnerRouterFactory.sol";
import {MetadataService} from "core/test/service/MetadataService.t.sol";
import {BaseDelegatorHints} from "lib/burners/lib/core/src/contracts/hints/DelegatorHints.sol";
import {VetoSlasher} from "core/src/contracts/slasher/VetoSlasher.sol";
import {iBTC_GlobalReceiver} from "src/iBTC_GlobalReceiver.sol";
import {NetworkMock} from "./mocks/NetworkMock.sol";
import {DefaultStakerRewards} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewards.sol";
import {DefaultOperatorRewards} from "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewards.sol";
import {VaultHints} from "@symbioticfi/core/src/contracts/hints/VaultHints.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {Vm} from "forge-std/Vm.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {MapWithTimeData} from "../src/libraries/MapWithTimeData.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {Hashes} from "@openzeppelin/contracts/utils/cryptography/Hashes.sol";

import {IVault} from "core/src/interfaces/vault/IVault.sol";
import {IBurnerRouter} from "burners/src/interfaces/router/IBurnerRouter.sol";
import {INetworkRestakeDelegator} from "core/src/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IBaseDelegator} from "core/src/interfaces/delegator/IBaseDelegator.sol";
import {IVetoSlasher} from "core/src/interfaces/slasher/IVetoSlasher.sol";
import {IBaseSlasher} from "core/src/interfaces/slasher/IBaseSlasher.sol";
import {IVaultConfigurator} from "core/src/interfaces/IVaultConfigurator.sol";
import {IRegistry} from "core/src/interfaces/common/IRegistry.sol";
import {IDefaultStakerRewardsFactory} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewardsFactory.sol";
import {IDefaultStakerRewards} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewards.sol";
import {IDefaultOperatorRewardsFactory} from
    "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewardsFactory.sol";
import {IDefaultOperatorRewards} from "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewards.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IBTC} from "test/mocks/iBTCMock.sol";
import {RewardTokenMock} from "test/mocks/RewardTokenMock.sol";
import {NetworkMiddlewareV2} from "test/mocks/iBTC_NetworkMiddlwareV2Mock.sol";

contract iBTC_NetworkMiddlewareTest is Test {
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
    uint16 threshold = 2; // for test case
    uint16 minimumThreshold = 2;
    EnumerableMap.AddressToUintMap operators;

    bytes32[] keys;

    address[] vaults;
    address alice;
    uint256 alicePrivateKey;
    address bob;
    uint256 bobPrivateKey;
    bytes32 alice_key = keccak256(abi.encodePacked("alice_key"));
    bytes32 bob_key = keccak256(abi.encodePacked("bob_key"));

    address approvedSigner1;
    uint256 approvedSigner1Key;
    address approvedSigner2;
    uint256 approvedSigner2Key;

    OptInService network_optIn_service;
    OptInService vault_optIn_service;
    NetworkMiddleware public iBTC_networkMiddleware;
    BurnerRouter public burner;
    VaultConfigurator public vaultConfigurator;
    Vault public vault;
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

        uint256 depositLimit = 1000e8;
        address hook = 0x0000000000000000000000000000000000000000;
        uint64 delegatorIndex = 0;
        uint64 slasherIndex = 1;
        bool withSlasher = true;

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
            Vault(vault_).grantRole(Vault(vault_).DEFAULT_ADMIN_ROLE(), OWNER);
            Vault(vault_).grantRole(Vault(vault_).DEPOSITOR_WHITELIST_ROLE(), deployer);

            for (uint256 i; i < whitelistedDepositors.length; ++i) {
                Vault(vault_).setDepositorWhitelistStatus(whitelistedDepositors[i], true);
            }

            Vault(vault_).renounceRole(Vault(vault_).DEPOSITOR_WHITELIST_ROLE(), deployer);
            Vault(vault_).renounceRole(Vault(vault_).DEFAULT_ADMIN_ROLE(), deployer);
        }
        vm.stopPrank();
        // ------------ End Vault Deployment ------------------
        vault = Vault(vault_);

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

    function testRegisterOperator() public {
        vm.startPrank(alice);
        OperatorRegistry(OPERATOR_REGISTRY).registerOperator();
        network_optIn_service.optIn(NETWORK);
        vm.stopPrank();
        vm.startPrank(OWNER);
        iBTC_networkMiddleware.registerOperator(alice, alice_key);

        (uint48 enabledTime, uint48 disabledTime) = iBTC_networkMiddleware.getOperatorInfo(alice);

        assertTrue(enabledTime > 0, "Enabled time should be greater than 0");
        assertTrue(disabledTime == 0, "Disabled time should be 0");
        console.log("enabledTime", enabledTime);
        console.log("disabledTime");
        vm.stopPrank();
    }

    function testUnregisterOperator() public {
        testRegisterOperator();

        vm.startPrank(OWNER);

        iBTC_networkMiddleware.pauseOperator(alice);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        iBTC_networkMiddleware.unregisterOperator(alice);

        bool isOperatorRegistered = iBTC_networkMiddleware.isOperatorRegistered(alice);
        assertFalse(isOperatorRegistered, "Operator should be unregistered");

        vm.stopPrank();
    }

    function testUpdateOperatorKey() public {
        testRegisterOperator();
        bytes32 newKey = keccak256(abi.encodePacked("new_alice_key"));
        assertEq(iBTC_networkMiddleware.getCurrentOperatorKey(alice), alice_key, "key should stay the same");
        uint256 timestampBeforeUpdate = Time.timestamp();
        uint256 timestampAfterUpdate = timestampBeforeUpdate + 1 days;
        vm.warp(timestampAfterUpdate);
        vm.startPrank(OWNER);
        iBTC_networkMiddleware.updateOperatorKey(alice, newKey);
        vm.stopPrank();
        assertNotEq(iBTC_networkMiddleware.getCurrentOperatorKey(alice), alice_key, "key should be updated");
        assertEq(iBTC_networkMiddleware.getCurrentOperatorKey(alice), newKey, "key should be updated");
        assertEq(
            iBTC_networkMiddleware.getOperatorKeyAt(alice, uint48(timestampBeforeUpdate)),
            alice_key,
            "key should be old in timestampBeforeUpdate"
        );
        assertEq(
            iBTC_networkMiddleware.getOperatorKeyAt(alice, uint48(timestampAfterUpdate)),
            newKey,
            "key should be updated in timestampAfterUpdate"
        );
    }

    function testPauseOperator() public {
        testRegisterOperator();
        vm.startPrank(OWNER);
        uint256 timestampBeforePause = Time.timestamp();
        uint256 timestampAfterPause = timestampBeforePause + 1 days;
        vm.warp(timestampAfterPause);
        iBTC_networkMiddleware.pauseOperator(alice);
        vm.stopPrank();
        (uint48 enabledTime, uint48 disabledTime) = iBTC_networkMiddleware.getOperatorInfo(alice);
        assertEq(disabledTime, timestampAfterPause, "operator should be paused");
        assertEq(enabledTime, timestampBeforePause, "enabledTime should be timestampBeforePause");
    }

    function testUnpauseOperator() public {
        testPauseOperator();
        vm.startPrank(OWNER);
        uint256 timestampBeforeUnpause = Time.timestamp();
        uint256 timestampAfterUnpause = timestampBeforeUnpause + 1 days;
        vm.warp(timestampAfterUnpause);
        iBTC_networkMiddleware.unpauseOperator(alice);
        vm.stopPrank();
        (uint48 enabledTime, uint48 disabledTime) = iBTC_networkMiddleware.getOperatorInfo(alice);
        assertEq(disabledTime, 0, "operator should be unpaused");
        assertEq(enabledTime, timestampAfterUnpause, "enabledTime should be timestampAfterUnpause");
    }

    function testRegisterVault() public {
        vm.startPrank(OWNER);

        iBTC_networkMiddleware.registerVault(vaults[0]);

        bool isVaultRegistered = iBTC_networkMiddleware.isVaultRegistered(vaults[0]);
        assertTrue(isVaultRegistered, "Vault should be registered");
        vm.stopPrank();
    }

    function testUnregisterVault() public {
        testPauseVault();
        vm.warp(Time.timestamp() + SLASHING_WINDOW + 1);
        vm.startPrank(OWNER);
        iBTC_networkMiddleware.unregisterVault(address(vault));
        vm.stopPrank();

        bool isVaultRegistered = iBTC_networkMiddleware.isVaultRegistered(vaults[0]);
        assertFalse(isVaultRegistered, "Vault should be unregistered");
    }

    function testPauseVault() public {
        testRegisterVault();
        uint256 timestampBeforePause = Time.timestamp();
        uint256 timestampAfterPause = timestampBeforePause + 1 days;
        vm.warp(timestampAfterPause);
        vm.startPrank(OWNER);
        iBTC_networkMiddleware.pauseVault(address(vault));
        vm.stopPrank();
        (uint48 enabledTime, uint48 disabledTime) = iBTC_networkMiddleware.getVaultInfo(address(vault));
        assertEq(disabledTime, timestampAfterPause, "vault should be paused");
        assertEq(enabledTime, timestampBeforePause, "enabledTime should be timestampBeforePause");
    }

    function testUnpauseVault() public {
        testPauseVault();
        uint256 timestampBeforeUnpause = Time.timestamp();
        uint256 timestampAfterUnpause = timestampBeforeUnpause + 1 days;
        vm.warp(timestampAfterUnpause);
        vm.startPrank(OWNER);
        iBTC_networkMiddleware.unpauseVault(address(vault));
        vm.stopPrank();
        (uint48 enabledTime, uint48 disabledTime) = iBTC_networkMiddleware.getVaultInfo(address(vault));
        assertEq(disabledTime, 0, "vault should be unpaused");
        assertEq(enabledTime, timestampAfterUnpause, "enabledTime should be timestampAfterUnpause");
    }

    function testSetSubnetworksCnt() public {
        vm.startPrank(OWNER);
        iBTC_networkMiddleware.setSubnetworksCnt(2);
        vm.stopPrank();
        assertEq(iBTC_networkMiddleware.subnetworksCnt(), 2, "subnetworks cnt should update");
    }

    function testOptInVault() public {
        testRegisterOperator();
        vm.startPrank(alice);
        vault_optIn_service.optIn(address(vault));
        assertTrue(vault_optIn_service.isOptedIn(alice, address(vault)));
        vm.stopPrank();
    }

    function testSlashAndExecuteOperator() public {
        uint256 depositAmount = 1e10;
        uint256 networkLimit = 1e10;

        vm.prank(OWNER);
        iBTC_networkMiddleware.registerVault(address(vault));

        assertEq(vault.delegator(), address(iBTC_delegator), "delegator should be right.");
        _setMaxNetworkLimit(NETWORK, 0, networkLimit * 100);
        _registerOperator(alice);

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);

        _optInOperatorVault(alice);

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);

        _optInOperatorNetwork(alice, NETWORK);

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);

        _setResolver(0, bob);

        assertEq(iBTC_slasher.resolver(NETWORK.subnetwork(0), ""), bob, "resolver should be setting correctly");

        vm.prank(OWNER);
        iBTC_networkMiddleware.registerOperator(alice, alice_key);
        (, uint256 mintedShares) = _deposit(alice, depositAmount);
        assertEq(depositAmount, vault.activeBalanceOfAt(alice, uint48(block.timestamp), ""), "Deposit should be done");

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);

        vm.prank(OWNER);
        iBTC_delegator.grantRole(NETWORK_LIMIT_SET_ROLE, alice);
        _setNetworkLimit(alice, NETWORK, networkLimit);

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);

        vm.prank(OWNER);
        iBTC_delegator.grantRole(OPERATOR_NETWORK_SHARES_SET_ROLE, alice);
        _setOperatorNetworkShares(alice, NETWORK, alice, mintedShares);
        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), mintedShares);

        (uint48 enabledTime, uint48 disabledTime) = iBTC_networkMiddleware.getOperatorInfo(alice);
        console.log("enabledTime", enabledTime);
        console.log("disabledTime", disabledTime);
        uint256 stakeAt = iBTC_delegator.stakeAt(NETWORK.subnetwork(0), alice, uint48(enabledTime), "");
        assertEq(stakeAt, mintedShares, "StakeAt should stand the same");

        uint48 epoch = iBTC_networkMiddleware.getCurrentEpoch();
        assertEq(
            iBTC_networkMiddleware.getOperatorStake(alice, epoch),
            iBTC_delegator.stake(NETWORK.subnetwork(0), alice),
            "stake should be the same"
        );

        uint256 cachedStake = iBTC_networkMiddleware.calcAndCacheStakes(epoch);
        assertEq(cachedStake, mintedShares, "cache should update");

        uint256 slashAmount = 1e9;
        vm.warp(Time.timestamp() + 1 days);

        uint48 epochStartTs = iBTC_networkMiddleware.getEpochStartTs(epoch);
        assertGe(
            epochStartTs,
            Time.timestamp() - vault.epochDuration(),
            "captureTimesstamp needs greater and equal that Time.timestamp()-vault.epochDuration()"
        );
        assertLt(epochStartTs, Time.timestamp(), "captureTimestamp needs less than Time.timestamp();");

        // **generate Signature**
        vm.startPrank(OWNER);
        iBTC_networkMiddleware.grantRole(APPROVED_SIGNER, approvedSigner1);
        assertTrue(iBTC_networkMiddleware.hasRole(APPROVED_SIGNER, approvedSigner1));
        iBTC_networkMiddleware.grantRole(APPROVED_SIGNER, approvedSigner2);
        assertTrue(iBTC_networkMiddleware.hasRole(APPROVED_SIGNER, approvedSigner2));

        vm.stopPrank();
        uint256[] memory approvedSignerKeys = new uint256[](2);
        approvedSignerKeys[0] = approvedSigner1Key;
        approvedSignerKeys[1] = approvedSigner2Key;
        uint256 slashIndex = 0;

        bytes[] memory signatures = _makeSignatures(slashIndex, epoch, alice, slashAmount, approvedSignerKeys);
        // **call slash*
        vm.startPrank(OWNER);
        iBTC_networkMiddleware.slash(epoch, alice, slashAmount, signatures);

        // **excute slash**
        vm.expectRevert();
        iBTC_networkMiddleware.executeSlash(0, address(vault), "");
        vm.warp(Time.timestamp() + 2 days);
        iBTC_networkMiddleware.executeSlash(0, address(vault), "");
        vm.stopPrank();

        uint256 amountAfterSlashed = vault.activeBalanceOf(alice);
        assertEq(amountAfterSlashed, depositAmount - slashAmount, "Cached stake should be reduced by slash amount");

        // **testing veto slash**
        vm.prank(OWNER);
        slashIndex++;
        signatures = _makeSignatures(slashIndex, epoch, alice, slashAmount, approvedSignerKeys);
        iBTC_networkMiddleware.slash(epoch, alice, slashAmount, signatures);
        vm.prank(bob);
        iBTC_slasher.vetoSlash(slashIndex, "");

        uint256 amountAfterVetoSlashed = vault.activeBalanceOf(alice);
        assertEq(amountAfterVetoSlashed, amountAfterSlashed, "Cached stake should stay the same");

        vm.expectRevert();
        vm.prank(OWNER);
        iBTC_networkMiddleware.executeSlash(slashIndex, address(vault), "this slash request sholud have been vetoed");
    }

    function testGlobalReceiver() public {
        uint256 slashAmount = 1e9;
        testSlashAndExecuteOperator();

        burner.triggerTransfer(address(iBTC_globalReceiver));
        assertEq(iBTC.balanceOf(address(iBTC_globalReceiver)), slashAmount);

        vm.prank(OWNER);
        iBTC_globalReceiver.redistributeTokens(bob, slashAmount);
        assertEq(iBTC.balanceOf(bob), slashAmount);
    }

    function testDistributeStakerRewards() public {
        // Setup initial conditions similar to test_DistributeRewards
        uint256 depositAmount = 1e8; // 1 iBTC
        uint256 distributeAmount = 10e18; // 10 Reward tokens
        uint256 networkLimit = 100e8;
        uint256 operatorNetworkShares = 10e8; // pricing by iBTC
        uint256 adminFee = 1e1;
        uint256 maxAdminFee = 1e10;

        uint48 blockTimestamp = uint48(Time.timestamp() + 1_720_700_948);
        console.log(blockTimestamp, "Block Timestamp");
        vm.warp(blockTimestamp);

        // Setup admin fee
        vm.startPrank(OWNER);
        defaultStakerRewards.grantRole(defaultStakerRewards.ADMIN_FEE_SET_ROLE(), OWNER);
        // base admin fee already initialized in DefaultStakerRewards = 1e4
        defaultStakerRewards.setAdminFee(adminFee);
        vm.stopPrank();

        // Setup network shares
        vm.startPrank(OWNER);
        iBTC_delegator.grantRole(NETWORK_LIMIT_SET_ROLE, alice);
        iBTC_delegator.grantRole(OPERATOR_NETWORK_SHARES_SET_ROLE, alice);
        vm.stopPrank();

        // Register vault and operator
        vm.prank(OWNER);
        iBTC_networkMiddleware.registerVault(address(vault));
        _registerOperator(alice);
        _optInOperatorVault(alice);
        _optInOperatorNetwork(alice, NETWORK);

        // Register operator in middleware
        vm.prank(OWNER);
        iBTC_networkMiddleware.registerOperator(alice, alice_key);

        _setMaxNetworkLimit(NETWORK, 0, networkLimit * 100);
        _setNetworkLimit(alice, NETWORK, networkLimit);
        // Setup deposits
        for (uint256 i; i < 10; ++i) {
            (, uint256 mintedShares) = _deposit(alice, depositAmount);
            uint256 currentStake = iBTC_delegator.stakeAt(NETWORK.subnetwork(0), alice, uint48(blockTimestamp), "");
            _setOperatorNetworkShares(alice, NETWORK, alice, currentStake + mintedShares);

            blockTimestamp = blockTimestamp + 1;
            vm.warp(blockTimestamp);
        }
        vm.assertEq(
            iBTC_delegator.stake(NETWORK.subnetwork(0), alice), operatorNetworkShares, "stake should set correctly"
        );

        // Mint and approve reward tokens
        vm.startPrank(OWNER);
        rewardToken.mint(address(iBTC_networkMiddleware), distributeAmount);
        vm.stopPrank();

        // VaultHints vaultHints = new VaultHints();

        // Record balances before distribution
        uint256 balanceBefore = rewardToken.balanceOf(STAKER_REWARDS);
        uint256 balanceBeforeNetworkMiddleware = rewardToken.balanceOf(address(iBTC_networkMiddleware));
        uint48 rewardTime = blockTimestamp + NETWORK_EPOCH;
        blockTimestamp = rewardTime + 1;
        vm.warp(blockTimestamp);
        assertEq(iBTC_delegator.stakeAt(NETWORK.subnetwork(0), alice, rewardTime, ""), operatorNetworkShares);
        assertEq(
            iBTC_delegator.stakeAt(
                NETWORK.subnetwork(0),
                alice,
                iBTC_networkMiddleware.getEpochStartTs(iBTC_networkMiddleware.getCurrentEpoch()),
                ""
            ),
            operatorNetworkShares,
            "should get the same stake"
        );
        assertEq(
            iBTC_networkMiddleware.getOperatorStake(alice, iBTC_networkMiddleware.getEpochAtTs(rewardTime)),
            operatorNetworkShares,
            "should get the same stake"
        );
        vm.startPrank(OWNER);
        vm.expectEmit(true, true, true, true);
        emit StakerRewardsDistributed(
            iBTC_networkMiddleware.getCurrentEpoch(), distributeAmount, operatorNetworkShares, block.timestamp
        );
        iBTC_networkMiddleware.distributeStakerRewards(distributeAmount, rewardTime, maxAdminFee, "", "");
        vm.stopPrank();

        // Verify balances and rewards
        assertEq(rewardToken.balanceOf(STAKER_REWARDS) - balanceBefore, distributeAmount, "balance should be right");
        assertEq(
            balanceBeforeNetworkMiddleware - rewardToken.balanceOf(address(iBTC_networkMiddleware)), distributeAmount
        );
        uint256 claimableAdminFee = distributeAmount.mulDiv(adminFee, ADMIN_FEE_BASE);
        assertEq(
            defaultStakerRewards.claimableAdminFee(address(rewardToken)), claimableAdminFee, "admin fee should be right"
        );
        assertEq(
            defaultStakerRewards.claimable(REWARD_TOKEN, alice, abi.encode(NETWORK, type(uint256).max)),
            distributeAmount - claimableAdminFee,
            "claimable should be right"
        );
    }

    function testClaimStakerRewards() public {
        uint256 distributeAmount = 10e18; // 10 Reward tokens
        uint256 adminFee = 1e1;

        testDistributeStakerRewards();
        uint256 claimableAdminFee = distributeAmount.mulDiv(adminFee, ADMIN_FEE_BASE);
        uint256 claimableAmount = distributeAmount - claimableAdminFee;

        vm.startPrank(alice);
        vm.expectEmit(true, true, true, true);
        emit ClaimRewards(address(rewardToken), NETWORK, alice, alice, 0, 1, claimableAmount);
        defaultStakerRewards.claimRewards(alice, address(rewardToken), abi.encode(NETWORK, type(uint256).max, ""));
        vm.stopPrank();
        assertEq(rewardToken.balanceOf(alice), claimableAmount, "claimable amount should be right");
    }

    function testDistributeOperatorRewards() public {
        // Setup initial conditions
        uint256 rewardAmount = 1e9;
        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(alice, rewardAmount))));
        bytes32 proof = keccak256(abi.encode("test_merkle_root"));
        bytes32 merkleRoot = Hashes.commutativeKeccak256(leaf, proof);

        // Mint reward tokens
        vm.startPrank(OWNER);
        rewardToken.mint(address(iBTC_networkMiddleware), rewardAmount);

        // Distribute rewards
        vm.expectEmit(true, true, true, true);
        emit OperatorRewardsDistributed(iBTC_networkMiddleware.getCurrentEpoch(), rewardAmount, block.timestamp);
        iBTC_networkMiddleware.distributeOperatorRewards(rewardAmount, merkleRoot);
        vm.stopPrank();
    }

    function testClaimOperatorRewards() public {
        testDistributeOperatorRewards();
        uint256 claimableAmount = 1e9;
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = keccak256(abi.encode("test_merkle_root"));
        vm.startPrank(alice);
        vm.expectEmit(true, true, true, true);
        emit ClaimRewards(alice, NETWORK, address(rewardToken), alice, claimableAmount);
        defaultOperatorRewards.claimRewards(alice, NETWORK, address(rewardToken), claimableAmount, proof);
        vm.stopPrank();
        assertEq(rewardToken.balanceOf(alice), claimableAmount, "claimable amount should be right");
    }

    //NOTE: still not done
    function testCalcAndCacheStakes() public {
        uint256 alice_depositAmount = 10e8; // 10 iBTC
        uint256 bob_depositAmount = 5e8; // 10 iBTC
        uint256 networkLimit = 1000e8;
        uint256 startTime = Time.timestamp();
        uint256 vaultEpoch = 0;

        _registerOperator(alice);
        _registerOperator(bob);
        _optInOperatorNetwork(alice, NETWORK);
        _optInOperatorNetwork(bob, NETWORK);
        _optInOperatorVault(alice);
        _optInOperatorVault(bob);

        vm.startPrank(OWNER);
        iBTC_delegator.grantRole(NETWORK_LIMIT_SET_ROLE, address(this));
        iBTC_delegator.grantRole(OPERATOR_NETWORK_SHARES_SET_ROLE, address(this));
        iBTC_networkMiddleware.registerOperator(alice, alice_key);
        iBTC_networkMiddleware.registerOperator(bob, bob_key);
        vm.stopPrank();

        _setMaxNetworkLimit(NETWORK, 0, networkLimit * 100);
        _setNetworkLimit(address(this), NETWORK, networkLimit);

        for (uint256 i; i < 10; ++i) {
            // if (Time.timestamp() >= startTime + vaultEpoch * NETWORK_EPOCH) {
            //     vaultEpoch++;
            //     _optInOperatorVault(alice);
            //     _optInOperatorVault(bob);
            // }

            (, uint256 alice_mintedShares) = _deposit(alice, alice_depositAmount);
            (, uint256 bob_mintedShares) = _deposit(bob, bob_depositAmount);
            iBTC_delegator.setOperatorNetworkShares(
                NETWORK.subnetwork(0),
                alice,
                iBTC_delegator.operatorNetworkShares(NETWORK.subnetwork(0), alice) + alice_mintedShares
            );
            iBTC_delegator.setOperatorNetworkShares(
                NETWORK.subnetwork(0),
                bob,
                iBTC_delegator.operatorNetworkShares(NETWORK.subnetwork(0), bob) + bob_mintedShares
            );
            assertEq(
                alice_depositAmount * (i + 1),
                vault.activeBalanceOfAt(alice, uint48(block.timestamp), ""),
                "Deposit should be done"
            );
            assertEq(
                bob_depositAmount * (i + 1),
                vault.activeBalanceOfAt(bob, uint48(block.timestamp), ""),
                "Deposit should be done"
            );
            if (i == 0) {
                assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), alice_mintedShares);
                assertEq(iBTC_delegator.operatorNetworkShares(NETWORK.subnetwork(0), alice), alice_mintedShares);
                assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), bob), bob_mintedShares);
                assertEq(iBTC_delegator.operatorNetworkShares(NETWORK.subnetwork(0), bob), bob_mintedShares);
            } else {
                assertEq(
                    iBTC_delegator.operatorNetworkShares(NETWORK.subnetwork(0), alice), alice_mintedShares * (i + 1)
                );
                assertEq(iBTC_delegator.operatorNetworkShares(NETWORK.subnetwork(0), bob), bob_mintedShares * (i + 1));
                assertEq(
                    iBTC_delegator.stake(NETWORK.subnetwork(0), alice),
                    alice_mintedShares
                        * (i + 1).mulDiv(
                            Math.min(vault.activeStake(), networkLimit),
                            iBTC_delegator.totalOperatorNetworkShares(NETWORK.subnetwork(0))
                        ),
                    "alice stake should be right"
                );
                assertEq(
                    iBTC_delegator.stake(NETWORK.subnetwork(0), bob),
                    bob_mintedShares
                        * (i + 1).mulDiv(
                            Math.min(vault.activeStake(), networkLimit),
                            iBTC_delegator.totalOperatorNetworkShares(NETWORK.subnetwork(0))
                        ),
                    "bob stake should be right"
                );
            }
            console.log(i, "epoch_i");
            console.log(
                iBTC_networkMiddleware.calcAndCacheStakes(iBTC_networkMiddleware.getCurrentEpoch()), "cachedStake_"
            );
            vm.warp(Time.timestamp() + NETWORK_EPOCH);
            // _optInOperatorNetwork(alice, NETWORK);
            // _optInOperatorNetwork(bob, NETWORK);
        }
    }

    function testUpgrade() public {
        // Deploy the new implementation
        NetworkMiddlewareV2 newImplementation = new NetworkMiddlewareV2();

        vm.startPrank(OWNER);
        proxyAdmin.upgradeAndCall(ITransparentUpgradeableProxy(address(proxy)), address(newImplementation), "");
        vm.stopPrank();

        NetworkMiddlewareV2 upgradedContract = NetworkMiddlewareV2(address(proxy));

        assertEq(upgradedContract.getTestVar(), 1e4, "The testVar should be initialized correctly");
    }

    function _makeSignatures(
        uint256 slashIndex,
        uint48 epoch,
        address operator,
        uint256 slashAmount,
        uint256[] memory approvedSignerKeys
    ) internal returns (bytes[] memory signatures) {
        bytes memory dataToSign = abi.encode(slashIndex, epoch, operator, slashAmount);
        bytes32 messageHash = keccak256(dataToSign);

        signatures = new bytes[](approvedSignerKeys.length);

        for (uint256 i = 0; i < approvedSignerKeys.length; i++) {
            signatures[i] = _signMessage(approvedSignerKeys[i], messageHash);
        }

        return signatures;
    }

    function _signMessage(uint256 signerPrivateKey, bytes32 messageHash) internal pure returns (bytes memory) {
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function _grantAdminFeeSetRole(address user, address account) internal {
        vm.startPrank(user);
        defaultStakerRewards.grantRole(defaultStakerRewards.ADMIN_FEE_SET_ROLE(), account);
        vm.stopPrank();
    }

    function _setAdminFee(address user, uint256 adminFee) internal {
        vm.startPrank(user);
        defaultStakerRewards.setAdminFee(adminFee);
        vm.stopPrank();
    }

    function _setResolver(uint96 identifier, address resolver) internal {
        vm.prank(NETWORK);
        iBTC_slasher.setResolver(identifier, resolver, "");
    }

    function _setMaxNetworkLimit(address user, uint96 identifier, uint256 amount) internal {
        vm.startPrank(user);
        iBTC_delegator.setMaxNetworkLimit(identifier, amount);
        vm.stopPrank();
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
        vault_optIn_service.optIn(address(vault));
        vm.stopPrank();
    }

    function _optInOperatorNetwork(address user, address network_) internal {
        vm.startPrank(user);
        network_optIn_service.optIn(network_);
        vm.stopPrank();
    }

    function _deposit(address user, uint256 amount) internal returns (uint256 depositedAmount, uint256 mintedShares) {
        vm.prank(iBTC.owner());
        iBTC.setMinter(address(this));
        iBTC.mint(user, amount);
        uint256 operatorBalance = iBTC.balanceOf(user);
        assertEq(operatorBalance, amount, "Operator should have minted tokens");
        vm.startPrank(user);
        iBTC.approve(address(vault), amount);
        (depositedAmount, mintedShares) = vault.deposit(user, amount);
        vm.stopPrank();
    }

    function _withdraw(address user, uint256 amount) internal returns (uint256 burnedShares, uint256 mintedShares) {
        vm.startPrank(user);
        (burnedShares, mintedShares) = vault.withdraw(user, amount);
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

    function _getAdminAddress(
        address proxy_
    ) internal view returns (address) {
        address CHEATCODE_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
        Vm vm = Vm(CHEATCODE_ADDRESS);

        bytes32 adminSlot = vm.load(proxy_, ERC1967Utils.ADMIN_SLOT);
        return address(uint160(uint256(adminSlot)));
    }
}
