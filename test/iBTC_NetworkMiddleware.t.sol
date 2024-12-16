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

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {MapWithTimeData} from "../src/libraries/MapWithTimeData.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

import {IVault} from "core/src/interfaces/vault/IVault.sol";
import {IBurnerRouter} from "burners/src/interfaces/router/IBurnerRouter.sol";
import {INetworkRestakeDelegator} from "core/src/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IBaseDelegator} from "core/src/interfaces/delegator/IBaseDelegator.sol";
import {IVetoSlasher} from "core/src/interfaces/slasher/IVetoSlasher.sol";
import {IBaseSlasher} from "core/src/interfaces/slasher/IBaseSlasher.sol";
import {IVaultConfigurator} from "core/src/interfaces/IVaultConfigurator.sol";
import {IRegistry} from "core/src/interfaces/common/IRegistry.sol";
import {IBTC} from "test/mocks/iBTCMock.sol";

contract iBTC_NetworkMiddlewareTest is Test {
    using Math for uint256;
    using Subnetwork for bytes32;
    using Subnetwork for address;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;

    uint256 sepoliaFork;
    string SEPOLIA_RPC_URL = vm.envString("SEPOLIA_RPC_URL");

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
    uint256 constant MAX_WITHDRAW_AMOUNT = 1e9;
    uint256 constant MIN_WITHDRAW_AMOUNT = 1e4;

    bytes32 public constant APPROVED_SIGNER = keccak256("APPROVED_SIGNER");
    bytes32 public constant NETWORK_LIMIT_SET_ROLE = keccak256("NETWORK_LIMIT_SET_ROLE");
    bytes32 public constant OPERATOR_NETWORK_SHARES_SET_ROLE = keccak256("OPERATOR_NETWORK_SHARES_SET_ROLE");

    address constant NETWORK = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266; // first address network should be a multisig contract
    address constant OWNER = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // second address

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

    event VetoSlash(uint256 indexed slashIndex, address indexed resolver);

    function setUp() public {
        sepoliaFork = vm.createSelectFork(SEPOLIA_RPC_URL);
        (alice, alicePrivateKey) = makeAddrAndKey("alice");
        (bob, bobPrivateKey) = makeAddrAndKey("bob");
        (approvedSigner1, approvedSigner1Key) = makeAddrAndKey("approvedSigner1");
        (approvedSigner2, approvedSigner2Key) = makeAddrAndKey("approvedSigner2");
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
        iBTC_globalReceiver = new iBTC_GlobalReceiver();
        iBTC_globalReceiver.initialize(COLLATERAL, OWNER);
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
        iBTC_delegator = NetworkRestakeDelegator(delegator_);
        iBTC_vault = iBTC_Vault(vault_);
        network_optIn_service = OptInService(NEWTORK_OPTIN_SERVICE);
        vault_optIn_service = OptInService(VAULT_OPTIN_SERVICE);
        //NOTICE
        // vm.prank(vault_);
        // NetworkRegistry(NETWORK_REGISTRY).registerNetwork();

        vaults.push(vault_);
        vm.startPrank(OWNER);
        iBTC_networkMiddleware = new NetworkMiddleware(
            NETWORK,
            OPERATOR_REGISTRY,
            NETWORK_REGISTRY,
            VAULT_FACTORY,
            NEWTORK_OPTIN_SERVICE,
            OWNER,
            NETWORK_EPOCH,
            SLASHING_WINDOW,
            threshold,
            minimumThreshold
        );

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
        address operator = address(0x1234);
        bytes32 key = keccak256(abi.encodePacked("operator_key"));
        vm.startPrank(operator);
        OperatorRegistry(OPERATOR_REGISTRY).registerOperator();
        network_optIn_service.optIn(NETWORK);
        vm.stopPrank();
        vm.startPrank(OWNER);
        iBTC_networkMiddleware.registerOperator(operator, key);

        (uint48 enabledTime, uint48 disabledTime) = iBTC_networkMiddleware.getOperatorInfo(operator);

        assertTrue(enabledTime > 0, "Enabled time should be greater than 0");
        assertTrue(disabledTime == 0, "Disabled time should be 0");
        console.log("enabledTime", enabledTime);
        console.log("disabledTime");
        vm.stopPrank();
    }

    function testUnregisterOperator() public {
        testRegisterOperator();
        address operator = address(0x1234);

        vm.startPrank(OWNER);

        iBTC_networkMiddleware.pauseOperator(operator);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        iBTC_networkMiddleware.unregisterOperator(operator);

        bool isOperatorRegistered = iBTC_networkMiddleware.isOperatorRegistered(operator);
        assertFalse(isOperatorRegistered, "Operator should be unregistered");

        vm.stopPrank();
    }

    function testRegisterVault() public {
        vm.startPrank(OWNER);

        iBTC_networkMiddleware.registerVault(vaults[0]);

        bool isVaultRegistered = iBTC_networkMiddleware.isVaultRegistered(vaults[0]);
        assertTrue(isVaultRegistered, "Vault should be registered");
        vm.stopPrank();
    }

    function testPauseAndUnpauseVault() public {
        testRegisterVault();
        vm.startPrank(OWNER);

        iBTC_networkMiddleware.pauseVault(address(iBTC_vault));

        (uint48 enabledTime, uint48 disabledTime) = iBTC_networkMiddleware.getVaultInfo(address(iBTC_vault));
        bool isVaultPaused = enabledTime == 0 || (disabledTime > 0 && disabledTime <= block.timestamp);

        assertTrue(isVaultPaused, "Vault should be paused");

        iBTC_networkMiddleware.unpauseVault(address(iBTC_vault));

        (enabledTime, disabledTime) = iBTC_networkMiddleware.getVaultInfo(address(iBTC_vault));
        isVaultPaused = enabledTime == 0 || (disabledTime > 0 && disabledTime <= block.timestamp);
        assertFalse(isVaultPaused, "Vault should be active");

        vm.stopPrank();
    }

    function testOptInVault() public {
        testRegisterOperator();
        address operator = address(0x1234);
        vm.prank(operator);
        vault_optIn_service.optIn(address(iBTC_vault));
        assertTrue(vault_optIn_service.isOptedIn(operator, address(iBTC_vault)));
    }

    function testSlashOperator() public {
        bytes32 key = keccak256(abi.encodePacked("alice_key"));
        uint256 depositAmount = 1e10;
        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        uint256 networkLimit = 1e10;
        uint256 operatorNetworkShares1 = 1e10;

        vm.prank(OWNER);
        iBTC_networkMiddleware.registerVault(address(iBTC_vault));

        assertEq(iBTC_vault.delegator(), address(iBTC_delegator), "delegator should be right.");
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
        iBTC_networkMiddleware.registerOperator(alice, key);
        _deposit(alice, depositAmount);
        assertEq(
            depositAmount, iBTC_vault.activeBalanceOfAt(alice, uint48(block.timestamp), ""), "Deposit should be done"
        );

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);

        vm.prank(OWNER);
        iBTC_delegator.grantRole(NETWORK_LIMIT_SET_ROLE, alice);
        _setNetworkLimit(alice, NETWORK, networkLimit);

        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), 0);

        vm.prank(OWNER);
        iBTC_delegator.grantRole(OPERATOR_NETWORK_SHARES_SET_ROLE, alice);
        _setOperatorNetworkShares(alice, NETWORK, alice, operatorNetworkShares1);
        assertEq(iBTC_delegator.stake(NETWORK.subnetwork(0), alice), operatorNetworkShares1);

        (uint48 enabledTime, uint48 disabledTime) = iBTC_networkMiddleware.getOperatorInfo(alice);
        console.log("enabledTime", enabledTime);
        console.log("disabledTime", disabledTime);
        uint256 stakeAt = iBTC_delegator.stakeAt(NETWORK.subnetwork(0), alice, uint48(enabledTime), "");
        assertEq(stakeAt, operatorNetworkShares1, "StakeAt should stand the same");

        uint48 epoch = iBTC_networkMiddleware.getCurrentEpoch();
        assertEq(
            iBTC_networkMiddleware.getOperatorStake(alice, epoch),
            iBTC_delegator.stake(NETWORK.subnetwork(0), alice),
            "stake should be the same"
        );

        uint256 cachedStake = iBTC_networkMiddleware.calcAndCacheStakes(epoch);
        assertEq(cachedStake, operatorNetworkShares1, "cache should update");

        uint256 slashAmount = 1e9;
        vm.warp(Time.timestamp() + 1 days);

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
        iBTC_networkMiddleware.executeSlash(0, address(iBTC_vault), "");
        vm.warp(Time.timestamp() + 2 days);
        iBTC_networkMiddleware.executeSlash(0, address(iBTC_vault), "");
        vm.stopPrank();

        uint256 amountAfterSlashed = iBTC_vault.activeBalanceOf(alice);
        assertEq(amountAfterSlashed, depositAmount - slashAmount, "Cached stake should be reduced by slash amount");

        // **testing veto slash**
        vm.prank(OWNER);
        slashIndex++;
        signatures = _makeSignatures(slashIndex, epoch, alice, slashAmount, approvedSignerKeys);
        iBTC_networkMiddleware.slash(epoch, alice, slashAmount, signatures);
        vm.prank(bob);
        iBTC_slasher.vetoSlash(slashIndex, "");

        uint256 amountAfterVetoSlashed = iBTC_vault.activeBalanceOf(alice);
        assertEq(amountAfterVetoSlashed, amountAfterSlashed, "Cached stake should stay the same");

        vm.expectRevert();
        vm.prank(OWNER);
        iBTC_networkMiddleware.executeSlash(slashIndex, address(iBTC_vault), "");
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

    function _signMessage(uint256 signerPrivateKey, bytes32 messageHash) internal returns (bytes memory) {
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPrivateKey, ethSignedMessageHash);
        return abi.encodePacked(r, s, v);
    }

    function testGlobalReceiver() public {
        uint256 slashAmount = 1e9;
        testSlashOperator();

        burner.triggerTransfer(address(iBTC_globalReceiver));
        assertEq(iBTC.balanceOf(address(iBTC_globalReceiver)), slashAmount);

        vm.prank(OWNER);
        iBTC_globalReceiver.redistributeTokens(bob, slashAmount);
        assertEq(iBTC.balanceOf(bob), slashAmount);
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
        vault_optIn_service.optIn(address(iBTC_vault));
        vm.stopPrank();
    }

    function _optInOperatorNetwork(address user, address network) internal {
        vm.startPrank(user);
        network_optIn_service.optIn(network);
        vm.stopPrank();
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

    function _setNetworkLimit(address user, address network, uint256 amount) internal {
        vm.startPrank(user);
        iBTC_delegator.setNetworkLimit(network.subnetwork(0), amount);
        vm.stopPrank();
    }

    function _setOperatorNetworkShares(address user, address network, address operator, uint256 shares) internal {
        vm.startPrank(user);
        iBTC_delegator.setOperatorNetworkShares(network.subnetwork(0), operator, shares);
        vm.stopPrank();
    }
}
