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
import {VaultConfigurator} from "src/iBTC_VaultConfigurator.sol";
import {BurnerRouter} from "burners/src/contracts/router/BurnerRouter.sol";
import {IVault} from "core/src/interfaces/vault/IVault.sol";
import {INetworkRestakeDelegator} from "core/src/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IBaseDelegator} from "core/src/interfaces/delegator/IBaseDelegator.sol";
import {IVetoSlasher} from "core/src/interfaces/slasher/IVetoSlasher.sol";
import {IBaseSlasher} from "core/src/interfaces/slasher/IBaseSlasher.sol";
import {IVaultConfigurator} from "core/src/interfaces/IVaultConfigurator.sol";
import {IRegistry} from "core/src/interfaces/common/IRegistry.sol";
import {IBTC} from "test/mocks/iBTCMock.sol";

contract iBTC_NetworkMiddlewareTest is Test {
    uint256 sepoliaFork;
    string SEPOLIA_RPC_URL = vm.envString("SEPOLIA_RPC_URL");
    address constant NETWORK_MIDDLEWARE_SERVICE = 0x62a1ddfD86b4c1636759d9286D3A0EC722D086e3;
    address constant NETWORK_REGISTRY = 0x7d03b7343BF8d5cEC7C0C27ecE084a20113D15C9;
    address constant OPERATOR_REGISTRY = 0x6F75a4ffF97326A00e52662d82EA4FdE86a2C548;
    address constant COLLATTERAL = 0xeb762Ed11a09E4A394C9c8101f8aeeaf5382ED74;
    address constant VAULT_FACTORY = 0x407A039D94948484D356eFB765b3c74382A050B4;
    address constant DELEGATOR_FACTORY = 0x890CA3f95E0f40a79885B7400926544B2214B03f;
    address constant SLASHER_FACTORY = 0xbf34bf75bb779c383267736c53a4ae86ac7bB299;
    address constant NEWTORK_OPTIN_SERVICE = 0x58973d16FFA900D11fC22e5e2B6840d9f7e13401;
    address constant VAULT_OPTIN_SERVICE = 0x95CC0a052ae33941877c9619835A233D21D57351;
    uint256 constant MAX_WITHDRAW_AMOUNT = 1e9;
    uint256 constant MIN_WITHDRAW_AMOUNT = 1e4;

    address constant NETWORK = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266; // first address network should be a multisig contract
    address constant OWNER = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8; // second address
    uint48 constant EPOCH_DURATION = 7 days;
    // uint48 constant NETWORK_EPOCH = 5 days;
    uint48 constant SLASHING_WINDOW = 7 days;
    uint48 vetoDuration = 0 days;

    address[] operators;
    bytes32[] keys;

    address[] vaults;

    OptInService network_optIn_service;
    OptInService vault_optIn_service;
    NetworkMiddleware public iBTC_middleware;
    BurnerRouter public burner;
    VaultConfigurator public vaultConfigurator;
    iBTC_Vault public iBTC_vault;
    NetworkRestakeDelegator public network_restake_delegator;

    function setUp() public {
        sepoliaFork = vm.createSelectFork(SEPOLIA_RPC_URL);
        address[] memory whitelistedDepositors;

        uint256 depositLimit = 1e10;
        address hook = 0x0000000000000000000000000000000000000000;
        uint64 delegatorIndex = 0;
        uint64 slasherIndex = 1;
        bool withSlasher = true;
        vm.startPrank(OWNER);

        vaultConfigurator = new VaultConfigurator(VAULT_FACTORY, DELEGATOR_FACTORY, SLASHER_FACTORY);
        burner = new BurnerRouter();
        (,, address deployer) = vm.readCallers();

        bool depositWhitelist = whitelistedDepositors.length != 0;

        bytes memory vaultParams = abi.encode(
            IVault.InitParams({
                collateral: COLLATTERAL,
                burner: address(burner),
                epochDuration: EPOCH_DURATION,
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
        network_restake_delegator = NetworkRestakeDelegator(delegator_);
        iBTC_vault = iBTC_Vault(vault_);
        network_optIn_service = OptInService(NEWTORK_OPTIN_SERVICE);
        vault_optIn_service = OptInService(VAULT_OPTIN_SERVICE);
        //NOTICE
        // vm.prank(vault_);
        // NetworkRegistry(NETWORK_REGISTRY).registerNetwork();
        vm.prank(NETWORK);
        NetworkRegistry(NETWORK_REGISTRY).registerNetwork();

        vaults.push(vault_);
        vm.startPrank(OWNER);
        iBTC_middleware = new NetworkMiddleware(
            NETWORK,
            OPERATOR_REGISTRY,
            NETWORK_REGISTRY,
            VAULT_FACTORY,
            NEWTORK_OPTIN_SERVICE,
            VAULT_OPTIN_SERVICE,
            OWNER,
            EPOCH_DURATION,
            SLASHING_WINDOW
        );

        vm.stopPrank();
        console.log("Vault: ", vault_);
        console.log("Delegator: ", delegator_);
        console.log("Slasher: ", slasher_);
        assertEq(IVault(vault_).slasher(), slasher_);

        vm.startPrank(address(iBTC_middleware));
        NetworkRegistry(NETWORK_REGISTRY).registerNetwork();
        NetworkMiddlewareService(NETWORK_MIDDLEWARE_SERVICE).setMiddleware(address(iBTC_middleware));
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
        iBTC_middleware.registerOperator(operator, key);

        (uint48 enabledTime, uint48 disabledTime) = iBTC_middleware.getOperatorInfo(operator);

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

        iBTC_middleware.pauseOperator(operator);

        vm.warp(block.timestamp + SLASHING_WINDOW + 1);
        iBTC_middleware.unregisterOperator(operator);

        bool isOperatorRegistered = iBTC_middleware.isOperatorRegistered(operator);
        assertFalse(isOperatorRegistered, "Operator should be unregistered");

        vm.stopPrank();
    }

    function testRegisterVault() public {
        vm.startPrank(OWNER);

        iBTC_middleware.registerVault(vaults[0]);

        bool isVaultRegistered = iBTC_middleware.isVaultRegistered(vaults[0]);
        assertTrue(isVaultRegistered, "Vault should be registered");
        vm.stopPrank();
    }

    function testPauseAndUnpauseVault() public {
        testRegisterVault();
        vm.startPrank(OWNER);

        iBTC_middleware.pauseVault(address(iBTC_vault));

        (uint48 enabledTime, uint48 disabledTime) = iBTC_middleware.getVaultInfo(address(iBTC_vault));
        bool isVaultPaused = enabledTime == 0 || (disabledTime > 0 && disabledTime <= block.timestamp);

        assertTrue(isVaultPaused, "Vault should be paused");

        iBTC_middleware.unpauseVault(address(iBTC_vault));

        (enabledTime, disabledTime) = iBTC_middleware.getVaultInfo(address(iBTC_vault));
        isVaultPaused = enabledTime == 0 || (disabledTime > 0 && disabledTime <= block.timestamp);
        assertFalse(isVaultPaused, "Vault should be active");

        vm.stopPrank();
    }

    function testSlashOperator() public {
        uint256 initialStaking = 1e10;
        testRegisterOperator();
        address operator = address(0x1234);

        vm.prank(IBTC(COLLATTERAL).owner());
        IBTC(COLLATTERAL).setMinter(address(this));
        IBTC(COLLATTERAL).mint(operator, initialStaking);

        uint256 operatorBalance = IBTC(COLLATTERAL).balanceOf(operator);
        assertEq(operatorBalance, initialStaking, "Operator should have minted tokens");

        vm.prank(operator);
        IBTC(COLLATTERAL).approve(address(iBTC_vault), initialStaking);

        vm.startPrank(OWNER);
        iBTC_middleware.registerVault(address(iBTC_vault));

        vm.stopPrank();

        uint48 epoch = iBTC_middleware.getCurrentEpoch();

        vm.prank(operator);
        iBTC_Vault(vaults[0]).deposit(operator, initialStaking);

        assertEq(
            initialStaking,
            iBTC_Vault(vaults[0]).activeBalanceOfAt(operator, uint48(block.timestamp), ""),
            "Initial staking should be done"
        );
        // OptIn vault, Network is already optIn
        vm.prank(operator);
        vault_optIn_service.optIn(address(iBTC_vault));

        vm.prank(address(iBTC_middleware));
        iBTC_middleware.calcAndCacheStakes(epoch);

        uint256 cachedStake = iBTC_middleware.operatorStakeCache(epoch, operator);
        assertEq(cachedStake, initialStaking, "Cached stake should match the initial stake");

        uint256 slashAmount = 100;

        vm.startPrank(OWNER);
        iBTC_middleware.slash(epoch, operator, slashAmount);

        cachedStake = iBTC_middleware.operatorStakeCache(epoch, operator);
        assertEq(cachedStake, initialStaking - slashAmount, "Cached stake should be reduced by slash amount");

        vm.stopPrank();
    }

    function testOptInVault() public {
        testRegisterOperator();
        address operator = address(0x1234);
        vm.prank(operator);
        vault_optIn_service.optIn(address(iBTC_vault));
    }
}
