// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Test, console2} from "forge-std/Test.sol";

import {VaultFactory} from "core/src/contracts/VaultFactory.sol";
import {DelegatorFactory} from "core/src/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "core/src/contracts/SlasherFactory.sol";
import {NetworkRegistry} from "core/src/contracts/NetworkRegistry.sol";
import {OperatorRegistry} from "core/src/contracts/OperatorRegistry.sol";
import {MetadataService} from "core/src/contracts/service/MetadataService.sol";
import {NetworkMiddlewareService} from "core/src/contracts/service/NetworkMiddlewareService.sol";
import {OptInService} from "core/src/contracts/service/OptInService.sol";

import {iBTC_Vault} from "src/iBTC_Vault.sol";
import {NetworkRestakeDelegator} from "core/src/contracts/delegator/NetworkRestakeDelegator.sol";
import {FullRestakeDelegator} from "core/src/contracts/delegator/FullRestakeDelegator.sol";
import {OperatorSpecificDelegator} from "core/src/contracts/delegator/OperatorSpecificDelegator.sol";
import {Slasher} from "core/src/contracts/slasher/Slasher.sol";
import {VetoSlasher} from "core/src/contracts/slasher/VetoSlasher.sol";

import {IVault} from "core/src/interfaces/vault/IVault.sol";

import {Token} from "core/test/mocks/Token.sol";
import {FeeOnTransferToken} from "core/test/mocks/FeeOnTransferToken.sol";
import {VaultConfigurator} from "core/src/contracts/VaultConfigurator.sol";
import {IVaultConfigurator} from "core/src/interfaces/IVaultConfigurator.sol";
import {INetworkRestakeDelegator} from "core/src/interfaces/delegator/INetworkRestakeDelegator.sol";
import {IFullRestakeDelegator} from "core/src/interfaces/delegator/IFullRestakeDelegator.sol";
import {IBaseDelegator} from "core/src/interfaces/delegator/IBaseDelegator.sol";
import {ISlasher} from "core/src/interfaces/slasher/ISlasher.sol";
import {IBaseSlasher} from "core/src/interfaces/slasher/IBaseSlasher.sol";

import {IVaultStorage} from "core/src/interfaces/vault/IVaultStorage.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {VaultHints} from "core/src/contracts/hints/VaultHints.sol";
import {Subnetwork} from "core/src/contracts/libraries/Subnetwork.sol";

contract VaultTest is Test {
    using Math for uint256;
    using Subnetwork for bytes32;
    using Subnetwork for address;

    address owner;
    address alice;
    uint256 alicePrivateKey;
    address bob;
    uint256 bobPrivateKey;

    VaultFactory vaultFactory;
    DelegatorFactory delegatorFactory;
    SlasherFactory slasherFactory;
    NetworkRegistry networkRegistry;
    OperatorRegistry operatorRegistry;
    MetadataService operatorMetadataService;
    MetadataService networkMetadataService;
    NetworkMiddlewareService networkMiddlewareService;
    OptInService operatorVaultOptInService;
    OptInService operatorNetworkOptInService;

    Token collateral;
    FeeOnTransferToken feeOnTransferCollateral;
    VaultConfigurator vaultConfigurator;

    iBTC_Vault iBTCVault;
    FullRestakeDelegator delegator;
    Slasher slasher;

    function setUp() public {
        owner = address(this);
        (alice, alicePrivateKey) = makeAddrAndKey("alice");
        (bob, bobPrivateKey) = makeAddrAndKey("bob");

        vaultFactory = new VaultFactory(owner);
        delegatorFactory = new DelegatorFactory(owner);
        slasherFactory = new SlasherFactory(owner);
        networkRegistry = new NetworkRegistry();
        operatorRegistry = new OperatorRegistry();
        operatorMetadataService = new MetadataService(address(operatorRegistry));
        networkMetadataService = new MetadataService(address(networkRegistry));
        networkMiddlewareService = new NetworkMiddlewareService(address(networkRegistry));
        operatorVaultOptInService =
            new OptInService(address(operatorRegistry), address(vaultFactory), "OperatorVaultOptInService");
        operatorNetworkOptInService =
            new OptInService(address(operatorRegistry), address(networkRegistry), "OperatorNetworkOptInService");

        address vaultImpl =
            address(new iBTC_Vault(address(delegatorFactory), address(slasherFactory), address(vaultFactory)));
        vaultFactory.whitelist(vaultImpl);

        address networkRestakeDelegatorImpl = address(
            new NetworkRestakeDelegator(
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(networkRestakeDelegatorImpl);

        address fullRestakeDelegatorImpl = address(
            new FullRestakeDelegator(
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(fullRestakeDelegatorImpl);

        address operatorSpecificDelegatorImpl = address(
            new OperatorSpecificDelegator(
                address(operatorRegistry),
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(operatorSpecificDelegatorImpl);

        address slasherImpl = address(
            new Slasher(
                address(vaultFactory),
                address(networkMiddlewareService),
                address(slasherFactory),
                slasherFactory.totalTypes()
            )
        );
        slasherFactory.whitelist(slasherImpl);

        address vetoSlasherImpl = address(
            new VetoSlasher(
                address(vaultFactory),
                address(networkMiddlewareService),
                address(networkRegistry),
                address(slasherFactory),
                slasherFactory.totalTypes()
            )
        );
        slasherFactory.whitelist(vetoSlasherImpl);

        collateral = new Token("Token");
        feeOnTransferCollateral = new FeeOnTransferToken("FeeOnTransferToken");

        vaultConfigurator =
            new VaultConfigurator(address(vaultFactory), address(delegatorFactory), address(slasherFactory));
    }

    function test_Create2(
        address burner,
        uint48 epochDuration,
        bool depositWhitelist,
        bool isDepositLimit,
        uint256 depositLimit
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        address[] memory networkLimitSetRoleHolders = new address[](1);
        networkLimitSetRoleHolders[0] = alice;
        address[] memory operatorNetworkSharesSetRoleHolders = new address[](1);
        operatorNetworkSharesSetRoleHolders[0] = alice;
        (address vault_, address delegator_,) = vaultConfigurator.create(
            IVaultConfigurator.InitParams({
                version: vaultFactory.lastVersion(),
                owner: address(0),
                vaultParams: abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: burner,
                        epochDuration: epochDuration,
                        depositWhitelist: depositWhitelist,
                        isDepositLimit: isDepositLimit,
                        depositLimit: depositLimit,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                ),
                delegatorIndex: 0,
                delegatorParams: abi.encode(
                    INetworkRestakeDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: alice,
                            hook: address(0),
                            hookSetRoleHolder: alice
                        }),
                        networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                        operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
                    })
                ),
                withSlasher: false,
                slasherIndex: 0,
                slasherParams: abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}))
            })
        );

        iBTCVault = iBTC_Vault(vault_);

        assertEq(iBTCVault.DEPOSIT_WHITELIST_SET_ROLE(), keccak256("DEPOSIT_WHITELIST_SET_ROLE"));
        assertEq(iBTCVault.DEPOSITOR_WHITELIST_ROLE(), keccak256("DEPOSITOR_WHITELIST_ROLE"));
        assertEq(iBTCVault.DELEGATOR_FACTORY(), address(delegatorFactory));
        assertEq(iBTCVault.SLASHER_FACTORY(), address(slasherFactory));

        assertEq(iBTCVault.owner(), address(0));
        assertEq(iBTCVault.collateral(), address(collateral));
        assertEq(iBTCVault.delegator(), delegator_);
        assertEq(iBTCVault.slasher(), address(0));
        assertEq(iBTCVault.burner(), burner);
        assertEq(iBTCVault.epochDuration(), epochDuration);
        assertEq(iBTCVault.depositWhitelist(), depositWhitelist);
        assertEq(iBTCVault.hasRole(iBTCVault.DEFAULT_ADMIN_ROLE(), alice), true);
        assertEq(iBTCVault.hasRole(iBTCVault.DEPOSITOR_WHITELIST_ROLE(), alice), true);
        assertEq(iBTCVault.epochDurationInit(), blockTimestamp);
        assertEq(iBTCVault.epochDuration(), epochDuration);
        vm.expectRevert(IVaultStorage.InvalidTimestamp.selector);
        assertEq(iBTCVault.epochAt(0), 0);
        assertEq(iBTCVault.epochAt(uint48(blockTimestamp)), 0);
        assertEq(iBTCVault.currentEpoch(), 0);
        assertEq(iBTCVault.currentEpochStart(), blockTimestamp);
        vm.expectRevert(IVaultStorage.NoPreviousEpoch.selector);
        iBTCVault.previousEpochStart();
        assertEq(iBTCVault.nextEpochStart(), blockTimestamp + epochDuration);
        assertEq(iBTCVault.totalStake(), 0);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), ""), 0);
        assertEq(iBTCVault.activeShares(), 0);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), 0);
        assertEq(iBTCVault.activeStake(), 0);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), ""), 0);
        assertEq(iBTCVault.activeSharesOf(alice), 0);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp), ""), 0);
        assertEq(iBTCVault.activeBalanceOf(alice), 0);
        assertEq(iBTCVault.withdrawals(0), 0);
        assertEq(iBTCVault.withdrawalShares(0), 0);
        assertEq(iBTCVault.isWithdrawalsClaimed(0, alice), false);
        assertEq(iBTCVault.depositWhitelist(), depositWhitelist);
        assertEq(iBTCVault.isDepositorWhitelisted(alice), false);
        assertEq(iBTCVault.slashableBalanceOf(alice), 0);
        assertEq(iBTCVault.isDelegatorInitialized(), true);
        assertEq(iBTCVault.isSlasherInitialized(), true);
        assertEq(iBTCVault.isInitialized(), true);

        blockTimestamp = blockTimestamp + iBTCVault.epochDuration() - 1;
        vm.warp(blockTimestamp);

        assertEq(iBTCVault.epochAt(uint48(blockTimestamp)), 0);
        assertEq(iBTCVault.epochAt(uint48(blockTimestamp + 1)), 1);
        assertEq(iBTCVault.currentEpoch(), 0);
        assertEq(iBTCVault.currentEpochStart(), blockTimestamp - (iBTCVault.epochDuration() - 1));
        vm.expectRevert(IVaultStorage.NoPreviousEpoch.selector);
        iBTCVault.previousEpochStart();
        assertEq(iBTCVault.nextEpochStart(), blockTimestamp + 1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        assertEq(iBTCVault.epochAt(uint48(blockTimestamp)), 1);
        assertEq(iBTCVault.epochAt(uint48(blockTimestamp + 2 * iBTCVault.epochDuration())), 3);
        assertEq(iBTCVault.currentEpoch(), 1);
        assertEq(iBTCVault.currentEpochStart(), blockTimestamp);
        assertEq(iBTCVault.previousEpochStart(), blockTimestamp - iBTCVault.epochDuration());
        assertEq(iBTCVault.nextEpochStart(), blockTimestamp + iBTCVault.epochDuration());

        blockTimestamp = blockTimestamp + iBTCVault.epochDuration() - 1;
        vm.warp(blockTimestamp);

        assertEq(iBTCVault.epochAt(uint48(blockTimestamp)), 1);
        assertEq(iBTCVault.epochAt(uint48(blockTimestamp + 1)), 2);
        assertEq(iBTCVault.currentEpoch(), 1);
        assertEq(iBTCVault.currentEpochStart(), blockTimestamp - (iBTCVault.epochDuration() - 1));
        assertEq(
            iBTCVault.previousEpochStart(), blockTimestamp - (iBTCVault.epochDuration() - 1) - iBTCVault.epochDuration()
        );
        assertEq(iBTCVault.nextEpochStart(), blockTimestamp + 1);
    }

    function test_CreateRevertInvalidEpochDuration() public {
        uint48 epochDuration = 0;

        address[] memory networkLimitSetRoleHolders = new address[](1);
        networkLimitSetRoleHolders[0] = alice;
        address[] memory operatorNetworkSharesSetRoleHolders = new address[](1);
        operatorNetworkSharesSetRoleHolders[0] = alice;
        uint64 lastVersion = vaultFactory.lastVersion();
        vm.expectRevert(IVault.InvalidEpochDuration.selector);
        vaultConfigurator.create(
            IVaultConfigurator.InitParams({
                version: lastVersion,
                owner: alice,
                vaultParams: abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: epochDuration,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                ),
                delegatorIndex: 0,
                delegatorParams: abi.encode(
                    INetworkRestakeDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: alice,
                            hook: address(0),
                            hookSetRoleHolder: alice
                        }),
                        networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                        operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
                    })
                ),
                withSlasher: false,
                slasherIndex: 0,
                slasherParams: abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}))
            })
        );
    }

    function test_CreateRevertInvalidCollateral(
        uint48 epochDuration
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));

        address[] memory networkLimitSetRoleHolders = new address[](1);
        networkLimitSetRoleHolders[0] = alice;
        address[] memory operatorNetworkSharesSetRoleHolders = new address[](1);
        operatorNetworkSharesSetRoleHolders[0] = alice;
        uint64 lastVersion = vaultFactory.lastVersion();
        vm.expectRevert(IVault.InvalidCollateral.selector);
        vaultConfigurator.create(
            IVaultConfigurator.InitParams({
                version: lastVersion,
                owner: alice,
                vaultParams: abi.encode(
                    IVault.InitParams({
                        collateral: address(0),
                        burner: address(0xdEaD),
                        epochDuration: epochDuration,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                ),
                delegatorIndex: 0,
                delegatorParams: abi.encode(
                    INetworkRestakeDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: alice,
                            hook: address(0),
                            hookSetRoleHolder: alice
                        }),
                        networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                        operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
                    })
                ),
                withSlasher: false,
                slasherIndex: 0,
                slasherParams: abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}))
            })
        );
    }

    function test_CreateRevertMissingRoles1(
        uint48 epochDuration
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));

        uint64 lastVersion = vaultFactory.lastVersion();

        vm.expectRevert(IVault.MissingRoles.selector);
        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: epochDuration,
                        depositWhitelist: true,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: address(0),
                        depositWhitelistSetRoleHolder: address(0),
                        depositorWhitelistRoleHolder: address(0),
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: address(0)
                    })
                )
            )
        );
    }

    function test_CreateRevertMissingRoles2(
        uint48 epochDuration
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));

        uint64 lastVersion = vaultFactory.lastVersion();

        vm.expectRevert(IVault.MissingRoles.selector);
        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: epochDuration,
                        depositWhitelist: false,
                        isDepositLimit: true,
                        depositLimit: 0,
                        defaultAdminRoleHolder: address(0),
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: address(0),
                        isDepositLimitSetRoleHolder: address(0),
                        depositLimitSetRoleHolder: address(0)
                    })
                )
            )
        );
    }

    function test_CreateRevertMissingRoles3(
        uint48 epochDuration
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));

        uint64 lastVersion = vaultFactory.lastVersion();

        vm.expectRevert(IVault.MissingRoles.selector);
        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: epochDuration,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: address(0),
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: address(0),
                        isDepositLimitSetRoleHolder: address(0),
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );
    }

    function test_CreateRevertMissingRoles4(
        uint48 epochDuration
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));

        uint64 lastVersion = vaultFactory.lastVersion();

        vm.expectRevert(IVault.MissingRoles.selector);
        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: epochDuration,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 1,
                        defaultAdminRoleHolder: address(0),
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: address(0),
                        isDepositLimitSetRoleHolder: address(0),
                        depositLimitSetRoleHolder: address(0)
                    })
                )
            )
        );
    }

    function test_CreateRevertMissingRoles5(
        uint48 epochDuration
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));

        uint64 lastVersion = vaultFactory.lastVersion();

        vm.expectRevert(IVault.MissingRoles.selector);
        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: epochDuration,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: address(0),
                        depositWhitelistSetRoleHolder: address(0),
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: address(0)
                    })
                )
            )
        );
    }

    function test_SetDelegator() public {
        uint64 lastVersion = vaultFactory.lastVersion();

        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        assertEq(iBTCVault.isDelegatorInitialized(), false);

        address[] memory networkLimitSetRoleHolders = new address[](1);
        networkLimitSetRoleHolders[0] = alice;
        address[] memory operatorNetworkLimitSetRoleHolders = new address[](1);
        operatorNetworkLimitSetRoleHolders[0] = alice;
        delegator = FullRestakeDelegator(
            delegatorFactory.create(
                1,
                abi.encode(
                    address(iBTCVault),
                    abi.encode(
                        IFullRestakeDelegator.InitParams({
                            baseParams: IBaseDelegator.BaseParams({
                                defaultAdminRoleHolder: alice,
                                hook: address(0),
                                hookSetRoleHolder: alice
                            }),
                            networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                            operatorNetworkLimitSetRoleHolders: operatorNetworkLimitSetRoleHolders
                        })
                    )
                )
            )
        );

        iBTCVault.setDelegator(address(delegator));

        assertEq(iBTCVault.delegator(), address(delegator));
        assertEq(iBTCVault.isDelegatorInitialized(), true);
        assertEq(iBTCVault.isInitialized(), false);
    }

    function test_SetDelegatorRevertDelegatorAlreadyInitialized() public {
        uint64 lastVersion = vaultFactory.lastVersion();

        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        address[] memory networkLimitSetRoleHolders = new address[](1);
        networkLimitSetRoleHolders[0] = alice;
        address[] memory operatorNetworkLimitSetRoleHolders = new address[](1);
        operatorNetworkLimitSetRoleHolders[0] = alice;
        delegator = FullRestakeDelegator(
            delegatorFactory.create(
                1,
                abi.encode(
                    address(iBTCVault),
                    abi.encode(
                        IFullRestakeDelegator.InitParams({
                            baseParams: IBaseDelegator.BaseParams({
                                defaultAdminRoleHolder: alice,
                                hook: address(0),
                                hookSetRoleHolder: alice
                            }),
                            networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                            operatorNetworkLimitSetRoleHolders: operatorNetworkLimitSetRoleHolders
                        })
                    )
                )
            )
        );

        iBTCVault.setDelegator(address(delegator));

        vm.expectRevert(IVault.DelegatorAlreadyInitialized.selector);
        iBTCVault.setDelegator(address(delegator));
    }

    function test_SetDelegatorRevertNotDelegator() public {
        uint64 lastVersion = vaultFactory.lastVersion();

        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        vm.expectRevert(IVault.NotDelegator.selector);
        iBTCVault.setDelegator(address(1));
    }

    function test_SetDelegatorRevertInvalidDelegator() public {
        uint64 lastVersion = vaultFactory.lastVersion();

        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        iBTC_Vault iBTC_Vault2 = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        address[] memory networkLimitSetRoleHolders = new address[](1);
        networkLimitSetRoleHolders[0] = alice;
        address[] memory operatorNetworkLimitSetRoleHolders = new address[](1);
        operatorNetworkLimitSetRoleHolders[0] = alice;
        delegator = FullRestakeDelegator(
            delegatorFactory.create(
                1,
                abi.encode(
                    address(iBTC_Vault2),
                    abi.encode(
                        IFullRestakeDelegator.InitParams({
                            baseParams: IBaseDelegator.BaseParams({
                                defaultAdminRoleHolder: alice,
                                hook: address(0),
                                hookSetRoleHolder: alice
                            }),
                            networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                            operatorNetworkLimitSetRoleHolders: operatorNetworkLimitSetRoleHolders
                        })
                    )
                )
            )
        );

        vm.expectRevert(IVault.InvalidDelegator.selector);
        iBTCVault.setDelegator(address(delegator));
    }

    function test_SetSlasher() public {
        uint64 lastVersion = vaultFactory.lastVersion();

        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        assertEq(iBTCVault.isSlasherInitialized(), false);

        slasher = Slasher(
            slasherFactory.create(
                0,
                abi.encode(
                    address(iBTCVault),
                    abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}))
                )
            )
        );

        iBTCVault.setSlasher(address(slasher));

        assertEq(iBTCVault.slasher(), address(slasher));
        assertEq(iBTCVault.isSlasherInitialized(), true);
        assertEq(iBTCVault.isInitialized(), false);
    }

    function test_SetSlasherRevertSlasherAlreadyInitialized() public {
        uint64 lastVersion = vaultFactory.lastVersion();

        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        slasher = Slasher(
            slasherFactory.create(
                0,
                abi.encode(
                    address(iBTCVault),
                    abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}))
                )
            )
        );

        iBTCVault.setSlasher(address(slasher));

        vm.expectRevert(IVault.SlasherAlreadyInitialized.selector);
        iBTCVault.setSlasher(address(slasher));
    }

    function test_SetSlasherRevertNotSlasher() public {
        uint64 lastVersion = vaultFactory.lastVersion();

        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        slasher = Slasher(
            slasherFactory.create(
                0,
                abi.encode(
                    address(iBTCVault),
                    abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}))
                )
            )
        );

        vm.expectRevert(IVault.NotSlasher.selector);
        iBTCVault.setSlasher(address(1));
    }

    function test_SetSlasherRevertInvalidSlasher() public {
        uint64 lastVersion = vaultFactory.lastVersion();

        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        iBTC_Vault iBTCVault2 = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        slasher = Slasher(
            slasherFactory.create(
                0,
                abi.encode(
                    address(iBTCVault2),
                    abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}))
                )
            )
        );

        vm.expectRevert(IVault.InvalidSlasher.selector);
        iBTCVault.setSlasher(address(slasher));
    }

    function test_SetSlasherZeroAddress() public {
        uint64 lastVersion = vaultFactory.lastVersion();

        iBTCVault = iBTC_Vault(
            vaultFactory.create(
                lastVersion,
                alice,
                abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: 7 days,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                )
            )
        );

        iBTCVault.setSlasher(address(0));
    }

    function test_DepositTwice(uint256 amount1, uint256 amount2) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        uint256 tokensBefore = collateral.balanceOf(address(iBTCVault));
        uint256 shares1 = amount1 * 10 ** 0;
        {
            (uint256 depositedAmount, uint256 mintedShares) = _deposit(alice, amount1);
            assertEq(depositedAmount, amount1);
            assertEq(mintedShares, shares1);
        }
        assertEq(collateral.balanceOf(address(iBTCVault)) - tokensBefore, amount1);

        assertEq(iBTCVault.totalStake(), amount1);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), ""), 0);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), ""), shares1);
        assertEq(iBTCVault.activeShares(), shares1);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), 0);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), amount1);
        assertEq(iBTCVault.activeStake(), amount1);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), ""), 0);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), ""), shares1);
        assertEq(iBTCVault.activeSharesOf(alice), shares1);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp - 1), ""), 0);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp), ""), amount1);
        assertEq(iBTCVault.activeBalanceOf(alice), amount1);
        assertEq(iBTCVault.slashableBalanceOf(alice), amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        uint256 shares2 = amount2 * (shares1 + 10 ** 0) / (amount1 + 1);
        {
            (uint256 depositedAmount, uint256 mintedShares) = _deposit(alice, amount2);
            assertEq(depositedAmount, amount2);
            assertEq(mintedShares, shares2);
        }

        assertEq(iBTCVault.totalStake(), amount1 + amount2);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), ""), shares1);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), ""), shares1 + shares2);
        assertEq(iBTCVault.activeShares(), shares1 + shares2);
        uint256 gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), abi.encode(1)), shares1);
        uint256 gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), abi.encode(0)), shares1);
        assertGt(gasSpent, gasLeft - gasleft());
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), abi.encode(0)), shares1 + shares2);
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), abi.encode(1)), shares1 + shares2);
        assertGt(gasSpent, gasLeft - gasleft());
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), amount1);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), amount1 + amount2);
        assertEq(iBTCVault.activeStake(), amount1 + amount2);
        gasLeft = gasleft();
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), abi.encode(1)), amount1);
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), abi.encode(0)), amount1);
        assertGt(gasSpent, gasLeft - gasleft());
        gasLeft = gasleft();
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), abi.encode(0)), amount1 + amount2);
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), abi.encode(1)), amount1 + amount2);
        assertGt(gasSpent, gasLeft - gasleft());
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), shares1);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), shares1 + shares2);
        assertEq(iBTCVault.activeSharesOf(alice), shares1 + shares2);
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), abi.encode(1)), shares1);
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), abi.encode(0)), shares1);
        assertGt(gasSpent, gasLeft - gasleft());
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), abi.encode(0)), shares1 + shares2);
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), abi.encode(1)), shares1 + shares2);
        assertGt(gasSpent, gasLeft - gasleft());
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp - 1), ""), amount1);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp), ""), amount1 + amount2);
        assertEq(iBTCVault.activeBalanceOf(alice), amount1 + amount2);
        assertEq(iBTCVault.slashableBalanceOf(alice), amount1 + amount2);
        gasLeft = gasleft();
        assertEq(
            iBTCVault.activeBalanceOfAt(
                alice,
                uint48(blockTimestamp - 1),
                abi.encode(
                    IVault.ActiveBalanceOfHints({
                        activeSharesOfHint: abi.encode(1),
                        activeStakeHint: abi.encode(1),
                        activeSharesHint: abi.encode(1)
                    })
                )
            ),
            amount1
        );
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(
            iBTCVault.activeBalanceOfAt(
                alice,
                uint48(blockTimestamp - 1),
                abi.encode(
                    IVault.ActiveBalanceOfHints({
                        activeSharesOfHint: abi.encode(0),
                        activeStakeHint: abi.encode(0),
                        activeSharesHint: abi.encode(0)
                    })
                )
            ),
            amount1
        );
        assertGt(gasSpent, gasLeft - gasleft());
        gasLeft = gasleft();
        assertEq(
            iBTCVault.activeBalanceOfAt(
                alice,
                uint48(blockTimestamp),
                abi.encode(
                    IVault.ActiveBalanceOfHints({
                        activeSharesOfHint: abi.encode(0),
                        activeStakeHint: abi.encode(0),
                        activeSharesHint: abi.encode(0)
                    })
                )
            ),
            amount1 + amount2
        );
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(
            iBTCVault.activeBalanceOfAt(
                alice,
                uint48(blockTimestamp),
                abi.encode(
                    IVault.ActiveBalanceOfHints({
                        activeSharesOfHint: abi.encode(1),
                        activeStakeHint: abi.encode(1),
                        activeSharesHint: abi.encode(1)
                    })
                )
            ),
            amount1 + amount2
        );
        assertGt(gasSpent, gasLeft - gasleft());
    }

    function test_DepositTwiceFeeOnTransferCollateral(uint256 amount1, uint256 amount2) public {
        amount1 = bound(amount1, 2, 100 * 10 ** 18);
        amount2 = bound(amount2, 2, 100 * 10 ** 18);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        {
            address[] memory networkLimitSetRoleHolders = new address[](1);
            networkLimitSetRoleHolders[0] = alice;
            address[] memory operatorNetworkSharesSetRoleHolders = new address[](1);
            operatorNetworkSharesSetRoleHolders[0] = alice;
            (address vault_,,) = vaultConfigurator.create(
                IVaultConfigurator.InitParams({
                    version: vaultFactory.lastVersion(),
                    owner: alice,
                    vaultParams: abi.encode(
                        IVault.InitParams({
                            collateral: address(feeOnTransferCollateral),
                            burner: address(0xdEaD),
                            epochDuration: epochDuration,
                            depositWhitelist: false,
                            isDepositLimit: false,
                            depositLimit: 0,
                            defaultAdminRoleHolder: alice,
                            depositWhitelistSetRoleHolder: alice,
                            depositorWhitelistRoleHolder: alice,
                            isDepositLimitSetRoleHolder: alice,
                            depositLimitSetRoleHolder: alice
                        })
                    ),
                    delegatorIndex: 0,
                    delegatorParams: abi.encode(
                        INetworkRestakeDelegator.InitParams({
                            baseParams: IBaseDelegator.BaseParams({
                                defaultAdminRoleHolder: alice,
                                hook: address(0),
                                hookSetRoleHolder: alice
                            }),
                            networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                            operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
                        })
                    ),
                    withSlasher: false,
                    slasherIndex: 0,
                    slasherParams: ""
                })
            );

            iBTCVault = iBTC_Vault(vault_);
        }

        uint256 tokensBefore = feeOnTransferCollateral.balanceOf(address(iBTCVault));
        uint256 shares1 = (amount1 - 1) * 10 ** 0;
        feeOnTransferCollateral.transfer(alice, amount1 + 1);
        vm.startPrank(alice);
        feeOnTransferCollateral.approve(address(iBTCVault), amount1);
        {
            (uint256 depositedAmount, uint256 mintedShares) = iBTCVault.deposit(alice, amount1);
            assertEq(depositedAmount, amount1 - 1);
            assertEq(mintedShares, shares1);
        }
        vm.stopPrank();
        assertEq(feeOnTransferCollateral.balanceOf(address(iBTCVault)) - tokensBefore, amount1 - 1);

        assertEq(iBTCVault.totalStake(), amount1 - 1);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), ""), 0);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), ""), shares1);
        assertEq(iBTCVault.activeShares(), shares1);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), 0);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), amount1 - 1);
        assertEq(iBTCVault.activeStake(), amount1 - 1);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), ""), 0);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), ""), shares1);
        assertEq(iBTCVault.activeSharesOf(alice), shares1);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp - 1), ""), 0);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp), ""), amount1 - 1);
        assertEq(iBTCVault.activeBalanceOf(alice), amount1 - 1);
        assertEq(iBTCVault.slashableBalanceOf(alice), amount1 - 1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        uint256 shares2 = (amount2 - 1) * (shares1 + 10 ** 0) / (amount1 - 1 + 1);
        feeOnTransferCollateral.transfer(alice, amount2 + 1);
        vm.startPrank(alice);
        feeOnTransferCollateral.approve(address(iBTCVault), amount2);
        {
            (uint256 depositedAmount, uint256 mintedShares) = iBTCVault.deposit(alice, amount2);
            assertEq(depositedAmount, amount2 - 1);
            assertEq(mintedShares, shares2);
        }
        vm.stopPrank();

        assertEq(iBTCVault.totalStake(), amount1 - 1 + amount2 - 1);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), ""), shares1);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), ""), shares1 + shares2);
        assertEq(iBTCVault.activeShares(), shares1 + shares2);
        uint256 gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), abi.encode(1)), shares1);
        uint256 gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), abi.encode(0)), shares1);
        assertGt(gasSpent, gasLeft - gasleft());
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), abi.encode(0)), shares1 + shares2);
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), abi.encode(1)), shares1 + shares2);
        assertGt(gasSpent, gasLeft - gasleft());
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), amount1 - 1);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), amount1 - 1 + amount2 - 1);
        assertEq(iBTCVault.activeStake(), amount1 - 1 + amount2 - 1);
        gasLeft = gasleft();
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), abi.encode(1)), amount1 - 1);
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), abi.encode(0)), amount1 - 1);
        assertGt(gasSpent, gasLeft - gasleft());
        gasLeft = gasleft();
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), abi.encode(0)), amount1 - 1 + amount2 - 1);
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), abi.encode(1)), amount1 - 1 + amount2 - 1);
        assertGt(gasSpent, gasLeft - gasleft());
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), shares1);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), shares1 + shares2);
        assertEq(iBTCVault.activeSharesOf(alice), shares1 + shares2);
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), abi.encode(1)), shares1);
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), abi.encode(0)), shares1);
        assertGt(gasSpent, gasLeft - gasleft());
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), abi.encode(0)), shares1 + shares2);
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), abi.encode(1)), shares1 + shares2);
        assertGt(gasSpent, gasLeft - gasleft());
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp - 1), ""), amount1 - 1);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp), ""), amount1 - 1 + amount2 - 1);
        assertEq(iBTCVault.activeBalanceOf(alice), amount1 - 1 + amount2 - 1);
        assertEq(iBTCVault.slashableBalanceOf(alice), amount1 - 1 + amount2 - 1);
        gasLeft = gasleft();
        assertEq(
            iBTCVault.activeBalanceOfAt(
                alice,
                uint48(blockTimestamp - 1),
                abi.encode(
                    IVault.ActiveBalanceOfHints({
                        activeSharesOfHint: abi.encode(1),
                        activeStakeHint: abi.encode(1),
                        activeSharesHint: abi.encode(1)
                    })
                )
            ),
            amount1 - 1
        );
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(
            iBTCVault.activeBalanceOfAt(
                alice,
                uint48(blockTimestamp - 1),
                abi.encode(
                    IVault.ActiveBalanceOfHints({
                        activeSharesOfHint: abi.encode(0),
                        activeStakeHint: abi.encode(0),
                        activeSharesHint: abi.encode(0)
                    })
                )
            ),
            amount1 - 1
        );
        assertGt(gasSpent, gasLeft - gasleft());
        gasLeft = gasleft();
        assertEq(
            iBTCVault.activeBalanceOfAt(
                alice,
                uint48(blockTimestamp),
                abi.encode(
                    IVault.ActiveBalanceOfHints({
                        activeSharesOfHint: abi.encode(0),
                        activeStakeHint: abi.encode(0),
                        activeSharesHint: abi.encode(0)
                    })
                )
            ),
            amount1 - 1 + amount2 - 1
        );
        gasSpent = gasLeft - gasleft();
        gasLeft = gasleft();
        assertEq(
            iBTCVault.activeBalanceOfAt(
                alice,
                uint48(blockTimestamp),
                abi.encode(
                    IVault.ActiveBalanceOfHints({
                        activeSharesOfHint: abi.encode(1),
                        activeStakeHint: abi.encode(1),
                        activeSharesHint: abi.encode(1)
                    })
                )
            ),
            amount1 - 1 + amount2 - 1
        );
        assertGt(gasSpent, gasLeft - gasleft());
    }

    function test_DepositBoth(uint256 amount1, uint256 amount2) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        uint256 shares1 = amount1 * 10 ** 0;
        {
            (uint256 depositedAmount, uint256 mintedShares) = _deposit(alice, amount1);
            assertEq(depositedAmount, amount1);
            assertEq(mintedShares, shares1);
        }

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        uint256 shares2 = amount2 * (shares1 + 10 ** 0) / (amount1 + 1);
        {
            (uint256 depositedAmount, uint256 mintedShares) = _deposit(bob, amount2);
            assertEq(depositedAmount, amount2);
            assertEq(mintedShares, shares2);
        }

        assertEq(iBTCVault.totalStake(), amount1 + amount2);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), ""), shares1);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), ""), shares1 + shares2);
        assertEq(iBTCVault.activeShares(), shares1 + shares2);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), amount1);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), amount1 + amount2);
        assertEq(iBTCVault.activeStake(), amount1 + amount2);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), ""), shares1);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), ""), shares1);
        assertEq(iBTCVault.activeSharesOf(alice), shares1);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp - 1), ""), amount1);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp), ""), amount1);
        assertEq(iBTCVault.activeBalanceOf(alice), amount1);
        assertEq(iBTCVault.slashableBalanceOf(alice), amount1);
        assertEq(iBTCVault.activeSharesOfAt(bob, uint48(blockTimestamp - 1), ""), 0);
        assertEq(iBTCVault.activeSharesOfAt(bob, uint48(blockTimestamp), ""), shares2);
        assertEq(iBTCVault.activeSharesOf(bob), shares2);
        assertEq(iBTCVault.activeBalanceOfAt(bob, uint48(blockTimestamp - 1), ""), 0);
        assertEq(iBTCVault.activeBalanceOfAt(bob, uint48(blockTimestamp), ""), amount2);
        assertEq(iBTCVault.activeBalanceOf(bob), amount2);
        assertEq(iBTCVault.slashableBalanceOf(bob), amount2);
    }

    function test_DepositRevertInvalidOnBehalfOf(
        uint256 amount1
    ) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        vm.startPrank(alice);
        vm.expectRevert(IVault.InvalidOnBehalfOf.selector);
        iBTCVault.deposit(address(0), amount1);
        vm.stopPrank();
    }

    function test_DepositRevertInsufficientDeposit() public {
        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        vm.startPrank(alice);
        vm.expectRevert(IVault.InsufficientDeposit.selector);
        iBTCVault.deposit(alice, 0);
        vm.stopPrank();
    }

    function test_WithdrawTwice(uint256 amount1, uint256 amount2, uint256 amount3) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        amount3 = bound(amount3, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2 + amount3);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        // uint48 epochDuration = 1;
        iBTCVault = _getVault(1);

        (, uint256 shares) = _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        uint256 burnedShares = amount2 * (shares + 10 ** 0) / (amount1 + 1);
        uint256 mintedShares = amount2 * 10 ** 0;
        (uint256 burnedShares_, uint256 mintedShares_) = _withdraw(alice, amount2);
        assertEq(burnedShares_, burnedShares);
        assertEq(mintedShares_, mintedShares);

        assertEq(iBTCVault.totalStake(), amount1);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), ""), shares);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), ""), shares - burnedShares);
        assertEq(iBTCVault.activeShares(), shares - burnedShares);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), amount1);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), amount1 - amount2);
        assertEq(iBTCVault.activeStake(), amount1 - amount2);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), ""), shares);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), ""), shares - burnedShares);
        assertEq(iBTCVault.activeSharesOf(alice), shares - burnedShares);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp - 1), ""), amount1);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp), ""), amount1 - amount2);
        assertEq(iBTCVault.activeBalanceOf(alice), amount1 - amount2);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch()), 0);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() + 1), amount2);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() + 2), 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch()), 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch() + 1), mintedShares);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch() + 2), 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch(), alice), 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch() + 1, alice), mintedShares);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch() + 2, alice), 0);
        assertEq(iBTCVault.slashableBalanceOf(alice), amount1);

        shares -= burnedShares;

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        burnedShares = amount3 * (shares + 10 ** 0) / (amount1 - amount2 + 1);
        mintedShares = amount3 * 10 ** 0;
        (burnedShares_, mintedShares_) = _withdraw(alice, amount3);
        assertEq(burnedShares_, burnedShares);
        assertEq(mintedShares_, mintedShares);

        assertEq(iBTCVault.totalStake(), amount1);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), ""), shares);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), ""), shares - burnedShares);
        assertEq(iBTCVault.activeShares(), shares - burnedShares);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), amount1 - amount2);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), amount1 - amount2 - amount3);
        assertEq(iBTCVault.activeStake(), amount1 - amount2 - amount3);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), ""), shares);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), ""), shares - burnedShares);
        assertEq(iBTCVault.activeSharesOf(alice), shares - burnedShares);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp - 1), ""), amount1 - amount2);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp), ""), amount1 - amount2 - amount3);
        assertEq(iBTCVault.activeBalanceOf(alice), amount1 - amount2 - amount3);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() - 1), 0);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch()), amount2);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() + 1), amount3);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() + 2), 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch() - 1), 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch()), amount2 * 10 ** 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch() + 1), amount3 * 10 ** 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch() + 2), 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch() - 1, alice), 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch(), alice), amount2 * 10 ** 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch() + 1, alice), amount3 * 10 ** 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch() + 2, alice), 0);
        assertEq(iBTCVault.slashableBalanceOf(alice), amount1);

        shares -= burnedShares;

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        assertEq(iBTCVault.totalStake(), amount1 - amount2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        assertEq(iBTCVault.totalStake(), amount1 - amount2 - amount3);
    }

    function test_WithdrawRevertInvalidClaimer(
        uint256 amount1
    ) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        vm.expectRevert(IVault.InvalidClaimer.selector);
        vm.startPrank(alice);
        iBTCVault.withdraw(address(0), amount1);
        vm.stopPrank();
    }

    function test_WithdrawRevertInsufficientWithdrawal(
        uint256 amount1
    ) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        vm.expectRevert(IVault.InsufficientWithdrawal.selector);
        _withdraw(alice, 0);
    }

    function test_WithdrawRevertTooMuchWithdraw(
        uint256 amount1
    ) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        vm.expectRevert(IVault.TooMuchWithdraw.selector);
        _withdraw(alice, amount1 + 1);
    }

    function test_RedeemTwice(uint256 amount1, uint256 amount2, uint256 amount3) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        amount3 = bound(amount3, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2 + amount3);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        // uint48 epochDuration = 1;
        iBTCVault = _getVault(1);

        (, uint256 shares) = _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        uint256 withdrawnAssets2 = amount2 * (amount1 + 1) / (shares + 10 ** 0);
        uint256 mintedShares = amount2 * 10 ** 0;
        (uint256 withdrawnAssets_, uint256 mintedShares_) = _redeem(alice, amount2);
        assertEq(withdrawnAssets_, withdrawnAssets2);
        assertEq(mintedShares_, mintedShares);

        assertEq(iBTCVault.totalStake(), amount1);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), ""), shares);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), ""), shares - amount2);
        assertEq(iBTCVault.activeShares(), shares - amount2);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), amount1);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), amount1 - withdrawnAssets2);
        assertEq(iBTCVault.activeStake(), amount1 - withdrawnAssets2);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), ""), shares);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), ""), shares - amount2);
        assertEq(iBTCVault.activeSharesOf(alice), shares - amount2);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp - 1), ""), amount1);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp), ""), amount1 - withdrawnAssets2);
        assertEq(iBTCVault.activeBalanceOf(alice), amount1 - withdrawnAssets2);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch()), 0);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() + 1), withdrawnAssets2);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() + 2), 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch()), 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch() + 1), mintedShares);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch() + 2), 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch(), alice), 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch() + 1, alice), mintedShares);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch() + 2, alice), 0);
        assertEq(iBTCVault.slashableBalanceOf(alice), amount1);

        shares -= amount2;

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        uint256 withdrawnAssets3 = amount3 * (amount1 - withdrawnAssets2 + 1) / (shares + 10 ** 0);
        mintedShares = amount3 * 10 ** 0;
        (withdrawnAssets_, mintedShares_) = _redeem(alice, amount3);
        assertEq(withdrawnAssets_, withdrawnAssets3);
        assertEq(mintedShares_, mintedShares);

        assertEq(iBTCVault.totalStake(), amount1);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp - 1), ""), shares);
        assertEq(iBTCVault.activeSharesAt(uint48(blockTimestamp), ""), shares - amount3);
        assertEq(iBTCVault.activeShares(), shares - amount3);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp - 1), ""), amount1 - withdrawnAssets2);
        assertEq(iBTCVault.activeStakeAt(uint48(blockTimestamp), ""), amount1 - withdrawnAssets2 - withdrawnAssets3);
        assertEq(iBTCVault.activeStake(), amount1 - withdrawnAssets2 - withdrawnAssets3);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp - 1), ""), shares);
        assertEq(iBTCVault.activeSharesOfAt(alice, uint48(blockTimestamp), ""), shares - amount3);
        assertEq(iBTCVault.activeSharesOf(alice), shares - amount3);
        assertEq(iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp - 1), ""), amount1 - withdrawnAssets2);
        assertEq(
            iBTCVault.activeBalanceOfAt(alice, uint48(blockTimestamp), ""),
            amount1 - withdrawnAssets2 - withdrawnAssets3
        );
        assertEq(iBTCVault.activeBalanceOf(alice), amount1 - withdrawnAssets2 - withdrawnAssets3);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() - 1), 0);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch()), withdrawnAssets2);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() + 1), withdrawnAssets3);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() + 2), 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch() - 1), 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch()), withdrawnAssets2 * 10 ** 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch() + 1), withdrawnAssets3 * 10 ** 0);
        assertEq(iBTCVault.withdrawalShares(iBTCVault.currentEpoch() + 2), 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch() - 1, alice), 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch(), alice), withdrawnAssets2 * 10 ** 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch() + 1, alice), withdrawnAssets3 * 10 ** 0);
        assertEq(iBTCVault.withdrawalSharesOf(iBTCVault.currentEpoch() + 2, alice), 0);
        assertEq(iBTCVault.slashableBalanceOf(alice), amount1);

        shares -= amount3;

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        assertEq(iBTCVault.totalStake(), amount1 - withdrawnAssets2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        assertEq(iBTCVault.totalStake(), amount1 - withdrawnAssets2 - withdrawnAssets3);
    }

    function test_RedeemRevertInvalidClaimer(
        uint256 amount1
    ) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        vm.expectRevert(IVault.InvalidClaimer.selector);
        vm.startPrank(alice);
        iBTCVault.redeem(address(0), amount1);
        vm.stopPrank();
    }

    function test_RedeemRevertInsufficientRedeemption(
        uint256 amount1
    ) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        vm.expectRevert(IVault.InsufficientRedemption.selector);
        _redeem(alice, 0);
    }

    function test_RedeemRevertTooMuchRedeem(
        uint256 amount1
    ) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        vm.expectRevert(IVault.TooMuchRedeem.selector);
        _redeem(alice, amount1 + 1);
    }

    function test_Claim(uint256 amount1, uint256 amount2) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        uint256 tokensBefore = collateral.balanceOf(address(iBTCVault));
        uint256 tokensBeforeAlice = collateral.balanceOf(alice);
        assertEq(_claim(alice, iBTCVault.currentEpoch() - 1), amount2);
        assertEq(tokensBefore - collateral.balanceOf(address(iBTCVault)), amount2);
        assertEq(collateral.balanceOf(alice) - tokensBeforeAlice, amount2);

        assertEq(iBTCVault.isWithdrawalsClaimed(iBTCVault.currentEpoch() - 1, alice), true);
    }

    function test_ClaimRevertInvalidRecipient(uint256 amount1, uint256 amount2) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        vm.startPrank(alice);
        uint256 currentEpoch = iBTCVault.currentEpoch();
        vm.expectRevert(IVault.InvalidRecipient.selector);
        iBTCVault.claim(address(0), currentEpoch - 1);
        vm.stopPrank();
    }

    function test_ClaimRevertInvalidEpoch(uint256 amount1, uint256 amount2) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        uint256 currentEpoch = iBTCVault.currentEpoch();
        vm.expectRevert(IVault.InvalidEpoch.selector);
        _claim(alice, currentEpoch);
    }

    function test_ClaimRevertAlreadyClaimed(uint256 amount1, uint256 amount2) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        uint256 currentEpoch = iBTCVault.currentEpoch();
        _claim(alice, currentEpoch - 1);

        vm.expectRevert(IVault.AlreadyClaimed.selector);
        _claim(alice, currentEpoch - 1);
    }

    function test_ClaimRevertInsufficientClaim(uint256 amount1, uint256 amount2) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        uint256 currentEpoch = iBTCVault.currentEpoch();
        vm.expectRevert(IVault.InsufficientClaim.selector);
        _claim(alice, currentEpoch - 2);
    }

    function test_ClaimBatch(uint256 amount1, uint256 amount2, uint256 amount3) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        amount3 = bound(amount3, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2 + amount3);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount3);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        uint256[] memory epochs = new uint256[](2);
        epochs[0] = iBTCVault.currentEpoch() - 1;
        epochs[1] = iBTCVault.currentEpoch() - 2;

        uint256 tokensBefore = collateral.balanceOf(address(iBTCVault));
        uint256 tokensBeforeAlice = collateral.balanceOf(alice);
        assertEq(_claimBatch(alice, epochs), amount2 + amount3);
        assertEq(tokensBefore - collateral.balanceOf(address(iBTCVault)), amount2 + amount3);
        assertEq(collateral.balanceOf(alice) - tokensBeforeAlice, amount2 + amount3);

        assertEq(iBTCVault.isWithdrawalsClaimed(iBTCVault.currentEpoch() - 1, alice), true);
    }

    function test_ClaimBatchRevertInvalidRecipient(uint256 amount1, uint256 amount2, uint256 amount3) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        amount3 = bound(amount3, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2 + amount3);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount3);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        uint256[] memory epochs = new uint256[](2);
        epochs[0] = iBTCVault.currentEpoch() - 1;
        epochs[1] = iBTCVault.currentEpoch() - 2;

        vm.expectRevert(IVault.InvalidRecipient.selector);
        vm.startPrank(alice);
        iBTCVault.claimBatch(address(0), epochs);
        vm.stopPrank();
    }

    function test_ClaimBatchRevertInvalidLengthEpochs(uint256 amount1, uint256 amount2, uint256 amount3) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        amount3 = bound(amount3, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2 + amount3);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount3);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        uint256[] memory epochs = new uint256[](0);
        vm.expectRevert(IVault.InvalidLengthEpochs.selector);
        _claimBatch(alice, epochs);
    }

    function test_ClaimBatchRevertInvalidEpoch(uint256 amount1, uint256 amount2, uint256 amount3) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        amount3 = bound(amount3, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2 + amount3);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount3);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        uint256[] memory epochs = new uint256[](2);
        epochs[0] = iBTCVault.currentEpoch() - 1;
        epochs[1] = iBTCVault.currentEpoch();

        vm.expectRevert(IVault.InvalidEpoch.selector);
        _claimBatch(alice, epochs);
    }

    function test_ClaimBatchRevertAlreadyClaimed(uint256 amount1, uint256 amount2, uint256 amount3) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        amount3 = bound(amount3, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2 + amount3);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount3);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        uint256[] memory epochs = new uint256[](2);
        epochs[0] = iBTCVault.currentEpoch() - 1;
        epochs[1] = iBTCVault.currentEpoch() - 1;

        vm.expectRevert(IVault.AlreadyClaimed.selector);
        _claimBatch(alice, epochs);
    }

    function test_ClaimBatchRevertInsufficientClaim(uint256 amount1, uint256 amount2, uint256 amount3) public {
        amount1 = bound(amount1, 1, 100 * 10 ** 18);
        amount2 = bound(amount2, 1, 100 * 10 ** 18);
        amount3 = bound(amount3, 1, 100 * 10 ** 18);
        vm.assume(amount1 >= amount2 + amount3);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        uint48 epochDuration = 1;
        iBTCVault = _getVault(epochDuration);

        _deposit(alice, amount1);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        _withdraw(alice, amount3);

        blockTimestamp = blockTimestamp + 2;
        vm.warp(blockTimestamp);

        uint256[] memory epochs = new uint256[](2);
        epochs[0] = iBTCVault.currentEpoch() - 1;
        epochs[1] = iBTCVault.currentEpoch() - 3;

        vm.expectRevert(IVault.InsufficientClaim.selector);
        _claimBatch(alice, epochs);
    }

    function test_SetDepositWhitelist() public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        _grantDepositWhitelistSetRole(alice, alice);
        _setDepositWhitelist(alice, true);
        assertEq(iBTCVault.depositWhitelist(), true);

        _setDepositWhitelist(alice, false);
        assertEq(iBTCVault.depositWhitelist(), false);
    }

    function test_SetDepositWhitelistRevertNotWhitelistedDepositor() public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        _deposit(alice, 1);

        _grantDepositWhitelistSetRole(alice, alice);
        _setDepositWhitelist(alice, true);

        vm.startPrank(alice);
        vm.expectRevert(IVault.NotWhitelistedDepositor.selector);
        iBTCVault.deposit(alice, 1);
        vm.stopPrank();
    }

    function test_SetDepositWhitelistRevertAlreadySet() public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        _grantDepositWhitelistSetRole(alice, alice);
        _setDepositWhitelist(alice, true);

        vm.expectRevert(IVault.AlreadySet.selector);
        _setDepositWhitelist(alice, true);
    }

    function test_SetDepositorWhitelistStatus() public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        _grantDepositWhitelistSetRole(alice, alice);
        _setDepositWhitelist(alice, true);

        _grantDepositorWhitelistRole(alice, alice);

        _setDepositorWhitelistStatus(alice, bob, true);
        assertEq(iBTCVault.isDepositorWhitelisted(bob), true);

        _deposit(bob, 1);

        _setDepositWhitelist(alice, false);

        _deposit(bob, 1);
    }

    function test_SetDepositorWhitelistStatusRevertInvalidAccount() public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        _grantDepositWhitelistSetRole(alice, alice);
        _setDepositWhitelist(alice, true);

        _grantDepositorWhitelistRole(alice, alice);

        vm.expectRevert(IVault.InvalidAccount.selector);
        _setDepositorWhitelistStatus(alice, address(0), true);
    }

    function test_SetDepositorWhitelistStatusRevertAlreadySet() public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        _grantDepositWhitelistSetRole(alice, alice);
        _setDepositWhitelist(alice, true);

        _grantDepositorWhitelistRole(alice, alice);

        _setDepositorWhitelistStatus(alice, bob, true);

        vm.expectRevert(IVault.AlreadySet.selector);
        _setDepositorWhitelistStatus(alice, bob, true);
    }

    function test_SetIsDepositLimit() public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        _grantIsDepositLimitSetRole(alice, alice);
        _setIsDepositLimit(alice, true);
        assertEq(iBTCVault.isDepositLimit(), true);

        _setIsDepositLimit(alice, false);
        assertEq(iBTCVault.isDepositLimit(), false);
    }

    function test_SetIsDepositLimitRevertAlreadySet() public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        _grantIsDepositLimitSetRole(alice, alice);
        _setIsDepositLimit(alice, true);

        vm.expectRevert(IVault.AlreadySet.selector);
        _setIsDepositLimit(alice, true);
    }

    function test_SetDepositLimit(uint256 limit1, uint256 limit2, uint256 depositAmount) public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        _grantIsDepositLimitSetRole(alice, alice);
        _setIsDepositLimit(alice, true);
        assertEq(iBTCVault.depositLimit(), 0);

        limit1 = bound(limit1, 1, type(uint256).max);
        _grantDepositLimitSetRole(alice, alice);
        _setDepositLimit(alice, limit1);
        assertEq(iBTCVault.depositLimit(), limit1);

        limit2 = bound(limit2, 1, 1000 ether);
        vm.assume(limit2 != limit1);
        _setDepositLimit(alice, limit2);
        assertEq(iBTCVault.depositLimit(), limit2);

        depositAmount = bound(depositAmount, 1, limit2);
        _deposit(alice, depositAmount);
    }

    function test_SetDepositLimitToNull(
        uint256 limit1
    ) public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        limit1 = bound(limit1, 1, type(uint256).max);
        _grantIsDepositLimitSetRole(alice, alice);
        _setIsDepositLimit(alice, true);
        _grantDepositLimitSetRole(alice, alice);
        _setDepositLimit(alice, limit1);

        _setIsDepositLimit(alice, false);

        _setDepositLimit(alice, 0);

        assertEq(iBTCVault.depositLimit(), 0);
    }

    function test_SetDepositLimitRevertDepositLimitReached(uint256 depositAmount, uint256 limit) public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        _deposit(alice, 1);

        limit = bound(limit, 2, 1000 ether);
        _grantIsDepositLimitSetRole(alice, alice);
        _setIsDepositLimit(alice, true);
        _grantDepositLimitSetRole(alice, alice);
        _setDepositLimit(alice, limit);

        depositAmount = bound(depositAmount, limit, 2000 ether);

        collateral.transfer(alice, depositAmount);
        vm.startPrank(alice);
        collateral.approve(address(iBTCVault), depositAmount);
        vm.expectRevert(IVault.DepositLimitReached.selector);
        iBTCVault.deposit(alice, depositAmount);
        vm.stopPrank();
    }

    function test_SetDepositLimitRevertAlreadySet(
        uint256 limit
    ) public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        limit = bound(limit, 1, type(uint256).max);
        _grantIsDepositLimitSetRole(alice, alice);
        _setIsDepositLimit(alice, true);
        _grantDepositLimitSetRole(alice, alice);
        _setDepositLimit(alice, limit);

        vm.expectRevert(IVault.AlreadySet.selector);
        _setDepositLimit(alice, limit);
    }

    function test_OnSlashRevertNotSlasher() public {
        uint48 epochDuration = 1;

        iBTCVault = _getVault(epochDuration);

        vm.startPrank(alice);
        vm.expectRevert(IVault.NotSlasher.selector);
        iBTCVault.onSlash(0, 0);
        vm.stopPrank();
    }

    struct Test_SlashStruct {
        uint256 slashAmountReal1;
        uint256 tokensBeforeBurner;
        uint256 activeStake1;
        uint256 withdrawals1;
        uint256 nextWithdrawals1;
        uint256 slashAmountSlashed2;
    }

    function test_Slash(
        // uint48 epochDuration,
        uint256 depositAmount,
        uint256 withdrawAmount1,
        uint256 withdrawAmount2,
        uint256 slashAmount1,
        uint256 slashAmount2,
        uint256 captureAgo
    ) public {
        // epochDuration = uint48(bound(epochDuration, 2, 10 days));
        depositAmount = bound(depositAmount, 1, 100 * 10 ** 18);
        withdrawAmount1 = bound(withdrawAmount1, 1, 100 * 10 ** 18);
        withdrawAmount2 = bound(withdrawAmount2, 1, 100 * 10 ** 18);
        slashAmount1 = bound(slashAmount1, 1, type(uint256).max / 2);
        slashAmount2 = bound(slashAmount2, 1, type(uint256).max / 2);
        captureAgo = bound(captureAgo, 1, 10 days);
        vm.assume(depositAmount > withdrawAmount1 + withdrawAmount2);
        vm.assume(depositAmount > slashAmount1);
        vm.assume(captureAgo <= 7 days);

        uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
        blockTimestamp = blockTimestamp + 1_720_700_948;
        vm.warp(blockTimestamp);

        (iBTCVault, delegator, slasher) = _getVaultAndDelegatorAndSlasher(7 days);

        // address network = alice;
        _registerNetwork(alice, alice);
        _setMaxNetworkLimit(alice, 0, type(uint256).max);

        _registerOperator(alice);
        _registerOperator(bob);

        _optInOperatorVault(alice);
        _optInOperatorVault(bob);

        _optInOperatorNetwork(alice, address(alice));
        _optInOperatorNetwork(bob, address(alice));

        _setNetworkLimit(alice, alice, type(uint256).max);

        _setOperatorNetworkLimit(alice, alice, alice, type(uint256).max / 2);
        _setOperatorNetworkLimit(alice, alice, bob, type(uint256).max / 2);

        _deposit(alice, depositAmount);
        _withdraw(alice, withdrawAmount1);

        blockTimestamp = blockTimestamp + iBTCVault.epochDuration();
        vm.warp(blockTimestamp);

        _withdraw(alice, withdrawAmount2);

        assertEq(iBTCVault.totalStake(), depositAmount);
        assertEq(iBTCVault.activeStake(), depositAmount - withdrawAmount1 - withdrawAmount2);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch()), withdrawAmount1);
        assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch() + 1), withdrawAmount2);

        blockTimestamp = blockTimestamp + 1;
        vm.warp(blockTimestamp);

        Test_SlashStruct memory test_SlashStruct;

        if (iBTCVault.epochAt(uint48(blockTimestamp - captureAgo)) != iBTCVault.currentEpoch()) {
            test_SlashStruct.slashAmountReal1 = Math.min(slashAmount1, depositAmount - withdrawAmount1);
            test_SlashStruct.tokensBeforeBurner = collateral.balanceOf(address(iBTCVault.burner()));
            assertEq(
                _slash(alice, alice, alice, slashAmount1, uint48(blockTimestamp - captureAgo), ""),
                test_SlashStruct.slashAmountReal1
            );
            assertEq(
                collateral.balanceOf(address(iBTCVault.burner())) - test_SlashStruct.tokensBeforeBurner,
                test_SlashStruct.slashAmountReal1
            );

            test_SlashStruct.activeStake1 = depositAmount - withdrawAmount1 - withdrawAmount2
                - (depositAmount - withdrawAmount1 - withdrawAmount2).mulDiv(
                    test_SlashStruct.slashAmountReal1, depositAmount
                );
            test_SlashStruct.withdrawals1 =
                withdrawAmount1 - withdrawAmount1.mulDiv(test_SlashStruct.slashAmountReal1, depositAmount);
            test_SlashStruct.nextWithdrawals1 =
                withdrawAmount2 - withdrawAmount2.mulDiv(test_SlashStruct.slashAmountReal1, depositAmount);
            assertEq(iBTCVault.totalStake(), depositAmount - test_SlashStruct.slashAmountReal1);
            assertTrue(test_SlashStruct.withdrawals1 - iBTCVault.withdrawals(iBTCVault.currentEpoch()) <= 2);
            assertTrue(test_SlashStruct.nextWithdrawals1 - iBTCVault.withdrawals(iBTCVault.currentEpoch() + 1) <= 1);
            assertEq(iBTCVault.activeStake(), test_SlashStruct.activeStake1);

            test_SlashStruct.slashAmountSlashed2 = Math.min(
                depositAmount - test_SlashStruct.slashAmountReal1,
                Math.min(slashAmount2, depositAmount - withdrawAmount1)
            );
            test_SlashStruct.tokensBeforeBurner = collateral.balanceOf(address(iBTCVault.burner()));
            assertEq(
                _slash(alice, alice, bob, slashAmount2, uint48(blockTimestamp - captureAgo), ""),
                Math.min(slashAmount2, depositAmount - withdrawAmount1)
            );
            assertEq(
                collateral.balanceOf(address(iBTCVault.burner())) - test_SlashStruct.tokensBeforeBurner,
                test_SlashStruct.slashAmountSlashed2
            );

            assertEq(
                iBTCVault.totalStake(),
                depositAmount - test_SlashStruct.slashAmountReal1 - test_SlashStruct.slashAmountSlashed2
            );
            assertTrue(
                (
                    test_SlashStruct.withdrawals1
                        - test_SlashStruct.withdrawals1.mulDiv(
                            test_SlashStruct.slashAmountSlashed2, depositAmount - test_SlashStruct.slashAmountReal1
                        )
                ) - iBTCVault.withdrawals(iBTCVault.currentEpoch()) <= 4
            );
            assertTrue(
                (
                    test_SlashStruct.nextWithdrawals1
                        - test_SlashStruct.nextWithdrawals1.mulDiv(
                            test_SlashStruct.slashAmountSlashed2, depositAmount - test_SlashStruct.slashAmountReal1
                        )
                ) - iBTCVault.withdrawals(iBTCVault.currentEpoch() + 1) <= 2
            );
            assertEq(
                iBTCVault.activeStake(),
                test_SlashStruct.activeStake1
                    - test_SlashStruct.activeStake1.mulDiv(
                        test_SlashStruct.slashAmountSlashed2, depositAmount - test_SlashStruct.slashAmountReal1
                    )
            );
        } else {
            test_SlashStruct.slashAmountReal1 =
                Math.min(slashAmount1, depositAmount - withdrawAmount1 - withdrawAmount2);
            test_SlashStruct.tokensBeforeBurner = collateral.balanceOf(address(iBTCVault.burner()));
            assertEq(
                _slash(alice, alice, alice, slashAmount1, uint48(blockTimestamp - captureAgo), ""),
                test_SlashStruct.slashAmountReal1
            );
            assertEq(
                collateral.balanceOf(address(iBTCVault.burner())) - test_SlashStruct.tokensBeforeBurner,
                test_SlashStruct.slashAmountReal1
            );

            test_SlashStruct.activeStake1 = depositAmount - withdrawAmount1 - withdrawAmount2
                - (depositAmount - withdrawAmount1 - withdrawAmount2).mulDiv(
                    test_SlashStruct.slashAmountReal1, depositAmount - withdrawAmount1
                );
            test_SlashStruct.withdrawals1 = withdrawAmount1;
            test_SlashStruct.nextWithdrawals1 = withdrawAmount2
                - withdrawAmount2.mulDiv(test_SlashStruct.slashAmountReal1, depositAmount - withdrawAmount1);
            assertEq(iBTCVault.totalStake(), depositAmount - test_SlashStruct.slashAmountReal1);
            assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch()), test_SlashStruct.withdrawals1);
            assertTrue(test_SlashStruct.nextWithdrawals1 - iBTCVault.withdrawals(iBTCVault.currentEpoch() + 1) <= 1);
            assertEq(iBTCVault.activeStake(), test_SlashStruct.activeStake1);

            test_SlashStruct.slashAmountSlashed2 = Math.min(
                depositAmount - withdrawAmount1 - test_SlashStruct.slashAmountReal1,
                Math.min(slashAmount2, depositAmount - withdrawAmount1 - withdrawAmount2)
            );
            test_SlashStruct.tokensBeforeBurner = collateral.balanceOf(address(iBTCVault.burner()));
            assertEq(
                _slash(alice, alice, bob, slashAmount2, uint48(blockTimestamp - captureAgo), ""),
                Math.min(slashAmount2, depositAmount - withdrawAmount1 - withdrawAmount2)
            );
            assertEq(
                collateral.balanceOf(address(iBTCVault.burner())) - test_SlashStruct.tokensBeforeBurner,
                test_SlashStruct.slashAmountSlashed2
            );

            assertEq(
                iBTCVault.totalStake(),
                depositAmount - test_SlashStruct.slashAmountReal1 - test_SlashStruct.slashAmountSlashed2
            );
            assertEq(iBTCVault.withdrawals(iBTCVault.currentEpoch()), test_SlashStruct.withdrawals1);
            assertTrue(
                (
                    test_SlashStruct.nextWithdrawals1
                        - test_SlashStruct.nextWithdrawals1.mulDiv(
                            test_SlashStruct.slashAmountSlashed2,
                            depositAmount - withdrawAmount1 - test_SlashStruct.slashAmountReal1
                        )
                ) - iBTCVault.withdrawals(iBTCVault.currentEpoch() + 1) <= 2
            );
            assertEq(
                iBTCVault.activeStake(),
                test_SlashStruct.activeStake1
                    - test_SlashStruct.activeStake1.mulDiv(
                        test_SlashStruct.slashAmountSlashed2,
                        depositAmount - withdrawAmount1 - test_SlashStruct.slashAmountReal1
                    )
            );
        }
    }

    // struct GasStruct {
    //     uint256 gasSpent1;
    //     uint256 gasSpent2;
    // }

    // struct HintStruct {
    //     uint256 num;
    //     bool back;
    //     uint256 secondsAgo;
    // }

    // function test_ActiveSharesHint(uint256 amount1, uint48 epochDuration, HintStruct memory hintStruct) public {
    //     amount1 = bound(amount1, 1, 100 * 10 ** 18);
    //     epochDuration = uint48(bound(epochDuration, 1, 7 days));
    //     hintStruct.num = bound(hintStruct.num, 0, 25);
    //     hintStruct.secondsAgo = bound(hintStruct.secondsAgo, 0, 1_720_700_948);

    //     uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
    //     blockTimestamp = blockTimestamp + 1_720_700_948;
    //     vm.warp(blockTimestamp);

    //     vault = _getVault(epochDuration);

    //     for (uint256 i; i < hintStruct.num; ++i) {
    //         _deposit(alice, amount1);

    //         blockTimestamp = blockTimestamp + epochDuration;
    //         vm.warp(blockTimestamp);
    //     }

    //     uint48 timestamp =
    //         uint48(hintStruct.back ? blockTimestamp - hintStruct.secondsAgo : blockTimestamp + hintStruct.secondsAgo);

    //     VaultHints vaultHints = new VaultHints();
    //     bytes memory hint = vaultHints.activeSharesHint(address(vault), timestamp);

    //     GasStruct memory gasStruct = GasStruct({gasSpent1: 1, gasSpent2: 1});
    //     vault.activeSharesAt(timestamp, new bytes(0));
    //     gasStruct.gasSpent1 = vm.lastCallGas().gasTotalUsed;
    //     vault.activeSharesAt(timestamp, hint);
    //     gasStruct.gasSpent2 = vm.lastCallGas().gasTotalUsed;
    //     assertApproxEqRel(gasStruct.gasSpent1, gasStruct.gasSpent2, 0.05e18);
    // }

    // function test_ActiveStakeHint(uint256 amount1, uint48 epochDuration, HintStruct memory hintStruct) public {
    //     amount1 = bound(amount1, 1, 100 * 10 ** 18);
    //     epochDuration = uint48(bound(epochDuration, 1, 7 days));
    //     hintStruct.num = bound(hintStruct.num, 0, 25);
    //     hintStruct.secondsAgo = bound(hintStruct.secondsAgo, 0, 1_720_700_948);

    //     uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
    //     blockTimestamp = blockTimestamp + 1_720_700_948;
    //     vm.warp(blockTimestamp);

    //     vault = _getVault(epochDuration);

    //     for (uint256 i; i < hintStruct.num; ++i) {
    //         _deposit(alice, amount1);

    //         blockTimestamp = blockTimestamp + epochDuration;
    //         vm.warp(blockTimestamp);
    //     }

    //     uint48 timestamp =
    //         uint48(hintStruct.back ? blockTimestamp - hintStruct.secondsAgo : blockTimestamp + hintStruct.secondsAgo);

    //     VaultHints vaultHints = new VaultHints();
    //     bytes memory hint = vaultHints.activeStakeHint(address(vault), timestamp);

    //     GasStruct memory gasStruct = GasStruct({gasSpent1: 1, gasSpent2: 1});
    //     vault.activeStakeAt(timestamp, new bytes(0));
    //     gasStruct.gasSpent1 = vm.lastCallGas().gasTotalUsed;
    //     vault.activeStakeAt(timestamp, hint);
    //     gasStruct.gasSpent2 = vm.lastCallGas().gasTotalUsed;
    //     assertGe(gasStruct.gasSpent1, gasStruct.gasSpent2);
    // }

    // function test_ActiveSharesOfHint(uint256 amount1, uint48 epochDuration, HintStruct memory hintStruct) public {
    //     amount1 = bound(amount1, 1, 100 * 10 ** 18);
    //     epochDuration = uint48(bound(epochDuration, 1, 7 days));
    //     hintStruct.num = bound(hintStruct.num, 0, 25);
    //     hintStruct.secondsAgo = bound(hintStruct.secondsAgo, 0, 1_720_700_948);

    //     uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
    //     blockTimestamp = blockTimestamp + 1_720_700_948;
    //     vm.warp(blockTimestamp);

    //     vault = _getVault(epochDuration);

    //     for (uint256 i; i < hintStruct.num; ++i) {
    //         _deposit(alice, amount1);

    //         blockTimestamp = blockTimestamp + epochDuration;
    //         vm.warp(blockTimestamp);
    //     }

    //     uint48 timestamp =
    //         uint48(hintStruct.back ? blockTimestamp - hintStruct.secondsAgo : blockTimestamp + hintStruct.secondsAgo);

    //     VaultHints vaultHints = new VaultHints();
    //     bytes memory hint = vaultHints.activeSharesOfHint(address(vault), alice, timestamp);

    //     GasStruct memory gasStruct = GasStruct({gasSpent1: 1, gasSpent2: 1});
    //     vault.activeSharesOfAt(alice, timestamp, new bytes(0));
    //     gasStruct.gasSpent1 = vm.lastCallGas().gasTotalUsed;
    //     vault.activeSharesOfAt(alice, timestamp, hint);
    //     gasStruct.gasSpent2 = vm.lastCallGas().gasTotalUsed;
    //     assertGe(gasStruct.gasSpent1, gasStruct.gasSpent2);
    // }

    // struct ActiveBalanceOfHintsUint32 {
    //     uint32 activeSharesOfHint;
    //     uint32 activeStakeHint;
    //     uint32 activeSharesHint;
    // }

    // function test_ActiveBalanceOfHint(
    //     uint256 amount1,
    //     uint48 epochDuration,
    //     HintStruct memory hintStruct,
    //     ActiveBalanceOfHintsUint32 memory activeBalanceOfHintsUint32
    // ) public {
    //     amount1 = bound(amount1, 1, 100 * 10 ** 18);
    //     epochDuration = uint48(bound(epochDuration, 1, 7 days));
    //     hintStruct.num = bound(hintStruct.num, 0, 25);
    //     hintStruct.secondsAgo = bound(hintStruct.secondsAgo, 0, 1_720_700_948);

    //     uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
    //     blockTimestamp = blockTimestamp + 1_720_700_948;
    //     vm.warp(blockTimestamp);

    //     vault = _getVault(epochDuration);

    //     for (uint256 i; i < hintStruct.num; ++i) {
    //         _deposit(alice, amount1);

    //         blockTimestamp = blockTimestamp + epochDuration;
    //         vm.warp(blockTimestamp);
    //     }

    //     uint48 timestamp =
    //         uint48(hintStruct.back ? blockTimestamp - hintStruct.secondsAgo : blockTimestamp + hintStruct.secondsAgo);

    //     VaultHints vaultHints = new VaultHints();
    //     bytes memory hint = vaultHints.activeBalanceOfHints(address(vault), alice, timestamp);

    //     GasStruct memory gasStruct = GasStruct({gasSpent1: 1, gasSpent2: 1});
    //     bytes memory activeBalanceOfHints = abi.encode(
    //         IVault.ActiveBalanceOfHints({
    //             activeSharesOfHint: abi.encode(activeBalanceOfHintsUint32.activeSharesOfHint),
    //             activeStakeHint: abi.encode(activeBalanceOfHintsUint32.activeStakeHint),
    //             activeSharesHint: abi.encode(activeBalanceOfHintsUint32.activeSharesHint)
    //         })
    //     );
    //     try vault.activeBalanceOfAt(alice, timestamp, activeBalanceOfHints) {
    //         gasStruct.gasSpent1 = vm.lastCallGas().gasTotalUsed;
    //     } catch {
    //         vault.activeBalanceOfAt(alice, timestamp, "");
    //         gasStruct.gasSpent1 = vm.lastCallGas().gasTotalUsed;
    //     }

    //     vault.activeBalanceOfAt(alice, timestamp, hint);
    //     gasStruct.gasSpent2 = vm.lastCallGas().gasTotalUsed;
    //     assertGe(gasStruct.gasSpent1, gasStruct.gasSpent2);
    // }

    // function test_ActiveBalanceOfHintMany(
    //     uint256 amount1,
    //     uint48 epochDuration,
    //     HintStruct memory hintStruct
    // ) public {
    //     amount1 = bound(amount1, 1, 1 * 10 ** 18);
    //     epochDuration = uint48(bound(epochDuration, 1, 7 days));
    //     hintStruct.num = 500;
    //     hintStruct.secondsAgo = bound(hintStruct.secondsAgo, 0, 1_720_700_948);

    //     uint256 blockTimestamp = block.timestamp * block.timestamp / block.timestamp * block.timestamp / block.timestamp;
    //     blockTimestamp = blockTimestamp + 1_720_700_948;
    //     vm.warp(blockTimestamp);

    //     vault = _getVault(epochDuration);

    //     for (uint256 i; i < hintStruct.num; ++i) {
    //         _deposit(alice, amount1);

    //         blockTimestamp = blockTimestamp + epochDuration;
    //         vm.warp(blockTimestamp);
    //     }

    //     uint48 timestamp =
    //         uint48(hintStruct.back ? blockTimestamp - hintStruct.secondsAgo : blockTimestamp + hintStruct.secondsAgo);

    //     VaultHints vaultHints = new VaultHints();
    //     bytes memory hint = vaultHints.activeBalanceOfHints(address(vault), alice, timestamp);

    //     GasStruct memory gasStruct = GasStruct({gasSpent1: 1, gasSpent2: 1});
    //     vault.activeBalanceOfAt(alice, timestamp, "");
    //     gasStruct.gasSpent1 = vm.lastCallGas().gasTotalUsed;
    //     vault.activeBalanceOfAt(alice, timestamp, hint);
    //     gasStruct.gasSpent2 = vm.lastCallGas().gasTotalUsed;
    //     assertGe(gasStruct.gasSpent1, gasStruct.gasSpent2);

    //     assertLt(gasStruct.gasSpent1 - gasStruct.gasSpent2, 10_000);
    // }

    function _getVault(
        uint48 epochDuration
    ) internal returns (iBTC_Vault) {
        address[] memory networkLimitSetRoleHolders = new address[](1);
        networkLimitSetRoleHolders[0] = alice;
        address[] memory operatorNetworkSharesSetRoleHolders = new address[](1);
        operatorNetworkSharesSetRoleHolders[0] = alice;
        (address vault_,,) = vaultConfigurator.create(
            IVaultConfigurator.InitParams({
                version: vaultFactory.lastVersion(),
                owner: alice,
                vaultParams: abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: epochDuration,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                ),
                delegatorIndex: 0,
                delegatorParams: abi.encode(
                    INetworkRestakeDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: alice,
                            hook: address(0),
                            hookSetRoleHolder: alice
                        }),
                        networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                        operatorNetworkSharesSetRoleHolders: operatorNetworkSharesSetRoleHolders
                    })
                ),
                withSlasher: false,
                slasherIndex: 0,
                slasherParams: abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}))
            })
        );

        return iBTC_Vault(vault_);
    }

    function _getVaultAndDelegatorAndSlasher(
        uint48 epochDuration
    ) internal returns (iBTC_Vault, FullRestakeDelegator, Slasher) {
        address[] memory networkLimitSetRoleHolders = new address[](1);
        networkLimitSetRoleHolders[0] = alice;
        address[] memory operatorNetworkLimitSetRoleHolders = new address[](1);
        operatorNetworkLimitSetRoleHolders[0] = alice;
        (address vault_, address delegator_, address slasher_) = vaultConfigurator.create(
            IVaultConfigurator.InitParams({
                version: vaultFactory.lastVersion(),
                owner: alice,
                vaultParams: abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: epochDuration,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                ),
                delegatorIndex: 1,
                delegatorParams: abi.encode(
                    IFullRestakeDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: alice,
                            hook: address(0),
                            hookSetRoleHolder: alice
                        }),
                        networkLimitSetRoleHolders: networkLimitSetRoleHolders,
                        operatorNetworkLimitSetRoleHolders: operatorNetworkLimitSetRoleHolders
                    })
                ),
                withSlasher: true,
                slasherIndex: 0,
                slasherParams: abi.encode(ISlasher.InitParams({baseParams: IBaseSlasher.BaseParams({isBurnerHook: false})}))
            })
        );

        return (iBTC_Vault(vault_), FullRestakeDelegator(delegator_), Slasher(slasher_));
    }

    function _registerOperator(
        address user
    ) internal {
        vm.startPrank(user);
        operatorRegistry.registerOperator();
        vm.stopPrank();
    }

    function _registerNetwork(address user, address middleware) internal {
        vm.startPrank(user);
        networkRegistry.registerNetwork();
        networkMiddlewareService.setMiddleware(middleware);
        vm.stopPrank();
    }

    function _grantDepositorWhitelistRole(address user, address account) internal {
        vm.startPrank(user);
        iBTC_Vault(address(iBTCVault)).grantRole(iBTCVault.DEPOSITOR_WHITELIST_ROLE(), account);
        vm.stopPrank();
    }

    function _grantDepositWhitelistSetRole(address user, address account) internal {
        vm.startPrank(user);
        iBTC_Vault(address(iBTCVault)).grantRole(iBTCVault.DEPOSIT_WHITELIST_SET_ROLE(), account);
        vm.stopPrank();
    }

    function _grantIsDepositLimitSetRole(address user, address account) internal {
        vm.startPrank(user);
        iBTC_Vault(address(iBTCVault)).grantRole(iBTCVault.IS_DEPOSIT_LIMIT_SET_ROLE(), account);
        vm.stopPrank();
    }

    function _grantDepositLimitSetRole(address user, address account) internal {
        vm.startPrank(user);
        iBTC_Vault(address(iBTCVault)).grantRole(iBTCVault.DEPOSIT_LIMIT_SET_ROLE(), account);
        vm.stopPrank();
    }

    function _deposit(address user, uint256 amount) internal returns (uint256 depositedAmount, uint256 mintedShares) {
        collateral.transfer(user, amount);
        vm.startPrank(user);
        collateral.approve(address(iBTCVault), amount);
        (depositedAmount, mintedShares) = iBTCVault.deposit(user, amount);
        vm.stopPrank();
    }

    function _withdraw(address user, uint256 amount) internal returns (uint256 burnedShares, uint256 mintedShares) {
        vm.startPrank(user);
        (burnedShares, mintedShares) = iBTCVault.withdraw(user, amount);
        vm.stopPrank();
    }

    function _redeem(address user, uint256 shares) internal returns (uint256 withdrawnAssets, uint256 mintedShares) {
        vm.startPrank(user);
        (withdrawnAssets, mintedShares) = iBTCVault.redeem(user, shares);
        vm.stopPrank();
    }

    function _claim(address user, uint256 epoch) internal returns (uint256 amount) {
        vm.startPrank(user);
        amount = iBTCVault.claim(user, epoch);
        vm.stopPrank();
    }

    function _claimBatch(address user, uint256[] memory epochs) internal returns (uint256 amount) {
        vm.startPrank(user);
        amount = iBTCVault.claimBatch(user, epochs);
        vm.stopPrank();
    }

    function _optInOperatorVault(
        address user
    ) internal {
        vm.startPrank(user);
        operatorVaultOptInService.optIn(address(iBTCVault));
        vm.stopPrank();
    }

    function _optOutOperatorVault(
        address user
    ) internal {
        vm.startPrank(user);
        operatorVaultOptInService.optOut(address(iBTCVault));
        vm.stopPrank();
    }

    function _optInOperatorNetwork(address user, address network) internal {
        vm.startPrank(user);
        operatorNetworkOptInService.optIn(network);
        vm.stopPrank();
    }

    function _optOutOperatorNetwork(address user, address network) internal {
        vm.startPrank(user);
        operatorNetworkOptInService.optOut(network);
        vm.stopPrank();
    }

    function _setDepositWhitelist(address user, bool status) internal {
        vm.startPrank(user);
        iBTCVault.setDepositWhitelist(status);
        vm.stopPrank();
    }

    function _setDepositorWhitelistStatus(address user, address depositor, bool status) internal {
        vm.startPrank(user);
        iBTCVault.setDepositorWhitelistStatus(depositor, status);
        vm.stopPrank();
    }

    function _setIsDepositLimit(address user, bool status) internal {
        vm.startPrank(user);
        iBTCVault.setIsDepositLimit(status);
        vm.stopPrank();
    }

    function _setDepositLimit(address user, uint256 amount) internal {
        vm.startPrank(user);
        iBTCVault.setDepositLimit(amount);
        vm.stopPrank();
    }

    function _setNetworkLimit(address user, address network, uint256 amount) internal {
        vm.startPrank(user);
        delegator.setNetworkLimit(network.subnetwork(0), amount);
        vm.stopPrank();
    }

    function _setOperatorNetworkLimit(address user, address network, address operator, uint256 amount) internal {
        vm.startPrank(user);
        delegator.setOperatorNetworkLimit(network.subnetwork(0), operator, amount);
        vm.stopPrank();
    }

    function _slash(
        address user,
        address network,
        address operator,
        uint256 amount,
        uint48 captureTimestamp,
        bytes memory hints
    ) internal returns (uint256 slashAmount) {
        vm.startPrank(user);
        slashAmount = slasher.slash(network.subnetwork(0), operator, amount, captureTimestamp, hints);
        vm.stopPrank();
    }

    function _setMaxNetworkLimit(address user, uint96 identifier, uint256 amount) internal {
        vm.startPrank(user);
        delegator.setMaxNetworkLimit(identifier, amount);
        vm.stopPrank();
    }
}
