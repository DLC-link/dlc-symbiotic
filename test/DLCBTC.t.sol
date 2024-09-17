// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/DLCBTC.sol";
import "../src/DLCManager.sol";

import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";

contract DLCBTCTest is Test {
    DLCBTC public dlcBtc;
    DLCManager public dlcManager;

    address public deployer;
    address public user;
    address public someRandomAccount;
    address public attestor1;
    address public attestor2;
    address public attestor3;

    address[] public attestors;
    uint256 public deposit = 100000000; // 1 BTC
    string public btcFeeRecipient =
        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

    bytes32 public mockUUID =
        0x96eecb386fb10e82f510aaf3e2b99f52f8dcba03f9e0521f7551b367d8ad4967;
    string public mockBTCTxId =
        "0x1234567890123456789012345678901234567890123456789012345678901234";
    string public mockTaprootPubkey =
        "0x1234567890123456789012345678901234567890123456789012345678901234";

    function setUp() public {
        // Set signers
        deployer = vm.addr(1);
        user = vm.addr(2);
        someRandomAccount = vm.addr(3);
        attestor1 = vm.addr(6);
        attestor2 = vm.addr(7);
        attestor3 = vm.addr(8);

        attestors = [attestor1, attestor2, attestor3];

        // Deploy contracts
        vm.startPrank(deployer);
        dlcBtc = new DLCBTC();
        dlcManager = new DLCManager();
        dlcManager.initialize(deployer, deployer, 3, dlcBtc, btcFeeRecipient);

        address proxy = Upgrades.deployTransparentProxy(
            "MyContract.sol",
            INITIAL_OWNER_ADDRESS_FOR_PROXY_ADMIN,
            abi.encodeCall(
                MyContract.initialize,
                ("arguments for the initialize function")
            )
        );
        vm.stopPrank();

        // Transfer ownership to DLCManager
        vm.startPrank(deployer);
        dlcBtc.transferOwnership(address(dlcManager));
        vm.stopPrank();
    }

    function testShouldDeploy() public {
        assertTrue(address(dlcBtc) != address(0));
    }

    function testShouldBeOwnedByDeployerAtStart() public {
        assertEq(dlcBtc.owner(), deployer);
    }

    function testShouldHave8Decimals() public {
        assertEq(dlcBtc.decimals(), 8);
    }

    function testShouldHaveZeroTotalSupply() public {
        assertEq(dlcBtc.totalSupply(), 0);
    }

    function testShouldRevertOnUnauthorizedMint() public {
        vm.expectRevert();
        vm.prank(user);
        dlcBtc.mint(user, deposit);
    }

    function testShouldRevertOnUnauthorizedBurn() public {
        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(user);
        dlcBtc.burn(user, deposit);
    }

    function testOwnerCanMintTokens() public {
        vm.prank(deployer);
        dlcBtc.mint(user, deposit);
        assertEq(dlcBtc.balanceOf(user), deposit);
    }

    function testOwnerCanBurnTokens() public {
        vm.startPrank(deployer);
        dlcBtc.mint(user, deposit);
        dlcBtc.burn(user, deposit);
        assertEq(dlcBtc.balanceOf(user), 0);
        vm.stopPrank();
    }

    function testShouldBeOwnedByDLCManagerAfterTransfer() public {
        vm.startPrank(deployer);
        dlcBtc.mint(user, deposit);
        dlcBtc.transferOwnership(address(dlcManager));
        vm.stopPrank();
        assertEq(dlcBtc.owner(), address(dlcManager));
    }

    function testShouldRevertOnMintCalledByPreviousOwner() public {
        vm.startPrank(deployer);
        dlcBtc.mint(user, deposit);
        dlcBtc.transferOwnership(address(dlcManager));
        vm.stopPrank();

        vm.expectRevert();
        vm.prank(deployer);
        dlcBtc.mint(user, deposit);
    }

    function testShouldRevertOnBurnCalledByPreviousOwner() public {
        vm.startPrank(deployer);
        dlcBtc.mint(user, deposit);
        dlcBtc.transferOwnership(address(dlcManager));
        vm.stopPrank();

        vm.expectRevert("Ownable: caller is not the owner");
        vm.prank(deployer);
        dlcBtc.burn(user, deposit);
    }

    function testDLCManagerCanMintTokens() public {
        vm.startPrank(deployer);
        dlcManager.whitelistAddress(user);
        vm.stopPrank();

        vm.startPrank(user);
        dlcManager.setupVault();
        vm.stopPrank();

        uint256 existingBalance = dlcBtc.balanceOf(user);

        // Set signatures and status
        setSignersAndStatuses(mockBTCTxId, mockTaprootPubkey, 0, deposit);

        assertEq(dlcBtc.balanceOf(user), existingBalance + deposit);
    }

    function testDLCManagerCanBurnTokens() public {
        vm.startPrank(deployer);
        dlcManager.whitelistAddress(user);
        vm.stopPrank();

        vm.startPrank(user);
        dlcManager.setupVault();
        vm.stopPrank();

        uint256 existingBalance = dlcBtc.balanceOf(user);

        // Set signatures and status
        setSignersAndStatuses(mockBTCTxId, mockTaprootPubkey, 0, deposit);

        assertEq(dlcBtc.balanceOf(user), existingBalance + deposit);

        vm.startPrank(user);
        dlcManager.withdraw(mockUUID, deposit);
        vm.stopPrank();

        assertEq(dlcBtc.balanceOf(user), existingBalance);
    }

    function setSignersAndStatuses(
        string memory btcTxId,
        string memory taprootPubkey,
        uint256 newLockedAmountPending,
        uint256 newLockedAmountFunded
    ) internal {
        // Mock function to set signatures and call status updates.
        bytes[] memory signatureBytesForPending = getSignatures(
            btcTxId,
            "set-status-pending",
            newLockedAmountPending
        );
        bytes[] memory signatureBytesForFunding = getSignatures(
            btcTxId,
            "set-status-funded",
            newLockedAmountFunded
        );

        vm.startPrank(attestor1);
        dlcManager.setStatusPending(
            mockUUID,
            btcTxId,
            signatureBytesForPending,
            taprootPubkey,
            0
        );
        dlcManager.setStatusFunded(
            mockUUID,
            btcTxId,
            signatureBytesForFunding,
            newLockedAmountFunded
        );
        vm.stopPrank();
    }

    function getSignatures(
        string memory btcTxId,
        string memory functionString,
        uint256 newLockedAmount
    ) internal pure returns (bytes[] memory) {
        // Mock function to return signatures for testing purposes
        bytes[] memory signatures = new bytes[](3);
        for (uint256 i = 0; i < 3; i++) {
            signatures[i] = abi.encodePacked(
                btcTxId,
                functionString,
                newLockedAmount
            );
        }
        return signatures;
    }
}
