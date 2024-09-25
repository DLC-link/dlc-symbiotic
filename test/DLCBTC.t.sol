// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.0;

// import {Upgrades} from "openzeppelin-foundry-upgrades/Upgrades.sol";
// import "forge-std/Test.sol";
// import "forge-std/console.sol";

// import "../src/DLCBTC.sol";
// import "../src/DLCManager.sol";

// contract DLCBTCTest is Test {
//     DLCBTC public dlcBtc;
//     DLCManager public dlcManager;
//     SignatureHelper public signatureHelper;

//     address public deployer;
//     address public user;
//     address public someRandomAccount;
//     address public attestor1;
//     address public attestor2;
//     address public attestor3;

//     address[] public attestors;
//     uint256 public deposit = 100000000; // 1 BTC
//     string public btcFeeRecipient =
//         "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

//     bytes32 public mockUUID =
//         0x96eecb386fb10e82f510aaf3e2b99f52f8dcba03f9e0521f7551b367d8ad4967;
//     string public mockBTCTxId =
//         "0x1234567890123456789012345678901234567890123456789012345678901234";
//     string public mockTaprootPubkey =
//         "0x1234567890123456789012345678901234567890123456789012345678901234";

//     function setUp() public {
//         signatureHelper = new SignatureHelper();
//         // Set signers
//         deployer = vm.addr(1);
//         user = vm.addr(2);
//         someRandomAccount = vm.addr(3);
//         attestor1 = vm.addr(6);
//         attestor2 = vm.addr(7);
//         attestor3 = vm.addr(8);

//         attestors = [attestor1, attestor2, attestor3];

//         // Deploy contracts
//         vm.startPrank(deployer);

//         address tokenProxy = Upgrades.deployTransparentProxy(
//             "DLCBTC.sol",
//             deployer,
//             abi.encodeCall(DLCBTC.initialize, ())
//         );

//         dlcBtc = DLCBTC(tokenProxy);

//         address proxy = Upgrades.deployTransparentProxy(
//             "DLCManager.sol",
//             deployer,
//             abi.encodeCall(
//                 DLCManager.initialize,
//                 (deployer, deployer, 3, dlcBtc, btcFeeRecipient)
//             )
//         );
//         dlcManager = DLCManager(proxy);
//         vm.stopPrank();

//         // Transfer ownership to DLCManager
//         vm.startPrank(deployer);
//         dlcBtc.transferOwnership(proxy);
//         vm.stopPrank();
//     }

//     function testShouldDeploy() public view {
//         assertTrue(address(dlcBtc) != address(0));
//     }

//     function testShouldHave8Decimals() public view {
//         assertEq(dlcBtc.decimals(), 8);
//     }

//     function testShouldHaveZeroTotalSupply() public view {
//         assertEq(dlcBtc.totalSupply(), 0);
//     }

//     function testShouldRevertOnUnauthorizedMint() public {
//         vm.expectRevert();
//         vm.prank(user);
//         dlcBtc.mint(user, deposit);
//     }

//     function testShouldRevertOnUnauthorizedBurn() public {
//         vm.expectRevert();
//         vm.prank(user);
//         dlcBtc.burn(user, deposit);
//     }

//     function testOwnerCanMintTokens() public {
//         vm.prank(address(dlcManager));
//         dlcBtc.mint(user, deposit);
//         assertEq(dlcBtc.balanceOf(user), deposit);
//     }

//     function testOwnerCanBurnTokens() public {
//         vm.startPrank(address(dlcManager));
//         dlcBtc.mint(user, deposit);
//         dlcBtc.burn(user, deposit);
//         assertEq(dlcBtc.balanceOf(user), 0);
//         vm.stopPrank();
//     }

//     // function testDLCManagerCanMintTokens() public {
//     //     vm.startPrank(deployer);
//     //     dlcManager.whitelistAddress(user);
//     //     vm.stopPrank();

//     //     vm.startPrank(user);
//     //     bytes32 _uuid = dlcManager.setupVault();
//     //     vm.stopPrank();

//     //     uint256 existingBalance = dlcBtc.balanceOf(user);

//     //     // Set signatures and status
//     //     setSignersAndStatuses(
//     //         _uuid,
//     //         mockBTCTxId,
//     //         mockTaprootPubkey,
//     //         0,
//     //         deposit
//     //     );

//     //     assertEq(dlcBtc.balanceOf(user), existingBalance + deposit);
//     // }

//     // function testDLCManagerCanBurnTokens() public {
//     //     vm.startPrank(deployer);
//     //     dlcManager.whitelistAddress(user);
//     //     vm.stopPrank();

//     //     vm.startPrank(user);
//     //     bytes32 _uuid = dlcManager.setupVault();
//     //     vm.stopPrank();

//     //     uint256 existingBalance = dlcBtc.balanceOf(user);

//     //     console.log("Existing balance: ", existingBalance);

//     //     // Set signatures and status
//     //     setSignersAndStatuses(
//     //         _uuid,
//     //         mockBTCTxId,
//     //         mockTaprootPubkey,
//     //         0,
//     //         deposit
//     //     );

//     //     assertEq(dlcBtc.balanceOf(user), existingBalance + deposit);

//     //     vm.startPrank(user);
//     //     dlcManager.withdraw(mockUUID, deposit);
//     //     vm.stopPrank();

//     //     assertEq(dlcBtc.balanceOf(user), existingBalance);
//     // }

//     // function setSignersAndStatuses(
//     //     bytes32 uuid,
//     //     string memory btcTxId,
//     //     string memory taprootPubkey,
//     //     uint256 newLockedAmountPending,
//     //     uint256 newLockedAmountFunded
//     // ) internal {
//     //     // Mock function to set signatures and call status updates.
//     //     bytes[] memory signatureBytesForPending = signatureHelper.getSignatures(
//     //         uuid,
//     //         btcTxId,
//     //         "set-status-pending",
//     //         newLockedAmountPending,
//     //         attestors,
//     //         3
//     //     );
//     //     bytes[] memory signatureBytesForFunding = signatureHelper.getSignatures(
//     //         uuid,
//     //         btcTxId,
//     //         "set-status-funded",
//     //         deposit,
//     //         attestors,
//     //         3
//     //     );

//     //     console.log("signatureBytesForPending: ", signatureBytesForPending);
//     //     console.log("signatureBytesForFunding: ", signatureBytesForFunding);

//     //     vm.startPrank(attestor1);
//     //     dlcManager.setStatusPending(
//     //         uuid,
//     //         btcTxId,
//     //         signatureBytesForPending,
//     //         taprootPubkey,
//     //         0
//     //     );
//     //     dlcManager.setStatusFunded(
//     //         uuid,
//     //         btcTxId,
//     //         signatureBytesForFunding,
//     //         newLockedAmountFunded
//     //     );
//     //     vm.stopPrank();
//     // }
// }
