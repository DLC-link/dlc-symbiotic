// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import "../src/iBTC_Treasury.sol";
import "../src/iBTC_Burner.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor() ERC20("Mock Token", "MOCK") {
        _mint(msg.sender, 1_000_000 ether); // Mint 1 million tokens to the deployer
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract iBTC_Treasury_BurnerTest is Test {
    MockERC20 public mockCollateral;
    iBTC_Treasury public treasury;
    iBTC_Burner public burner;

    address public user = address(0x1234);
    address public burnerDeployer = address(0x5678);

    uint256 public constant MAX_WITHDRAW_AMOUNT = 100 ether;
    uint256 public constant MIN_WITHDRAW_AMOUNT = 10 ether;

    function setUp() public {
        // Deploy Mock ERC20 Token
        mockCollateral = new MockERC20();

        // Deploy Treasury
        treasury = new iBTC_Treasury(address(mockCollateral), MAX_WITHDRAW_AMOUNT, MIN_WITHDRAW_AMOUNT);

        // Deploy Burner
        vm.startPrank(burnerDeployer);
        burner = new iBTC_Burner(address(mockCollateral), address(treasury));
        vm.stopPrank();

        // Distribute mock collateral to user and burner for testing
        mockCollateral.mint(user, 500 ether);
        mockCollateral.mint(address(burner), 500 ether);
    }

    function testCreateWithdrawalRequest() public {
        // User approves and creates a withdrawal request
        vm.startPrank(user);
        mockCollateral.approve(address(treasury), 50 ether);

        // Create withdrawal request
        treasury.createWithdrawRequest(50 ether);

        // Verify request
        assertEq(treasury.balanceOf(user), 1); // User should own one ERC721 token
        assertEq(treasury.withdrawalRequests(1), 50 ether); // Verify request amount
        vm.stopPrank();
    }

    function testTriggerWithdrawalFromBurner() public {
        // Burner holds collateral and approves Treasury
        uint256 burnerBalance = mockCollateral.balanceOf(address(burner));
        assertEq(burnerBalance, 500 ether);

        vm.startPrank(burnerDeployer);

        // Trigger a withdrawal using the burner
        (uint256 firstRequestId, uint256 lastRequestId) = burner.triggerWithdrawal(2);

        // Verify request creation
        assertEq(firstRequestId, 1); // First request ID should be 1
        assertEq(lastRequestId, 2); // Last request ID should be 2

        uint256 finalRequestId = treasury.getLastrequestIdCreated();
        assertEq(finalRequestId, 2); // Verify the last created request ID matches

        vm.stopPrank();
    }

    function testFinalizeWithdrawal() public {
        // User creates a withdrawal request
        vm.startPrank(user);
        mockCollateral.approve(address(treasury), 50 ether);
        treasury.createWithdrawRequest(50 ether);
        vm.stopPrank();

        // User finalizes the withdrawal
        vm.startPrank(address(this)); // 让 user 调用 finalizeWithdrawal
        treasury.finalizeWithdrawal(1);
        vm.stopPrank();

        // Verify collateral transfer back to user
        assertEq(mockCollateral.balanceOf(user), 500 ether); // 用户余额恢复到初始值
        assertEq(treasury.balanceOf(user), 0); // ERC721 token 应该已被销毁
    }

    function testBatchProcessWithdrawals() public {
        assertEq(mockCollateral.balanceOf(user), 500 ether);
        vm.startPrank(user);
        mockCollateral.approve(address(treasury), 200 ether);
        treasury.createWithdrawRequest(100 ether);
        treasury.createWithdrawRequest(100 ether);
        vm.stopPrank();

        assertEq(mockCollateral.balanceOf(user), 300 ether);
        vm.prank(address(this));
        treasury.processWithdrawals(2);

        uint256 finalUserBalance = mockCollateral.balanceOf(user);
        console.log("Final user balance:", finalUserBalance);
        assertEq(finalUserBalance, 500 ether);

        uint256 finalTreasuryBalance = mockCollateral.balanceOf(address(treasury));
        console.log("Final treasury balance:", finalTreasuryBalance);
        assertEq(finalTreasuryBalance, 0 ether);
    }
}
