pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {RewardTokenMock} from "../test/mocks/RewardTokenMock.sol";
import {IDefaultStakerRewards} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewards.sol";
import {IDefaultOperatorRewards} from "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewards.sol";
import {IDefaultStakerRewardsFactory} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewardsFactory.sol";
import {IDefaultOperatorRewardsFactory} from
    "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewardsFactory.sol";
import {ReadFile} from "./libs/ReadFile.sol";

contract DeployRewards is Script {
    address DEFAULT_STAKER_REWARDS_FACTORY;
    address DEFAULT_OPERATOR_REWARDS_FACTORY;
    address constant OWNER = 0x8Ae0F53A071F5036910509FE48eBB8b3558fa9fD; //NOTE: Rayer's testing account

    function run(uint256 _chainId, address vault) external {
        ReadFile readFile = new ReadFile();
        DEFAULT_STAKER_REWARDS_FACTORY = readFile.readInput(_chainId, "symbiotic", "DEFAULT_STAKER_REWARDS_FACTORY");
        DEFAULT_OPERATOR_REWARDS_FACTORY = readFile.readInput(_chainId, "symbiotic", "DEFAULT_OPERATOR_REWARDS_FACTORY");
        vm.startBroadcast();
        address defaultStakerRewards_ = IDefaultStakerRewardsFactory(DEFAULT_STAKER_REWARDS_FACTORY).create(
            IDefaultStakerRewards.InitParams({
                vault: vault,
                adminFee: 1000, // admin fee percent to get from all the rewards distributions (10% = 1_000 | 100% = 10_000)
                defaultAdminRoleHolder: OWNER, // address of the main admin (can manage all roles)
                adminFeeClaimRoleHolder: OWNER, // address of the admin fee claimer
                adminFeeSetRoleHolder: OWNER // address of the admin fee setter
            })
        );
        address defaultOperatorRewards_ = IDefaultOperatorRewardsFactory(DEFAULT_OPERATOR_REWARDS_FACTORY).create();
        console2.log("DefaultStakerRewards deployed at:", address(defaultStakerRewards_));
        console2.log("DefaultOperatorRewards deployed at:", address(defaultOperatorRewards_));
        vm.stopBroadcast();
    }
}
