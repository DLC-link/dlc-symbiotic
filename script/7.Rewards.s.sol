pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {RewardTokenMock} from "../test/mocks/RewardTokenMock.sol";
import {IDefaultStakerRewards} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewards.sol";
import {IDefaultOperatorRewards} from "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewards.sol";
import {IDefaultStakerRewardsFactory} from "rewards/src/contracts/defaultStakerRewards/DefaultStakerRewardsFactory.sol";
import {IDefaultOperatorRewardsFactory} from
    "rewards/src/contracts/defaultOperatorRewards/DefaultOperatorRewardsFactory.sol";

contract DeployRewards is Script {
    address constant DEFAULT_STAKER_REWARDS_FACTORY = 0x70C618a13D1A57f7234c0b893b9e28C5cA8E7f37;
    address constant DEFAULT_OPERATOR_REWARDS_FACTORY = 0x8D6C873cb7ffa6BE615cE1D55801a9417Ed55f9B;
    address constant OWNER = 0x8Ae0F53A071F5036910509FE48eBB8b3558fa9fD; //NOTE: Rayer's testing account

    function run(
        address vault
    ) external {
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
