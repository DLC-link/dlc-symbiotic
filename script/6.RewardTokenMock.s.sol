pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {RewardTokenMock} from "../test/mocks/RewardTokenMock.sol";

contract DeployRewardTokenMock is Script {
    function run() external {
        vm.startBroadcast();
        RewardTokenMock rewardTokenMock = new RewardTokenMock("reward", "REWARD", 100e18);
        console2.log("RewardTokenMock deployed at:", address(rewardTokenMock));
        vm.stopBroadcast();
    }
}
