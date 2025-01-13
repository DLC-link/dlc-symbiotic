pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {iBTC_GlobalReceiver} from "../src/iBTC_GlobalReceiver.sol";

contract DeployGlobalReceiver is Script {
    iBTC_GlobalReceiver iBTC_globalReceiver;
    address constant COLLATERAL = 0xeb762Ed11a09E4A394C9c8101f8aeeaf5382ED74;
    address constant OWNER = 0x8Ae0F53A071F5036910509FE48eBB8b3558fa9fD; //NOTE: Rayer's testing account

    function run() external {
        vm.startBroadcast();
        iBTC_globalReceiver = new iBTC_GlobalReceiver();
        iBTC_globalReceiver.initialize(COLLATERAL, OWNER);
        console2.log("iBTC_globalReceiver deployed at:", address(iBTC_globalReceiver));
        vm.stopBroadcast();
    }
}
