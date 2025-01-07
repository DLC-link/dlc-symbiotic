pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {NetworkMock} from "../test/mocks/NetworkMock.sol";

contract DeployNetworkMock is Script {
    address constant OWNER = 0x8Ae0F53A071F5036910509FE48eBB8b3558fa9fD; //NOTE: Rayer's testing account

    function run() external {
        vm.startBroadcast();
        NetworkMock networkMock = new NetworkMock();
        console2.log("NetworkMock deployed at:", address(networkMock));
        vm.stopBroadcast();
    }
}
