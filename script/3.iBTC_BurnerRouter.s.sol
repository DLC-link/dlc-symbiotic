pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {BurnerRouter} from "burners/src/contracts/router/BurnerRouter.sol";
import {BurnerRouterFactory} from "burners/src/contracts/router/BurnerRouterFactory.sol";
import {IBurnerRouter} from "burners/src/interfaces/router/IBurnerRouter.sol";

contract DeployBurnerRouter is Script {
    BurnerRouter burner;

    address constant OWNER = 0x8Ae0F53A071F5036910509FE48eBB8b3558fa9fD; //NOTE: Rayer's testing account
    address constant COLLATERAL = 0xeb762Ed11a09E4A394C9c8101f8aeeaf5382ED74;

    function run(
        address iBTC_globalReceiver
    ) external {
        vm.startBroadcast();
        IBurnerRouter.InitParams memory params = IBurnerRouter.InitParams({
            owner: OWNER,
            collateral: COLLATERAL,
            delay: 0,
            globalReceiver: iBTC_globalReceiver,
            networkReceivers: new IBurnerRouter.NetworkReceiver[](0),
            operatorNetworkReceivers: new IBurnerRouter.OperatorNetworkReceiver[](0)
        });
        BurnerRouter burnerTemplate = new BurnerRouter();
        BurnerRouterFactory burnerRouterFactory = new BurnerRouterFactory(address(burnerTemplate));
        address burnerAddress = address(burnerRouterFactory.create(params));
        burner = BurnerRouter(burnerAddress);
        console2.log("BurnerRouter deployed at:", address(burner));
        vm.stopBroadcast();
    }
}
