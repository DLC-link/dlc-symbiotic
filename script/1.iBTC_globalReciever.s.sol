pragma solidity 0.8.25;

import {Script, console2} from "forge-std/Script.sol";
import {iBTC_GlobalReceiver} from "../src/iBTC_GlobalReceiver.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyAdmin} from "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {ReadFile} from "./libs/ReadFile.sol";
import {Vm} from "forge-std/Vm.sol";

contract DeployGlobalReceiver is Script {
    iBTC_GlobalReceiver iBTC_globalReceiver;
    address COLLATERAL;
    address constant OWNER = 0x8Ae0F53A071F5036910509FE48eBB8b3558fa9fD; //NOTE: Rayer's testing account

    function run(
        uint256 _chainId
    ) external {
        ReadFile readFile = new ReadFile();
        vm.startBroadcast();
        COLLATERAL = readFile.readInput(_chainId, "iBTC", "COLLATERAL");
        iBTC_GlobalReceiver grImplementation = new iBTC_GlobalReceiver();
        TransparentUpgradeableProxy gr_proxy = new TransparentUpgradeableProxy(
            address(grImplementation),
            OWNER,
            abi.encodeWithSelector(iBTC_GlobalReceiver.initialize.selector, COLLATERAL, OWNER)
        );
        ProxyAdmin proxyAdmin = ProxyAdmin(_getAdminAddress(address(gr_proxy)));
        iBTC_globalReceiver = iBTC_GlobalReceiver(address(gr_proxy));

        console2.log("iBTC_globalReceiver deployed at:", address(iBTC_globalReceiver));
        console2.log("ProxyAdmin deployed at:", address(proxyAdmin));
        vm.stopBroadcast();
    }

    function _getAdminAddress(
        address proxy_
    ) internal view returns (address) {
        address CHEATCODE_ADDRESS = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D;
        Vm vm = Vm(CHEATCODE_ADDRESS);

        bytes32 adminSlot = vm.load(proxy_, ERC1967Utils.ADMIN_SLOT);
        return address(uint160(uint256(adminSlot)));
    }
}
