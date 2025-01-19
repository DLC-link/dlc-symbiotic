// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {Vm} from "forge-std/Vm.sol";

contract ReadFile is Script {
    function readInput(
        uint256 _chainId,
        string memory _part,
        string memory _contractName
    ) public view returns (address) {
        string memory inputDir = string.concat(vm.projectRoot(), "/script/addresses/");
        string memory chainDir = string.concat(vm.toString(uint256(_chainId)), "/");
        string memory file = string.concat("contract_addresses", ".json");
        string memory json = vm.readFile(string.concat(inputDir, chainDir, file));
        bytes memory addressBytes =
            vm.parseJson(json, string.concat(".", _part, ".contracts.", _contractName, ".address"));
        return bytesToAddress(addressBytes);
    }

    function bytesToAddress(
        bytes memory data
    ) public pure returns (address addr) {
        require(data.length >= 20, "Invalid bytes length");
        assembly {
            addr := mload(add(data, 32))
        }
    }
}
