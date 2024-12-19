// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../../lib/core/src/contracts/libraries/Subnetwork.sol";
import {NetworkRegistry} from "core/src/contracts/NetworkRegistry.sol";

contract NetworkMock {
    using Subnetwork for address;
    using Subnetwork for bytes32;

    // Mapping to store subnetwork information
    mapping(uint96 identifier => bytes32 subnetwork) private _subnetworks;
    mapping(bytes32 subnetworkId => bool) private _registeredSubnetworks;

    event SubnetworkRegistered(uint96 indexed identifier, bytes32 indexed subnetworkId);
    event SubnetworkUnregistered(uint96 indexed identifier, bytes32 indexed subnetworkId);

    function registerInRegistry(
        NetworkRegistry registry
    ) external {
        registry.registerNetwork();
    }

    function registerSubnetwork(
        uint96 identifier
    ) external returns (bytes32) {
        bytes32 subnetworkId = address(this).subnetwork(identifier);
        require(!_registeredSubnetworks[subnetworkId], "NetworkMock: subnetwork already registered");

        _subnetworks[identifier] = subnetworkId;
        _registeredSubnetworks[subnetworkId] = true;

        emit SubnetworkRegistered(identifier, subnetworkId);
        return subnetworkId;
    }

    function unregisterSubnetwork(
        uint96 identifier
    ) external {
        bytes32 subnetworkId = _subnetworks[identifier];
        require(_registeredSubnetworks[subnetworkId], "NetworkMock: subnetwork not registered");

        delete _subnetworks[identifier];
        delete _registeredSubnetworks[subnetworkId];

        emit SubnetworkUnregistered(identifier, subnetworkId);
    }

    function subnetwork(
        uint96 identifier
    ) external view returns (bytes32) {
        bytes32 subnetworkId = _subnetworks[identifier];
        require(_registeredSubnetworks[subnetworkId], "NetworkMock: subnetwork not registered");
        return subnetworkId;
    }

    function network(
        bytes32 subnetworkId
    ) external view returns (address) {
        require(_registeredSubnetworks[subnetworkId], "NetworkMock: subnetwork not registered");
        return subnetworkId.network();
    }

    function identifier(
        bytes32 subnetworkId
    ) external view returns (uint96) {
        require(_registeredSubnetworks[subnetworkId], "NetworkMock: subnetwork not registered");
        return subnetworkId.identifier();
    }

    function isRegistered(
        bytes32 subnetworkId
    ) external view returns (bool) {
        return _registeredSubnetworks[subnetworkId];
    }

    function getSubnetworkId(
        uint96 identifier
    ) external view returns (bytes32) {
        return _subnetworks[identifier];
    }
}
