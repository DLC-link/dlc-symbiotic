pragma solidity ^0.8.0;

import {Script, console2} from "forge-std/Script.sol";
import {NetworkRestakeDelegator} from "core/src/contracts/delegator/NetworkRestakeDelegator.sol";
import {NetworkMiddleware} from "../../src/iBTC_NetworkMiddleware.sol";

contract GrantRoles is Script {
    bytes32 public constant APPROVED_SIGNER = keccak256("APPROVED_SIGNER");
    bytes32 public constant NETWORK_LIMIT_SET_ROLE = keccak256("NETWORK_LIMIT_SET_ROLE");
    bytes32 public constant OPERATOR_NETWORK_SHARES_SET_ROLE = keccak256("OPERATOR_NETWORK_SHARES_SET_ROLE");

    NetworkRestakeDelegator iBTC_delegator;
    NetworkMiddleware iBTC_networkMiddleware;

    function run(bytes32 role, address account, address delegator, address networkMiddleware) public {
        require(account != address(0), "Account is required");
        require(role != bytes32(0), "Role is required");

        vm.startBroadcast();
        if (role == "NETWORK_LIMIT_SET_ROLE") {
            require(delegator != address(0), "Delegator is required");
            iBTC_delegator = NetworkRestakeDelegator(delegator);

            _grantRoleInDelegator(account, role);
        } else if (role == "OPERATOR_NETWORK_SHARES_SET_ROLE") {
            require(delegator != address(0), "Delegator is required");
            iBTC_delegator = NetworkRestakeDelegator(delegator);

            _grantRoleInDelegator(account, role);
        } else if (role == "APPROVED_SIGNER") {
            require(networkMiddleware != address(0), "iBTC_networkMiddleware is required");
            iBTC_networkMiddleware = NetworkMiddleware(networkMiddleware);
            _grantRoleInNetworkMiddleware(account, role);
        } else {
            revert("Role not found");
        }
        vm.stopBroadcast();
    }

    function _grantRoleInDelegator(address account, bytes32 role) internal {
        iBTC_delegator.grantRole(role, account);
    }

    function _grantRoleInNetworkMiddleware(address account, bytes32 role) internal {
        iBTC_networkMiddleware.grantRole(role, account);
    }
}
