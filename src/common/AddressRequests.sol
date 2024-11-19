// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IAddressRequests} from "../../interfaces/common/IAddressRequests.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

contract AddressRequests is IAddressRequests {
    using Math for uint256;
    using EnumerableSet for EnumerableSet.AddressSet;

    EnumerableSet.AddressSet private _requestIds;

    /**
     * @inheritdoc IAddressRequests
     */
    function requestIdsLength() external view returns (uint256) {
        return _requestIds.length();
    }

    /**
     * @inheritdoc IAddressRequests
     */
    function requestIds(uint256 index, uint256 maxRequestIds) external view returns (address[] memory requestIds_) {
        uint256 length = Math.min(index + maxRequestIds, _requestIds.length()) - index;

        requestIds_ = new address[](length);
        for (uint256 i; i < length;) {
            requestIds_[i] = _requestIds.at(index);
            unchecked {
                ++i;
                ++index;
            }
        }
    }

    function _addRequestId(
        address requestId
    ) internal {
        _requestIds.add(requestId);
    }

    function _removeRequestId(
        address requestId
    ) internal {
        if (!_requestIds.remove(requestId)) {
            revert InvalidRequestId();
        }
    }
}
