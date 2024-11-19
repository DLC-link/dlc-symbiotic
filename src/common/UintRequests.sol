// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {IUintRequests} from "../interfaces/common/IUintRequests.sol";

import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

contract UintRequests is IUintRequests {
    using Math for uint256;
    using EnumerableSet for EnumerableSet.UintSet;

    EnumerableSet.UintSet internal _requestIds;

    /**
     * @inheritdoc IUintRequests
     */
    function requestIdsLength() external view returns (uint256) {
        return _requestIds.length();
    }

    /**
     * @inheritdoc IUintRequests
     */
    function requestIds(uint256 index, uint256 maxRequestIds) external view returns (uint256[] memory requestIds_) {
        uint256 length = Math.min(index + maxRequestIds, _requestIds.length()) - index;

        requestIds_ = new uint256[](length);
        for (uint256 i; i < length;) {
            requestIds_[i] = _requestIds.at(index);
            unchecked {
                ++i;
                ++index;
            }
        }
    }

    function _addRequestId(
        uint256 requestId
    ) internal {
        _requestIds.add(requestId);
    }

    function _removeRequestId(
        uint256 requestId
    ) internal {
        if (!_requestIds.remove(requestId)) {
            revert InvalidRequestId();
        }
    }
}
