// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IiBTC_Treasury {
    function getLastrequestIdCreated() external view returns (uint256);

    function withdrawRequestMaximum() external view returns (uint256);

    function withdrawRequestMinimum() external view returns (uint256);

    function processWithdrawals(
        uint256 _lastTokenIdToProcess
    ) external;

    function createWithdrawRequest(
        uint256 amount
    ) external;

    function finalizeWithdrawal(
        uint256 tokenId
    ) external;
}
