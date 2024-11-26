// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IUintRequests} from "@symbiotic-burners/contracts/common/UintRequests.sol";

interface IiBTC_Burner is IUintRequests {
    error InsufficientWithdrawal();

    /**
     * @notice Emitted when a withdrawal is triggered.
     * @param caller caller of the function
     * @param firstRequestId first request ID that was created
     * @param lastRequestId last request ID that was created
     */
    event TriggerWithdrawal(address indexed caller, uint256 firstRequestId, uint256 lastRequestId);

    /**
     * @notice Get an address of the collateral.
     */
    function COLLATERAL() external view returns (address);

    /**
     * @notice Get an address of the dlcBTC Exit contract.
     */
    function iBTCTreasury() external view returns (address);

    /**
     * @notice Trigger a withdrawal of BTC from the collateral's underlying asset.
     * @param maxRequests maximum number of withdrawal requests to create
     * @return firstRequestId first request ID that was created
     * @return lastRequestId last request ID that was created
     */
    function triggerWithdrawal(uint256 maxRequests) external returns (uint256 firstRequestId, uint256 lastRequestId);
}
