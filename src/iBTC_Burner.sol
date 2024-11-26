// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// import {SelfDestruct} from "src/common/SelfDestruct.sol"; we don't need selfDestruct
import {UintRequests} from "@symbiotic-burners/contracts/common/UintRequests.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {IiBTC_Burner} from "./interfaces/IiBTC_Burner.sol";
import {IiBTC_Treasury} from "./interfaces/IiBTC_Treasury.sol";

contract iBTC_Burner is UintRequests, IiBTC_Burner, IERC721Receiver {
    using Math for uint256;

    address public immutable Collateral;

    address public immutable IBTCTreasury;

    constructor(address collateral, address iBTCtreasury) {
        Collateral = collateral;

        IBTCTreasury = iBTCtreasury;

        IERC20(Collateral).approve(IBTCTreasury, type(uint256).max);
    }

    /**
     *  IiBTC_Burner
     * This function triggers a withdrawal by creating one or more withdrawal requests.
     * It splits the total collateral balance into multiple requests based on the maximum withdrawal limit.
     */
    function triggerWithdrawal(uint256 maxRequests) external returns (uint256 firstRequestId, uint256 lastRequestId) {
        // Get the current balance of the COLLATERAL token held by this contract
        uint256 amount = IERC20(Collateral).balanceOf(address(this));

        // Fetch the maximum and minimum withdrawal amounts from the treasury
        uint256 maxWithdrawalAmount = IiBTC_Treasury(IBTCTreasury).withdrawRequestMaximum();
        uint256 minWithdrawalAmount = IiBTC_Treasury(IBTCTreasury).withdrawRequestMinimum();

        // Calculate the number of full requests that can be made using the maximum withdrawal amount
        uint256 requests = amount / maxWithdrawalAmount;

        // If there's a remaining amount greater than the minimum withdrawal amount, add an additional request
        if (amount % maxWithdrawalAmount >= minWithdrawalAmount) {
            requests += 1;
        }

        // Ensure the number of requests does not exceed the user-specified maximum (`maxRequests`)
        requests = Math.min(requests, maxRequests);

        // If no requests can be made (e.g., insufficient collateral), revert with an error
        if (requests == 0) {
            revert InsufficientWithdrawal();
        }

        // Calculate the range of request IDs that will be created
        uint256 requestsMinusOne = requests - 1; // Total requests minus one
        firstRequestId = IiBTC_Treasury(IBTCTreasury).getLastrequestIdCreated() + 1; // First request ID
        lastRequestId = firstRequestId + requestsMinusOne; // Last request ID

        // Initialize `requestId` with the first request ID
        uint256 requestId = firstRequestId;

        // Loop through all but the last request and create withdrawal requests with the maximum withdrawal amount
        for (; requestId < lastRequestId; ++requestId) {
            // Add the request ID to the tracking list
            _addRequestId(requestId);

            // Create a withdrawal request for the maximum withdrawal amount
            IiBTC_Treasury(IBTCTreasury).createWithdrawRequest(maxWithdrawalAmount);
        }

        // Add the final request ID to the tracking list
        _addRequestId(requestId);

        // For the last request, calculate the remaining amount and ensure it doesn't exceed the maximum limit
        IiBTC_Treasury(IBTCTreasury).createWithdrawRequest(
            Math.min(amount - requestsMinusOne * maxWithdrawalAmount, maxWithdrawalAmount)
        );

        // Emit an event to record the range of request IDs that were created
        emit TriggerWithdrawal(msg.sender, firstRequestId, lastRequestId);

        // Return the first and last request IDs to the caller
        return (firstRequestId, lastRequestId);
    }

    // function onSlash(bytes32 subnetwork, address operator, uint256 amount, uint48 captureTimestamp) external;

    /**
     * @notice Get an address of the collateral.
     */
    function COLLATERAL() external view returns (address) {
        return Collateral;
    }

    /**
     * @notice Get an address of the dlcBTC Exit contract.
     */
    function iBTCTreasury() external view returns (address) {
        return IBTCTreasury;
    }

    /**
     * @inheritdoc IERC721Receiver
     */
    function onERC721Received(address, address, uint256, bytes calldata) external view returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    receive() external payable {}
}
