// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

// import {SelfDestruct} from "src/common/SelfDestruct.sol"; we don't need selfDestruct
import {UintRequests} from "src/common/UintRequests.sol";

import {IdlcBTCBurner} from "../interfaces/IdlcBTC_Burner.sol";
import {IdlcBTCEXIT} from "../interfaces/IdlcBTC_EXIT.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

contract dlcBTC_Burner is UintRequests, IswETH_Burner, IERC721Receiver {
    using Math for uint256;

    /**
     * @inheritdoc IdlcBTC_Burner
     */
    address public immutable COLLATERAL;

    /**
     * @inheritdoc IdlcBTC_Burner
     */
    address public immutable DLCBTCEXIT;

    constructor(address collateral, address dlcBTCEXIT) {
        COLLATERAL = collateral;

        DLCBTCEXIT = dlcBTCEXIT;

        IERC20(COLLATERAL).approve(DLCBTCEXIT, type(uint256).max);
    }

    /**
     * @inheritdoc IdlcBTC_Burner
     */
    function triggerWithdrawal(
        uint256 maxRequests
    ) external returns (uint256 firstRequestId, uint256 lastRequestId) {
        uint256 amount = IERC20(COLLATERAL).balanceOf(address(this));

        uint256 maxWithdrawalAmount = IdlcBTCEXIT(DLCBTCEXIT).withdrawRequestMaximum();
        uint256 minWithdrawalAmount = IdlcBTCEXIT(DLCBTCEXIT).withdrawRequestMinimum();

        uint256 requests = amount / maxWithdrawalAmount;
        if (amount % maxWithdrawalAmount >= minWithdrawalAmount) {
            requests += 1;
        }
        requests = Math.min(requests, maxRequests);

        if (requests == 0) {
            revert InsufficientWithdrawal();
        }

        uint256 requestsMinusOne = requests - 1;
        firstRequestId = IdlcBTCEXIT(DLCBTCEXIT).getLastTokenIdCreated() + 1;
        lastRequestId = firstRequestId + requestsMinusOne;
        uint256 requestId = firstRequestId;
        for (; requestId < lastRequestId; ++requestId) {
            _addRequestId(requestId);
            IdlcBTCEXIT(DLCBTCEXIT).createWithdrawRequest(maxWithdrawalAmount);
        }
        _addRequestId(requestId);
        IdlcBTCEXIT(DLCBTCEXIT).createWithdrawRequest(
            Math.min(amount - requestsMinusOne * maxWithdrawalAmount, maxWithdrawalAmount)
        );

        emit TriggerWithdrawal(msg.sender, firstRequestId, lastRequestId);

        return (firstRequestId, lastRequestId);
    }

    /**
     * @inheritdoc IERC721Receiver
     */
    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    receive() external payable {}
}
