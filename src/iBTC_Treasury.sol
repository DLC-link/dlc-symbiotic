// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "./libraries/Counter.sol";

contract iBTC_Treasury is ERC721, Ownable {
    using Counters for Counters.Counter;

    // Counter for the token IDs of withdrawal requests
    Counters.Counter private _requestIds;

    // ERC20 token used as collateral
    IERC20 public immutable collateral;

    // Maximum and minimum amounts for withdrawal requests
    uint256 public maxWithdrawAmount;
    uint256 public minWithdrawAmount;
    mapping(uint256 requestId => uint256 withdrawalAmounts) public withdrawalRequests;

    mapping(uint256 requestId => bool hasFinalized) public finalizedWithdrawals;

    // Event emitted when a withdrawal request is created
    event WithdrawalRequestCreated(address indexed requester, uint256 requestId, uint256 amount);

    // Event emitted when a withdrawal is finalized
    event WithdrawalFinalized(address indexed requester, uint256 requestId, uint256 amount);

    constructor(
        address _collateral,
        uint256 _maxWithdrawAmount,
        uint256 _minWithdrawAmount
    ) ERC721("iBTC Withdrawal Request", "iBTC-WR") Ownable(msg.sender) {
        // Ensure that the maximum withdrawal amount is greater than the minimum
        require(_maxWithdrawAmount > _minWithdrawAmount, "Invalid withdrawal limits");

        collateral = IERC20(_collateral);
        maxWithdrawAmount = _maxWithdrawAmount;
        minWithdrawAmount = _minWithdrawAmount;
    }

    /**
     * @dev Returns the last request ID created for a withdrawal request.
     */
    function getLastrequestIdCreated() external view returns (uint256) {
        return _requestIds.current();
    }

    /**
     * @dev Updates the maximum and minimum withdrawal limits.
     * Only the contract owner can call this function.
     */
    function setWithdrawalLimits(uint256 _maxWithdrawAmount, uint256 _minWithdrawAmount) external onlyOwner {
        require(_maxWithdrawAmount > _minWithdrawAmount, "Invalid withdrawal limits");
        maxWithdrawAmount = _maxWithdrawAmount;
        minWithdrawAmount = _minWithdrawAmount;
    }

    /**
     * @dev Allows users to create a withdrawal request.
     * Transfers collateral from the caller to the treasury and mints an ERC721 token.
     */
    function createWithdrawRequest(
        uint256 amount
    ) external {
        require(amount >= minWithdrawAmount, "Amount below minimum limit");
        require(amount <= maxWithdrawAmount, "Amount exceeds maximum limit");

        // Transfer the collateral from the user to the treasury
        require(collateral.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        // Increment the token ID counter
        _requestIds.increment();
        uint256 requestId = _requestIds.current();

        // Store the withdrawal amount associated with the token ID
        withdrawalRequests[requestId] = amount;

        // Mint an ERC721 token representing the withdrawal request
        _mint(msg.sender, requestId);

        emit WithdrawalRequestCreated(msg.sender, requestId, amount);
    }

    /**
     * @dev Finalizes a withdrawal request and burns the corresponding token.
     * Transfers the collateral back to the token owner.
     */
    function finalizeWithdrawal(
        uint256 requestId
    ) external onlyOwner {
        require(!finalizedWithdrawals[requestId], "Already finalized");

        address requester = ownerOf(requestId);
        uint256 amount = withdrawalRequests[requestId];
        require(amount > 0, "Invalid withdrawal request");

        // Mark the withdrawal as finalized
        finalizedWithdrawals[requestId] = true;

        // Burn the ERC721 token representing the request
        _burn(requestId);

        // Transfer the collateral back to the requester
        require(collateral.transfer(requester, amount), "Transfer failed");

        emit WithdrawalFinalized(requester, requestId, amount);
    }

    /**
     * @dev Batch process withdrawals up to a specified token ID.
     * Only callable by the contract owner.
     */
    function processWithdrawals(
        uint256 _lastrequestIdToProcess
    ) external onlyOwner {
        for (uint256 requestId = 1; requestId <= _lastrequestIdToProcess; requestId++) {
            if (_exits(requestId) && !finalizedWithdrawals[requestId]) {
                address requester = ownerOf(requestId);
                uint256 amount = withdrawalRequests[requestId];

                // Finalize the withdrawal
                finalizedWithdrawals[requestId] = true;
                _burn(requestId);
                require(collateral.transfer(requester, amount), "Transfer failed");

                emit WithdrawalFinalized(requester, requestId, amount);
            }
        }
    }

    function withdrawRequestMaximum() external view returns (uint256) {
        return maxWithdrawAmount;
    }

    function withdrawRequestMinimum() external view returns (uint256) {
        return minWithdrawAmount;
    }

    function _exits(
        uint256 requestId
    ) internal view returns (bool) {
        return ownerOf(requestId) != address(0);
    }
}
