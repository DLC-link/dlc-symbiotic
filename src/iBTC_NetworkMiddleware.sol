// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

import {IDefaultOperatorRewards} from "rewards/src/interfaces/defaultOperatorRewards/IDefaultOperatorRewards.sol";
import {IDefaultStakerRewards} from "rewards/src/interfaces/defaultStakerRewards/IDefaultStakerRewards.sol";
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {IBaseSlasher} from "@symbiotic/interfaces/slasher/IBaseSlasher.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {ISlasher} from "@symbiotic/interfaces/slasher/ISlasher.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";

import {MultisigValidated} from "./libraries/MultisigValidated.sol";
import {SimpleKeyRegistry32} from "./libraries/SimpleKeyRegistry32.sol";
import {MapWithTimeData} from "./libraries/MapWithTimeData.sol";

contract NetworkMiddleware is SimpleKeyRegistry32, Ownable, MultisigValidated {
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;
    using SafeERC20 for IERC20;
    using Subnetwork for address;

    error ZeroOwner();
    error ZeroNetwork();
    error ZeroOperatorRegistry();
    error ZeroVaultRegistry();
    error ZeroOperatorNetOptin();

    error NotOperator();
    error NotVault();

    error OperatorNotOptedIn();
    error OperatorNotRegistred();
    error OperarorGracePeriodNotPassed();
    error OperatorAlreadyRegistred();
    error OperatorNotEnoughStaked();

    error VaultAlreadyRegistred();
    error VaultEpochTooShort();
    error VaultGracePeriodNotPassed();

    error InvalidSubnetworksCnt();

    error TooOldEpoch();
    error InvalidEpoch();

    error SlashingWindowTooShort();
    error TooBigSlashAmount();
    error UnknownSlasherType();
    error NotVetoSlasher();

    error ZeroTotalStake();
    error ZeroRewardAmount();
    error InsufficientBalance();

    struct ValidatorData {
        uint256 stake;
        bytes32 key;
    }

    struct SlashedInfo {
        uint48 epoch;
        address operator;
        uint256 slashedAmount;
        uint256 timeStamp;
    }

    address public immutable NETWORK;
    address public immutable OPERATOR_REGISTRY;
    address public immutable VAULT_REGISTRY;
    address public immutable OPERATOR_NET_OPTIN;
    address public immutable OPERATOR_VAULT_OPTIN;
    address public immutable OWNER;
    address public immutable STAKER_REWARDS;
    address public immutable OPERATOR_REWARDS;
    address public immutable REWARD_TOKEN;
    uint48 public immutable EPOCH_DURATION;
    uint48 public immutable SLASHING_WINDOW;
    uint48 public immutable START_TIME;

    uint48 private constant INSTANT_SLASHER_TYPE = 0;
    uint48 private constant VETO_SLASHER_TYPE = 1;

    uint256 public slashIndex;
    uint256 public subnetworksCnt;
    mapping(uint256 slashIndex => SlashedInfo) slashedInfos;
    mapping(uint48 => uint256) public totalStakeCache;
    mapping(uint48 => bool) public totalStakeCached;
    mapping(uint48 epoch => mapping(address operator => uint256 amounts)) public operatorStakeCache;
    EnumerableMap.AddressToUintMap private operators;
    EnumerableMap.AddressToUintMap private vaults;

    event StakerRewardsDistributed(uint48 indexed epoch, uint256 rewardAmount, uint256 totalStake, uint256 timestamp);
    event OperatorRewardsDistributed(uint48 indexed epoch, uint256 rewardAmount, uint256 timestamp);

    modifier updateStakeCache(
        uint48 epoch
    ) {
        if (!totalStakeCached[epoch]) {
            calcAndCacheStakes(epoch);
        }
        _;
    }

    constructor(
        address _network,
        address _operatorRegistry,
        address _vaultRegistry,
        address _operatorNetOptin,
        address _owner,
        address _stakerReward,
        address _operatorReward,
        address _rewardToken,
        uint48 _epochDuration,
        uint48 _slashingWindow,
        uint16 _threshold,
        uint16 _minimumThreshold
    ) SimpleKeyRegistry32() MultisigValidated(_owner, _minimumThreshold, _threshold) {
        if (_slashingWindow < _epochDuration) {
            revert SlashingWindowTooShort();
        }

        if (_network == address(0)) {
            revert ZeroNetwork();
        }

        if (_operatorRegistry == address(0)) {
            revert ZeroOperatorRegistry();
        }

        if (_vaultRegistry == address(0)) {
            revert ZeroVaultRegistry();
        }

        if (_operatorNetOptin == address(0)) {
            revert ZeroOperatorNetOptin();
        }

        if (_owner == address(0)) {
            revert ZeroOwner();
        }

        START_TIME = Time.timestamp();
        EPOCH_DURATION = _epochDuration;
        NETWORK = _network;
        OWNER = _owner;
        STAKER_REWARDS = _stakerReward;
        OPERATOR_REWARDS = _operatorReward;
        REWARD_TOKEN = _rewardToken;
        OPERATOR_REGISTRY = _operatorRegistry;
        VAULT_REGISTRY = _vaultRegistry;
        OPERATOR_NET_OPTIN = _operatorNetOptin;
        SLASHING_WINDOW = _slashingWindow;

        subnetworksCnt = 1;
    }

    function getEpochStartTs(
        uint48 epoch
    ) public view returns (uint48 timestamp) {
        return START_TIME + epoch * EPOCH_DURATION;
    }

    function getEpochAtTs(
        uint48 timestamp
    ) public view returns (uint48 epoch) {
        return (timestamp - START_TIME) / EPOCH_DURATION;
    }

    function isOperatorRegistered(
        address operator
    ) public view returns (bool) {
        return operators.contains(operator);
    }

    function getOperatorInfo(
        address operator
    ) public view returns (uint48, uint48) {
        (uint48 enabledTime, uint48 disabledTime) = operators.getTimes(operator);
        return (enabledTime, disabledTime);
    }

    function isVaultRegistered(
        address vault
    ) public view returns (bool) {
        return vaults.contains(vault);
    }

    function getVaultInfo(
        address vault
    ) public view returns (uint48, uint48) {
        (uint48 enabledTime, uint48 disabledTime) = vaults.getTimes(vault);
        return (enabledTime, disabledTime);
    }

    function getCurrentEpoch() public view returns (uint48 epoch) {
        return getEpochAtTs(Time.timestamp());
    }

    function registerOperator(address operator, bytes32 key) external onlyOwner {
        if (operators.contains(operator)) {
            revert OperatorAlreadyRegistred();
        }

        if (!IRegistry(OPERATOR_REGISTRY).isEntity(operator)) {
            revert NotOperator();
        }

        if (!IOptInService(OPERATOR_NET_OPTIN).isOptedIn(operator, NETWORK)) {
            revert OperatorNotOptedIn();
        }

        updateKey(operator, key);
        operators.add(operator);
        operators.enable(operator);
    }

    function updateOperatorKey(address operator, bytes32 key) external onlyOwner {
        if (!operators.contains(operator)) {
            revert OperatorNotRegistred();
        }

        updateKey(operator, key);
    }

    function pauseOperator(
        address operator
    ) external onlyOwner {
        operators.disable(operator);
    }

    function unpauseOperator(
        address operator
    ) external onlyOwner {
        operators.enable(operator);
    }

    function unregisterOperator(
        address operator
    ) external onlyOwner {
        (, uint48 disabledTime) = operators.getTimes(operator);

        if (disabledTime == 0 || disabledTime + SLASHING_WINDOW > Time.timestamp()) {
            revert OperarorGracePeriodNotPassed();
        }

        operators.remove(operator);
    }

    function registerVault(
        address vault
    ) external onlyOwner {
        if (vaults.contains(vault)) {
            revert VaultAlreadyRegistred();
        }

        if (!IRegistry(VAULT_REGISTRY).isEntity(vault)) {
            revert NotVault();
        }

        uint48 vaultEpoch = IVault(vault).epochDuration();

        address slasher = IVault(vault).slasher();
        if (slasher != address(0) && IEntity(slasher).TYPE() == VETO_SLASHER_TYPE) {
            vaultEpoch -= IVetoSlasher(slasher).vetoDuration();
        }

        if (vaultEpoch < SLASHING_WINDOW) {
            revert VaultEpochTooShort();
        }

        vaults.add(vault);
        vaults.enable(vault);
    }

    function pauseVault(
        address vault
    ) external onlyOwner {
        vaults.disable(vault);
    }

    function unpauseVault(
        address vault
    ) external onlyOwner {
        vaults.enable(vault);
    }

    function unregisterVault(
        address vault
    ) external onlyOwner {
        (, uint48 disabledTime) = vaults.getTimes(vault);

        if (disabledTime == 0 || disabledTime + SLASHING_WINDOW > Time.timestamp()) {
            revert VaultGracePeriodNotPassed();
        }

        vaults.remove(vault);
    }

    function setSubnetworksCnt(
        uint256 _subnetworksCnt
    ) external onlyOwner {
        if (subnetworksCnt >= _subnetworksCnt) {
            revert InvalidSubnetworksCnt();
        }

        subnetworksCnt = _subnetworksCnt;
    }

    function getOperatorStake(address operator, uint48 epoch) public view returns (uint256 stake) {
        if (totalStakeCached[epoch]) {
            return operatorStakeCache[epoch][operator];
        }

        uint48 epochStartTs = getEpochStartTs(epoch);

        for (uint256 i; i < vaults.length(); ++i) {
            (address vault, uint48 enabledTime, uint48 disabledTime) = vaults.atWithTimes(i);

            // just skip the vault if it was enabled after the target epoch or not enabled
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            for (uint96 j = 0; j < subnetworksCnt; ++j) {
                stake += IBaseDelegator(IVault(vault).delegator()).stakeAt(
                    NETWORK.subnetwork(j), operator, epochStartTs, new bytes(0)
                );
            }
        }

        return stake;
    }

    function getTotalStake(
        uint48 epoch
    ) public view returns (uint256) {
        if (totalStakeCached[epoch]) {
            return totalStakeCache[epoch];
        }
        return _calcTotalStake(epoch);
    }

    function getValidatorSet(
        uint48 epoch
    ) public view returns (ValidatorData[] memory validatorsData) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        validatorsData = new ValidatorData[](operators.length());
        uint256 valIdx = 0;

        for (uint256 i; i < operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            bytes32 key = getOperatorKeyAt(operator, epochStartTs);
            if (key == bytes32(0)) {
                continue;
            }

            uint256 stake = getOperatorStake(operator, epoch);

            validatorsData[valIdx++] = ValidatorData(stake, key);
        }

        // shrink array to skip unused slots
        /// @solidity memory-safe-assembly
        assembly {
            mstore(validatorsData, valIdx)
        }
    }

    function slash(
        uint48 epoch,
        address operator,
        uint256 amount,
        bytes[] calldata signatures
    ) public onlyMultisig(abi.encode(slashIndex, epoch, operator, amount), signatures) updateStakeCache(epoch) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        if (epochStartTs < Time.timestamp() - SLASHING_WINDOW) {
            revert TooOldEpoch();
        }

        uint256 totalOperatorStake = getOperatorStake(operator, epoch);

        if (totalOperatorStake < amount) {
            revert TooBigSlashAmount();
        }

        // simple pro-rata slasher
        for (uint256 i; i < vaults.length(); ++i) {
            (address vault, uint48 enabledTime, uint48 disabledTime) = vaults.atWithTimes(i);

            // just skip the vault if it was enabled after the target epoch or not enabled
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }
            for (uint96 j = 0; j < subnetworksCnt; ++j) {
                bytes32 subnetwork = NETWORK.subnetwork(j);
                uint256 vaultStake =
                    IBaseDelegator(IVault(vault).delegator()).stakeAt(subnetwork, operator, epochStartTs, new bytes(0));
                _slashVault(epochStartTs, vault, subnetwork, operator, (amount * vaultStake) / totalOperatorStake);
                slashedInfos[slashIndex++] =
                    SlashedInfo({epoch: epoch, operator: operator, slashedAmount: amount, timeStamp: block.timestamp});
            }
        }
    }

    function executeSlash(
        uint256 slashIndex_,
        address vault,
        bytes calldata hints
    ) public onlyOwner updateStakeCache(getCurrentEpoch()) {
        address slasher = IVault(vault).slasher();
        uint256 slasherType = IEntity(slasher).TYPE();
        if (slasherType != VETO_SLASHER_TYPE) {
            revert NotVetoSlasher();
        }
        IVetoSlasher(slasher).executeSlash(slashIndex_, hints);
    }

    function calcAndCacheStakes(
        uint48 epoch
    ) public returns (uint256 totalStake) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        // for epoch older than SLASHING_WINDOW total stake can be invalidated (use cache)
        if (epochStartTs < Time.timestamp() - SLASHING_WINDOW) {
            revert TooOldEpoch();
        }

        if (epochStartTs > Time.timestamp()) {
            revert InvalidEpoch();
        }

        for (uint256 i; i < operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            uint256 operatorStake = getOperatorStake(operator, epoch);
            operatorStakeCache[epoch][operator] = operatorStake;

            totalStake += operatorStake;
        }

        totalStakeCached[epoch] = true;
        totalStakeCache[epoch] = totalStake;
    }

    function distributeStakerRewards(
        uint256 distributeAmount,
        uint48 timestamp,
        uint256 maxAdminFee,
        bytes calldata activeSharesHint,
        bytes calldata activeStakeHint
    ) public onlyOwner updateStakeCache(getCurrentEpoch()) {
        uint48 epoch = getEpochAtTs(timestamp);
        uint256 totalStake = getTotalStake(epoch);
        //TODO: Calculate the cumulative reward amount

        if (totalStake == 0) {
            revert ZeroTotalStake();
        }

        if (distributeAmount == 0) {
            revert ZeroRewardAmount();
        }

        if (IERC20(REWARD_TOKEN).balanceOf(address(this)) < distributeAmount) {
            revert InsufficientBalance();
        }

        IERC20(REWARD_TOKEN).approve(STAKER_REWARDS, distributeAmount);
        bytes memory distributionData = abi.encode(timestamp, maxAdminFee, activeSharesHint, activeStakeHint);

        IDefaultStakerRewards(STAKER_REWARDS).distributeRewards(
            NETWORK, REWARD_TOKEN, distributeAmount, distributionData
        );

        emit StakerRewardsDistributed(epoch, distributeAmount, totalStake, block.timestamp);
    }

    function distributeOperatorRewards(
        uint256 distributeAmount,
        bytes32 merkleRoot
    ) public onlyOwner updateStakeCache(getCurrentEpoch()) {

        //TODO: Calculate the cumulative reward amount
        if (distributeAmount == 0) {
            revert ZeroRewardAmount();
        }
        if (IERC20(REWARD_TOKEN).balanceOf(address(this)) < distributeAmount) {
            revert InsufficientBalance();
        }
        IERC20(REWARD_TOKEN).approve(OPERATOR_REWARDS, distributeAmount);
        IDefaultOperatorRewards(OPERATOR_REWARDS).distributeRewards(NETWORK, REWARD_TOKEN, distributeAmount, merkleRoot);

        emit OperatorRewardsDistributed(getCurrentEpoch(), distributeAmount, block.timestamp);
    }

    function _calcTotalStake(
        uint48 epoch
    ) private view returns (uint256 totalStake) {
        uint48 epochStartTs = getEpochStartTs(epoch);

        // for epoch older than SLASHING_WINDOW total stake can be invalidated (use cache)
        if (epochStartTs < Time.timestamp() - SLASHING_WINDOW) {
            revert TooOldEpoch();
        }

        if (epochStartTs > Time.timestamp()) {
            revert InvalidEpoch();
        }

        for (uint256 i; i < operators.length(); ++i) {
            (address operator, uint48 enabledTime, uint48 disabledTime) = operators.atWithTimes(i);

            // just skip operator if it was added after the target epoch or paused
            if (!_wasActiveAt(enabledTime, disabledTime, epochStartTs)) {
                continue;
            }

            uint256 operatorStake = getOperatorStake(operator, epoch);
            totalStake += operatorStake;
        }
    }

    function _wasActiveAt(uint48 enabledTime, uint48 disabledTime, uint48 timestamp) private pure returns (bool) {
        return enabledTime != 0 && enabledTime <= timestamp && (disabledTime == 0 || disabledTime >= timestamp);
    }

    function _slashVault(
        uint48 timestamp,
        address vault,
        bytes32 subnetwork,
        address operator,
        uint256 amount
    ) private {
        address slasher = IVault(vault).slasher();
        uint256 slasherType = IEntity(slasher).TYPE();
        if (slasherType == INSTANT_SLASHER_TYPE) {
            ISlasher(slasher).slash(subnetwork, operator, amount, timestamp, new bytes(0));
        } else if (slasherType == VETO_SLASHER_TYPE) {
            IVetoSlasher(slasher).requestSlash(subnetwork, operator, amount, timestamp, new bytes(0));
        } else {
            revert UnknownSlasherType();
        }
    }
}
