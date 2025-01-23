// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {EnumerableMap} from "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";
import {MultisigValidated} from "./libraries/MultisigValidated.sol";
import {SimpleKeyRegistry32} from "./libraries/SimpleKeyRegistry32.sol";
import {MapWithTimeData} from "./libraries/MapWithTimeData.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

import {IDefaultOperatorRewards} from "rewards/src/interfaces/defaultOperatorRewards/IDefaultOperatorRewards.sol";
import {IDefaultStakerRewards} from "rewards/src/interfaces/defaultStakerRewards/IDefaultStakerRewards.sol";
import {IRegistry} from "@symbiotic/interfaces/common/IRegistry.sol";
import {IEntity} from "@symbiotic/interfaces/common/IEntity.sol";
import {IVault} from "@symbiotic/interfaces/vault/IVault.sol";
import {IBaseDelegator} from "@symbiotic/interfaces/delegator/IBaseDelegator.sol";
import {IOptInService} from "@symbiotic/interfaces/service/IOptInService.sol";
import {IVetoSlasher} from "@symbiotic/interfaces/slasher/IVetoSlasher.sol";
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Subnetwork} from "@symbiotic/contracts/libraries/Subnetwork.sol";

contract NetworkMiddleware is Initializable, SimpleKeyRegistry32, OwnableUpgradeable, MultisigValidated {
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using MapWithTimeData for EnumerableMap.AddressToUintMap;
    using SafeERC20 for IERC20;
    using Subnetwork for address;

    ////////////////////////////////////////////////////////////////
    //                           ERRORS                           //
    ////////////////////////////////////////////////////////////////
    error ZeroOwner();
    error ZeroNetwork();
    error ZeroOperatorRegistry();
    error ZeroVaultRegistry();
    error ZeroEpochDuration();
    error ZeroSlashingWindow();
    error ZeroOperatorNetOptin();

    error NotOperator();
    error NotVault();

    error OperatorNotOptedIn();
    error OperatorNotRegistred();
    error OperarorGracePeriodNotPassed();
    error OperatorAlreadyRegistred();

    error VaultAlreadyRegistred();
    error VaultEpochTooShort();
    error VaultGracePeriodNotPassed();

    error InvalidSubnetworksCnt();

    error TooOldEpoch();
    error InvalidEpoch();

    error StakerRewardNotSet();
    error OperatorRewardNotSet();

    error SlashingWindowTooShort();

    error ZeroTotalStake();
    error ZeroRewardAmount();
    error InsufficientBalance();

    ////////////////////////////////////////////////////////////////
    //                      STATE VARIABLES                       //
    ////////////////////////////////////////////////////////////////
    struct ValidatorData {
        uint256 stake;
        bytes32 key;
    }

    address public NETWORK;
    address public OPERATOR_REGISTRY;
    address public VAULT_REGISTRY;
    address public OPERATOR_NET_OPTIN;
    address public OWNER;
    address public STAKER_REWARDS;
    address public OPERATOR_REWARDS;
    address public REWARD_TOKEN;
    uint48 public EPOCH_DURATION;
    uint48 public SLASHING_WINDOW;
    uint48 public START_TIME;
    bytes32 public constant REWARD_DISTRIBUTION_ROLE =
        0x9f89a45310bee56665a077229020c3130eedbd18bff771c3dc399fb850b2e12f; // keccak256("REWARD_DISTRIBUTION_ROLE");

    uint48 private constant VETO_SLASHER_TYPE = 1;

    uint256 public subnetworksCnt;
    mapping(uint48 => uint256) public totalStakeCache;
    mapping(uint48 => bool) public totalStakeCached;
    mapping(uint48 epoch => mapping(address operator => uint256 amounts)) public operatorStakeCache;
    EnumerableMap.AddressToUintMap private operators;
    EnumerableMap.AddressToUintMap private vaults;

    uint256[50] __gap;

    ////////////////////////////////////////////////////////////////
    //                          EVENTS                            //
    ////////////////////////////////////////////////////////////////
    event OperatorRegistered(address indexed operator, bytes32 key, uint256 timestamp);
    event OperatorKeyUpdated(address indexed operator, bytes32 key, uint256 timestamp);
    event OperatorPaused(address indexed operator, uint256 timestamp);
    event OperatorUnpaused(address indexed operator, uint256 timestamp);
    event OperatorUnregistered(address indexed operator, uint256 timestamp);
    event VaultRegistered(address indexed vault, uint256 timestamp);
    event VaultPaused(address indexed vault, uint256 timestamp);
    event VaultUnpaused(address indexed vault, uint256 timestamp);
    event VaultUnregistered(address indexed vault, uint256 timestamp);
    event SubnetworksCntSet(uint256 subnetworksCnt, uint256 timestamp);
    event RewardTokenSet(address rewardToken, uint256 timestamp);
    event StakerRewardsSet(address stakerRewards, uint256 timestamp);
    event OperatorRewardsSet(address operatorRewards, uint256 timestamp);
    event StakerRewardsDistributed(uint48 indexed epoch, uint256 rewardAmount, uint256 totalStake, uint256 timestamp);
    event OperatorRewardsDistributed(uint48 indexed epoch, uint256 rewardAmount, uint256 timestamp);

    ////////////////////////////////////////////////////////////////
    //                        MODIFIERS                           //
    ////////////////////////////////////////////////////////////////

    modifier updateStakeCache(
        uint48 epoch
    ) {
        if (!totalStakeCached[epoch]) {
            calcAndCacheStakes(epoch);
        }
        _;
    }

    ////////////////////////////////////////////////////////////////
    //                          SETUP                             //
    ////////////////////////////////////////////////////////////////
    constructor() {
        _disableInitializers();
    }

    function initialize(
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
    ) public initializer {
        __Ownable_init(_owner);
        MultisigValidated.initialize(_owner, _minimumThreshold, _threshold);

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

        if (_slashingWindow < _epochDuration) {
            revert SlashingWindowTooShort();
        }
        if (_epochDuration == 0) {
            revert ZeroEpochDuration();
        }
        if (_slashingWindow == 0) {
            revert ZeroSlashingWindow();
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

    ////////////////////////////////////////////////////////////////
    //                        GETTERS                             //
    ////////////////////////////////////////////////////////////////
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

    ////////////////////////////////////////////////////////////////
    //                        ADMINISTRATION                      //
    ////////////////////////////////////////////////////////////////
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
        emit OperatorRegistered(operator, key, Time.timestamp());
    }

    function updateOperatorKey(address operator, bytes32 key) external onlyOwner {
        if (!operators.contains(operator)) {
            revert OperatorNotRegistred();
        }

        updateKey(operator, key);
        emit OperatorKeyUpdated(operator, key, Time.timestamp());
    }

    function pauseOperator(
        address operator
    ) external onlyOwner {
        operators.disable(operator);
        emit OperatorPaused(operator, Time.timestamp());
    }

    function unpauseOperator(
        address operator
    ) external onlyOwner {
        operators.enable(operator);
        emit OperatorUnpaused(operator, Time.timestamp());
    }

    function unregisterOperator(
        address operator
    ) external onlyOwner {
        (, uint48 disabledTime) = operators.getTimes(operator);

        if (disabledTime == 0 || disabledTime + SLASHING_WINDOW > Time.timestamp()) {
            revert OperarorGracePeriodNotPassed();
        }

        operators.remove(operator);
        emit OperatorUnregistered(operator, Time.timestamp());
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
        emit VaultRegistered(vault, Time.timestamp());
    }

    function pauseVault(
        address vault
    ) external onlyOwner {
        vaults.disable(vault);
        emit VaultPaused(vault, Time.timestamp());
    }

    function unpauseVault(
        address vault
    ) external onlyOwner {
        vaults.enable(vault);
        emit VaultUnpaused(vault, Time.timestamp());
    }

    function unregisterVault(
        address vault
    ) external onlyOwner {
        (, uint48 disabledTime) = vaults.getTimes(vault);

        if (disabledTime == 0 || disabledTime + SLASHING_WINDOW > Time.timestamp()) {
            revert VaultGracePeriodNotPassed();
        }

        vaults.remove(vault);
        emit VaultUnregistered(vault, Time.timestamp());
    }

    function setSubnetworksCnt(
        uint256 _subnetworksCnt
    ) external onlyOwner {
        if (subnetworksCnt >= _subnetworksCnt) {
            revert InvalidSubnetworksCnt();
        }

        subnetworksCnt = _subnetworksCnt;
        emit SubnetworksCntSet(_subnetworksCnt, Time.timestamp());
    }

    function setRewardToken(
        address _rewardToken
    ) external onlyOwner {
        REWARD_TOKEN = _rewardToken;
        emit RewardTokenSet(_rewardToken, Time.timestamp());
    }

    function setStakerRewards(
        address _stakerRewards
    ) external onlyOwner {
        STAKER_REWARDS = _stakerRewards;
        emit StakerRewardsSet(_stakerRewards, Time.timestamp());
    }

    function setOperatorRewards(
        address _operatorRewards
    ) external onlyOwner {
        OPERATOR_REWARDS = _operatorRewards;
        emit OperatorRewardsSet(_operatorRewards, Time.timestamp());
    }

    ////////////////////////////////////////////////////////////////
    //                     STAKE AND OPS                          //
    ////////////////////////////////////////////////////////////////
    function getOperatorStake(address operator, uint48 epoch) public view returns (uint256 stake) {
        if (!operators.contains(operator)) {
            revert OperatorNotRegistred();
        }

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
    ) public onlyRole(REWARD_DISTRIBUTION_ROLE) updateStakeCache(getCurrentEpoch()) {
        if (STAKER_REWARDS == address(0)) {
            revert StakerRewardNotSet();
        }

        uint48 epoch = getEpochAtTs(timestamp);
        uint256 totalStake = getTotalStake(epoch);

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
    ) public onlyRole(REWARD_DISTRIBUTION_ROLE) updateStakeCache(getCurrentEpoch()) {
        if (OPERATOR_REWARDS == address(0)) {
            revert OperatorRewardNotSet();
        }
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
}
