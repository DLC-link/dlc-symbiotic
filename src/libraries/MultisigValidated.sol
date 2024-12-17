// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";

contract MultisigValidated is Ownable, AccessControl {
    bytes32 public constant APPROVED_SIGNER = keccak256("APPROVED_SIGNER");

    uint16 private _minimumThreshold;
    uint16 private _threshold;
    uint16 private _signerCount;

    // Track seen signers to prevent duplicate signatures
    mapping(address => mapping(bytes32 => bool)) private _seenSigners;

    error NotEnoughSignatures();
    error InvalidSigner();
    error DuplicateSignature();
    error DuplicateSigner(address signer);
    error SignerNotApproved(address signer);
    error ThresholdTooLow(uint16 _minimumThreshold);
    error ThresholdMinimumReached(uint16 _minimumThreshold);

    event SetThreshold(uint16 newThreshold);

    constructor(address initialOwner, uint16 minimumThreshold, uint16 threshold) Ownable(initialOwner) {
        _grantRole(DEFAULT_ADMIN_ROLE, initialOwner);

        require(minimumThreshold > 0, "Minimum threshold must be greater than 0");
        require(threshold >= minimumThreshold, "Threshold must be >= minimum threshold");

        _minimumThreshold = minimumThreshold;
        _threshold = threshold;
        _signerCount = 0;
    }

    modifier onlyMultisig(bytes memory message, bytes[] memory signatures) {
        _validateSignatures(message, signatures);
        _;
    }

    function _validateSignatures(bytes memory message, bytes[] memory signatures) internal {
        if (signatures.length < _threshold) revert NotEnoughSignatures();

        bytes32 prefixedMessageHash = MessageHashUtils.toEthSignedMessageHash(keccak256(message));

        for (uint256 i = 0; i < signatures.length; i++) {
            address signerPubkey = ECDSA.recover(prefixedMessageHash, signatures[i]);
            if (!hasRole(APPROVED_SIGNER, signerPubkey)) {
                revert InvalidSigner();
            }
            _checkSignerUnique(signerPubkey, prefixedMessageHash);
        }
    }

    function _checkSignerUnique(address signerPubkey, bytes32 messageHash) internal {
        if (_seenSigners[signerPubkey][messageHash]) {
            revert DuplicateSigner(signerPubkey);
        }
        _seenSigners[signerPubkey][messageHash] = true;
    }

    function setThreshold(
        uint16 newThreshold
    ) external onlyOwner {
        if (newThreshold < _minimumThreshold) {
            revert ThresholdTooLow(_minimumThreshold);
        }
        _threshold = newThreshold;
        emit SetThreshold(newThreshold);
    }

    function getThreshold() external view returns (uint16) {
        return _threshold;
    }

    function getMinimumThreshold() external view returns (uint16) {
        return _minimumThreshold;
    }

    function getSignerCount() external view returns (uint16) {
        return _signerCount;
    }

    // Role management overrides
    function grantRole(bytes32 role, address account) public override {
        super.grantRole(role, account);
        if (role == APPROVED_SIGNER) _signerCount++;
    }

    function revokeRole(bytes32 role, address account) public override {
        super.revokeRole(role, account);
        if (role == APPROVED_SIGNER) {
            if (_signerCount == _minimumThreshold) {
                revert ThresholdMinimumReached(_minimumThreshold);
            }
            _signerCount--;
        }
    }
}
