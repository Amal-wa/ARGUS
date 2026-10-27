// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {HospitalRegistry} from "./HospitalRegistry.sol";
import {PatientRegistry} from "./PatientRegistry.sol";
import {FULL_SCOPE, RecordType, scopeBit} from "./HealthTypes.sol";

/// @title ConsentManager
/// @notice Patients approve hospitals for a scope of record types until an expiry date, and can
///         revoke at any time. `isAuthorized` is the single access rule the rest of the system uses.
/// @dev Consent is granted at hospital level: the patient trusts an institution, and the
///      institution manages its own staff through HospitalRegistry.
contract ConsentManager {
    struct Consent {
        /// Bitmask over RecordType (see HealthTypes.scopeBit).
        uint8 scope;
        /// 0 means no consent was ever granted.
        uint64 grantedAt;
        /// Consent is valid while block.timestamp < expiry.
        uint64 expiry;
        /// 0 means not revoked.
        uint64 revokedAt;
    }

    HospitalRegistry public immutable hospitalRegistry;
    PatientRegistry public immutable patientRegistry;

    mapping(address patient => mapping(address hospital => Consent)) private _consents;

    /// @notice Emitted when a patient grants (or renews/replaces) consent for a hospital.
    event ConsentGranted(address indexed patient, address indexed hospital, uint8 scope, uint64 expiry);
    /// @notice Emitted when a patient revokes a hospital's consent.
    event ConsentRevoked(address indexed patient, address indexed hospital);

    error ZeroAddress();
    error NotEnrolledPatient(address caller);
    error HospitalNotActive(address hospital);
    error InvalidScope(uint8 scope);
    error ExpiryNotInFuture(uint64 expiry);
    error NoActiveConsent(address patient, address hospital);

    constructor(HospitalRegistry hospitalRegistry_, PatientRegistry patientRegistry_) {
        if (address(hospitalRegistry_) == address(0) || address(patientRegistry_) == address(0)) {
            revert ZeroAddress();
        }
        hospitalRegistry = hospitalRegistry_;
        patientRegistry = patientRegistry_;
    }

    /// @notice Approves `hospital` for the record types in `scope` until `expiry`.
    /// @dev Replaces any previous consent for that hospital, including a revoked one.
    /// @param hospital Whitelisted hospital to approve.
    /// @param scope Non-zero bitmask over RecordType, at most FULL_SCOPE.
    /// @param expiry Unix timestamp after which the consent no longer applies.
    function approveHospital(address hospital, uint8 scope, uint64 expiry) external {
        if (!patientRegistry.isEnrolled(msg.sender)) revert NotEnrolledPatient(msg.sender);
        if (!hospitalRegistry.isActiveHospital(hospital)) revert HospitalNotActive(hospital);
        if (scope == 0 || scope & ~FULL_SCOPE != 0) revert InvalidScope(scope);
        if (expiry <= block.timestamp) revert ExpiryNotInFuture(expiry);

        _consents[msg.sender][hospital] =
            Consent({scope: scope, grantedAt: uint64(block.timestamp), expiry: expiry, revokedAt: 0});
        emit ConsentGranted(msg.sender, hospital, scope, expiry);
    }

    /// @notice Revokes the caller's consent for `hospital`. Takes effect from the next block on;
    ///         it cannot un-read data the hospital already decrypted.
    function revokeHospital(address hospital) external {
        Consent storage c = _consents[msg.sender][hospital];
        if (c.grantedAt == 0 || c.revokedAt != 0) revert NoActiveConsent(msg.sender, hospital);

        c.revokedAt = uint64(block.timestamp);
        emit ConsentRevoked(msg.sender, hospital);
    }

    /// @notice The access rule. True only if ALL of the following hold:
    ///         staff is active, their hospital is whitelisted, the patient approved that hospital,
    ///         the scope covers `recordType`, and the consent is neither expired nor revoked.
    /// @dev A consent can only exist for an enrolled patient, so enrollment needs no extra check.
    function isAuthorized(address staff, address patient, RecordType recordType) external view returns (bool) {
        address hospital = hospitalRegistry.activeStaffHospital(staff);
        if (hospital == address(0)) return false;
        return hasValidConsent(patient, hospital, recordType);
    }

    /// @notice True if `patient` currently allows `hospital` to access records of `recordType`.
    function hasValidConsent(address patient, address hospital, RecordType recordType) public view returns (bool) {
        Consent storage c = _consents[patient][hospital];
        return c.grantedAt != 0 && c.revokedAt == 0 && block.timestamp < c.expiry
            && (c.scope & scopeBit(recordType)) != 0;
    }

    /// @notice Raw consent record (for the patient UI and the audit view).
    function getConsent(address patient, address hospital) external view returns (Consent memory) {
        return _consents[patient][hospital];
    }
}
