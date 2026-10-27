// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {HospitalRegistry} from "./HospitalRegistry.sol";

/// @title PatientRegistry
/// @notice Enrolls patients and stores their encryption public key.
/// @dev Trust assumption: the enrolling staff member has checked the patient's identity in
///      person. That check happens off-chain; on-chain we only record who vouched for the patient.
///      The patient's wallet is their stable identity; the encryption key is what recovery
///      (added in phase 3) will rotate.
contract PatientRegistry {
    struct Patient {
        /// X25519 public key the patient's record keys are sealed to.
        bytes32 encryptionPublicKey;
        /// Staff member who performed the in-person ID check.
        address enrolledBy;
        /// Hospital of that staff member at enrollment time.
        address hospital;
        /// 0 means not enrolled.
        uint64 enrolledAt;
    }

    HospitalRegistry public immutable hospitalRegistry;

    mapping(address patient => Patient) private _patients;

    /// @notice Emitted when a staff member enrolls a patient.
    event PatientEnrolled(
        address indexed patient, address indexed hospital, address indexed staff, bytes32 encryptionPublicKey
    );

    error ZeroAddress();
    error InvalidPublicKey();
    error NotActiveStaff(address caller);
    error AddressIsStaffOrHospital(address account);
    error PatientAlreadyEnrolled(address patient);

    constructor(HospitalRegistry hospitalRegistry_) {
        if (address(hospitalRegistry_) == address(0)) revert ZeroAddress();
        hospitalRegistry = hospitalRegistry_;
    }

    /// @notice Enrolls a patient after an off-chain, in-person identity check.
    /// @dev Callable by any active staff member of an active hospital. Staff and hospital
    ///      addresses cannot be enrolled, which also rules out self-enrollment.
    /// @param patient Patient wallet (their pseudonymous on-chain identity).
    /// @param publicKey X25519 public key generated on the patient's device.
    function enrollPatient(address patient, bytes32 publicKey) external {
        address hospital = hospitalRegistry.activeStaffHospital(msg.sender);
        if (hospital == address(0)) revert NotActiveStaff(msg.sender);
        if (patient == address(0)) revert ZeroAddress();
        if (publicKey == bytes32(0)) revert InvalidPublicKey();
        if (hospitalRegistry.isRegistered(patient)) revert AddressIsStaffOrHospital(patient);
        if (_patients[patient].enrolledAt != 0) revert PatientAlreadyEnrolled(patient);

        _patients[patient] = Patient({
            encryptionPublicKey: publicKey,
            enrolledBy: msg.sender,
            hospital: hospital,
            enrolledAt: uint64(block.timestamp)
        });
        emit PatientEnrolled(patient, hospital, msg.sender, publicKey);
    }

    /// @notice True if `patient` is enrolled.
    function isEnrolled(address patient) external view returns (bool) {
        return _patients[patient].enrolledAt != 0;
    }

    /// @notice Current encryption public key of `patient` (zero if not enrolled).
    function encryptionPublicKey(address patient) external view returns (bytes32) {
        return _patients[patient].encryptionPublicKey;
    }

    /// @notice Full patient record (no health data: key, enrolling staff, hospital, timestamp).
    function getPatient(address patient) external view returns (Patient memory) {
        return _patients[patient];
    }
}
