// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

import {Ownable, Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {StaffRole} from "./HealthTypes.sol";

/// @title HospitalRegistry
/// @notice Trust anchor of the platform. The platform owner whitelists hospitals; each hospital
///         admin then registers and deactivates its own staff. Stores no patient data.
/// @dev A hospital is identified by its admin wallet address. A staff address belongs to exactly
///      one hospital for its whole lifetime, and an address is never both a hospital and a staff
///      member (separation of duties).
contract HospitalRegistry is Ownable2Step {
    struct Hospital {
        string name;
        /// X25519 public key the record keys are sealed to (MVP: one keypair per hospital).
        bytes32 encryptionPublicKey;
        /// 0 means the address was never whitelisted.
        uint64 whitelistedAt;
        bool active;
    }

    struct Staff {
        /// Hospital that registered this staff member; address(0) means unregistered.
        address hospital;
        StaffRole role;
        bool active;
    }

    mapping(address hospital => Hospital) private _hospitals;
    mapping(address staff => Staff) private _staff;

    /// @notice Emitted when the platform owner whitelists a hospital.
    event HospitalWhitelisted(address indexed hospital, string name, bytes32 encryptionPublicKey);
    /// @notice Emitted when the platform owner removes a hospital from the whitelist.
    event HospitalDeactivated(address indexed hospital);
    /// @notice Emitted when a hospital admin registers a staff member.
    event StaffRegistered(address indexed hospital, address indexed staff, StaffRole role);
    /// @notice Emitted when a hospital admin deactivates one of its staff members.
    event StaffDeactivated(address indexed hospital, address indexed staff);

    error ZeroAddress();
    error InvalidPublicKey();
    error InvalidRole();
    error HospitalAlreadyRegistered(address hospital);
    error HospitalNotActive(address hospital);
    error StaffAlreadyRegistered(address staff);
    error StaffNotActive(address staff);
    error NotStaffOfCaller(address staff);
    error AddressIsHospital(address account);
    error AddressIsStaff(address account);
    error RenounceOwnershipDisabled();

    /// @dev Restricts a function to a currently whitelisted hospital admin.
    modifier onlyActiveHospital() {
        if (!_hospitals[msg.sender].active) revert HospitalNotActive(msg.sender);
        _;
    }

    /// @param initialOwner Platform owner allowed to manage the hospital whitelist.
    constructor(address initialOwner) Ownable(initialOwner) {}

    // ---------------------------------------------------------------- platform owner

    /// @notice Whitelists a hospital. Its admin wallet can then register staff.
    /// @param hospital Admin wallet that identifies the hospital.
    /// @param name Human-readable hospital name (public information, not patient data).
    /// @param encryptionPublicKey X25519 public key the hospital receives record keys on.
    function whitelistHospital(address hospital, string calldata name, bytes32 encryptionPublicKey)
        external
        onlyOwner
    {
        if (hospital == address(0)) revert ZeroAddress();
        if (encryptionPublicKey == bytes32(0)) revert InvalidPublicKey();
        if (_hospitals[hospital].whitelistedAt != 0) revert HospitalAlreadyRegistered(hospital);
        if (_staff[hospital].hospital != address(0)) revert AddressIsStaff(hospital);

        _hospitals[hospital] = Hospital({
            name: name,
            encryptionPublicKey: encryptionPublicKey,
            whitelistedAt: uint64(block.timestamp),
            active: true
        });
        emit HospitalWhitelisted(hospital, name, encryptionPublicKey);
    }

    /// @notice Removes a hospital from the whitelist. Its staff lose all access at once,
    ///         because every authorization check requires an active hospital.
    function deactivateHospital(address hospital) external onlyOwner {
        Hospital storage h = _hospitals[hospital];
        if (!h.active) revert HospitalNotActive(hospital);

        h.active = false;
        emit HospitalDeactivated(hospital);
    }

    /// @notice Disabled: without an owner no hospital could ever be whitelisted or removed again.
    function renounceOwnership() public view override onlyOwner {
        revert RenounceOwnershipDisabled();
    }

    // ---------------------------------------------------------------- hospital admin

    /// @notice Registers a staff member in the caller's hospital.
    /// @param staff Wallet of the staff member.
    /// @param role Professional role (must not be NONE).
    function registerStaff(address staff, StaffRole role) external onlyActiveHospital {
        if (staff == address(0)) revert ZeroAddress();
        if (role == StaffRole.NONE) revert InvalidRole();
        if (_staff[staff].hospital != address(0)) revert StaffAlreadyRegistered(staff);
        if (_hospitals[staff].whitelistedAt != 0) revert AddressIsHospital(staff);

        _staff[staff] = Staff({hospital: msg.sender, role: role, active: true});
        emit StaffRegistered(msg.sender, staff, role);
    }

    /// @notice Deactivates a staff member of the caller's hospital. Deactivation is final.
    /// @dev Allowed even if the hospital itself was deactivated: removing access is always safe.
    function deactivateStaff(address staff) external {
        Staff storage s = _staff[staff];
        if (s.hospital != msg.sender) revert NotStaffOfCaller(staff);
        if (!s.active) revert StaffNotActive(staff);

        s.active = false;
        emit StaffDeactivated(msg.sender, staff);
    }

    // ---------------------------------------------------------------- views

    /// @notice True if `hospital` is currently whitelisted.
    function isActiveHospital(address hospital) external view returns (bool) {
        return _hospitals[hospital].active;
    }

    /// @notice Returns the hospital of `staff` if the staff member AND their hospital are both
    ///         active, otherwise address(0). This is the single staff check used by other contracts.
    function activeStaffHospital(address staff) external view returns (address) {
        Staff storage s = _staff[staff];
        if (!s.active || !_hospitals[s.hospital].active) return address(0);
        return s.hospital;
    }

    /// @notice True if `account` was ever registered as a hospital or a staff member.
    function isRegistered(address account) external view returns (bool) {
        return _hospitals[account].whitelistedAt != 0 || _staff[account].hospital != address(0);
    }

    /// @notice Full hospital record.
    function getHospital(address hospital) external view returns (Hospital memory) {
        return _hospitals[hospital];
    }

    /// @notice Full staff record.
    function getStaff(address staff) external view returns (Staff memory) {
        return _staff[staff];
    }
}
