// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @notice The four kinds of medical records the platform tracks.
/// @dev The numeric value of each type is its bit position in a consent scope:
///      VISIT_NOTE = bit 0 (1), LAB_RESULT = bit 1 (2), PRESCRIPTION = bit 2 (4), IMAGING = bit 3 (8).
enum RecordType {
    VISIT_NOTE,
    LAB_RESULT,
    PRESCRIPTION,
    IMAGING
}

/// @notice Professional role of a hospital staff member. NONE marks an unregistered address.
enum StaffRole {
    NONE,
    DOCTOR,
    LAB,
    RADIOLOGIST,
    PHARMACIST
}

// Scope bitmask covering every record type (0b1111).
uint8 constant FULL_SCOPE = 0x0F;

/// @notice Returns the scope bit that represents `recordType`.
function scopeBit(RecordType recordType) pure returns (uint8) {
    return uint8(1 << uint8(recordType));
}
