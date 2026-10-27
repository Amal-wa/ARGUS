import type { HardhatEthers } from "@nomicfoundation/hardhat-ethers/types";
import { id } from "ethers";

// Mirrors of the Solidity enums in contracts/HealthTypes.sol.
export const RecordType = { VISIT_NOTE: 0, LAB_RESULT: 1, PRESCRIPTION: 2, IMAGING: 3 } as const;
export const StaffRole = { NONE: 0, DOCTOR: 1, LAB: 2, RADIOLOGIST: 3, PHARMACIST: 4 } as const;

// Scope bits: 1 << RecordType.
export const Scope = { VISIT_NOTE: 1, LAB_RESULT: 2, PRESCRIPTION: 4, IMAGING: 8, ALL: 0x0f } as const;

export const ONE_DAY = 24 * 60 * 60;

/** Deterministic stand-in for an X25519 public key (32 bytes). Real keys come from libsodium. */
export function fakeKey(label: string): string {
  return id(label);
}

/**
 * Deploys HospitalRegistry, PatientRegistry and ConsentManager, then sets up a small world:
 * hospitals A and B whitelisted, a doctor and a lab technician in A, a doctor in B,
 * and one patient enrolled by A's doctor (after the off-chain ID check).
 */
export async function deployRegistries(ethers: HardhatEthers) {
  const [owner, hospitalA, hospitalB, doctorA, labA, doctorB, patient, outsider] = await ethers.getSigners();

  const hospitals = await ethers.deployContract("HospitalRegistry", [owner.address]);
  const patients = await ethers.deployContract("PatientRegistry", [await hospitals.getAddress()]);
  const consents = await ethers.deployContract("ConsentManager", [
    await hospitals.getAddress(),
    await patients.getAddress(),
  ]);

  await hospitals.whitelistHospital(hospitalA.address, "Hospital A", fakeKey("hospitalA"));
  await hospitals.whitelistHospital(hospitalB.address, "Hospital B", fakeKey("hospitalB"));
  await hospitals.connect(hospitalA).registerStaff(doctorA.address, StaffRole.DOCTOR);
  await hospitals.connect(hospitalA).registerStaff(labA.address, StaffRole.LAB);
  await hospitals.connect(hospitalB).registerStaff(doctorB.address, StaffRole.DOCTOR);
  await patients.connect(doctorA).enrollPatient(patient.address, fakeKey("patient"));

  return {
    hospitals,
    patients,
    consents,
    accounts: { owner, hospitalA, hospitalB, doctorA, labA, doctorB, patient, outsider },
  };
}
