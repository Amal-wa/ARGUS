# health-records

A blockchain **trust layer** for medical records. The smart contracts store **no medical data**;
they enforce three things only:

1. **Consent**: a patient approves a hospital for a scope of record types until an expiry date, and can revoke.
2. **Integrity**: each record's hash and metadata are registered on-chain.
3. **Auditability**: every read or write of a record is logged as an event.

Record content stays off-chain, end-to-end encrypted.

> Status: **phase 1 of 5** (HospitalRegistry, PatientRegistry, ConsentManager + tests).
> The full README (WSL2 setup, Sepolia deployment, demo script) comes in phase 5.

## Stack

| Tool | Version | Why |
|---|---|---|
| Node.js | 24 LTS | current LTS line |
| Hardhat | 3.x (TypeScript, Mocha + ethers template) | official toolchain, built-in coverage |
| Solidity | **0.8.37**, pinned exactly | newest release with weeks of field use; only known compiler bug is low severity |
| OpenZeppelin Contracts | 5.6.1 | audited `Ownable2Step` instead of hand-written access control |
| ethers | v6 | |

## Contracts (phase 1)

| Contract | Responsibility |
|---|---|
| `HealthTypes.sol` | `RecordType` and `StaffRole` enums, scope bitmask helpers |
| `HospitalRegistry.sol` | platform owner whitelists hospitals; each hospital admin registers/deactivates its own staff |
| `PatientRegistry.sol` | active staff enroll patients (after an off-chain in-person ID check) and store their encryption public key |
| `ConsentManager.sol` | `approveHospital`, `revokeHospital`, and `isAuthorized(staff, patient, recordType)`, the single access rule |

`isAuthorized` is true only if the staff member is active, their hospital is whitelisted, the patient
approved that hospital, the scope covers the record type, and the consent is neither expired nor revoked.

## Run

```bash
npm install
npm test            # all tests
npm run coverage    # tests + Solidity coverage report (coverage/html)
npm run typecheck   # compile, then type-check the TypeScript tests
```

On a machine that cannot reach `binaries.soliditylang.org`, download the solc 0.8.37 static binary,
verify its SHA-256 against the official `list.json`, and point Hardhat at it:
`SOLC_PATH=/path/to/solc-0.8.37 npm test`.

## Known dependency advisory

`npm audit` reports GHSA-mrhx-c7xc-m3w5 (zod < 4.6.6, memory exhaustion on oversized input) through
Hardhat, which requires zod 3.x; no patched 3.x exists. Zod only validates our own Hardhat config at
development time and never receives untrusted input, so the issue is not reachable. It is not shipped
in any deployed artifact.
