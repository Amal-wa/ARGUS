import { expect } from "chai";
import { network } from "hardhat";
import { deployRegistries, fakeKey } from "./helpers.js";

const { ethers, networkHelpers } = await network.create();

describe("PatientRegistry", function () {
  async function deployFixture() {
    return deployRegistries(ethers);
  }

  it("lets active staff enroll a patient and emits PatientEnrolled", async function () {
    const { patients, accounts } = await networkHelpers.loadFixture(deployFixture);
    const key = fakeKey("outsider-patient");

    await expect(patients.connect(accounts.doctorB).enrollPatient(accounts.outsider.address, key))
      .to.emit(patients, "PatientEnrolled")
      .withArgs(accounts.outsider.address, accounts.hospitalB.address, accounts.doctorB.address, key);

    expect(await patients.isEnrolled(accounts.outsider.address)).to.equal(true);
    expect(await patients.encryptionPublicKey(accounts.outsider.address)).to.equal(key);
    const p = await patients.getPatient(accounts.outsider.address);
    expect(p.enrolledBy).to.equal(accounts.doctorB.address);
    expect(p.hospital).to.equal(accounts.hospitalB.address);
  });

  it("rejects enrollment by an address that is not staff", async function () {
    const { patients, accounts } = await networkHelpers.loadFixture(deployFixture);

    await expect(patients.connect(accounts.outsider).enrollPatient(accounts.outsider.address, fakeKey("k")))
      .to.be.revertedWithCustomError(patients, "NotActiveStaff")
      .withArgs(accounts.outsider.address);
    // A hospital admin is not staff either.
    await expect(
      patients.connect(accounts.hospitalA).enrollPatient(accounts.outsider.address, fakeKey("k")),
    ).to.be.revertedWithCustomError(patients, "NotActiveStaff");
  });

  it("rejects enrollment by inactive staff", async function () {
    const { hospitals, patients, accounts } = await networkHelpers.loadFixture(deployFixture);
    await hospitals.connect(accounts.hospitalA).deactivateStaff(accounts.doctorA.address);

    await expect(
      patients.connect(accounts.doctorA).enrollPatient(accounts.outsider.address, fakeKey("k")),
    ).to.be.revertedWithCustomError(patients, "NotActiveStaff");
  });

  it("rejects enrollment by staff of a de-whitelisted hospital", async function () {
    const { hospitals, patients, accounts } = await networkHelpers.loadFixture(deployFixture);
    await hospitals.deactivateHospital(accounts.hospitalB.address);

    await expect(
      patients.connect(accounts.doctorB).enrollPatient(accounts.outsider.address, fakeKey("k")),
    ).to.be.revertedWithCustomError(patients, "NotActiveStaff");
  });

  it("rejects double enrollment", async function () {
    const { patients, accounts } = await networkHelpers.loadFixture(deployFixture);

    await expect(patients.connect(accounts.doctorB).enrollPatient(accounts.patient.address, fakeKey("other")))
      .to.be.revertedWithCustomError(patients, "PatientAlreadyEnrolled")
      .withArgs(accounts.patient.address);
  });

  it("rejects staff or hospital addresses as patients (no self-enrollment)", async function () {
    const { patients, accounts } = await networkHelpers.loadFixture(deployFixture);

    await expect(patients.connect(accounts.doctorA).enrollPatient(accounts.doctorA.address, fakeKey("k")))
      .to.be.revertedWithCustomError(patients, "AddressIsStaffOrHospital")
      .withArgs(accounts.doctorA.address);
    await expect(
      patients.connect(accounts.doctorA).enrollPatient(accounts.hospitalB.address, fakeKey("k")),
    ).to.be.revertedWithCustomError(patients, "AddressIsStaffOrHospital");
  });

  it("rejects the zero address and an empty encryption key", async function () {
    const { patients, accounts } = await networkHelpers.loadFixture(deployFixture);

    await expect(
      patients.connect(accounts.doctorA).enrollPatient(ethers.ZeroAddress, fakeKey("k")),
    ).to.be.revertedWithCustomError(patients, "ZeroAddress");
    await expect(
      patients.connect(accounts.doctorA).enrollPatient(accounts.outsider.address, ethers.ZeroHash),
    ).to.be.revertedWithCustomError(patients, "InvalidPublicKey");
  });

  it("refuses a zero HospitalRegistry address at deployment", async function () {
    const factory = await ethers.getContractFactory("PatientRegistry");
    await expect(ethers.deployContract("PatientRegistry", [ethers.ZeroAddress])).to.be.revertedWithCustomError(
      factory,
      "ZeroAddress",
    );
  });
});
