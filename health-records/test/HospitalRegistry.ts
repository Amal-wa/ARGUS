import { expect } from "chai";
import { network } from "hardhat";
import { deployRegistries, fakeKey, StaffRole } from "./helpers.js";

const { ethers, networkHelpers } = await network.create();

describe("HospitalRegistry", function () {
  async function deployFixture() {
    return deployRegistries(ethers);
  }

  describe("hospital whitelist (platform owner)", function () {
    it("whitelists a hospital and emits HospitalWhitelisted", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);
      const key = fakeKey("hospitalC");

      await expect(hospitals.whitelistHospital(accounts.outsider.address, "Hospital C", key))
        .to.emit(hospitals, "HospitalWhitelisted")
        .withArgs(accounts.outsider.address, "Hospital C", key);

      expect(await hospitals.isActiveHospital(accounts.outsider.address)).to.equal(true);
      const h = await hospitals.getHospital(accounts.outsider.address);
      expect(h.name).to.equal("Hospital C");
      expect(h.encryptionPublicKey).to.equal(key);
    });

    it("rejects a whitelist call from anyone but the owner", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(
        hospitals.connect(accounts.hospitalA).whitelistHospital(accounts.outsider.address, "X", fakeKey("x")),
      )
        .to.be.revertedWithCustomError(hospitals, "OwnableUnauthorizedAccount")
        .withArgs(accounts.hospitalA.address);
    });

    it("rejects double registration of a hospital", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(hospitals.whitelistHospital(accounts.hospitalA.address, "Again", fakeKey("again")))
        .to.be.revertedWithCustomError(hospitals, "HospitalAlreadyRegistered")
        .withArgs(accounts.hospitalA.address);
    });

    it("rejects the zero address and an empty encryption key", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(hospitals.whitelistHospital(ethers.ZeroAddress, "X", fakeKey("x"))).to.be.revertedWithCustomError(
        hospitals,
        "ZeroAddress",
      );
      await expect(
        hospitals.whitelistHospital(accounts.outsider.address, "X", ethers.ZeroHash),
      ).to.be.revertedWithCustomError(hospitals, "InvalidPublicKey");
    });

    it("refuses to whitelist an address that is already staff", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(hospitals.whitelistHospital(accounts.doctorA.address, "X", fakeKey("x")))
        .to.be.revertedWithCustomError(hospitals, "AddressIsStaff")
        .withArgs(accounts.doctorA.address);
    });

    it("deactivates a hospital, which also cuts off its staff", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(hospitals.deactivateHospital(accounts.hospitalA.address))
        .to.emit(hospitals, "HospitalDeactivated")
        .withArgs(accounts.hospitalA.address);

      expect(await hospitals.isActiveHospital(accounts.hospitalA.address)).to.equal(false);
      expect(await hospitals.activeStaffHospital(accounts.doctorA.address)).to.equal(ethers.ZeroAddress);
      await expect(hospitals.deactivateHospital(accounts.hospitalA.address)).to.be.revertedWithCustomError(
        hospitals,
        "HospitalNotActive",
      );
    });

    it("cannot renounce ownership, and transfers it in two steps", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(hospitals.renounceOwnership()).to.be.revertedWithCustomError(hospitals, "RenounceOwnershipDisabled");

      await hospitals.transferOwnership(accounts.outsider.address);
      expect(await hospitals.owner()).to.equal(accounts.owner.address); // not yet accepted
      await hospitals.connect(accounts.outsider).acceptOwnership();
      expect(await hospitals.owner()).to.equal(accounts.outsider.address);
    });
  });

  describe("staff management (hospital admin)", function () {
    it("registers staff with a role and emits StaffRegistered", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(hospitals.connect(accounts.hospitalA).registerStaff(accounts.outsider.address, StaffRole.RADIOLOGIST))
        .to.emit(hospitals, "StaffRegistered")
        .withArgs(accounts.hospitalA.address, accounts.outsider.address, StaffRole.RADIOLOGIST);

      const s = await hospitals.getStaff(accounts.outsider.address);
      expect(s.hospital).to.equal(accounts.hospitalA.address);
      expect(s.role).to.equal(StaffRole.RADIOLOGIST);
      expect(s.active).to.equal(true);
      expect(await hospitals.activeStaffHospital(accounts.outsider.address)).to.equal(accounts.hospitalA.address);
    });

    it("rejects staff registration by a non-whitelisted hospital", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(hospitals.connect(accounts.outsider).registerStaff(accounts.patient.address, StaffRole.DOCTOR))
        .to.be.revertedWithCustomError(hospitals, "HospitalNotActive")
        .withArgs(accounts.outsider.address);
    });

    it("rejects staff registration by a deactivated hospital", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);
      await hospitals.deactivateHospital(accounts.hospitalA.address);

      await expect(
        hospitals.connect(accounts.hospitalA).registerStaff(accounts.outsider.address, StaffRole.DOCTOR),
      ).to.be.revertedWithCustomError(hospitals, "HospitalNotActive");
    });

    it("rejects double registration, also across hospitals", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(hospitals.connect(accounts.hospitalA).registerStaff(accounts.doctorA.address, StaffRole.DOCTOR))
        .to.be.revertedWithCustomError(hospitals, "StaffAlreadyRegistered")
        .withArgs(accounts.doctorA.address);
      await expect(
        hospitals.connect(accounts.hospitalB).registerStaff(accounts.doctorA.address, StaffRole.DOCTOR),
      ).to.be.revertedWithCustomError(hospitals, "StaffAlreadyRegistered");
    });

    it("rejects role NONE, the zero address, and hospital addresses as staff", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);
      const admin = hospitals.connect(accounts.hospitalA);

      await expect(admin.registerStaff(accounts.outsider.address, StaffRole.NONE)).to.be.revertedWithCustomError(
        hospitals,
        "InvalidRole",
      );
      await expect(admin.registerStaff(ethers.ZeroAddress, StaffRole.DOCTOR)).to.be.revertedWithCustomError(
        hospitals,
        "ZeroAddress",
      );
      await expect(admin.registerStaff(accounts.hospitalB.address, StaffRole.DOCTOR))
        .to.be.revertedWithCustomError(hospitals, "AddressIsHospital")
        .withArgs(accounts.hospitalB.address);
    });

    it("deactivates its own staff and emits StaffDeactivated", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(hospitals.connect(accounts.hospitalA).deactivateStaff(accounts.doctorA.address))
        .to.emit(hospitals, "StaffDeactivated")
        .withArgs(accounts.hospitalA.address, accounts.doctorA.address);

      expect(await hospitals.activeStaffHospital(accounts.doctorA.address)).to.equal(ethers.ZeroAddress);
      await expect(
        hospitals.connect(accounts.hospitalA).deactivateStaff(accounts.doctorA.address),
      ).to.be.revertedWithCustomError(hospitals, "StaffNotActive");
    });

    it("cannot deactivate another hospital's staff", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      await expect(hospitals.connect(accounts.hospitalB).deactivateStaff(accounts.doctorA.address))
        .to.be.revertedWithCustomError(hospitals, "NotStaffOfCaller")
        .withArgs(accounts.doctorA.address);
    });

    it("can still deactivate staff after the hospital itself was deactivated", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);
      await hospitals.deactivateHospital(accounts.hospitalA.address);

      await expect(hospitals.connect(accounts.hospitalA).deactivateStaff(accounts.labA.address)).to.emit(
        hospitals,
        "StaffDeactivated",
      );
    });

    it("reports which addresses are registered", async function () {
      const { hospitals, accounts } = await networkHelpers.loadFixture(deployFixture);

      expect(await hospitals.isRegistered(accounts.hospitalA.address)).to.equal(true);
      expect(await hospitals.isRegistered(accounts.doctorA.address)).to.equal(true);
      expect(await hospitals.isRegistered(accounts.patient.address)).to.equal(false);
    });
  });
});
