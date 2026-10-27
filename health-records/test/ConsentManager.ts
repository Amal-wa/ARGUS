import { expect } from "chai";
import { network } from "hardhat";
import { deployRegistries, ONE_DAY, RecordType, Scope } from "./helpers.js";

const { ethers, networkHelpers } = await network.create();

describe("ConsentManager", function () {
  async function deployFixture() {
    return deployRegistries(ethers);
  }

  /** Same world, plus: the patient approved hospital A for visit notes and lab results, 30 days. */
  async function consentFixture() {
    const world = await deployRegistries(ethers);
    const expiry = (await networkHelpers.time.latest()) + 30 * ONE_DAY;
    await world.consents
      .connect(world.accounts.patient)
      .approveHospital(world.accounts.hospitalA.address, Scope.VISIT_NOTE | Scope.LAB_RESULT, expiry);
    return { ...world, expiry };
  }

  describe("approveHospital", function () {
    it("records the consent and emits ConsentGranted", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(deployFixture);
      const expiry = (await networkHelpers.time.latest()) + 30 * ONE_DAY;

      await expect(consents.connect(accounts.patient).approveHospital(accounts.hospitalA.address, Scope.ALL, expiry))
        .to.emit(consents, "ConsentGranted")
        .withArgs(accounts.patient.address, accounts.hospitalA.address, Scope.ALL, expiry);

      const c = await consents.getConsent(accounts.patient.address, accounts.hospitalA.address);
      expect(c.scope).to.equal(Scope.ALL);
      expect(c.expiry).to.equal(expiry);
      expect(c.revokedAt).to.equal(0n);
    });

    it("rejects a caller who is not an enrolled patient", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(deployFixture);
      const expiry = (await networkHelpers.time.latest()) + ONE_DAY;

      await expect(consents.connect(accounts.outsider).approveHospital(accounts.hospitalA.address, Scope.ALL, expiry))
        .to.be.revertedWithCustomError(consents, "NotEnrolledPatient")
        .withArgs(accounts.outsider.address);
    });

    it("rejects a non-whitelisted or deactivated hospital", async function () {
      const { hospitals, consents, accounts } = await networkHelpers.loadFixture(deployFixture);
      const expiry = (await networkHelpers.time.latest()) + ONE_DAY;

      await expect(consents.connect(accounts.patient).approveHospital(accounts.outsider.address, Scope.ALL, expiry))
        .to.be.revertedWithCustomError(consents, "HospitalNotActive")
        .withArgs(accounts.outsider.address);

      await hospitals.deactivateHospital(accounts.hospitalB.address);
      await expect(
        consents.connect(accounts.patient).approveHospital(accounts.hospitalB.address, Scope.ALL, expiry),
      ).to.be.revertedWithCustomError(consents, "HospitalNotActive");
    });

    it("rejects an empty scope and unknown scope bits", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(deployFixture);
      const expiry = (await networkHelpers.time.latest()) + ONE_DAY;
      const asPatient = consents.connect(accounts.patient);

      await expect(asPatient.approveHospital(accounts.hospitalA.address, 0, expiry))
        .to.be.revertedWithCustomError(consents, "InvalidScope")
        .withArgs(0);
      await expect(asPatient.approveHospital(accounts.hospitalA.address, 0x10, expiry))
        .to.be.revertedWithCustomError(consents, "InvalidScope")
        .withArgs(0x10);
    });

    it("rejects an expiry that is not in the future", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(deployFixture);
      const now = await networkHelpers.time.latest();

      await expect(
        consents.connect(accounts.patient).approveHospital(accounts.hospitalA.address, Scope.ALL, now),
      ).to.be.revertedWithCustomError(consents, "ExpiryNotInFuture");
    });

    it("replaces an existing consent (e.g. to widen the scope)", async function () {
      const { consents, accounts, expiry } = await networkHelpers.loadFixture(consentFixture);

      await consents.connect(accounts.patient).approveHospital(accounts.hospitalA.address, Scope.ALL, expiry);
      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.patient.address, RecordType.IMAGING),
      ).to.equal(true);
    });
  });

  describe("revokeHospital", function () {
    it("revokes and emits ConsentRevoked", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(consentFixture);

      await expect(consents.connect(accounts.patient).revokeHospital(accounts.hospitalA.address))
        .to.emit(consents, "ConsentRevoked")
        .withArgs(accounts.patient.address, accounts.hospitalA.address);
      expect((await consents.getConsent(accounts.patient.address, accounts.hospitalA.address)).revokedAt).to.not.equal(
        0n,
      );
    });

    it("rejects revoking a consent that does not exist or is already revoked", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(consentFixture);
      const asPatient = consents.connect(accounts.patient);

      await expect(asPatient.revokeHospital(accounts.hospitalB.address))
        .to.be.revertedWithCustomError(consents, "NoActiveConsent")
        .withArgs(accounts.patient.address, accounts.hospitalB.address);

      await asPatient.revokeHospital(accounts.hospitalA.address);
      await expect(asPatient.revokeHospital(accounts.hospitalA.address)).to.be.revertedWithCustomError(
        consents,
        "NoActiveConsent",
      );
    });

    it("lets the patient approve again after revoking", async function () {
      const { consents, accounts, expiry } = await networkHelpers.loadFixture(consentFixture);
      const asPatient = consents.connect(accounts.patient);

      await asPatient.revokeHospital(accounts.hospitalA.address);
      await asPatient.approveHospital(accounts.hospitalA.address, Scope.VISIT_NOTE, expiry);
      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.patient.address, RecordType.VISIT_NOTE),
      ).to.equal(true);
    });
  });

  describe("isAuthorized: every condition of the access rule", function () {
    it("is true for active staff of an approved hospital, in scope, before expiry", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(consentFixture);

      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.patient.address, RecordType.VISIT_NOTE),
      ).to.equal(true);
      expect(
        await consents.isAuthorized(accounts.labA.address, accounts.patient.address, RecordType.LAB_RESULT),
      ).to.equal(true);
    });

    it("is false for a record type outside the scope", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(consentFixture);

      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.patient.address, RecordType.IMAGING),
      ).to.equal(false);
      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.patient.address, RecordType.PRESCRIPTION),
      ).to.equal(false);
    });

    it("is false for staff of a hospital the patient did not approve", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(consentFixture);

      expect(
        await consents.isAuthorized(accounts.doctorB.address, accounts.patient.address, RecordType.VISIT_NOTE),
      ).to.equal(false);
    });

    it("is false for inactive staff", async function () {
      const { hospitals, consents, accounts } = await networkHelpers.loadFixture(consentFixture);
      await hospitals.connect(accounts.hospitalA).deactivateStaff(accounts.doctorA.address);

      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.patient.address, RecordType.VISIT_NOTE),
      ).to.equal(false);
    });

    it("is false once the hospital is removed from the whitelist", async function () {
      const { hospitals, consents, accounts } = await networkHelpers.loadFixture(consentFixture);
      await hospitals.deactivateHospital(accounts.hospitalA.address);

      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.patient.address, RecordType.VISIT_NOTE),
      ).to.equal(false);
    });

    it("is false once the consent has expired", async function () {
      const { consents, accounts, expiry } = await networkHelpers.loadFixture(consentFixture);

      await networkHelpers.time.increaseTo(expiry - 1);
      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.patient.address, RecordType.VISIT_NOTE),
      ).to.equal(true);

      await networkHelpers.time.increaseTo(expiry);
      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.patient.address, RecordType.VISIT_NOTE),
      ).to.equal(false);
    });

    it("is false once the consent is revoked", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(consentFixture);
      await consents.connect(accounts.patient).revokeHospital(accounts.hospitalA.address);

      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.patient.address, RecordType.VISIT_NOTE),
      ).to.equal(false);
    });

    it("is false for unknown staff, hospital admins and unenrolled patients", async function () {
      const { consents, accounts } = await networkHelpers.loadFixture(consentFixture);

      expect(
        await consents.isAuthorized(accounts.outsider.address, accounts.patient.address, RecordType.VISIT_NOTE),
      ).to.equal(false);
      expect(
        await consents.isAuthorized(accounts.hospitalA.address, accounts.patient.address, RecordType.VISIT_NOTE),
      ).to.equal(false);
      expect(
        await consents.isAuthorized(accounts.doctorA.address, accounts.outsider.address, RecordType.VISIT_NOTE),
      ).to.equal(false);
    });
  });

  it("refuses zero registry addresses at deployment", async function () {
    const { hospitals } = await networkHelpers.loadFixture(deployFixture);
    const factory = await ethers.getContractFactory("ConsentManager");

    await expect(
      ethers.deployContract("ConsentManager", [await hospitals.getAddress(), ethers.ZeroAddress]),
    ).to.be.revertedWithCustomError(factory, "ZeroAddress");
  });
});
