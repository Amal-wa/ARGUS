from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from app.core import totp as totp_module
from app.core.redis_client import InMemoryRedis
from app.core.repositories import UserMfaRecord
from app.core.security import VerifiedJWT
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext
from app.schemas.authorization import RiskScoreResult
from app.services.mfa_challenge import MfaChallengeService, MfaVerificationStatus

FROZEN_TIME = 1_700_000_000


@dataclass(slots=True)
class FakeUserMfaRepository:
    records: dict[UUID, UserMfaRecord] = field(default_factory=dict)

    async def get(self, user_id):
        return self.records.get(user_id)

    async def create(self, user_id, totp_secret_ciphertext):
        self.records[user_id] = UserMfaRecord(
            user_id=user_id,
            totp_secret_ciphertext=totp_secret_ciphertext,
            failed_attempts=0,
            locked_until=None,
        )

    async def record_failed_attempt(self, user_id, *, max_attempts, lockout_duration_minutes):
        record = self.records[user_id]
        incremented = record.failed_attempts + 1
        if incremented >= max_attempts:
            record.failed_attempts = 0
            record.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_duration_minutes)
        else:
            record.failed_attempts = incremented
        return record

    async def reset_on_success(self, user_id):
        record = self.records[user_id]
        record.failed_attempts = 0
        record.locked_until = None


@dataclass(slots=True)
class FakeEnrollmentService:
    secrets: dict[UUID, bytes] = field(default_factory=dict)

    async def get_decrypted_secret(self, user_id):
        return self.secrets.get(user_id)


def _settings(**overrides) -> GatewaySettings:
    defaults = dict(
        mfa_max_failed_attempts=3,
        mfa_lockout_duration_minutes=15,
        mfa_challenge_ttl_seconds=120,
        totp_replay_ttl_seconds=90,
        mfa_verified_ttl_seconds=300,
    )
    defaults.update(overrides)
    return GatewaySettings(**defaults)


def _claims(user_id: UUID) -> VerifiedJWT:
    return VerifiedJWT(
        subject=user_id,
        issuer="zt-api-gateway",
        audience="zt-api",
        issued_at=FROZEN_TIME,
        expires_at=FROZEN_TIME + 60,
        jti=uuid4(),
        role="user",
        risk_ctx=None,
        raw_claims={},
    )


def _service(settings: GatewaySettings | None = None):
    redis = InMemoryRedis()
    repository = FakeUserMfaRepository()
    enrollment = FakeEnrollmentService()
    service = MfaChallengeService(
        redis_client=redis,
        repository=repository,
        enrollment=enrollment,
        settings=settings or _settings(),
    )
    return service, redis, repository, enrollment


async def _enroll(repository: FakeUserMfaRepository, enrollment: FakeEnrollmentService, user_id: UUID, secret: bytes) -> None:
    await repository.create(user_id, "vault:v1:fake-ciphertext")
    enrollment.secrets[user_id] = secret


def _wrong_code(secret: bytes) -> str:
    real_code = totp_module.compute_totp(secret, totp_module.current_time_step(FROZEN_TIME))
    return "".join("9" if c != "9" else "8" for c in real_code)


def test_challenge_expired_when_missing(monkeypatch):
    monkeypatch.setattr("app.core.totp.time.time", lambda: FROZEN_TIME)

    async def _run():
        service, _redis, _repository, _enrollment = _service()
        user_id = uuid4()

        result = await service.verify_challenge(challenge_id="nonexistent", code="000000", claims=_claims(user_id))

        assert result.status == MfaVerificationStatus.CHALLENGE_EXPIRED

    asyncio.run(_run())


def test_challenge_user_mismatch_treated_as_expired(monkeypatch):
    monkeypatch.setattr("app.core.totp.time.time", lambda: FROZEN_TIME)

    async def _run():
        service, _redis, repository, enrollment = _service()
        owner_id = uuid4()
        attacker_id = uuid4()
        await _enroll(repository, enrollment, owner_id, b"0" * 20)
        context = RequestContext(claims=_claims(owner_id))
        challenge_id = await service.create_challenge(context, RiskScoreResult(risk_score=0.9, model_version="m1"))

        result = await service.verify_challenge(challenge_id=challenge_id, code="000000", claims=_claims(attacker_id))

        assert result.status == MfaVerificationStatus.CHALLENGE_EXPIRED

    asyncio.run(_run())


def test_create_challenge_returns_none_when_not_enrolled(monkeypatch):
    monkeypatch.setattr("app.core.totp.time.time", lambda: FROZEN_TIME)

    async def _run():
        service, _redis, _repository, _enrollment = _service()
        user_id = uuid4()
        context = RequestContext(claims=_claims(user_id))

        challenge_id = await service.create_challenge(context, RiskScoreResult(risk_score=0.9, model_version="m1"))

        assert challenge_id is None

    asyncio.run(_run())


def test_verify_challenge_not_enrolled_defensive_branch(monkeypatch):
    monkeypatch.setattr("app.core.totp.time.time", lambda: FROZEN_TIME)

    async def _run():
        service, _redis, repository, enrollment = _service()
        user_id = uuid4()
        await _enroll(repository, enrollment, user_id, b"0" * 20)
        context = RequestContext(claims=_claims(user_id))
        challenge_id = await service.create_challenge(context, RiskScoreResult(risk_score=0.9, model_version="m1"))

        del repository.records[user_id]

        result = await service.verify_challenge(challenge_id=challenge_id, code="000000", claims=_claims(user_id))

        assert result.status == MfaVerificationStatus.NOT_ENROLLED

    asyncio.run(_run())


def test_locked_pre_check_rejects_before_verifying_code(monkeypatch):
    monkeypatch.setattr("app.core.totp.time.time", lambda: FROZEN_TIME)

    async def _run():
        service, _redis, repository, enrollment = _service()
        user_id = uuid4()
        secret = b"1" * 20
        await _enroll(repository, enrollment, user_id, secret)
        repository.records[user_id].locked_until = datetime.now(timezone.utc) + timedelta(minutes=5)
        context = RequestContext(claims=_claims(user_id))
        challenge_id = await service.create_challenge(context, RiskScoreResult(risk_score=0.9, model_version="m1"))

        correct_code = totp_module.compute_totp(secret, totp_module.current_time_step(FROZEN_TIME))
        result = await service.verify_challenge(challenge_id=challenge_id, code=correct_code, claims=_claims(user_id))

        assert result.status == MfaVerificationStatus.LOCKED

    asyncio.run(_run())


def test_invalid_code_below_threshold(monkeypatch):
    monkeypatch.setattr("app.core.totp.time.time", lambda: FROZEN_TIME)

    async def _run():
        service, _redis, repository, enrollment = _service(_settings(mfa_max_failed_attempts=3))
        user_id = uuid4()
        secret = b"2" * 20
        await _enroll(repository, enrollment, user_id, secret)
        context = RequestContext(claims=_claims(user_id))
        challenge_id = await service.create_challenge(context, RiskScoreResult(risk_score=0.9, model_version="m1"))

        result = await service.verify_challenge(challenge_id=challenge_id, code=_wrong_code(secret), claims=_claims(user_id))

        assert result.status == MfaVerificationStatus.INVALID_CODE
        assert repository.records[user_id].failed_attempts == 1
        assert repository.records[user_id].locked_until is None

    asyncio.run(_run())


def test_invalid_code_hits_threshold_locks_now(monkeypatch):
    monkeypatch.setattr("app.core.totp.time.time", lambda: FROZEN_TIME)

    async def _run():
        service, _redis, repository, enrollment = _service(_settings(mfa_max_failed_attempts=1))
        user_id = uuid4()
        secret = b"3" * 20
        await _enroll(repository, enrollment, user_id, secret)
        context = RequestContext(claims=_claims(user_id))
        challenge_id = await service.create_challenge(context, RiskScoreResult(risk_score=0.9, model_version="m1"))

        result = await service.verify_challenge(challenge_id=challenge_id, code=_wrong_code(secret), claims=_claims(user_id))

        assert result.status == MfaVerificationStatus.LOCKED_NOW
        assert repository.records[user_id].locked_until is not None

    asyncio.run(_run())


def test_totp_replay_detected_on_second_challenge_with_same_code(monkeypatch):
    monkeypatch.setattr("app.core.totp.time.time", lambda: FROZEN_TIME)

    async def _run():
        service, _redis, repository, enrollment = _service()
        user_id = uuid4()
        secret = b"4" * 20
        await _enroll(repository, enrollment, user_id, secret)
        context = RequestContext(claims=_claims(user_id))
        code = totp_module.compute_totp(secret, totp_module.current_time_step(FROZEN_TIME))

        first_challenge_id = await service.create_challenge(context, RiskScoreResult(risk_score=0.9, model_version="m1"))
        first_result = await service.verify_challenge(challenge_id=first_challenge_id, code=code, claims=_claims(user_id))
        assert first_result.status == MfaVerificationStatus.VERIFIED

        second_challenge_id = await service.create_challenge(context, RiskScoreResult(risk_score=0.9, model_version="m1"))
        second_result = await service.verify_challenge(challenge_id=second_challenge_id, code=code, claims=_claims(user_id))

        assert second_result.status == MfaVerificationStatus.TOTP_REPLAYED

    asyncio.run(_run())


def test_success_resets_attempts_deletes_challenge_and_sets_marker(monkeypatch):
    monkeypatch.setattr("app.core.totp.time.time", lambda: FROZEN_TIME)

    async def _run():
        service, redis, repository, enrollment = _service()
        user_id = uuid4()
        secret = b"5" * 20
        await _enroll(repository, enrollment, user_id, secret)
        repository.records[user_id].failed_attempts = 2
        context = RequestContext(claims=_claims(user_id))
        challenge_id = await service.create_challenge(context, RiskScoreResult(risk_score=0.9, model_version="m1"))

        code = totp_module.compute_totp(secret, totp_module.current_time_step(FROZEN_TIME))
        result = await service.verify_challenge(challenge_id=challenge_id, code=code, claims=_claims(user_id))

        assert result.status == MfaVerificationStatus.VERIFIED
        assert result.context is not None
        assert result.context.user_id == user_id
        assert repository.records[user_id].failed_attempts == 0
        assert await redis.exists(f"challenge:{challenge_id}") is False
        assert await redis.get(f"mfa:verified:{user_id}") == "1"

    asyncio.run(_run())
