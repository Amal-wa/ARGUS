from __future__ import annotations

import argparse
import asyncio
import logging
import random

import httpx

from .attacks import (
    scenario_a_resource_enumeration,
    scenario_b_password_spraying,
    scenario_c_session_hijack,
    scenario_d_privilege_escalation,
)
from .behaviors import run_persona_normal
from .client import PersonaClient
from .personas import SEED_USER_PASSWORD_DEFAULT, Persona, assign_resource_pool, build_personas

logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Zero Trust synthetic traffic generator (host-side tool, not a service)")
    parser.add_argument("--mode", choices=["normal", "attack"], default="normal")
    parser.add_argument("--scenario", choices=["A", "B", "C", "D"], default=None, help="required when --mode attack")
    parser.add_argument("--duration", type=float, default=None, help="seconds; omit to run until Ctrl-C")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--redis-url", default="redis://localhost:6379/0")
    parser.add_argument("--password", default=SEED_USER_PASSWORD_DEFAULT)
    return parser.parse_args(argv)


async def _check_gateway_reachable(base_url: str) -> None:
    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        response = await client.get("/health")
        if response.status_code != 200:
            raise SystemExit(f"FATAL: gateway not healthy at {base_url}/health: {response.status_code}")


async def _check_seeded_users_exist(base_url: str, personas: list[Persona]) -> None:
    probe = personas[0]
    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        response = await client.post("/auth/login", json={"email": probe.email, "password": probe.password})
    if response.status_code != 200:
        raise SystemExit(
            f"FATAL: could not log in as seeded user {probe.email}: {response.status_code} {response.text}\n"
            "Run scripts/seed_business_data.py against the gateway first (it also runs scripts/seed_users.py's job)."
        )
    if response.json().get("mfa_enrollment_required"):
        # Not fatal -- PersonaClient.login() self-heals via POST /mfa/enroll
        # (see client.py) -- but this means seed_business_data.py's MFA
        # enrollment step wasn't run (or is stale), which is worth surfacing.
        print(
            f"  NOTE: {probe.email} is not MFA-enrolled yet (mandatory MFA); "
            "PersonaClient will auto-enroll on first login. Re-run "
            "scripts/seed_business_data.py to pre-enroll and silence this."
        )


async def _check_xff_honored(base_url: str, redis_url: str) -> None:
    """The single most important pre-flight check: if X-Forwarded-For is not
    honored, every persona collapses onto one IP and the whole multi-day run
    produces a worthless dataset. Verified directly against Redis (published
    on the host per docker-compose), not inferred."""
    import redis.asyncio as aioredis

    probe_ip_a = "203.0.113.201"
    probe_ip_b = "203.0.113.202"
    key_a = f"ratelimit:ip:{probe_ip_a}"
    key_b = f"ratelimit:ip:{probe_ip_b}"

    redis_client = aioredis.from_url(redis_url, decode_responses=True)
    try:
        await redis_client.delete(key_a, key_b)

        async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
            await client.post(
                "/auth/login", json={"email": "xff-probe@zt.local", "password": "x"}, headers={"X-Forwarded-For": probe_ip_a}
            )
            await client.post(
                "/auth/login", json={"email": "xff-probe@zt.local", "password": "x"}, headers={"X-Forwarded-For": probe_ip_b}
            )

        exists_a = await redis_client.exists(key_a)
        exists_b = await redis_client.exists(key_b)
        await redis_client.delete(key_a, key_b)
    finally:
        await redis_client.aclose()

    if not (exists_a and exists_b):
        raise SystemExit(
            "\n"
            + "=" * 70
            + "\n"
            "FATAL: X-Forwarded-For is NOT being honored by the gateway.\n"
            "Every persona would collapse onto a single IP and every IP-based\n"
            "feature (distinct-IPs-per-user, per-IP rate limiting) would be dead\n"
            "for the entire run -- do not proceed, the dataset would be worthless.\n"
            "\n"
            "Fix: add this generator's peer IP, AS THE GATEWAY SEES IT, to\n"
            "TRUSTED_PROXIES in docker/docker-compose.yml. Find that IP with:\n"
            "    curl -s -X POST http://localhost:8000/auth/login -H 'Content-Type: application/json' -d '{}'\n"
            "    docker exec redis redis-cli --scan --pattern 'ratelimit:ip:*'\n"
            "then set TRUSTED_PROXIES=<that IP> and recreate the api-gateway container.\n" + "=" * 70
        )


async def _login_and_get_pair(client: httpx.AsyncClient, email: str, password: str, ip: str) -> dict:
    """Raw (non-PersonaClient) login helper that copes with mandatory MFA the
    same way PersonaClient.login() does: auto-enrolls (no code/proof required)
    if the account isn't pre-enrolled yet, then returns the full pair body."""
    response = await client.post("/auth/login", json={"email": email, "password": password}, headers={"X-Forwarded-For": ip})
    response.raise_for_status()
    body = response.json()
    if body.get("mfa_enrollment_required"):
        enroll_response = await client.post("/mfa/enroll", headers={"Authorization": f"Bearer {body['enrollment_token']}"})
        enroll_response.raise_for_status()
        body = enroll_response.json()
    return body


async def _fetch_resource_pool(base_url: str, admin: Persona) -> tuple[list[str], list[str]]:
    async with httpx.AsyncClient(base_url=base_url, timeout=10.0) as client:
        pair = await _login_and_get_pair(client, admin.email, admin.password, admin.ip)
        headers = {"Authorization": f"Bearer {pair['access_token']}", "X-Forwarded-For": admin.ip}

        documents = await client.get("/documents", params={"limit": 1000}, headers=headers)
        documents.raise_for_status()
        document_ids = [d["document_id"] for d in documents.json()["documents"]]

        orders = await client.get("/orders", params={"limit": 1000}, headers=headers)
        orders.raise_for_status()
        order_ids = [o["order_id"] for o in orders.json()["orders"]]

    return document_ids, order_ids


def _print_summary(clients: dict[str, PersonaClient]) -> None:
    total_requests = sum(c.stats["requests"] for c in clients.values())
    total_denies = sum(c.stats["denies"] for c in clients.values())
    total_refreshes = sum(c.stats["refreshes"] for c in clients.values())
    status_totals: dict[int, int] = {}
    for client in clients.values():
        for status, count in client.stats["status_counts"].items():
            status_totals[status] = status_totals.get(status, 0) + count

    print()
    print("=" * 70)
    print("SUMMARY")
    print(f"total requests: {total_requests}   denies (403): {total_denies}   token refreshes: {total_refreshes}")
    print("status counts:", status_totals)
    print("per-persona:")
    for email, client in clients.items():
        print(f"  {email}: {client.stats}")
    print("=" * 70)


async def async_main(args: argparse.Namespace) -> None:
    if args.mode == "attack" and args.scenario is None:
        raise SystemExit("--scenario is required when --mode attack")

    personas = build_personas(args.seed, args.password)

    print(f"Checking gateway reachability at {args.base_url} ...")
    await _check_gateway_reachable(args.base_url)

    print("Checking seeded users exist and can log in ...")
    await _check_seeded_users_exist(args.base_url, personas)

    print("Checking X-Forwarded-For is honored (TRUSTED_PROXIES) ...")
    await _check_xff_honored(args.base_url, args.redis_url)
    print("  OK: distinct X-Forwarded-For values get distinct rate-limit budgets.")

    admin_persona = next(p for p in personas if p.role == "admin")
    print("Fetching resource pool (documents/orders) ...")
    document_ids, order_ids = await _fetch_resource_pool(args.base_url, admin_persona)
    print(f"  {len(document_ids)} documents, {len(order_ids)} orders")
    assign_resource_pool(personas, document_ids, order_ids, args.seed)

    print()
    print("=" * 70)
    print(f"mode={args.mode}" + (f"  scenario={args.scenario}" if args.scenario else ""))
    print(f"personas={len(personas)}  seed={args.seed}  duration={args.duration if args.duration else 'until Ctrl-C'}")
    sample_ips = ", ".join(f"{p.email}={p.ip}" for p in personas[:5])
    print(f"sample persona IPs: {sample_ips}{' ...' if len(personas) > 5 else ''}")
    if args.mode == "normal":
        print("PHASE 1 RULE: normal traffic ONLY. Never run this training window")
        print("concurrently with an attack scenario -- an attack in ml_training_samples")
        print("is learned as normal and will never be detected.")
    print("=" * 70)
    print()

    stop_event = asyncio.Event()
    rng = random.Random(args.seed)
    clients: dict[str, PersonaClient] = {}
    tasks: list[asyncio.Task] = []

    for persona in personas:
        client = PersonaClient(args.base_url, persona.email, persona.password, persona.ip)
        clients[persona.email] = client
        tasks.append(
            asyncio.create_task(run_persona_normal(persona, client, random.Random(rng.random()), stop_event))
        )

    attack_task: asyncio.Task | None = None
    if args.mode == "attack":
        actor_persona = next(p for p in personas if p.role == "reader")
        actor_client = clients[actor_persona.email]
        await asyncio.sleep(3)  # let the actor's normal task log in first

        attack_duration = args.duration or 300.0
        if args.scenario == "A":
            attack_task = asyncio.create_task(
                scenario_a_resource_enumeration(actor_client, document_ids, duration_seconds=attack_duration, requests_per_minute=80)
            )
        elif args.scenario == "B":
            candidate_emails = [p.email for p in personas]
            attack_task = asyncio.create_task(
                scenario_b_password_spraying(
                    args.base_url, "198.51.100.7", candidate_emails, common_password="Password123!", delay_seconds=3.0
                )
            )
        elif args.scenario == "C":
            attack_task = asyncio.create_task(
                scenario_c_session_hijack(actor_client, document_ids, duration_seconds=attack_duration, requests_per_minute=20)
            )
        elif args.scenario == "D":
            attack_task = asyncio.create_task(
                scenario_d_privilege_escalation(actor_client, document_ids, duration_seconds=attack_duration, requests_per_minute=20)
            )

    stop_timer_task: asyncio.Task | None = None
    if args.duration is not None:
        async def _timer() -> None:
            await asyncio.sleep(args.duration)
            stop_event.set()

        stop_timer_task = asyncio.create_task(_timer())

    try:
        if stop_timer_task is not None:
            await stop_timer_task
        elif attack_task is not None:
            await attack_task
            print("Attack scenario finished; background normal traffic continues. Press Ctrl-C to stop.")
            await asyncio.Event().wait()
        else:
            await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        stop_event.set()
        if attack_task is not None and not attack_task.done():
            attack_task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for client in clients.values():
            await client.close()
        _print_summary(clients)


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    args = parse_args(argv)
    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
