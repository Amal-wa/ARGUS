from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app.core.redis_client import InMemoryRedis
from app.core.settings import GatewaySettings
from app.middleware.context import RequestContext, resolve_client_ip
from app.middleware.rate_limit import enforce_ip_rate_limit


def _request(*, peer: str, forwarded_for: str | None = None):
    headers = {}
    if forwarded_for is not None:
        headers["x-forwarded-for"] = forwarded_for
    return SimpleNamespace(client=SimpleNamespace(host=peer), headers=headers)


def test_untrusted_peer_spoofed_header_is_ignored():
    request = _request(peer="203.0.113.9", forwarded_for="1.2.3.4")

    resolved = resolve_client_ip(request, trusted_proxies=frozenset())

    assert resolved == "203.0.113.9"


def test_trusted_peer_uses_forwarded_for():
    request = _request(peer="172.18.0.1", forwarded_for="1.2.3.4")

    resolved = resolve_client_ip(request, trusted_proxies=frozenset({"172.18.0.1"}))

    assert resolved == "1.2.3.4"


def test_trusted_peer_takes_first_entry_of_chain():
    request = _request(peer="172.18.0.1", forwarded_for="1.2.3.4, 10.0.0.1, 10.0.0.2")

    resolved = resolve_client_ip(request, trusted_proxies=frozenset({"172.18.0.1"}))

    assert resolved == "1.2.3.4"


def test_trusted_peer_malformed_header_falls_back_to_peer():
    request = _request(peer="172.18.0.1", forwarded_for="not-an-ip")

    resolved = resolve_client_ip(request, trusted_proxies=frozenset({"172.18.0.1"}))

    assert resolved == "172.18.0.1"


def test_trusted_peer_injection_attempt_falls_back_to_peer():
    request = _request(peer="172.18.0.1", forwarded_for="../../etc/passwd")

    resolved = resolve_client_ip(request, trusted_proxies=frozenset({"172.18.0.1"}))

    assert resolved == "172.18.0.1"


def test_trusted_peer_no_header_falls_back_to_peer():
    request = _request(peer="172.18.0.1")

    resolved = resolve_client_ip(request, trusted_proxies=frozenset({"172.18.0.1"}))

    assert resolved == "172.18.0.1"


def test_empty_allowlist_default_always_ignores_header():
    settings = GatewaySettings()
    assert settings.trusted_proxies == frozenset()

    request = _request(peer="172.18.0.1", forwarded_for="1.2.3.4")
    resolved = resolve_client_ip(request, trusted_proxies=settings.trusted_proxies)

    assert resolved == "172.18.0.1"


def test_rate_limit_bypass_is_closed_for_untrusted_peer():
    async def _run():
        redis = InMemoryRedis()
        settings = GatewaySettings(rate_limit_ip_limit=1, rate_limit_window_seconds=60)

        events = []

        class Recorder:
            async def write(self, payload):
                events.append(payload)

        # Same untrusted peer, two different spoofed XFF values -- must NOT
        # get separate rate-limit budgets.
        request_a = _request(peer="203.0.113.9", forwarded_for="1.1.1.1")
        request_b = _request(peer="203.0.113.9", forwarded_for="2.2.2.2")

        ip_a = resolve_client_ip(request_a, trusted_proxies=frozenset())
        ip_b = resolve_client_ip(request_b, trusted_proxies=frozenset())
        assert ip_a == ip_b == "203.0.113.9"

        context_a = RequestContext(ip_address=ip_a)
        context_b = RequestContext(ip_address=ip_b)

        first = await enforce_ip_rate_limit(context=context_a, settings=settings, redis_client=redis, event_logger=Recorder())
        second = await enforce_ip_rate_limit(context=context_b, settings=settings, redis_client=redis, event_logger=Recorder())

        assert first.exceeded is False
        assert second.exceeded is True  # shared budget: the 2nd request already exceeds limit=1

    asyncio.run(_run())


def test_rate_limit_separates_correctly_for_trusted_proxy_generator():
    async def _run():
        redis = InMemoryRedis()
        settings = GatewaySettings(rate_limit_ip_limit=1, rate_limit_window_seconds=60)

        events = []

        class Recorder:
            async def write(self, payload):
                events.append(payload)

        trusted_proxies = frozenset({"172.18.0.1"})
        # Same trusted peer (the traffic generator's container), two different
        # persona IPs via XFF -- each persona must get its OWN budget.
        request_a = _request(peer="172.18.0.1", forwarded_for="10.10.10.1")
        request_b = _request(peer="172.18.0.1", forwarded_for="10.10.10.2")

        ip_a = resolve_client_ip(request_a, trusted_proxies=trusted_proxies)
        ip_b = resolve_client_ip(request_b, trusted_proxies=trusted_proxies)
        assert ip_a != ip_b

        context_a = RequestContext(ip_address=ip_a)
        context_b = RequestContext(ip_address=ip_b)

        first = await enforce_ip_rate_limit(context=context_a, settings=settings, redis_client=redis, event_logger=Recorder())
        second = await enforce_ip_rate_limit(context=context_b, settings=settings, redis_client=redis, event_logger=Recorder())

        assert first.exceeded is False
        assert second.exceeded is False  # separate budgets: neither hits limit=1 on its own first request

    asyncio.run(_run())
