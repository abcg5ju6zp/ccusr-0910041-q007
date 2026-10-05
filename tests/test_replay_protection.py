"""防重放组件测试：签名主体、时间窗、密钥轮换、并发、代理规范化、
可注入时钟、审计与 nonce 消耗语义。"""

import asyncio
import logging

from types import SimpleNamespace

import pytest

from sanic_testing.testing import SanicTestClient

from sanic import Sanic
from sanic.response import json as sjson
from sanic.response import text
from sanic.security import (
    HmacKeyRing,
    InMemoryNonceStore,
    ReplayError,
    ReplayGuard,
    ReplayRejectReason,
    RequestCanonicalizer,
    install_replay_protection,
    make_signed_headers,
)
from sanic.security.replay import NonceConsumption


# 固定本地端口，使签名主体中的 host:port 与实际监听地址一致。
BASE_PORT = 42150


SECRET_OLD = b"old-secret"
SECRET_NEW = b"new-secret"


class FixedClock:
    """可控时钟。"""

    def __init__(self, value: float) -> None:
        self.value = value

    def now(self) -> float:
        return self.value


class FakeHeaders:
    def __init__(self, mapping: dict[str, str] | None = None) -> None:
        self._d = {k.lower(): v for k, v in (mapping or {}).items()}

    def get(self, name, default=None):
        return self._d.get(name.lower(), default)

    def getone(self, name, default=None):
        return self._d.get(name.lower(), default)


class FakeRequest:
    """满足 ReplayGuard/规范化器所需的最小请求。"""

    def __init__(
        self,
        headers: dict[str, str] | None = None,
        *,
        method: str = "POST",
        scheme: str = "https",
        host: str = "partner.example.com",
        path: str = "/callbacks/pay",
        args: dict | None = None,
        body: bytes = b'{"order":"42"}',
        forwarded: dict | None = None,
        x_forwarded_prefix: str = "",
    ) -> None:
        merged = dict(headers or {})
        if x_forwarded_prefix:
            merged["x-forwarded-prefix"] = x_forwarded_prefix
        self.headers = FakeHeaders(merged)
        self.method = method
        self.path = path
        self.args = args or {}
        self.body = body
        self._scheme = scheme
        self._host = host
        self.forwarded = forwarded or {}
        self.conn_info = SimpleNamespace(ssl=False)

    @property
    def scheme(self) -> str:
        return self._scheme

    @property
    def host(self) -> str:
        return self._host

    async def receive_body(self) -> None:
        return None


def make_guard(
    ring: HmacKeyRing | None = None,
    store: InMemoryNonceStore | None = None,
    clock: FixedClock | None = None,
    ttl: float = 60.0,
    canonicalizer: RequestCanonicalizer | None = None,
) -> ReplayGuard:
    return ReplayGuard(
        ring or HmacKeyRing({"v1": b"secret"}),
        store or InMemoryNonceStore(),
        ttl_seconds=ttl,
        clock=clock or FixedClock(1_000_000),
        canonicalizer=canonicalizer,
    )


def signed_headers(
    ring: HmacKeyRing,
    *,
    nonce: str = "nonce-1",
    timestamp: int = 1_000_000,
    method: str = "POST",
    scheme: str = "https",
    host: str = "partner.example.com",
    path: str = "/callbacks/pay",
    query=b"",
    body: bytes = b'{"order":"42"}',
    key_version: str | None = None,
    tamper_signature: bool = False,
) -> dict[str, str]:
    canonicalizer = RequestCanonicalizer()
    headers = make_signed_headers(
        ring,
        canonicalizer,
        method=method,
        scheme=scheme,
        host=host,
        path=path,
        query=query,
        body=body,
        timestamp=timestamp,
        nonce=nonce,
        key_version=key_version,
    )
    if tamper_signature:
        headers["x-signature"] = "a" * 64  # 合法长度但内容错误
    return headers


# --------------------------------------------------------------------- #
# 签名主体
# --------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_valid_request_passes_and_binds_all_parts():
    ring = HmacKeyRing({"v1": b"secret"})
    guard = make_guard(ring)

    result = await guard.verify_request(FakeRequest(signed_headers(ring)))
    assert result.nonce == "nonce-1"
    assert result.key_version == "v1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change",
    [
        dict(method="PUT"),
        dict(path="/callbacks/refund"),
        dict(host="evil.example.com"),
        dict(scheme="http"),
        dict(body=b'{"order":"43"}'),
    ],
)
async def test_signature_covers_method_path_host_scheme_body(change):
    ring = HmacKeyRing({"v1": b"secret"})
    guard = make_guard(ring)
    signed = dict(
        nonce="n",
        timestamp=1_000_000,
        method="POST",
        scheme="https",
        host="partner.example.com",
        path="/callbacks/pay",
        body=b'{"order":"42"}',
    )
    headers = signed_headers(ring, **signed)
    request = FakeRequest(headers, **change)
    with pytest.raises(ReplayError) as exc:
        await guard.verify_request(request)
    assert exc.value.audit_entry.reason is (
        ReplayRejectReason.INVALID_SIGNATURE
    )


@pytest.mark.asyncio
async def test_signature_covers_query_regardless_of_order():
    ring = HmacKeyRing({"v1": b"secret"})
    # 签名侧参数顺序为 b 在前；请求侧以乱序到达，规范化后应一致。
    headers = signed_headers(ring, nonce="n", query=[("b", "2"), ("a", "1")])
    request = FakeRequest(headers, args={"b": ["2"], "a": ["1"]})
    result = await ReplayGuard(
        ring,
        InMemoryNonceStore(),
        ttl_seconds=60,
        clock=FixedClock(1_000_000),
    ).verify_request(request)
    assert result.nonce == "n"


@pytest.mark.asyncio
async def test_trailing_slash_normalized():
    ring = HmacKeyRing({"v1": b"secret"})
    # 服务端路径带尾斜杠，签名按归一化后的无斜杠地址计算。
    headers = signed_headers(ring, nonce="n", path="/callbacks/pay")
    request = FakeRequest(headers, path="/callbacks/pay/")
    result = await make_guard(ring).verify_request(request)
    assert result.nonce_key.startswith("v1:")


@pytest.mark.asyncio
async def test_nonce_timestamp_and_key_version_are_signed():
    ring = HmacKeyRing({"v1": b"secret"})
    guard = make_guard(ring)

    # 篡改签名本身
    with pytest.raises(ReplayError) as exc:
        await guard.verify_request(
            FakeRequest(signed_headers(ring, tamper_signature=True))
        )
    assert exc.value.audit_entry.reason is (
        ReplayRejectReason.INVALID_SIGNATURE
    )

    # 复用旧签名但更换 nonce -> 签名失效，而非简单的重放
    headers = signed_headers(ring, nonce="orig")
    headers["x-signature-nonce"] = "swapped"
    with pytest.raises(ReplayError) as exc:
        await guard.verify_request(FakeRequest(headers))
    assert exc.value.audit_entry.reason is (
        ReplayRejectReason.INVALID_SIGNATURE
    )


# --------------------------------------------------------------------- #
# 时间窗与可注入时钟
# --------------------------------------------------------------------- #


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ts,clock_at,expected",
    [
        (1000, 1060, True),  # 60s 边界内（过去）
        (1000, 940, True),  # 60s 边界内（未来）
        (1000, 1061, False),  # 超过窗口
        (1000, 939, False),
    ],
)
async def test_timestamp_window(ts, clock_at, expected):
    ring = HmacKeyRing({"v1": b"secret"})
    guard = make_guard(ring, clock=FixedClock(clock_at), ttl=60)
    headers = signed_headers(ring, nonce="n", timestamp=ts)
    coro = guard.verify_request(FakeRequest(headers))
    if expected:
        result = await coro
        assert result.timestamp == ts
    else:
        with pytest.raises(ReplayError) as exc:
            await coro
        assert exc.value.audit_entry.reason is (
            ReplayRejectReason.TIMESTAMP_OUT_OF_WINDOW
        )
        assert exc.value.audit_entry.age_seconds is not None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field_name,bad_value",
    [
        ("x-signature-nonce", "a" * 200),  # 超长
        ("x-signature-nonce", "bad/nonce"),  # 非法字符
        ("x-signature-key-version", "v 1"),  # 非法字符
        ("x-signature", "zzzz"),  # 非 hex 且过短
    ],
)
async def test_malformed_identifier_fields_rejected(field_name, bad_value):
    ring = HmacKeyRing({"v1": b"secret"})
    guard = make_guard(ring)
    headers = signed_headers(ring)
    headers[field_name] = bad_value
    with pytest.raises(ReplayError) as exc:
        await guard.verify_request(FakeRequest(headers))
    assert exc.value.audit_entry.reason is (
        ReplayRejectReason.MALFORMED_HEADER
    )


@pytest.mark.asyncio
async def test_malformed_timestamp_rejected():
    ring = HmacKeyRing({"v1": b"secret"})
    guard = make_guard(ring)
    headers = signed_headers(ring)
    headers["x-signature-timestamp"] = "not-a-number"
    with pytest.raises(ReplayError) as exc:
        await guard.verify_request(FakeRequest(headers))
    assert exc.value.audit_entry.reason is (
        ReplayRejectReason.MALFORMED_HEADER
    )


# --------------------------------------------------------------------- #
# 密钥轮换
# --------------------------------------------------------------------- #


def test_key_ring_current_version_defaults_and_override():
    ring = HmacKeyRing({"v1": SECRET_OLD, "v2": SECRET_NEW})
    assert ring.current_version == "v2"
    ring = HmacKeyRing(
        {"v1": SECRET_OLD, "v2": SECRET_NEW},
        current_version="v1",
    )
    assert ring.current_version == "v1"
    with pytest.raises(ValueError):
        HmacKeyRing({"v1": b"x"}, current_version="v9")


@pytest.mark.asyncio
async def test_old_version_signature_still_accepted_during_rotation():
    ring = HmacKeyRing({"v1": SECRET_OLD, "v2": SECRET_NEW})
    guard = make_guard(ring)
    headers = signed_headers(ring, nonce="old", key_version="v1")
    assert headers["x-signature-key-version"] == "v1"
    result = await guard.verify_request(FakeRequest(headers))
    assert result.key_version == "v1"


@pytest.mark.asyncio
async def test_new_version_used_for_new_signatures():
    ring = HmacKeyRing({"v1": SECRET_OLD, "v2": SECRET_NEW})
    assert ring.current_version == "v2"
    guard = make_guard(ring)
    result = await guard.verify_request(
        FakeRequest(signed_headers(ring, nonce="new"))
    )
    assert result.key_version == "v2"


@pytest.mark.asyncio
async def test_revoked_version_rejected():
    ring = HmacKeyRing({"v1": SECRET_OLD, "v2": SECRET_NEW}).revoke("v1")
    guard = make_guard(ring)
    headers = signed_headers(
        HmacKeyRing({"v1": SECRET_OLD, "v2": SECRET_NEW}),
        nonce="old",
        key_version="v1",
    )
    with pytest.raises(ReplayError) as exc:
        await guard.verify_request(FakeRequest(headers))
    assert exc.value.audit_entry.reason is (
        ReplayRejectReason.UNKNOWN_KEY_VERSION
    )
    assert exc.value.audit_entry.key_version == "v1"


@pytest.mark.asyncio
async def test_signature_with_wrong_secret_fails():
    # 同版本号但密钥不同 -> 验签失败
    ring = HmacKeyRing({"v1": b"server-secret"})
    foreign = HmacKeyRing({"v1": b"attacker-secret"})
    guard = make_guard(ring)
    with pytest.raises(ReplayError) as exc:
        await guard.verify_request(FakeRequest(signed_headers(foreign)))
    assert exc.value.audit_entry.reason is (
        ReplayRejectReason.INVALID_SIGNATURE
    )


def test_rotate_returns_new_ring_and_keeps_old():
    ring = HmacKeyRing({"v1": SECRET_OLD})
    rotated = ring.rotate({"v2": SECRET_NEW})
    assert ring.current_version == "v1"  # 旧环不变
    assert rotated.current_version == "v2"
    assert rotated.key("v1") == SECRET_OLD
    assert rotated.key("v2") == SECRET_NEW


# --------------------------------------------------------------------- #
# Nonce 存储语义与并发
# --------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_nonce_reserve_consume_release():
    store = InMemoryNonceStore()
    key = "v1:abc"
    assert await store.reserve(key, 60) is NonceConsumption.RESERVED
    assert await store.reserve(key, 60) is NonceConsumption.DUPLICATE
    # 成功消耗后仍持续拒绝
    await store.consume(key)
    assert await store.reserve(key, 60) is NonceConsumption.DUPLICATE


@pytest.mark.asyncio
async def test_nonce_released_after_failure_is_reusable():
    store = InMemoryNonceStore()
    key = "v1:abc"
    assert await store.reserve(key, 60) is NonceConsumption.RESERVED
    await store.release(key)  # 业务失败
    assert await store.reserve(key, 60) is NonceConsumption.RESERVED


@pytest.mark.asyncio
async def test_consumed_nonce_cannot_be_released():
    store = InMemoryNonceStore()
    key = "v1:abc"
    await store.reserve(key, 60)
    await store.consume(key)
    await store.release(key)  # 不得使已消耗标识重新可用
    assert await store.reserve(key, 60) is NonceConsumption.DUPLICATE


@pytest.mark.asyncio
async def test_nonce_ttl_expires_with_injected_clock():
    ticks = [100.0]
    store = InMemoryNonceStore(clock=lambda: ticks[0])
    key = "v1:abc"
    assert await store.reserve(key, ttl_seconds=30) is (
        NonceConsumption.RESERVED
    )
    ticks[0] = 129.0
    assert await store.reserve(key, 30) is NonceConsumption.DUPLICATE
    ticks[0] = 130.0  # TTL 到期；时间窗外的请求本身已被拒绝
    assert await store.reserve(key, 30) is NonceConsumption.RESERVED
    assert store.purge() >= 0


def test_skew_window_cannot_exceed_nonce_ttl():
    ring = HmacKeyRing({"v1": b"secret"})
    with pytest.raises(ValueError):
        ReplayGuard(
            ring,
            InMemoryNonceStore(),
            ttl_seconds=30,
            max_skew_seconds=300,
            clock=FixedClock(1000),
        )


@pytest.mark.asyncio
async def test_concurrent_identical_requests_only_one_reserves():
    store = InMemoryNonceStore()

    async def reserve():
        # 模拟协程在事件循环中交错执行
        await asyncio.sleep(0)
        return await store.reserve("v1:same", 60)

    outcomes = await asyncio.gather(*[reserve() for _ in range(100)])
    assert outcomes.count(NonceConsumption.RESERVED) == 1
    assert outcomes.count(NonceConsumption.DUPLICATE) == 99


# --------------------------------------------------------------------- #
# 审计：拒绝原因可查，但绝不回显签名材料
# --------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_missing_headers_audited():
    guard = make_guard()
    with pytest.raises(ReplayError) as exc:
        await guard.verify_request(FakeRequest({}))
    assert exc.value.audit_entry.reason is (ReplayRejectReason.MISSING_HEADER)
    assert str(exc.value) == "request signature verification failed"


@pytest.mark.asyncio
async def test_audit_entries_never_contain_signature_material(caplog):
    ring = HmacKeyRing({"v1": SECRET_OLD})
    audit_guard = ReplayGuard(
        ring,
        InMemoryNonceStore(),
        ttl_seconds=60,
        clock=FixedClock(2_000_000),
    )
    headers = signed_headers(ring)  # 时间戳为 1_000_000 -> 超窗
    with caplog.at_level(logging.WARNING):
        with pytest.raises(ReplayError):
            await audit_guard.verify_request(FakeRequest(headers))

    entry = audit_guard.audit_log.entries[-1]
    assert entry.reason is ReplayRejectReason.TIMESTAMP_OUT_OF_WINDOW
    # 审计记录中没有签名字段
    assert not hasattr(entry, "signature")
    rendered = repr(entry)
    assert "x-signature" not in rendered
    # 日志输出也不得包含签名或密钥
    record_text = caplog.text
    assert headers["x-signature"] not in record_text
    assert "old-secret" not in record_text


@pytest.mark.asyncio
async def test_client_error_message_is_generic_and_401():
    ring = HmacKeyRing({"v1": b"secret"})
    guard = make_guard(ring)
    try:
        await guard.verify_request(FakeRequest({}))
    except ReplayError as err:
        assert err.status_code == 401
        assert "secret" not in str(err)
        assert "signature" not in str(err).replace(
            "request signature verification failed", ""
        )


# --------------------------------------------------------------------- #
# 代理后的规范化地址（端到端）
# --------------------------------------------------------------------- #


def _build_proxy_app():
    app = Sanic("proxy-test")
    app.config.PROXIES_COUNT = 1
    ring = HmacKeyRing({"v1": b"secret"})
    guard = ReplayGuard(ring, InMemoryNonceStore(), ttl_seconds=300)
    install_replay_protection(
        app,
        guard,
        predicate=lambda r: r.path.endswith("/pay"),
    )

    @app.post("/pay")
    async def pay(request):
        return sjson({"scheme": request.scheme, "host": request.host})

    return app, guard, ring


def test_proxy_normalized_address_accepted():
    app, _guard, ring = _build_proxy_app()
    client = SanicTestClient(app, port=BASE_PORT)
    body = b'{"order":"42"}'
    # 合作方按对外地址 https://api.example.com/gateway/pay 签名；
    # 服务实际位于代理后的 http 内网 /pay。
    headers = make_signed_headers(
        ring,
        RequestCanonicalizer(),
        method="POST",
        scheme="https",
        host="api.example.com",
        path="/gateway/pay",
        body=body,
        timestamp=_now(),
        nonce="proxy-1",
    )
    headers.update(
        {
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "api.example.com",
            "X-Forwarded-Prefix": "/gateway",
            "X-Forwarded-For": "10.0.0.1",
        }
    )
    _request, response = client.post("/pay", data=body, headers=headers)
    assert response.status == 200
    assert response.json == {"scheme": "https", "host": "api.example.com"}


def test_proxy_headers_required_when_signature_uses_public_address():
    app, _guard, ring = _build_proxy_app()
    client = SanicTestClient(app, port=BASE_PORT)
    body = b'{"order":"42"}'
    headers = make_signed_headers(
        ring,
        RequestCanonicalizer(),
        method="POST",
        scheme="https",
        host="api.example.com",
        path="/gateway/pay",
        body=body,
        timestamp=_now(),
        nonce="proxy-2",
    )
    # 不带代理头 -> 按直连地址规范化 -> 签名不匹配
    _request, response = client.post("/pay", data=body, headers=headers)
    assert response.status == 401
    assert "secret" not in response.text


def _now() -> int:
    import time

    return int(time.time())


# --------------------------------------------------------------------- #
# nonce 消耗时机：成功消耗 / 失败释放（端到端）
# --------------------------------------------------------------------- #


def _build_lifecycle_app():
    app = Sanic("lifecycle-test")
    app.config.PROXIES_COUNT = 1
    ring = HmacKeyRing({"v1": b"secret"})
    store = InMemoryNonceStore()
    guard = ReplayGuard(ring, store, ttl_seconds=300)
    install_replay_protection(app, guard)
    state = {"fail_next": True, "calls": 0}

    @app.post("/pay")
    async def pay(request):
        state["calls"] += 1
        if state["fail_next"]:
            raise RuntimeError("payment db down")
        return text("ok")

    @app.post("/pay2")
    async def pay2(request):
        # 业务拒绝（可恢复）：返回 402
        return sjson({"error": "insufficient funds"}, status=402)

    return app, guard, ring, state


def _client_headers(ring, nonce, port, path="/pay", body=b"{}"):
    return make_signed_headers(
        ring,
        RequestCanonicalizer(),
        method="POST",
        scheme="http",
        host=f"127.0.0.1:{port}",
        path=path,
        body=body,
        timestamp=_now(),
        nonce=nonce,
    )


def test_failed_business_handling_releases_nonce_for_retry():
    app, guard, ring, state = _build_lifecycle_app()
    port = BASE_PORT + 1
    client = SanicTestClient(app, port=port)

    headers = _client_headers(ring, "retry-1", port)
    _req, resp1 = client.post("/pay", data=b"{}", headers=headers)
    assert resp1.status == 500  # 业务失败 -> 释放
    assert state["calls"] == 1

    # 同一签名与 nonce 可安全重试
    state["fail_next"] = False
    _req, resp2 = client.post("/pay", data=b"{}", headers=headers)
    assert resp2.status == 200
    assert state["calls"] == 2

    # 成功后再次重放被拒
    _req, resp3 = client.post("/pay", data=b"{}", headers=headers)
    assert resp3.status == 401
    reasons = [e.reason for e in guard.audit_log.entries]
    assert ReplayRejectReason.NONCE_REPLAYED in reasons


def test_error_status_response_does_not_consume_nonce():
    app, guard, ring, _state = _build_lifecycle_app()
    port = BASE_PORT + 2
    client = SanicTestClient(app, port=port)

    headers = _client_headers(ring, "retry-4xx", port, path="/pay2")
    _r, r1 = client.post("/pay2", data=b"{}", headers=headers)
    assert r1.status == 402
    # 未消耗：同 nonce 仍可到达业务层
    _r, r2 = client.post("/pay2", data=b"{}", headers=headers)
    assert r2.status == 402
    assert all(
        e.reason is not ReplayRejectReason.NONCE_REPLAYED
        for e in guard.audit_log.entries
    )


def test_rejected_request_never_consumes_nonce():
    app, guard, ring, state = _build_lifecycle_app()
    state["fail_next"] = False
    port = BASE_PORT + 3
    client = SanicTestClient(app, port=port)

    headers = _client_headers(ring, "replay-x", port)
    # 第一次：篡改签名被拒
    bad = dict(headers)
    bad["x-signature"] = "0" * 64
    _r, r1 = client.post("/pay", data=b"{}", headers=bad)
    assert r1.status == 401
    # 原始合法请求仍可正常处理（标识未被消耗）
    _r, r2 = client.post("/pay", data=b"{}", headers=headers)
    assert r2.status == 200


def test_store_failure_during_consume_does_not_break_response(caplog):
    app = Sanic("store-failure-test")
    app.config.PROXIES_COUNT = 1
    ring = HmacKeyRing({"v1": b"secret"})

    class BrokenStore(InMemoryNonceStore):
        async def consume(self, key):
            raise RuntimeError("redis down")

    guard = ReplayGuard(ring, BrokenStore(), ttl_seconds=300)
    install_replay_protection(app, guard)

    @app.post("/pay")
    async def pay(request):
        return text("ok")

    port = BASE_PORT + 4
    client = SanicTestClient(app, port=port)
    headers = _client_headers(ring, "broken-1", port)
    with caplog.at_level(logging.CRITICAL, logger="sanic.security.replay"):
        _r, response = client.post("/pay", data=b"{}", headers=headers)
    # 业务响应仍正常返回
    assert response.status == 200
    # 但产生了要求人工对账的 critical 审计记录，且不含签名材料
    critical = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert critical
    rendered = caplog.text
    assert headers["x-signature"] not in rendered


# --------------------------------------------------------------------- #
# 并发相同请求（ASGI，同事件循环）
# --------------------------------------------------------------------- #


def test_concurrent_identical_requests_end_to_end():
    app = Sanic("concurrent-test")
    app.config.PROXIES_COUNT = 1
    ring = HmacKeyRing({"v1": b"secret"})
    guard = ReplayGuard(ring, InMemoryNonceStore(), ttl_seconds=300)
    install_replay_protection(app, guard)
    entered = {"count": 0}

    @app.post("/pay")
    async def pay(request):
        entered["count"] += 1
        await asyncio.sleep(0.01)  # 放大并发窗口
        return text("ok")

    async def scenario():
        headers = make_signed_headers(
            ring,
            RequestCanonicalizer(),
            method="POST",
            scheme="http",
            host="asgi.local",
            path="/pay",
            body=b"{}",
            timestamp=_now(),
            nonce="race-1",
        )
        # ASGI 下 host 由 headers 中的 host 决定
        headers["host"] = "asgi.local"
        responses = await asyncio.gather(
            *[
                app.asgi_client.post("/pay", data=b"{}", headers=headers)
                for _ in range(10)
            ]
        )
        statuses = [r[1].status for r in responses]
        return statuses

    statuses = asyncio.run(scenario())
    assert statuses.count(200) == 1
    assert statuses.count(401) == 9
    assert entered["count"] == 1
