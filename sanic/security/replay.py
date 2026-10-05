"""可复用的回调签名校验与防重放组件。

设计要点
========

* 签名主体 (:class:`RequestCanonicalizer`) 把请求方法、规范化地址
  （经可信代理头还原）与请求体序列化为字节串；签名覆盖该主体。
* 签名头同时携带 **时间戳**、**一次性标识 (nonce)** 与 **密钥版本**，
  四者与签名主体绑定，缺一不可。
* :class:`ReplayGuard` 依次执行：头存在性 -> 标识格式 -> 时间窗 ->
  取密钥 -> 验签 -> nonce 预占。任何一步失败都通过
  :class:`ReplayAuditLog` 记录可审计的拒绝原因，但对外只返回不含任何
  签名材料的固定消息。
* nonce 的消耗分两阶段：

  - ``reserve``  在业务处理前原子预占（并发的相同请求只有一个胜出）；
  - ``consume``  业务处理 *成功* 后最终消耗；
  - ``release``  业务处理 *失败*（抛异常）后释放预占，允许调用方
    在故障恢复后用同一标识重试。

  被拒绝的重放请求从未通过校验，自然不消耗标识。
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import logging
import re
import time

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlencode

from sanic.exceptions import SanicException
from sanic.request.types import Request


logger = logging.getLogger("sanic.security.replay")

# 标识类字段的格式与长度限制，防止恶意超长值灌爆 nonce 存储/日志。
_NONCE_RE = re.compile(r"[A-Za-z0-9._\-]{1,128}")
_KEY_VERSION_RE = re.compile(r"[A-Za-z0-9._\-]{1,32}")
_SIGNATURE_RE = re.compile(r"[A-Fa-f0-9]{16,256}")

# --------------------------------------------------------------------- #
# 时钟
# --------------------------------------------------------------------- #


@runtime_checkable
class AbstractClock(Protocol):
    """可注入时钟，便于在测试中确定时间。"""

    def now(self) -> float:
        """返回当前 Unix 时间戳（秒）。"""
        ...


class SystemClock:
    """基于系统时间的默认时钟。"""

    def now(self) -> float:
        return time.time()


# --------------------------------------------------------------------- #
# 密钥环与签名
# --------------------------------------------------------------------- #


class UnknownKeyVersion(Exception):
    """签名头引用的密钥版本不存在。"""

    def __init__(self, key_version: str) -> None:
        # 密钥版本属于标识而非秘密，保留它有助于轮换排查。
        super().__init__(f"unknown key version: {key_version}")
        self.key_version = key_version


class HmacKeyRing:
    """支持轮换的 HMAC 密钥环。

    每个密钥以版本号标识，例如::

        ring = HmacKeyRing({"v1": b"old-secret", "v2": b"new-secret"})
        ring.current_version  # 默认取最大版本号 -> "v2"

    验签接受环内的 *任意* 版本（宽限旧版本，便于灰度轮换）；
    新签名只使用 :attr:`current_version`。轮换即向环中加入新版本并把
    流量切到新版本，确认旧版本不再出现后将其移除。
    """

    def __init__(
        self,
        keys: dict[str, bytes | str],
        *,
        current_version: str | None = None,
        digest: str = "sha256",
    ) -> None:
        if not keys:
            raise ValueError("HmacKeyRing requires at least one key")
        versions = frozenset(keys)
        if current_version is not None:
            if current_version not in versions:
                raise ValueError(
                    f"current_version {current_version!r} not in key ring"
                )
            self._current_version = current_version
        else:
            # 版本号按字符串排序取最大；调用方也可显式指定。
            self._current_version = max(versions)
        self._keys: dict[str, bytes] = {
            version: self._to_bytes(secret) for version, secret in keys.items()
        }
        self._digest = digest

    @staticmethod
    def _to_bytes(secret: bytes | str) -> bytes:
        if isinstance(secret, str):
            return secret.encode("utf-8")
        return secret

    @property
    def current_version(self) -> str:
        return self._current_version

    @property
    def digest(self) -> str:
        return self._digest

    def key(self, version: str) -> bytes:
        try:
            return self._keys[version]
        except KeyError:
            raise UnknownKeyVersion(version) from None

    def rotate(
        self,
        keys: dict[str, bytes | str] | None = None,
        *,
        current_version: str | None = None,
    ) -> "HmacKeyRing":
        """返回带新增/替换密钥的新密钥环（不可变轮换）。

        传入的密钥按版本合并进现有环；被显式置为 ``None`` 的版本
        通过 :meth:`revoke` 移除。这里只处理“加入新版本”。
        """
        merged: dict[str, bytes | str] = {
            version: secret for version, secret in self._keys.items()
        }
        if keys:
            merged.update(keys)
        return HmacKeyRing(
            merged, current_version=current_version, digest=self._digest
        )

    def revoke(self, version: str) -> "HmacKeyRing":
        """返回移除指定旧版本的新密钥环。"""
        remaining: dict[str, bytes | str] = {
            ver: secret for ver, secret in self._keys.items() if ver != version
        }
        current = (
            self._current_version if self._current_version != version else None
        )
        return HmacKeyRing(
            remaining, current_version=current, digest=self._digest
        )


class Signer:
    """生成与校验签名。

    签名输入为::

        canonical_request || b"\\n" || timestamp || b"." || key_version
            || b"." || nonce

    即签名 *同时覆盖* 请求主体、时间窗材料、密钥版本与一次性标识，
    攻击者无法把合法签名嫁接给另一个请求、时间或 nonce。
    """

    def __init__(self, key_ring: HmacKeyRing) -> None:
        self._key_ring = key_ring

    def _signed_payload(
        self,
        canonical: bytes,
        timestamp: str,
        key_version: str,
        nonce: str,
    ) -> bytes:
        return b"\n".join(
            [
                canonical,
                b".".join(
                    [
                        timestamp.encode("ascii"),
                        key_version.encode("utf-8"),
                        nonce.encode("utf-8"),
                    ]
                ),
            ]
        )

    def sign(
        self,
        canonical: bytes,
        timestamp: str | int | float,
        nonce: str,
        *,
        key_version: str | None = None,
    ) -> str:
        """为请求主体生成十六进制 HMAC 摘要。"""
        version = key_version or self._key_ring.current_version
        ts = str(int(timestamp))
        payload = self._signed_payload(canonical, ts, version, nonce)
        return hmac.new(
            self._key_ring.key(version), payload, self._key_ring.digest
        ).hexdigest()

    def verify(
        self,
        canonical: bytes,
        timestamp: str,
        key_version: str,
        nonce: str,
        signature: str,
    ) -> bool:
        """常量时间比较校验签名。

        未知密钥版本返回 ``False``（交由上层统一审计），不抛出密钥信息。
        """
        try:
            secret = self._key_ring.key(key_version)
        except UnknownKeyVersion:
            return False
        expected = hmac.new(
            secret,
            self._signed_payload(canonical, timestamp, key_version, nonce),
            self._key_ring.digest,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)


# --------------------------------------------------------------------- #
# 请求规范化
# --------------------------------------------------------------------- #


class RequestCanonicalizer:
    """把请求序列化为稳定的签名字节串。

    地址规范化规则：

    * 当 ``proxy=True`` 时，地址取自 Sanic 依据 ``X-Forwarded-*`` /
      ``Forwarded`` 解析出的 :attr:`Request.scheme` 与主机，保证代理
      前后签名一致；``X-Forwarded-Prefix`` 会被还原到路径前；
    * 其余情况取直连的 scheme/host；
    * 查询串按参数名+值排序，消除顺序差异；
    * 路径末尾斜杠归一化（``/pay/`` 与 ``/pay`` 视为同一地址，
      可通过 ``strip_trailing_slash=False`` 关闭）。
    """

    def __init__(
        self,
        *,
        proxy: bool = True,
        strip_trailing_slash: bool = True,
    ) -> None:
        self._proxy = proxy
        self._strip_trailing_slash = strip_trailing_slash

    def _authority(self, request: Request) -> tuple[str, str]:
        if self._proxy:
            # request.scheme / request.host 已依据可信代理头
            # （X-Forwarded-Proto / X-Forwarded-Host）还原。
            scheme = request.scheme
            host = request.host
        else:
            ssl = bool(request.conn_info and request.conn_info.ssl)
            scheme = "https" if ssl else "http"
            host = request.headers.getone("host", "")
        return scheme, host.lower()

    def _path(self, request: Request) -> str:
        path = request.path
        prefix = ""
        if self._proxy:
            prefix = request.headers.get("x-forwarded-prefix", "")
        path = prefix.rstrip("/") + path
        if self._strip_trailing_slash and len(path) > 1:
            path = path.rstrip("/")
        return path or "/"

    def _query(self, request: Request) -> list[tuple[str, str]]:
        # 保留重复参数；按 (name, value) 排序后规范化编码。
        return sorted(
            (name, value)
            for name, values in (request.args or {}).items()
            for value in values
        )

    def _host_bytes(self, host: str) -> bytes:
        # host 可能带端口（127.0.0.1:8000）；只对主机名部分做 IDNA，
        # IPv4/IPv6 字面量与端口保持原样。
        if host.startswith("["):  # IPv6 字面量 [::1]:443
            name, separator, port = host.rpartition("]")
            return (name + separator + port).encode("ascii")
        if host.count(":") == 1:
            name, port = host.rsplit(":", 1)
            if port.isdigit():
                try:
                    return name.encode("idna") + f":{port}".encode("ascii")
                except UnicodeError:
                    return host.encode("ascii")
        try:
            return host.encode("idna")
        except UnicodeError:
            return host.encode("ascii")

    def canonicalize_parts(
        self,
        method: str,
        scheme: str,
        host: str,
        path: str,
        query_pairs: list[tuple[str, str]] | bytes,
        body: bytes,
    ) -> bytes:
        """与 :meth:`canonicalize` 相同的序列化，供签名方直接复用。

        ``query_pairs`` 可以是 ``(name, value)`` 列表（会排序并规范化
        编码），也可以是已经编码好的字节串。
        """
        if isinstance(query_pairs, bytes):
            query = query_pairs
        else:
            query = urlencode(sorted(query_pairs), doseq=True).encode("ascii")
        return b"\n".join(
            [
                method.upper().encode("ascii"),
                scheme.encode("ascii"),
                self._host_bytes(host.lower()),
                path.encode("utf-8"),
                query,
                bytes(body or b""),
            ]
        )

    def canonicalize(self, request: Request) -> bytes:
        scheme, host = self._authority(request)
        path = self._path(request)
        return self.canonicalize_parts(
            request.method,
            scheme,
            host,
            path,
            self._query(request),
            request.body or b"",
        )


# --------------------------------------------------------------------- #
# Nonce 存储
# --------------------------------------------------------------------- #


class NonceConsumption(enum.Enum):
    """nonce 预占结果。"""

    RESERVED = "reserved"  # 本次请求成功预占，可进入业务处理
    DUPLICATE = "duplicate"  # 已存在（进行中或已消耗），判定为重放


@runtime_checkable
class AbstractNonceStore(Protocol):
    """nonce 存储的最小接口。

    实现必须保证 :meth:`reserve` 的原子性：并发相同请求只能有一个
    得到 :attr:`NonceConsumption.RESERVED`。
    """

    async def reserve(
        self, key: str, ttl_seconds: float
    ) -> NonceConsumption: ...

    async def consume(self, key: str) -> None: ...

    async def release(self, key: str) -> None: ...


class InMemoryNonceStore:
    """进程内 nonce 存储，基于单调到期时间。

    适合单进程或作为参考实现；多实例部署应替换为带 ``SET NX PX``
    语义的 Redis 等共享存储（实现同一接口即可）。

    条目两种状态：

    * ``expires_at`` + ``consumed=False``：业务进行中的预占；
    * ``consumed=True``：业务已成功，标识被永久消耗（在 TTL 内持续
      拒绝重放，TTL 外时间窗本身已拒绝，可安全过期）。
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._entries: dict[str, tuple[float, bool]] = {}
        self._clock = clock

    def _expired(self, expires_at: float, now: float) -> bool:
        return expires_at <= now

    async def reserve(self, key: str, ttl_seconds: float) -> NonceConsumption:
        now = self._clock()
        existing = self._entries.get(key)
        if existing is not None:
            expires_at, _consumed = existing
            if not self._expired(expires_at, now):
                return NonceConsumption.DUPLICATE
        self._entries[key] = (now + ttl_seconds, False)
        return NonceConsumption.RESERVED

    async def consume(self, key: str) -> None:
        existing = self._entries.get(key)
        if existing is not None:
            expires_at, _ = existing
            self._entries[key] = (expires_at, True)

    async def release(self, key: str) -> None:
        # 仅释放“进行中”的预占；已消耗的标识绝不允许重新可用。
        existing = self._entries.get(key)
        if existing is not None and not existing[1]:
            self._entries.pop(key, None)

    def purge(self) -> int:
        """清理已过期条目，返回清理数量（维护用）。"""
        now = self._clock()
        stale = [
            key
            for key, (expires_at, _) in self._entries.items()
            if self._expired(expires_at, now)
        ]
        for key in stale:
            self._entries.pop(key, None)
        return len(stale)


# --------------------------------------------------------------------- #
# 拒绝原因与审计
# --------------------------------------------------------------------- #


class ReplayRejectReason(enum.Enum):
    MISSING_HEADER = "missing_header"
    MALFORMED_HEADER = "malformed_header"
    TIMESTAMP_OUT_OF_WINDOW = "timestamp_out_of_window"
    UNKNOWN_KEY_VERSION = "unknown_key_version"
    INVALID_SIGNATURE = "invalid_signature"
    NONCE_REPLAYED = "nonce_replayed"


@dataclass(frozen=True)
class ReplayAuditEntry:
    """一条审计记录。

    只包含排障所需的 *标识类* 信息，永远不包含签名、密钥或请求体等
    敏感材料，因此该结构可安全写入日志或审计后端。
    """

    reason: ReplayRejectReason
    key_version: str | None = None
    nonce: str | None = None
    path: str | None = None
    age_seconds: float | None = None
    detail: str | None = None


class ReplayAuditLog:
    """收集拒绝事件，同时输出结构化日志。"""

    def __init__(self, *, logger_object: Any = None) -> None:
        self._entries: list[ReplayAuditEntry] = []
        self._logger = logger_object or logger

    @property
    def entries(self) -> tuple[ReplayAuditEntry, ...]:
        return tuple(self._entries)

    def record(self, entry: ReplayAuditEntry) -> None:
        self._entries.append(entry)
        self._logger.warning(
            "rejected signed request: reason=%s key_version=%s nonce=%s "
            "path=%s age=%s detail=%s",
            entry.reason.value,
            entry.key_version,
            entry.nonce,
            entry.path,
            entry.age_seconds,
            entry.detail,
        )

    def clear(self) -> None:
        self._entries.clear()


# --------------------------------------------------------------------- #
# 对外异常
# --------------------------------------------------------------------- #


class ReplayError(SanicException):
    """签名/防重放校验失败。

    对外消息固定为通用文案，**绝不**回显签名、密钥、时间戳或请求体；
    具体拒绝原因只存在于审计日志与 ``self.audit_entry``（服务端内部）。
    """

    status_code = 401
    # 固定文案：不泄露校验进行到了哪一步，避免给攻击者提供预言机。
    message = "request signature verification failed"
    # 拒绝是常规审计事件，不应产生异常堆栈噪音。
    quiet = True

    def __init__(self, entry: ReplayAuditEntry) -> None:
        super().__init__(self.message, status_code=self.status_code)
        self.audit_entry = entry


# --------------------------------------------------------------------- #
# 校验结果
# --------------------------------------------------------------------- #


@dataclass
class ReplayResult:
    """校验通过后的上下文，供处理链完成消耗/释放。"""

    nonce_key: str
    key_version: str
    nonce: str
    timestamp: int
    canonical: bytes = field(repr=False)


# --------------------------------------------------------------------- #
# 核心门面
# --------------------------------------------------------------------- #


class ReplayGuard:
    """把签名主体、时间窗、密钥版本与一次性标识结合起来的校验器。

    典型用法（由 :func:`sanic.security.replay_protection` 接入处理链）::

        guard = ReplayGuard(
            key_ring=HmacKeyRing({"v1": b"secret"}),
            nonce_store=InMemoryNonceStore(),
        )
        result = await guard.verify_request(request)
        try:
            ...  # 业务处理
        except Exception:
            await guard.mark_failed(result)
            raise
        else:
            await guard.mark_succeeded(result)
    """

    def __init__(
        self,
        key_ring: HmacKeyRing,
        nonce_store: AbstractNonceStore | None = None,
        *,
        ttl_seconds: float = 300.0,
        max_skew_seconds: float | None = None,
        clock: AbstractClock | None = None,
        canonicalizer: RequestCanonicalizer | None = None,
        audit_log: ReplayAuditLog | None = None,
        signer: Signer | None = None,
        header_name: str = "x-signature",
        timestamp_header: str = "x-signature-timestamp",
        nonce_header: str = "x-signature-nonce",
        key_version_header: str = "x-signature-key-version",
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._key_ring = key_ring
        self._signer = signer or Signer(key_ring)
        self._store = nonce_store or InMemoryNonceStore()
        self._clock = clock or SystemClock()
        self._canonicalizer = canonicalizer or RequestCanonicalizer()
        self._audit = audit_log or ReplayAuditLog()
        self._ttl = float(ttl_seconds)
        self._max_skew = (
            float(max_skew_seconds)
            if max_skew_seconds is not None
            else self._ttl
        )
        if self._max_skew > self._ttl:
            # nonce 的保留期必须覆盖整个时间窗，否则旧请求在 nonce
            # 过期后仍落在时间窗内，会形成重放空隙。
            raise ValueError(
                "ttl_seconds must be >= max_skew_seconds "
                f"(ttl={self._ttl}, skew={self._max_skew})"
            )
        self._header_name = header_name.lower()
        self._timestamp_header = timestamp_header.lower()
        self._nonce_header = nonce_header.lower()
        self._key_version_header = key_version_header.lower()

    @property
    def audit_log(self) -> ReplayAuditLog:
        return self._audit

    @property
    def nonce_store(self) -> AbstractNonceStore:
        return self._store

    def _reject(
        self,
        reason: ReplayRejectReason,
        request: Request,
        *,
        key_version: str | None = None,
        nonce: str | None = None,
        age_seconds: float | None = None,
        detail: str | None = None,
    ) -> ReplayError:
        entry = ReplayAuditEntry(
            reason=reason,
            key_version=key_version,
            # nonce 是一次性随机标识，本身可用于关联审计，不是签名材料。
            nonce=nonce,
            path=request.path,
            age_seconds=age_seconds,
            detail=detail,
        )
        self._audit.record(entry)
        return ReplayError(entry)

    async def verify_request(self, request: Request) -> ReplayResult:
        """执行完整校验并预占 nonce；失败抛 :class:`ReplayError`。"""
        headers = request.headers
        signature = headers.get(self._header_name)
        timestamp_raw = headers.get(self._timestamp_header)
        nonce = headers.get(self._nonce_header)
        key_version = headers.get(self._key_version_header)

        # 1. 四个头必须齐备。
        if not all([signature, timestamp_raw, nonce, key_version]):
            raise self._reject(
                ReplayRejectReason.MISSING_HEADER,
                request,
                key_version=key_version,
                nonce=nonce,
            )
        assert signature is not None
        assert timestamp_raw is not None
        assert nonce is not None
        assert key_version is not None

        # 2. 标识字段必须符合格式与长度约束（防存储/日志滥用）。
        if not _NONCE_RE.fullmatch(nonce):
            raise self._reject(
                ReplayRejectReason.MALFORMED_HEADER,
                request,
                key_version=key_version,
                detail="nonce has invalid format or length",
            )
        if not _KEY_VERSION_RE.fullmatch(key_version):
            # 不回显原始值：它刚被判定为非法，可能超长或含控制字符。
            raise self._reject(
                ReplayRejectReason.MALFORMED_HEADER,
                request,
                nonce=nonce,
                detail="key version has invalid format or length",
            )
        if not _SIGNATURE_RE.fullmatch(signature):
            raise self._reject(
                ReplayRejectReason.MALFORMED_HEADER,
                request,
                key_version=key_version,
                nonce=nonce,
                detail="signature has invalid format or length",
            )

        # 3. 时间戳必须为整数秒。
        try:
            timestamp = int(timestamp_raw)
        except (TypeError, ValueError):
            raise self._reject(
                ReplayRejectReason.MALFORMED_HEADER,
                request,
                key_version=key_version,
                nonce=nonce,
                detail="timestamp is not an integer unix timestamp",
            ) from None

        # 4. 时间窗：|now - timestamp| 不得超过容差。
        now = self._clock.now()
        age = now - timestamp
        if abs(age) > self._max_skew:
            raise self._reject(
                ReplayRejectReason.TIMESTAMP_OUT_OF_WINDOW,
                request,
                key_version=key_version,
                nonce=nonce,
                age_seconds=age,
                detail=f"max skew is {self._max_skew}s",
            )

        # 5. 密钥版本必须存在（先于验签，原因可独立审计）。
        try:
            self._key_ring.key(key_version)
        except UnknownKeyVersion:
            raise self._reject(
                ReplayRejectReason.UNKNOWN_KEY_VERSION,
                request,
                key_version=key_version,
                nonce=nonce,
                age_seconds=age,
            ) from None

        # 6. 规范化请求并验签（确保 body 已接收）。
        await request.receive_body()
        canonical = self._canonicalizer.canonicalize(request)
        if not self._signer.verify(
            canonical, str(timestamp), key_version, nonce, signature
        ):
            raise self._reject(
                ReplayRejectReason.INVALID_SIGNATURE,
                request,
                key_version=key_version,
                nonce=nonce,
                age_seconds=age,
            )

        # 7. 原子预占 nonce。key 绑定密钥版本与标识，杜绝跨主体碰撞。
        nonce_key = self._nonce_key(key_version, nonce)
        outcome = await self._store.reserve(nonce_key, self._ttl)
        if outcome is NonceConsumption.DUPLICATE:
            raise self._reject(
                ReplayRejectReason.NONCE_REPLAYED,
                request,
                key_version=key_version,
                nonce=nonce,
                age_seconds=age,
            )

        return ReplayResult(
            nonce_key=nonce_key,
            key_version=key_version,
            nonce=nonce,
            timestamp=timestamp,
            canonical=canonical,
        )

    @staticmethod
    def _nonce_key(key_version: str, nonce: str) -> str:
        digest = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        return f"{key_version}:{digest}"

    async def mark_succeeded(self, result: ReplayResult) -> None:
        """业务处理成功：nonce 被最终消耗。"""
        await self._store.consume(result.nonce_key)

    async def mark_failed(self, result: ReplayResult) -> None:
        """业务处理失败：释放预占，允许同一标识稍后重试。"""
        await self._store.release(result.nonce_key)
