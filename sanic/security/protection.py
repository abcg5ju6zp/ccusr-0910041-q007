"""把 :class:`ReplayGuard` 接入 Sanic 请求处理链。

nonce 生命周期与处理链的对应关系::

    请求进入
      │  request 中间件：验签 + reserve（原子预占）
      │     校验失败 → 抛 ReplayError，标识 *未消耗*
      ▼
    业务 handler
      │  成功 → http.lifecycle.response 信号 → consume（最终消耗）
      └  失败 → http.lifecycle.exception 信号 → release（释放，可重试）

选择信号而非 response 中间件来感知失败，是因为 handler 抛异常后 Sanic
不会运行 response 中间件，但 ``http.lifecycle.exception`` 与
``http.lifecycle.response`` 两个信号在两条路径上都会分发。
"""

from __future__ import annotations

import logging

from collections.abc import Callable
from typing import Any

from sanic.request.types import Request
from sanic.signals import Event

from .replay import (
    HmacKeyRing,
    ReplayError,
    ReplayGuard,
    ReplayResult,
    RequestCanonicalizer,
    Signer,
)


_RESULT_ATTR = "_sanic_security_replay_result"
_FAILED_ATTR = "_sanic_security_replay_failed"

_protection_logger = logging.getLogger("sanic.security.replay")


def install_replay_protection(
    app: Any,
    guard: ReplayGuard,
    *,
    predicate: Callable[[Request], bool] | None = None,
) -> ReplayGuard:
    """在应用上安装防重放 request 中间件 + consume/release 信号。

    :param app: ``Sanic`` 应用（也支持蓝图组合后的应用级安装）。
    :param guard: 配置好密钥环、nonce 存储、时钟等的校验器。
    :param predicate: 可选的请求过滤条件，只对返回 ``True`` 的请求
        强制校验，例如 ``lambda r: r.path.startswith("/callbacks")``。
    :returns: 传入的 ``guard``，便于链式使用与测试断言。
    """

    @app.on_request
    async def replay_protection_request(request: Request) -> None:
        if predicate is not None and not predicate(request):
            return
        # 防止极端情况下错误处理路径重入中间件导致二次预占。
        if getattr(request.ctx, _RESULT_ATTR, None) is not None:
            return
        # 校验失败直接抛出：ReplayError 不消耗任何标识。
        result = await guard.verify_request(request)
        setattr(request.ctx, _RESULT_ATTR, result)

    @app.signal(Event.HTTP_LIFECYCLE_EXCEPTION.value)
    async def replay_protection_exception(
        request: Request, exception: BaseException
    ) -> None:
        result: ReplayResult | None = getattr(request.ctx, _RESULT_ATTR, None)
        if result is None or isinstance(exception, ReplayError):
            return
        # 业务（或后续中间件）失败：释放预占，调用方可安全重试。
        setattr(request.ctx, _RESULT_ATTR, None)
        setattr(request.ctx, _FAILED_ATTR, True)
        await _safe_mark(guard.mark_failed, result)

    @app.signal(Event.HTTP_LIFECYCLE_RESPONSE.value)
    async def replay_protection_response(request: Request, response: Any):
        result: ReplayResult | None = getattr(request.ctx, _RESULT_ATTR, None)
        if result is None:
            return
        if getattr(request.ctx, _FAILED_ATTR, False):
            return
        if getattr(response, "status", 200) >= 400:
            # 业务自身返回了错误响应：按“未成功处理”处理，释放标识，
            # 允许合作方修正后用同一 nonce 重试。
            setattr(request.ctx, _RESULT_ATTR, None)
            await _safe_mark(guard.mark_failed, result)
            return
        setattr(request.ctx, _RESULT_ATTR, None)
        await _safe_mark(guard.mark_succeeded, result)

    return guard


async def _safe_mark(action, result: ReplayResult) -> None:
    """执行消耗/释放；存储故障不得影响已生成的业务响应。

    失败时记录 critical 级日志（nonce 处于未知状态，必须通过对账
    人工确认，避免支付状态被重复推进）。
    """
    try:
        await action(result)
    except Exception:  # noqa: BLE001 - 存储后端故障时只记录
        _protection_logger.critical(
            "nonce state transition failed; manual reconciliation "
            "required: key_version=%s nonce=%s",
            result.key_version,
            result.nonce,
            exc_info=True,
        )


def make_signed_headers(
    key_ring: HmacKeyRing,
    canonicalizer: RequestCanonicalizer,
    *,
    method: str,
    scheme: str,
    host: str,
    path: str,
    query: list[tuple[str, str]] | bytes = b"",
    body: bytes = b"",
    timestamp: int | str,
    nonce: str,
    key_version: str | None = None,
    header_name: str = "x-signature",
    timestamp_header: str = "x-signature-timestamp",
    nonce_header: str = "x-signature-nonce",
    key_version_header: str = "x-signature-key-version",
) -> dict[str, str]:
    """为测试或合作方 SDK 生成一整套签名头。

    签名主体与服务端 :class:`RequestCanonicalizer` 完全一致。
    """
    version = key_version or key_ring.current_version
    canonical = canonicalizer.canonicalize_parts(
        method, scheme, host, path, query, body
    )
    signature = Signer(key_ring).sign(
        canonical, timestamp, nonce, key_version=version
    )
    return {
        header_name: signature,
        timestamp_header: str(timestamp),
        nonce_header: nonce,
        key_version_header: version,
    }


__all__ = (
    "install_replay_protection",
    "make_signed_headers",
)
