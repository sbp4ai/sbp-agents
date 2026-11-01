"""生成「给客户端的连接信息」。

产物两个文件（都在工作目录，权限 600）：
  .copy2client   每台客户端一行 `sbp1.<base64url(json)>`，整段复制到控制台/小程序的
                 「粘贴导入」框即可，一次导入全部客户端（默认两台：网页 + 小程序）。
                 里面含客户端私钥 —— 只在可信通道里发一次，别贴到公开地方。
  .copy4relay    给 sbp-dispatcher 的 SBP_TRUSTED_KEYS= 一行（只有公钥）。

线格式与 sbp-console/e2ee.js、sbp_client 完全一致：rk 是 64-hex 原始路由密钥，
sign_sk 是 64 字节 libsodium 形态（seed||pk），两边都能直接用。
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime
from pathlib import Path

from .identity import Identity

PREFIX = "sbp1."
CONNECT_V = "sbp-connect/1"
CONSOLE_URL = "https://console.example.com/sbp-console"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def connect_payload(ident: Identity, client) -> dict:
    """一个客户端的完整连接信息（字段与 sbp-console 的服务器配置一一对应）。"""
    return {
        "v": CONNECT_V,
        "name": f"{ident.did} · {client.label}",
        "url": ident.relay,
        "e2ee": True,
        "auth": "e2ee",
        "did": ident.did,
        "myKeyId": client.key_id,
        "box_sk": client.box_sk,
        "sign_sk": client.sign_sk,
        "box_pk": client.box_pk,
        "sign_pk": client.sign_pk,
        "rk": ident.rk,
        "peerKeyId": ident.key_id,
        "peerBoxPk": ident.box_pk,
        "peerSignPk": ident.sign_pk,
    }


def encode_connect(payload: dict) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return PREFIX + _b64u(raw)


def decode_connect(line: str) -> dict:
    line = line.strip()
    if not line.startswith(PREFIX):
        raise ValueError("不是 sbp1. 连接串")
    raw = line[len(PREFIX):]
    pad = "=" * (-len(raw) % 4)
    return json.loads(base64.urlsafe_b64decode(raw + pad).decode("utf-8"))


# ------------------------------------------------------------------ 渲染
def render_copy2client(ident: Identity) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    L = [
        "# ============================================================",
        f"# SBP 连接信息 · {ident.did} · 生成于 {ts}",
        "#",
        f"# 用法：整段复制下面的内容，粘贴进 {CONSOLE_URL}",
        "#       的「服务器管理 → 粘贴导入」框，一次导入下面 "
        f"{len(ident.clients)} 台客户端。",
        "#       小程序同理（设置页 → 粘贴导入）。",
        "#",
        "# 注意：连接串里含客户端私钥，只走你自己的可信通道，别贴到公开地方。",
        "# ============================================================",
        "",
    ]
    for c in ident.clients:
        L.append(f"# {c.label}（{c.key_id}）")
        L.append(encode_connect(connect_payload(ident, c)))
        L.append("")
    if not ident.relay:
        L += [
            "# ! 还没填中继地址：在 .env 里把 SBP_BRIDGE_E2EE 设成",
            "#   wss://你的中继/ws-e2ee，重启后本文件会带上正确地址。",
            "",
        ]
    return "\n".join(L).rstrip() + "\n"


def render_copy4relay(ident: Identity) -> str:
    return (
        "# 给 sbp-dispatcher 的公钥目录（只有公钥，可以明文发给中继）\n"
        f"SBP_TRUSTED_KEYS={ident.trusted_keys_env()}\n"
    )


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def write_copy2client(ident: Identity, path: str = ".copy2client") -> Path:
    return _write(Path(path), render_copy2client(ident))


def write_copy4relay(ident: Identity, path: str = ".copy4relay") -> Path:
    return _write(Path(path), render_copy4relay(ident))


__all__ = [
    "connect_payload", "encode_connect", "decode_connect",
    "render_copy2client", "render_copy4relay",
    "write_copy2client", "write_copy4relay", "PREFIX", "CONNECT_V",
]
