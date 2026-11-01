"""身份与密钥托管。

策略（SBP-0.4 §密钥托管）：
  * 私钥只在这台机器上生成、只落在这台机器的 .env 里，永远不上中继；
  * 第一次启动全部随机生成，之后固化 —— 用户可以手改 .env 再重启来换成自己的密钥；
  * 客户端（网页控制台 / 微信小程序）的密钥也在这里一并生成，这样 .copy4client
    里的连接串是自洽的：agent 已经把对应公钥登记进 SBP_E2EE_PEERS，中继那边
    只要认公钥就行。

.env 里的字段：
  SBP_E2EE_DID        设备 id（会话 scope 的前缀，客户端要用它算 tag）
  SBP_E2EE_KEY_ID     本设备在公钥目录里的 keyId（默认 = DID）
  SBP_E2EE_KEY        box_sk_b64:sign_sk_b64    ← 私钥
  SBP_E2EE_RK         路由密钥（64-hex 原始密钥，或口令 → Argon2id）
  SBP_E2EE_PEERS      peerId:box_pk:sign_pk,... ← 允许连进来的客户端公钥
  SBP_CLIENT_KEYS     peerId:box_sk:sign_sk,... ← 客户端私钥，用于导出 .copy4client
  SBP_BRIDGE_E2EE     中继地址 wss://host/ws-e2ee
"""
from __future__ import annotations

import os
import re
import secrets
import socket
from dataclasses import dataclass, field
from pathlib import Path

from sbp_client.crypto import KeyPair, b64e

ENV_FILE = ".env"

# 默认给两台客户端各发一份身份：网页控制台 + 微信小程序
CLIENT_PRESETS = (
    ("cli-web", "网页控制台"),
    ("cli-minis", "微信小程序"),
)


# --------------------------------------------------------------------- 模型
@dataclass
class ClientIdentity:
    key_id: str
    label: str
    box_sk: str      # base64url，私钥
    sign_sk: str     # base64url，64 字节 libsodium 形态
    box_pk: str
    sign_pk: str


@dataclass
class Identity:
    did: str
    key_id: str
    box_sk: str
    sign_sk: str
    box_pk: str
    sign_pk: str
    rk: str                                  # 64-hex
    relay: str                               # wss://host/ws-e2ee
    clients: list = field(default_factory=list)

    def peers_env(self) -> str:
        return ",".join(f"{c.key_id}:{c.box_pk}:{c.sign_pk}" for c in self.clients)

    def client_keys_env(self) -> str:
        return ",".join(f"{c.key_id}:{c.box_sk}:{c.sign_sk}" for c in self.clients)

    def trusted_keys_env(self) -> str:
        """给 sbp-dispatcher 的 SBP_TRUSTED_KEYS（keyId:sign_pk[:box_pk]）。"""
        parts = [f"{self.key_id}:{self.sign_pk}:{self.box_pk}"]
        parts += [f"{c.key_id}:{c.sign_pk}:{c.box_pk}" for c in self.clients]
        return ",".join(parts)


# --------------------------------------------------------------------- .env
def _env_path() -> Path:
    return Path(os.environ.get("SBP_ENV_FILE", "") or (Path.cwd() / ENV_FILE))


def load_env_file() -> None:
    p = _env_path()
    if not p.exists():
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(p, override=False)
    except Exception:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def env_file_keys() -> set:
    """已在 .env 里出现过的键（含被注释掉的）。"""
    p = _env_path()
    if not p.exists():
        return set()
    keys = set()
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip().lstrip("#").strip()
        if "=" not in line:
            continue
        keys.add(line.split("=", 1)[0].strip())
    return keys


def update_env_file(pairs: dict, header: str = "") -> Path:
    """把 pairs 写进 .env：已存在的键就地替换，没有的追加到末尾（不动其他键）。"""
    p = _env_path()
    lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    out, seen = [], set()
    pat = {k: re.compile(rf"^#?\s*{re.escape(k)}\s*=") for k in pairs}
    for line in lines:
        hit = None
        for k, rx in pat.items():
            if rx.match(line):
                hit = k
                break
        if hit:
            out.append(f"{hit}={pairs[hit]}")
            seen.add(hit)
        else:
            out.append(line)
    rest = {k: v for k, v in pairs.items() if k not in seen}
    if rest:
        if header:
            out += ["", header]
        out += [f"{k}={v}" for k, v in rest.items()]
    txt = "\n".join(out).rstrip() + "\n"
    p.write_text(txt, encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    os.environ.update(pairs)
    return p


# ------------------------------------------------------------------ 生成 / 解析
def _new_kp() -> dict:
    return KeyPair.generate().to_strings()


def _default_did() -> str:
    try:
        host = socket.gethostname().split(".")[0]
    except OSError:
        host = "host"
    host = re.sub(r"[^A-Za-z0-9_-]", "", host)[:16] or "host"
    return f"dev-{host}-{secrets.token_hex(2)}"


def _parse_triples(raw: str):
    """'a:b:c,d:e:f' -> [('a','b','c'), ...]"""
    out = []
    for part in (raw or "").split(","):
        part = part.strip()
        if part.count(":") < 2:
            continue
        a, b, c = part.split(":", 2)
        a, b, c = a.strip(), b.strip(), c.strip()
        if a and b and c:
            out.append((a, b, c))
    return out


def ensure_identity(relay: str = "") -> Identity:
    """读 .env；缺什么生成什么，然后把新生成的部分写回 .env。"""
    load_env_file()

    did = (os.environ.get("SBP_E2EE_DID") or "").strip()
    key_id = (os.environ.get("SBP_E2EE_KEY_ID") or "").strip()
    rk = (os.environ.get("SBP_E2EE_RK") or "").strip()
    relay = (relay or os.environ.get("SBP_BRIDGE_E2EE") or "").strip()

    raw_key = (os.environ.get("SBP_E2EE_KEY") or "").strip()
    box_sk = sign_sk = ""
    if raw_key.count(":") >= 1:
        box_sk, sign_sk = raw_key.split(":", 1)
        box_sk, sign_sk = box_sk.strip(), sign_sk.strip()

    fresh = {}
    if not did:
        did = _default_did()
        fresh["SBP_E2EE_DID"] = did
    if not key_id:
        key_id = did
        fresh["SBP_E2EE_KEY_ID"] = key_id
    if not rk:
        rk = secrets.token_hex(32)          # 64-hex → 直接当 32 字节原始 rk
        fresh["SBP_E2EE_RK"] = rk
    if not (box_sk and sign_sk):
        kp = _new_kp()
        box_sk, sign_sk = kp["box_sk"], kp["sign_sk"]
        fresh["SBP_E2EE_KEY"] = f"{box_sk}:{sign_sk}"

    # ---- 客户端身份：SBP_CLIENT_KEYS 里有就复用，缺的在末尾补
    have = {}
    for cid, cbox, csig in _parse_triples(os.environ.get("SBP_CLIENT_KEYS", "")):
        have[cid] = (cbox, csig)
    clients: list[ClientIdentity] = []
    changed = False
    for cid, label in CLIENT_PRESETS:
        if cid in have:
            cbox, csig = have[cid]
            kp = KeyPair.from_strings(cbox, csig)
            pub = {"box_pk": b64e(bytes(kp.box_sk.public_key)),
                   "sign_pk": b64e(bytes(kp.sign_sk.verify_key))}
        else:
            kp = _new_kp()
            cbox, csig = kp["box_sk"], kp["sign_sk"]
            pub = {"box_pk": kp["box_pk"], "sign_pk": kp["sign_pk"]}
            changed = True
        clients.append(ClientIdentity(cid, label, cbox, csig, pub["box_pk"], pub["sign_pk"]))
    # 用户自定义的额外客户端（不在预设名单里的）也带上
    for cid, (cbox, csig) in have.items():
        if any(c.key_id == cid for c in clients):
            continue
        kp = KeyPair.from_strings(cbox, csig)
        clients.append(ClientIdentity(cid, cid, cbox, csig,
                                      b64e(bytes(kp.box_sk.public_key)),
                                      b64e(bytes(kp.sign_sk.verify_key))))

    # 设备自身公钥
    dev = KeyPair.from_strings(box_sk, sign_sk)
    ident = Identity(
        did=did, key_id=key_id, box_sk=box_sk, sign_sk=sign_sk,
        box_pk=b64e(bytes(dev.box_sk.public_key)),
        sign_pk=b64e(bytes(dev.sign_sk.verify_key)),
        rk=rk, relay=relay, clients=clients,
    )

    if changed:
        fresh["SBP_CLIENT_KEYS"] = ident.client_keys_env()
    # 命令行 / 环境变量给的中继地址也固化下来，下次直接启动就能连
    if relay and "SBP_BRIDGE_E2EE" not in env_file_keys():
        fresh["SBP_BRIDGE_E2EE"] = relay
    if fresh:
        fresh["SBP_E2EE_PEERS"] = ident.peers_env()
        update_env_file(fresh, header="# ---- SBP E2EE（端到端加密）· 自动生成，可手改后重启 ----")

    os.environ["SBP_E2EE_DID"] = did
    os.environ["SBP_E2EE_KEY_ID"] = key_id
    os.environ["SBP_E2EE_KEY"] = f"{box_sk}:{sign_sk}"
    os.environ["SBP_E2EE_RK"] = rk
    os.environ["SBP_E2EE_PEERS"] = ident.peers_env()
    os.environ["SBP_CLIENT_KEYS"] = ident.client_keys_env()
    if relay:
        os.environ["SBP_BRIDGE_E2EE"] = relay
    return ident


__all__ = ["Identity", "ClientIdentity", "ensure_identity", "load_env_file", "update_env_file"]
