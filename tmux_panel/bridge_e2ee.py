"""E2EE variant of the bridge: device reports to an untrusted sbp-dispatcher.

The device still runs the same local panel logic; only the *transport* changes:
frames are sealed into SBP-0.4 envelopes (crypto_box to the pinned client box key +
Ed25519 signature) before going over the WebSocket, and incoming envelopes are opened
before being handed to the existing handlers. The relay sees only opaque tags +
ciphertext. See sbp-spec/spec/SBP-0.4-e2ee.md.
"""
from __future__ import annotations

import asyncio
import json
import os
from typing import Optional

from sbp_client import KeyPair, KeyRing, derive_rk, E2EELink, SecurityError, VERSION as E2EE_VERSION
from .bridge import Bridge, _aiohttp, now_ms, CAPS, VERSION


def load_e2ee_config():
    """Read E2EE identity + peer + routing key from env (set by the operator)."""
    key_id = os.environ.get("SBP_E2EE_KEY_ID", "dev")
    raw = os.environ.get("SBP_E2EE_KEY", "")
    if ":" not in raw:
        raise RuntimeError("E2EE 需要 SBP_E2EE_KEY=boxB64:signB64")
    box_b64, sign_b64 = raw.split(":", 1)
    rk = derive_rk(os.environ.get("SBP_E2EE_RK", ""))
    did = os.environ.get("SBP_E2EE_DID", key_id)
    peers = []
    for part in os.environ.get("SBP_E2EE_PEERS", "").split(","):
        if ":" not in part:
            continue
        pid, pv = part.split(":", 1)
        if pv.count(":") < 1:
            continue
        pb, ps = pv.split(":", 1)
        peers.append((pid.strip(), pb.strip(), ps.strip()))
    if not peers:
        raise RuntimeError("E2EE 需要 SBP_E2EE_PEERS=peerId:boxB64:signB64")
    return key_id, box_b64, sign_b64, rk, did, peers


class E2EEBridge(Bridge):
    def __init__(self, ws_url: str, hub, name: str = ""):
        super().__init__(ws_url, hub, name=name)
        key_id, box_b64, sign_b64, rk, did, peers = load_e2ee_config()
        self.kp = KeyPair.from_strings(box_b64, sign_b64)
        self.ring = KeyRing()
        # 所有登记过的客户端都进 ring：.copy2client 一次可能导出两台（网页 + 小程序）
        for pid, pb, ps in peers:
            self.ring.add(pid, pb, ps)
        self._peer_ids = [p[0] for p in peers]
        self._peer_id = self._peer_ids[0]
        self._reply_kid = self._peer_id          # 最近一次来信的人，回包定向回他
        self.rk = rk
        self.did = did
        self.link = E2EELink(self.kp, self.ring, rk, key_id, did, role="device")
        self._subscribed: set[str] = set()

    # -- scope resolution
    def _scope_for(self, obj: dict) -> str:
        sid = obj.get("sid") or (obj.get("payload") or {}).get("sid")
        return self.link.scope.session(sid) if sid else self.link.scope.device()

    def _targets(self, obj: dict) -> list:
        """回包只给来信的那个客户端；广播事件则给每个登记过的客户端各封一份。"""
        if obj.get("type") == "evt":
            return self._peer_ids
        return [self._reply_kid or self._peer_id]

    # -- outgoing: wrap every SBP frame into an envelope
    async def send(self, obj: dict) -> None:
        if self.ws is None or self.ws.closed:
            return
        scope = self._scope_for(obj)
        try:
            for kid in self._targets(obj):
                env = self.link.send(obj, scope, kid)
                await self.ws.send_json(env)
        except Exception:
            pass

    def _subscribe_session(self, sid: str) -> None:
        tag = self.link.scope.session(sid)
        if tag in self._subscribed:
            return
        self._subscribed.add(tag)
        asyncio.create_task(self.ws.send_json(self.link.subscribe(tag)) if self.ws else _noop())

    async def _subscribe_all(self) -> None:
        data = await self.hub.index()
        for g in data.get("groups") or []:
            for it in g.get("items") or []:
                sid = it.get("sid")
                if sid:
                    self._subscribe_session(sid)

    # -- 客户端直连设备（没有 server 层聚合），所以补一条控制台用的 session.list
    async def _on_req(self, frame: dict) -> None:
        name = frame.get("name")
        if name in ("session.list", "sessions.index", "session.index"):
            data = await self.hub.index(force=True)
            groups = []
            for g in data.get("groups") or []:
                items = g.get("items") or []
                gg = dict(g)
                gg.setdefault("live", True)
                gg["count"] = len(items)
                groups.append(gg)
            await self.send({
                "v": VERSION, "type": "res", "ref": frame.get("id"), "name": name,
                "ok": True, "ts": now_ms(),
                "payload": {"groups": groups, "sessions": data.get("sessions") or []},
            })
            return
        await super()._on_req(frame)

    # -- main loop (no device registration; keys are pre-trusted at the relay)
    async def run(self) -> None:
        aiohttp = _aiohttp()
        backoff = 1.0
        async with aiohttp.ClientSession() as session:
            while not self._stop:
                try:
                    async with session.ws_connect(
                        self.ws_url, protocols=(E2EE_VERSION,), heartbeat=25
                    ) as ws:
                        self.ws = ws
                        self._subscribed = set()
                        await ws.send_json(self.link.hello())
                        await ws.send_json(self.link.subscribe(self.link.scope.device()))
                        # 让服务端级/客户端能看到设备（hello.ok 之后推索引）
                        await self._push_index(force=True)
                        await self._subscribe_all()
                        self.hub.clients.add(self.sink)
                        backoff = 1.0
                        async for msg in ws:
                            if msg.type != aiohttp.WSMsgType.TEXT:
                                continue
                            env = json.loads(msg.data or "{}")
                            if env.get("ctl"):      # relay-local control, ignore
                                continue
                            kid = env.get("kid")
                            if kid and self.ring.has(kid):
                                self._reply_kid = kid      # 记住来信的人，回包定向回他
                            elif kid and kid not in self._peer_ids:
                                continue                   # 没登记过的 keyId，直接丢
                            try:
                                inner = self.link.recv(env)
                            except SecurityError:
                                continue
                            if inner.get("type") == "req":
                                await self._on_req(inner)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    print(f"  [bridge-e2ee] 断线：{exc}", file=__import__("sys").stderr, flush=True)
                finally:
                    self.hub.clients.discard(self.sink)
                    self.hub.detach_all(self.sink)
                    self.ws = None
                await asyncio.sleep(min(backoff, 30))
                backoff = min(backoff * 2, 30)


async def _noop():
    return None


def start_bridge_e2ee(hub, url: str, name: str = "") -> Optional[asyncio.Task]:
    url = (url or os.environ.get("SBP_BRIDGE_E2EE") or "").strip()
    if not url:
        return None
    b = E2EEBridge(url, hub, name=name)
    print(f"  [bridge-e2ee] 加密上报到 {url}", file=__import__("sys").stderr, flush=True)
    return asyncio.create_task(b.run(), name="sbp-bridge-e2ee")


__all__ = ["E2EEBridge", "start_bridge_e2ee", "load_e2ee_config"]
