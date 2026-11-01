"""CLI：端口占用自动 +1、首次启动生成 .env（含 E2EE 随机密钥）、打印访问地址与连接信息。

用法：
    python -m tmux_panel                 # 127.0.0.1:20016 起
    python -m tmux_panel --host 0.0.0.0  # 局域网访问
    PORT=9999 python -m tmux_panel

启动后会在工作目录写两个文本文件：
    .copy2client   客户端连接串（每台一行 sbp1.xxx），整段复制粘贴到控制台/小程序即可导入
    .copy4relay    给 sbp-dispatcher 的 SBP_TRUSTED_KEYS（只有公钥）
"""
from __future__ import annotations

import argparse
import os
import secrets
import socket
import sys
from pathlib import Path

from .identity import ensure_identity
from .copy2client import connect_payload, encode_connect, write_copy2client, write_copy4relay

DEFAULT_PORT = 20016
DEFAULT_HOST = "127.0.0.1"


def find_free_port(start: int, tries: int = 50) -> int:
    for port in range(start, start + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("0.0.0.0", port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"端口 {start}~{start + tries - 1} 全被占用")


def ensure_env() -> tuple[str, str, bool]:
    """cwd 无 .env 时生成随机账号密码。返回 (account, password, created)。"""
    p = Path.cwd() / ".env"
    if p.exists():
        from dotenv import load_dotenv
        load_dotenv(p)
        return os.getenv("PANEL_ACCOUNT", ""), os.getenv("PANEL_SECERT", ""), False
    acc = secrets.token_hex(4)
    pwd = secrets.token_urlsafe(12)
    try:
        p.write_text(f"# 首次启动自动生成，可编辑后重启生效\nPANEL_ACCOUNT={acc}\nPANEL_SECERT={pwd}\n")
        os.chmod(p, 0o600)
    except OSError:
        return "", "", False
    return acc, pwd, True


def main(argv: list[str] | None = None) -> int:
    # 面板日志走 uvicorn，这里的启动信息要立刻可见（systemd/docker 里 stdout 是管道）
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    ap = argparse.ArgumentParser("tmux-panel", description="tmux + Claude Code 本地面板")
    ap.add_argument("--port", "-p", type=int, default=int(os.getenv("PORT", DEFAULT_PORT)))
    ap.add_argument("--host", "-H", default=os.getenv("HOST", DEFAULT_HOST))
    ap.add_argument("--no-auth", action="store_true", help="关闭登录（仅本机调试）")
    ap.add_argument("--bridge", default=os.getenv("SBP_BRIDGE", ""), metavar="WS_URL",
                    help="把本机会话上报到 sbp-server，例如 ws://127.0.0.1:8787/ws"
                         "（也可设环境变量 SBP_BRIDGE）。配了它，客户端就能通过那台"
                         "服务器看到本机，而本机不用对外开放任何端口。")
    ap.add_argument("--bridge-e2ee", "--relay", dest="bridge_e2ee",
                    default=os.getenv("SBP_BRIDGE_E2EE", ""), metavar="WS_URL",
                   help="E2EE 上报：走 /ws-e2ee，端到端加密（中继看不到明文）。密钥默认随机生成"
                        "并写入 .env，也可以手改 .env 里的 SBP_E2EE_KEY / SBP_E2EE_RK / "
                        "SBP_E2EE_PEERS / SBP_CLIENT_KEYS（见 sbp-spec SBP-0.4）。")
    ap.add_argument("--version", action="version", version="tmux-ai-coder-panel 1.0.9")
    args = ap.parse_args(argv)
    if args.bridge:
        os.environ["SBP_BRIDGE"] = args.bridge
    if args.bridge_e2ee:
        os.environ["SBP_BRIDGE_E2EE"] = args.bridge_e2ee

    acc, pwd, created = ensure_env()
    # 身份与密钥：第一次启动全部随机生成并固化到 .env，之后沿用（用户可手改）
    ident = ensure_identity(relay=args.bridge_e2ee)
    if args.no_auth:
        os.environ["PANEL_ACCOUNT"] = ""
        os.environ["PANEL_SECERT"] = ""
        acc = ""

    port = find_free_port(args.port)
    import uvicorn
    from .server import app

    # 绝对路径：用户可能从任意目录拉起，只有绝对路径才找得到文件
    env_path = (Path.cwd() / ".env").resolve()
    client_path = (Path.cwd() / ".copy2client").resolve()
    relay_path = (Path.cwd() / ".copy4relay").resolve()

    print("=" * 62)
    print("  tmux-claude-panel 已启动")
    print(f"  本机访问:  http://127.0.0.1:{port}")
    if args.host == "0.0.0.0":
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            ip = "127.0.0.1"
        print(f"  局域网:    http://{ip}:{port}")
    if acc:
        if created:
            print(f"  账号:      {acc}")
            print(f"  密码:      {pwd}   （已写入 .env，可修改）")
        else:
            print(f"  账号:      {acc}   （见 .env）")
    else:
        print("  登录:      已关闭（--no-auth）")
    if args.bridge:
        print(f"  上报:      {args.bridge}")
    if ident.relay:
        print(f"  E2EE 上报: {ident.relay}")
    print(f"  配置文件:  {env_path}")
    print(f"  连接信息:  {client_path}")
    print("  Ctrl+C 停止")
    print("=" * 62)

    # ---- 连接信息：另起一段打印，同时落到 .copy2client ----
    try:
        write_copy2client(ident, str(client_path))
        write_copy4relay(ident, str(relay_path))
        # 旧文件名（.copy4client）留过就删掉，免得两份密钥各自改一半
        legacy = Path.cwd() / ".copy4client"
        if legacy.exists():
            try:
                legacy.unlink()
            except OSError:
                pass
    except OSError as e:
        print(f"  [warn] 写 {client_path} 失败：{e}")
    print()
    print(f"  连接信息已写入 {client_path}")
    print("  用法：cat .copy2client → 整段复制 → 粘进控制台/小程序的「粘贴导入」框，")
    print("        一次导入两台客户端（cli-web 网页控制台 + cli-minis 微信小程序）。")
    print()
    if ident.relay:
        print("  E2EE 连接信息（同样内容就在上面的文件里，可直接整段复制）:")
    else:
        print("  E2EE 连接信息（还没填中继地址，"
              "在 .env 里设 SBP_BRIDGE_E2EE 后重启会带上正确地址）:")
    for c in ident.clients:
        print(f"    [{c.key_id}] {c.label}")
        print("      " + encode_connect(connect_payload(ident, c)))
    print(f"  中继公钥目录（已写入 {relay_path} —— 只有公钥，可明文发给中继）:")
    print("      SBP_TRUSTED_KEYS=" + ident.trusted_keys_env())
    print()

    try:
        uvicorn.run(app, host=args.host, port=port, log_level="warning")
    except KeyboardInterrupt:
        print("\n已停止")
    return 0


if __name__ == "__main__":
    sys.exit(main())
