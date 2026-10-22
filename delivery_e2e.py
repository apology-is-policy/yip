#!/usr/bin/env python3
"""Isolated CLI/MCP/configuration and real-PTY broadcast checks; no live wakes."""
import fcntl
import glob
import json
import os
import pathlib
import pty
import re
import select
import struct
import subprocess
import tempfile
import termios
import time
import tomllib

binary = os.environ.get("YIP_TEST_BIN", "/tmp/yiptest")
thread = "00000000-0000-4000-8000-000000000001"
with tempfile.TemporaryDirectory(prefix="yip-delivery-e2e-") as temp:
    root = pathlib.Path(temp)
    env = dict(os.environ, YIP_ROOT=str(root / "line"), YIP_HOME=str(root / "home"), NO_COLOR="1", TERM="xterm", YIP_REDUCED_MOTION="1")
    checkouts = {}
    def run(*args, body=None, cwd=None):
        return subprocess.check_output([binary, *args], input=body, text=True, cwd=cwd or root, env=env)
    for name in ("a", "b"):
        path = root / name
        path.mkdir()
        checkouts[name] = path
        run("install", "--runtime", "codex", "--line", "fixture", "--as", name, cwd=path)
        cfg = tomllib.loads((path / ".codex/config.toml").read_text())
        assert cfg["mcp_servers"]["yip"]["command"] == binary
        assert cfg["mcp_servers"]["yip"]["env"] == {"YIP_ROOT": env["YIP_ROOT"], "YIP_HOME": env["YIP_HOME"]}
        assert cfg["mcp_servers"]["yip"]["args"] == ["serve", "--line", "fixture", "--as", name]
    run("call", "b", "existing call", "--as", "a", body="request")
    hook_cfg = json.loads((checkouts["b"] / ".codex/hooks.json").read_text())
    command = hook_cfg["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    output = subprocess.check_output(command, shell=True, input=json.dumps({"cwd": str(checkouts["b"]), "tool_name": "read"}), text=True, cwd=root, env={k:v for k,v in env.items() if k not in ("YIP_ROOT", "YIP_HOME")})
    parsed = json.loads(output)
    assert set(parsed) == {"hookSpecificOutput"}
    assert parsed["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    run("delivery", "register", thread, "--as", "b")
    fakebin = root / "bin"
    fakebin.mkdir()
    log = root / "queue-args.jsonl"
    # A fake runtime records literal argv and never contacts a session.
    fake = fakebin / "codex"
    fake.write_text("#!/usr/bin/env python3\nimport json,os,sys\nwith open(os.environ['YIP_ARG_LOG'],'a') as f: f.write(json.dumps(sys.argv[1:])+'\\n')\n")
    fake.chmod(0o700)
    env.update(PATH=str(fakebin) + ":" + os.environ["PATH"], YIP_ARG_LOG=str(log))
    run("broadcast", "briefing", "--to", "a,b", "--by", "test operator", body="report your blockers")
    run("delivery", "dispatch", "--as", "b")
    run("delivery", "dispatch", "--as", "b")
    args = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(args) == 1 and args[0][:4] == ["queue", "--thread", thread, "--message"]
    status = json.loads(run("delivery", "status", "--as", "b"))
    event = status["events"][0]
    run("api", "delivery_ack", json.dumps({"id": event["id"]}), "--as", "b")
    broadcast_id = event["source"].split(":", 1)[1]
    # Exercise the MCP dispatch rather than only its CLI alias.
    rpc = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "broadcast_read", "arguments": {"id": broadcast_id}}}) + "\n"
    response = json.loads(run("serve", "--as", "b", body=rpc))
    assert "report your blockers" in str(response)
    run("api", "broadcast_reply", json.dumps({"id": broadcast_id, "body": "no blockers"}), "--as", "b")
    assert "reply requested" in run("api", "broadcasts", "--as", "a")
    assert "reply requested" not in run("api", "broadcasts", "--as", "b")
    print("PASS isolated Codex install, generated hook, literal queue argv, restart deduplication, acknowledgment, MCP read and per-recipient replies")

    # Start a real terminal with an isolated line, then use only operator keys.
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(root)
        os.execve(binary, [binary, "switchboard", "--by", "test operator"], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 110, 0, 0))
    capture = bytearray()
    def until(needle, timeout=8):
        end = time.monotonic() + timeout
        segment = bytearray()
        while time.monotonic() < end:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                block = os.read(fd, 65536)
                capture.extend(block)
                segment.extend(block)
                if needle in segment:
                    return
        raise AssertionError("PTY did not show " + repr(needle) + "; captured tail: " + repr(bytes(capture[-2000:])))
    try:
        until(b"SWITCHBOARD")
        os.write(fd, b"b")
        until(b"recipients")
        # Defaults already contain a,b. Accept them, then replace announcement.
        os.write(fd, b"\r")
        until(b"kind:")
        os.write(fd, b"\x7f" * len("announcement") + b"briefing\r")
        until(b"broadcast text")
        os.write(fd, b"PTY status request\r")
        until(b"type SEND")
        assert len(glob.glob(str(root / "line/broadcasts/*.json"))) == 1
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        os.write(fd, b"SEND\r")
        until(b"recorded broadcast")
        assert len(glob.glob(str(root / "line/broadcasts/*.json"))) == 2
        os.write(fd, b"q")
        # Drain the terminal while the UI restores its mode, with a deadline.
        deadline = time.monotonic() + 8
        while True:
            done, code = os.waitpid(pid, os.WNOHANG)
            if done:
                break
            if time.monotonic() > deadline:
                raise AssertionError("PTY did not exit")
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    capture.extend(os.read(fd, 65536))
                except OSError:
                    pass
        pid = 0
        assert os.waitstatus_to_exitcode(code) == 0
    finally:
        if pid:
            # Only the test-owned child, never another Yip/session process.
            os.kill(pid, 9)
            os.waitpid(pid, 0)
        os.close(fd)
    artifact = os.environ.get("YIP_PTY_CAPTURE")
    if artifact:
        pathlib.Path(artifact).write_bytes(capture)
    print("PASS real PTY compose, preview before send, resize, record and clean exit")
