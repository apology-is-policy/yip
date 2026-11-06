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

# install records the resolved path, and on macOS /tmp is a symlink.
binary = os.path.realpath(os.environ.get("YIP_TEST_BIN", "/tmp/yiptest"))
thread = "00000000-0000-4000-8000-000000000001"
with tempfile.TemporaryDirectory(prefix="yip-delivery-e2e-") as temp:
    root = pathlib.Path(temp)
    env = dict(os.environ, YIP_ROOT=str(root / "line"), YIP_HOME=str(root / "home"), NO_COLOR="1", TERM="xterm", YIP_REDUCED_MOTION="1")
    # Run from inside a Codex shell, this would make the CLI answer as a seat.
    for leaked in ("CODEX_THREAD_ID", "CODEX_HOME", "YIP_AGENT", "YIP_LINE"):
        env.pop(leaked, None)
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
        assert cfg["mcp_servers"]["yip"]["args"] == ["serve", "--codex", "--line", "fixture", "--as", name]
        assert cfg["mcp_servers"]["yip"]["env_vars"] == ["CODEX_HOME"]
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

    # Seats: a Codex reviewer beside a Claude member, and one with no checkout.
    shared = root / "shared"
    shared.mkdir()
    run("install", "--runtime", "claude", "--line", "fixture", "--as", "main", "--local", cwd=shared)
    out = run("install", "--runtime", "codex", "--line", "fixture", "--as", "reviewer", cwd=shared)
    assert "seat:" in out and "main is unaffected" in out, out
    assert run("whoami", "--line", "fixture", cwd=shared).startswith("main "), "co-located seat re-pointed the checkout"
    codex_home = root / "codex-home"
    codex_home.mkdir()
    env["CODEX_HOME"] = str(codex_home)
    run("install", "--runtime", "codex", "--line", "fixture", "--as", "roamer", "--profile", "yip-roamer", cwd=root)
    profile = tomllib.loads((codex_home / "yip-roamer.config.toml").read_text())
    assert profile["mcp_servers"]["yip"]["args"] == ["serve", "--codex", "--line", "fixture", "--as", "roamer"]
    for event in ("SessionStart", "PostToolUse", "Stop"):
        handlers = profile["hooks"][event][0]["hooks"]
        assert len(handlers) == 1 and handlers[0]["type"] == "command" and "--as 'roamer'" in handlers[0]["command"], handlers
    lines = run("line", "--line", "fixture")
    assert "reviewer" in lines and "profile yip-roamer" in lines and "no session bound yet" in lines, lines
    print("PASS co-located seat keeps the checkout member; profile seat is valid TOML with inline hooks")

    # Live delivery: the session's own server binds from _meta.threadId and
    # queues to exactly that thread, with no registration or dispatcher.
    log.write_text("")
    live = "01a1b037-0000-7000-8000-0000000000e2"
    proc = subprocess.Popen([binary, "serve", "--codex", "--line", "fixture", "--as", "reviewer"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=shared, env=env)
    def rpc_call(msg):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline()) if "id" in msg else None
    try:
        init = rpc_call({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}})
        assert init["result"]["instructions"].startswith("You are reviewer"), init
        rpc_call({"jsonrpc": "2.0", "method": "notifications/initialized"})
        ring = rpc_call({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "ring", "arguments": {}, "_meta": {"threadId": live, "progressToken": 0}}})
        assert "Delivery connected" in ring["result"]["content"][0]["text"], ring
        assert "session live" in run("delivery", "status", "--as", "reviewer") or "session live" in run("line", "--line", "fixture")
        run("call", "reviewer", "Review request", "--as", "main", "--line", "fixture", body="please review the diff", cwd=shared)
        deadline = time.monotonic() + 10
        queued = []
        while time.monotonic() < deadline and not queued:
            queued = [json.loads(l) for l in log.read_text().splitlines() if live in l]
            time.sleep(0.2)
        assert len(queued) == 1 and queued[0][:3] == ["queue", "--thread", live] and "Yip coordination notices" in queued[0][4], queued
        # Inside that Codex chat's shell, the CLI answers as the seat, not main.
        shell_env = dict(env, CODEX_THREAD_ID=live)
        who = subprocess.check_output([binary, "whoami", "--line", "fixture"], text=True, cwd=shared, env=shell_env)
        assert who.startswith("reviewer "), who
    finally:
        proc.stdin.close()
        proc.wait(10)
    status = run("line", "--line", "fixture")
    assert "session closed" in status, status
    print("PASS live Codex binding from _meta.threadId, in-server queue to that exact thread, thread-bound CLI identity, release on exit")

    # claude-rewake in a launch folder shared with a Codex seat, on a NAMED line.
    # No YIP_ROOT here: the hooks must find the line themselves, which the
    # unnamed hook commands used to get wrong (they derived the folder's line).
    work = root / "strategies"
    work.mkdir()
    env2 = {k: v for k, v in env.items() if k != "YIP_ROOT"}
    env2["YIP_HOME"] = str(root / "home2")
    def run2(*args, body=None):
        return subprocess.check_output([binary, *args], input=body, text=True, cwd=work, env=env2)
    run2("install", "--runtime", "claude-rewake", "--as", "claude", "--line", "strategies", "--local", "--wake-window", "5m")
    run2("install", "--runtime", "codex", "--as", "codex", "--line", "strategies")
    hooks = json.loads((work / ".claude/settings.local.json").read_text())["hooks"]
    rewake = [h for g in hooks["Stop"] for h in g["hooks"] if h.get("asyncRewake")]
    assert len(rewake) == 1 and rewake[0]["timeout"] == 300, rewake
    session_start = hooks["SessionStart"][0]["hooks"][0]["command"]
    hook_env = {k: v for k, v in env2.items() if k not in ("YIP_LINE",)}
    stdin = json.dumps({"session_id": "e2e-session", "cwd": str(work), "hook_event_name": "Stop"})
    waiter = subprocess.Popen(["sh", "-c", rewake[0]["command"]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, cwd=work, env=hook_env)
    waiter.stdin.write(stdin)
    waiter.stdin.close()
    deadline = time.monotonic() + 10
    while "rewake armed" not in run2("line", "--line", "strategies"):
        assert time.monotonic() < deadline and waiter.poll() is None, "waiter never armed"
        time.sleep(0.1)
    second = subprocess.run(["sh", "-c", rewake[0]["command"]], input=stdin, capture_output=True, text=True, cwd=work, env=hook_env, timeout=10)
    assert second.returncode == 0, "a second waiter armed beside the first"
    run2("call", "claude", "Review done", "--as", "codex", "--line", "strategies", body="Two findings in the locking.")
    _, err = waiter.communicate(timeout=10)
    assert waiter.returncode == 2 and "Yip coordination notices" in err and "Review done" in err, (waiter.returncode, err)
    started = subprocess.run(["sh", "-c", session_start], input=json.dumps({"cwd": str(work), "source": "startup"}),
                             capture_output=True, text=True, cwd=work, env=hook_env, timeout=10)
    assert "codex spoke" in started.stdout or "0001-review-done" in started.stdout, started
    doctor = run2("doctor", "--runtime", "claude-rewake", "--line", "strategies")
    assert "rewake (2/2)" in doctor and "not armed" in doctor, doctor
    print("PASS claude-rewake: generated hook arms one waiter, a Codex call wakes it with exit 2, named-line hooks resolve the right line")
