#!/usr/bin/env python3
"""Real Yip subprocess + simulated Claude MCP client, entirely isolated state.
Does not start Claude, approve preview flags or contact existing sessions.
"""
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time

binary = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix="yip-channels-e2e-") as tmp:
    root = Path(tmp)
    env = dict(os.environ, YIP_ROOT=str(root / "state"), YIP_HOME=str(root / "home"))
    def run(*args, body=None, ok=True):
        result = subprocess.run([binary, *args], cwd=root, env=env, input=body,
                                text=True, capture_output=True, timeout=10)
        if ok:
            assert result.returncode == 0, (args, result.stderr)
        return result

    for flag in ["--help", "--help-agents"]:
        assert "channel_ack" in run(flag).stdout
    assert not (root / "state").exists() and not (root / "home").exists()
    run("install", "--runtime", "claude-channels", "--as", "a")
    config = json.loads((root / ".mcp.json").read_text())
    assert config["mcpServers"]["yip"]["args"][:2] == ["serve", "--channels"]
    assert run("doctor", "--runtime", "claude-channels", ok=False).returncode == 1
    handles = []
    def start():
        proc = subprocess.Popen([binary, "serve", "--channels", "--as", "a"],
                                cwd=root, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, bufsize=1)
        handles.append(proc)
        frames = queue.Queue()
        def read():
            try:
                for line in proc.stdout:
                    frames.put(json.loads(line))
            except Exception as error:
                frames.put(error)
        threading.Thread(target=read, daemon=True).start()
        def send(method, params=None, ident=None):
            frame = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                frame["params"] = params
            if ident is not None:
                frame["id"] = ident
            proc.stdin.write(json.dumps(frame) + "\n")
            proc.stdin.flush()
        def receive():
            frame = frames.get(timeout=8)
            assert isinstance(frame, dict), frame
            return frame
        send("initialize", {"protocolVersion": "2026-07-28"}, 1)
        init = receive()["result"]
        assert init["protocolVersion"] == "2024-11-05"
        assert init["capabilities"]["experimental"]["claude/channel"] == {}
        assert frames.empty(), "notification before initialization"
        assert run("doctor", "--runtime", "claude-channels", ok=False).returncode == 1
        send("notifications/initialized")
        send("notifications/initialized")
        probe = receive()
        assert probe["method"] == "notifications/claude/channel"
        # IDs are extracted from received content, not from endpoint state.
        probe_id = probe["params"]["content"].splitlines()[1].split()[0]
        send("tools/call", {"name": "channel_ack", "arguments": {"id": probe_id}}, 2)
        ack = receive()
        assert ack["id"] == 2 and not ack["result"].get("isError"), ack
        assert run("doctor", "--runtime", "claude-channels").returncode == 0
        return proc, send, receive, frames, probe_id

    try:
        proc, send, receive, frames, first_probe = start()
        duplicate = run("serve", "--channels", "--as", "a", body="", ok=False)
        assert duplicate.returncode == 1 and "another Channels server" in duplicate.stderr
        run("delivery", "pause")
        run("broadcast", "briefing", "--to", "a", body="Give a fixture-only briefing.")
        time.sleep(1.3)
        assert frames.empty(), "paused channel sent a notice"
        run("delivery", "resume")
        notice = receive()
        assert notice["method"] == "notifications/claude/channel"
        event_id = notice["params"]["content"].splitlines()[1].split()[0]
        send("tools/call", {"name": "delivery_ack", "arguments": {"id": event_id}}, 3)
        assert receive()["id"] == 3
        send("tools/call", {"name": "broadcasts", "arguments": {}}, 4)
        assert "briefing" in json.dumps(receive())
        time.sleep(1.3)
        assert frames.empty(), "automatic duplicate"
        # Force-stop ONLY this fixture's child to test OS-lock crash recovery.
        proc.kill()
        proc.wait(timeout=5)
        assert run("doctor", "--runtime", "claude-channels", ok=False).returncode == 1
        run("broadcast", "announcement", "--to", "a", body="Created while disconnected.")
        proc, send, receive, frames, new_probe = start()
        assert new_probe != first_probe
        backlog = receive()
        assert "announcement" in backlog["params"]["content"].lower(), backlog
        assert event_id not in backlog["params"]["content"], "replayed an acknowledged event"
        send("tools/call", {"name": "channel_ack", "arguments": {"id": first_probe}}, 5)
        assert receive()["result"]["isError"], "old probe accepted"
        proc.stdin.close()
        assert proc.wait(timeout=5) == 0
        status = json.loads(run("delivery", "status").stdout)
        assert not status.get("channel_connected") and not status.get("channel_ready")
        assert run("doctor", "--runtime", "claude-channels", ok=False).returncode == 1
        print("PASS: help has no writes; install; handshake; acknowledged probe; owner fencing; pause/resume; broadcast; dedup; crash/reconnect; backlog; stale-probe rejection; clean disconnect")
    finally:
        for proc in handles:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
