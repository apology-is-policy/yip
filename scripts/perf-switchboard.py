#!/usr/bin/env python3
"""Drive a real switchboard in a pty and measure what the operator feels when scrolling: a burst of
wheel packets, then how long the screen keeps moving after the last packet, and how long a keypress
takes to show. A thread reads the pty the whole time, as a terminal does; a harness that writes and
reads in turn deadlocks once both buffers fill. Usage: perf-switchboard.py BIN YIP_ROOT [rows cols].
Point YIP_ROOT at a copy of a line."""
import fcntl, json, os, pty, struct, subprocess, sys, termios, threading, time

bin_, root = sys.argv[1], sys.argv[2]
rows, cols = (int(sys.argv[3]), int(sys.argv[4])) if len(sys.argv) > 4 else (50, 200)
m, s = pty.openpty()
fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
env = dict(os.environ, YIP_ROOT=root, TERM='xterm-256color')


def preexec():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


p = subprocess.Popen([bin_, 'switchboard', '--by', 'perf'], stdin=s, stdout=s, stderr=s, env=env,
                     preexec_fn=preexec, close_fds=True)
os.close(s)

total = 0
last = time.monotonic()
stop = False
recent = b''


def reader():
    global total, last, recent
    while not stop:
        try:
            d = os.read(m, 1 << 16)
        except OSError:
            return
        if not d:
            return
        total += len(d)
        last = time.monotonic()
        recent = (recent + d)[-(1 << 18):]


threading.Thread(target=reader, daemon=True).start()
time.sleep(1.5)
b0 = total
time.sleep(5.0)
idle_rate = (total - b0) / 5.0
print(f'idle output: {idle_rate:,.0f} bytes/s', flush=True)

def biggest_call():
    best, best_n = None, -1
    calls = os.path.join(root, 'calls')
    for name in os.listdir(calls):
        turns = os.path.join(calls, name, 'turns')
        if os.path.isdir(turns):
            n = len(os.listdir(turns))
            if n > best_n:
                best, best_n = name, n
    with open(os.path.join(calls, best, 'call.json')) as f:
        return json.load(f)['subject'], best_n


def select_call(subject):
    """Press n until the title row shows it, so both builds scroll the same text whatever their list order."""
    needle = subject[:40].encode()
    for i in range(400):
        recent_mark = total
        os.write(m, b'n')
        t = time.monotonic()
        while total == recent_mark and time.monotonic() - t < 2:
            time.sleep(0.001)
        time.sleep(0.05)
        if needle in recent[-(1 << 15):]:
            return i + 1
    return -1


def burst(name, x, y):
    N, rate = 400, 250.0
    down = b'\x1b[<65;%d;%dM' % (x, y)
    up = b'\x1b[<64;%d;%dM' % (x, y)
    time.sleep(1.2)
    b0 = total
    t0 = time.monotonic()
    for i in range(N):
        os.write(m, down if (i // 50) % 2 == 0 else up)
        d = t0 + (i + 1) / rate - time.monotonic()
        if d > 0:
            time.sleep(d)
    sent = time.monotonic()
    # Settled means back to the idle rate, for long enough that the tick's own frame cannot hide it. A
    # plain gap in the output never comes on a build that repaints every second.
    limit = max(idle_rate, 200.0) * 2.5
    quiet_since, settled_at = None, sent
    prev, prev_t = total, time.monotonic()
    while time.monotonic() - sent < 60:
        time.sleep(0.25)
        t, b = time.monotonic(), total
        if (b - prev) / (t - prev_t) > limit:
            quiet_since, settled_at = None, t
        elif quiet_since is None:
            quiet_since = t
        prev, prev_t = b, t
        if quiet_since is not None and t - quiet_since > 2.0:
            break
    written = total - b0
    print(f'{name}: {N} packets offered in {sent - t0:.2f}s (planned {N / rate:.2f}s); settled within '
          f'{max(0.0, settled_at - sent) * 1000:.0f} ms of the last; {written:,} bytes written', flush=True)
    if written == 0:
        print(f'  FIXTURE: {name} moved nothing, so this line measures nothing', flush=True)


subject, turns = biggest_call()
pressed = select_call(subject)
print(f'selected the longest call ({turns} turns) with {pressed} presses', flush=True)
if pressed < 0:
    print('  FIXTURE: could not select it', flush=True)
burst('transcript', cols // 2, rows // 2)
burst('call list', 5, rows // 2)

lat = []
for i in range(15):
    time.sleep(0.27)
    b0 = total
    t = time.monotonic()
    os.write(m, b'n')
    while total == b0 and time.monotonic() - t < 5:
        time.sleep(0.0005)
    lat.append((time.monotonic() - t) * 1000)
lat.sort()
print(f'key to first output: median {lat[len(lat) // 2]:.1f} ms, worst {lat[-1]:.1f} ms', flush=True)
try:
    os.write(m, b'q')
except OSError:
    pass
time.sleep(0.3)
stop = True
p.kill()
