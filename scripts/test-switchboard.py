import fcntl
import json
import os
import re
from pathlib import Path
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unicodedata

def terminal_rows(data, width, height):
    """Apply tcell's cursor-addressed cell updates to a fixed-size screen."""
    cells = [[' '] * width for _ in range(height)]
    x = y = 0
    tokens = r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[ -?]*[@-~]|\x1b\([AB0]|.'
    for token in re.findall(tokens, data.decode(errors='replace'), re.S):
        if token.startswith('\x1b'):
            if token.startswith('\x1b[') and token.endswith('H'):
                coords = token[2:-1].split(';')
                y = int(coords[0] or 1) - 1
                x = int(coords[1] or 1) - 1 if len(coords) > 1 else 0
        elif token == '\r':
            x = 0
        elif token == '\n':
            y += 1
        elif token.isprintable():
            if 0 <= y < height and 0 <= x < width:
                cells[y][x] = token
            x += 2 if unicodedata.east_asian_width(token) in ('W', 'F') else 1
    return [''.join(row) for row in cells]


binary = str(Path(sys.argv[1]).resolve())
evidence = Path(sys.argv[2]).resolve()
evidence.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='yip-pty-') as tmp:
    root = Path(tmp)
    env = dict(os.environ, YIP_ROOT=str(root/'line'), YIP_HOME=str(root/'home'),
               YIP_LINE='isolated-ui-fixture', TERM='xterm-256color')
    env.pop('NO_COLOR', None)
    def cli(*args, body=None):
        return subprocess.run([binary, *args], input=body, text=True, env=env,
                              cwd=root, check=True, capture_output=True).stdout
    cli('init', '--as', 'fixture-a')
    cli('call', '--as', 'fixture-a', 'fixture-b', 'PTY fixture', body='A synthetic conversation for terminal verification.')
    cli('call', '--as', 'fixture-a', 'fixture-c', 'Second call', body='A second selectable conversation.')
    before_turns = list((root/'line/calls').glob('*/turns/*.md'))
    results = []
    for mode in ['quit', 'signal', 'native', 'native-signal']:
        master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 44, 160, 0, 0))
        saved = termios.tcgetattr(slave)
        def setup():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        report=root/(mode+'-terminal.json')
        pidfile=root/(mode+'-pid')
        launcher = """import fcntl,json,subprocess,sys,termios
+from pathlib import Path
+before=termios.tcgetattr(0)
+p=subprocess.Popen([sys.argv[1],'switchboard','--reference','--by','test-operator'])
+Path(sys.argv[3]).write_text(str(p.pid))
+rc=p.wait()
+# Darwin resolves its transient PENDIN flag on the next input-queue query.
+# This observes the queue without consuming any of the caller's keystrokes.
+if sys.platform == 'darwin': fcntl.ioctl(0,termios.FIONREAD,bytes(4))
+Path(sys.argv[2]).write_text(json.dumps(dict(rc=rc,restored=before==termios.tcgetattr(0))))
+sys.exit(rc)
+""".replace('\n+','\n')
        if mode.startswith('native'):
            launcher = launcher.replace(",'--reference'", "")
        child = subprocess.Popen([sys.executable,'-c',launcher,binary,str(report),str(pidfile)],
                                 stdin=slave, stdout=slave, stderr=slave, env=env,
                                 cwd=root, preexec_fn=setup)
        output = bytearray()
        def drain(seconds):
            end = time.monotonic()+seconds
            while time.monotonic() < end:
                ready, _, _ = select.select([master], [], [], min(.05, max(0, end-time.monotonic())))
                if ready:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
        try:
            drain(1)
            assert b'SWITCHBOARD' in output.upper(), output[-2000:]
            if not mode.startswith('native'):
                assert b'\x1b[?1000h' in output and b'\x1b[?1006h' in output
            def screen():
                rows = {}
                for row, line in re.findall(rb'\x1b\[(\d+);1H(.*?)\x1b\[K', bytes(output), re.S):
                    rows[int(row)] = re.sub(rb'\x1b\[[0-9;]*m', b'', line).decode()
                return rows
            if mode == 'quit':
                assert 'floor: fixture-c' in ''.join(screen().values())
                expected = screen()[12][:27].strip()
                # SGR click on the second conversation, delivered in fragments.
                for fragment in [b'\x1b', b'[<0;', b'4;11', b'M']:
                    os.write(master, fragment)
                    drain(.015)
                assert screen()[4].strip() == expected, (expected, screen()[4])
                os.write(master, b'r')
                for byte in 'UI fixture café界'.encode():
                    os.write(master, bytes([byte]))
                    drain(.015)
                # Mouse input during a prompt must neither cancel it nor type
                # its escape payload into the human decision.
                os.write(master, b'\x1b[<0;4;8M\x1b[<65;150;10M')
                drain(.1)
                os.write(master, b'\r')
                drain(.2)
                notes = list((root/'line/calls').glob('*/notes/*.md'))
                assert len(notes)==1 and 'UI fixture café界' in notes[0].read_text()
                os.write(master, b'rdiscard this\x1b')
                drain(.2)
                assert 'ratify as' not in screen()[43]
                for fragment in [b'\x1b', b'[', b'A']:
                    os.write(master, fragment)
                    drain(.03)
                # A new broadcast joins the same rail and opens a colored transcript.
                (root/'line/members.json').write_text(json.dumps(dict(line='isolated-ui-fixture', members={str(root/'a'):'fixture-a', str(root/'b'):'fixture-b'})))
                cli('broadcast','regroup','--to','fixture-a,fixture-b','--by','test-operator',body='Regroup for the next milestone.')
                broadcast = json.loads(next((root/'line/broadcasts').glob('*.json')).read_text())
                cli('api','broadcast_reply',json.dumps(dict(id=broadcast['id'],body='The checkpoint is complete.')),'--as','fixture-b')
                drain(2.3)
                rows=screen()
                row=next(row for row,text in rows.items() if 'BROADCAST / regroup' in text[:27])
                os.write(master, ('\x1b[<0;4;%dM'%row).encode())
                drain(.2)
                os.write(master,b'g')
                drain(.2)
                current='\n'.join(screen().values())
                assert 'RECIPIENTS' in current and 'REPLY' in current and 'The checkpoint is complete.' in current, current
                assert b'\x1b[38;5;183m' in output and b'\x1b[38;5;117m' in output
                (evidence/'broadcast-frame.txt').write_text(current)
                # Grouped view and narrow conversation list retain broadcasts.
                os.write(master,b'4')
                drain(.2)
                assert 'BROADCASTS / b' in '\n'.join(screen().values())
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH',24,80,0,0))
                os.kill(int(pidfile.read_text()),signal.SIGWINCH)
                drain(.3)
                os.write(master,b'2jj1q')
            elif mode == 'native':
                for key,label in [(b'\x1bOR',b'Line topology'),(b'\x1bOS',b'Relays'),(b'\x1b[15~',b'Broadcasts'),(b'\x1b[17~',b'Roadmaps'),(b'\x1b[18~',b'Configuration')]:
                    os.write(master,key)
                    drain(.3)
                    rows = terminal_rows(output, 160, 44)
                    assert any(label.decode() in row for row in rows), (label, rows[:12])
                    os.write(master,key)
                    drain(.15)
                os.write(master,b'q')
            else:
                os.kill(int(pidfile.read_text()),signal.SIGTERM)
            drain(.5)
            rc=child.wait(timeout=5)
            assert rc==0, rc
            assert json.loads(report.read_text())['restored'], 'terminal mode not restored'
            if not mode.startswith('native'):
                assert b'\x1b[?1006l' in output and b'\x1b[?1000l' in output
            assert b'\x1b[?1049l' in output and b'\x1b[?25h' in output
            assert len(list((root/'line/calls').glob('*/turns/*.md')))==len(before_turns)
            (evidence/f'pty-{mode}.ansi').write_bytes(output)
            results.append(dict(exit=mode, rc=rc, terminal_restored=True, bytes=len(output)))
        finally:
            if child.poll() is None:
                if pidfile.exists():
                    try: os.kill(int(pidfile.read_text()),signal.SIGTERM)
                    except ProcessLookupError: pass
                drain(.6)
                child.wait(timeout=5)
            os.close(master)
            os.close(slave)
    (evidence/'pty-passed.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results))
