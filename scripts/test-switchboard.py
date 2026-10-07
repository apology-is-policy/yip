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
    for mode in ['quit', 'signal']:
        master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 44, 160, 0, 0))
        saved = termios.tcgetattr(slave)
        def setup():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        report=root/(mode+'-terminal.json')
        pidfile=root/(mode+'-pid')
        launcher = """import json,subprocess,sys,termios
+from pathlib import Path
+before=termios.tcgetattr(0)
+p=subprocess.Popen([sys.argv[1],'switchboard','--by','test-operator'])
+Path(sys.argv[3]).write_text(str(p.pid))
+rc=p.wait()
+Path(sys.argv[2]).write_text(json.dumps(dict(rc=rc,restored=before==termios.tcgetattr(0))))
+sys.exit(rc)
+""".replace('\n+','\n')
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
            assert b'SWITCHBOARD' in output, output[-2000:]
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
                assert screen()[3].strip() == expected, (expected, screen()[3])
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
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH',24,80,0,0))
                os.kill(int(pidfile.read_text()),signal.SIGWINCH)
                drain(.3)
                os.write(master,b'2jj1q')
            else:
                os.kill(int(pidfile.read_text()),signal.SIGTERM)
            drain(.5)
            rc=child.wait(timeout=5)
            assert rc==0, rc
            assert json.loads(report.read_text())['restored'], 'terminal mode not restored'
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
                child.wait(timeout=5)
            os.close(master)
            os.close(slave)
    (evidence/'pty-passed.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results))
