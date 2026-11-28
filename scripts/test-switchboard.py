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

from terminal_screen import terminal_rows


binary = str(Path(sys.argv[1]).resolve())
evidence = Path(sys.argv[2]).resolve()
evidence.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='yip-pty-') as tmp:
    root = Path(tmp)
    env = dict(os.environ, HOME=str(root), YIP_ROOT=str(root/'line'), YIP_HOME=str(root/'home'),
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
        def wait_for(condition, description):
            deadline = time.monotonic() + 10
            while not condition():
                if child.poll() is not None or time.monotonic() >= deadline:
                    raise AssertionError(f"{mode}: waiting for {description}; last output {output[-1500:]!r}")
                drain(.05)
        try:
            wait_for(lambda: b'SWITCHBOARD' in output.upper(), 'Switchboard to open')
            if not mode.startswith('native'):
                assert b'\x1b[?1000h' in output and b'\x1b[?1006h' in output
            def screen():
                rows = {}
                for row, line in re.findall(rb'\x1b\[(\d+);1H(.*?)\x1b\[K', bytes(output), re.S):
                    rows[int(row)] = re.sub(rb'\x1b\[[0-9;]*m', b'', line).decode()
                return rows
            if mode == 'quit':
                wait_for(lambda: 'floor: fixture-c' in ''.join(screen().values()), 'both conversations to load')
                expected = screen()[12][:27].strip()
                # SGR click on the second conversation, delivered in fragments.
                for fragment in [b'\x1b[', b'<0;', b'4;11', b'M']:
                    os.write(master, fragment)
                    drain(.015)
                wait_for(lambda: screen().get(4, '').strip() == expected, f'selected title {expected!r}')
                os.write(master, b'r')
                for byte in 'UI fixture café界'.encode():
                    os.write(master, bytes([byte]))
                    drain(.015)
                # Mouse input during a prompt must neither cancel it nor type
                # its escape payload into the human decision.
                os.write(master, b'\x1b[<0;4;8M\x1b[<65;150;10M')
                drain(.1)
                os.write(master, b'\r')
                wait_for(lambda: any((root/'line/calls').glob('*/notes/*.md')), 'ratification note')
                notes = list((root/'line/calls').glob('*/notes/*.md'))
                assert len(notes)==1 and 'UI fixture café界' in notes[0].read_text()
                os.write(master, b'rdiscard this\x1b')
                wait_for(lambda: 'ratify as' not in screen()[43], 'ratification prompt to close')
                for fragment in [b'\x1b', b'[', b'A']:
                    os.write(master, fragment)
                    drain(.03)
                # A new broadcast joins the same rail and opens a colored transcript.
                (root/'line/members.json').write_text(json.dumps(dict(line='isolated-ui-fixture', members={str(root/'a'):'fixture-a', str(root/'b'):'fixture-b'})))
                cli('broadcast','regroup','--to','fixture-a,fixture-b','--by','test-operator',body='Regroup for the next milestone.')
                broadcast = json.loads(next((root/'line/broadcasts').glob('*.json')).read_text())
                cli('api','broadcast_reply',json.dumps(dict(id=broadcast['id'],body='The checkpoint is complete.')),'--as','fixture-b')
                wait_for(lambda: any('BROADCAST / regroup' in line[:27] for line in screen().values()),
                         'new broadcast in the call list')
                rows=screen()
                row=next(row for row,text in rows.items() if 'BROADCAST / regroup' in text[:27])
                os.write(master, ('\x1b[<0;4;%dM'%row).encode())
                drain(.2)
                os.write(master,b'g')
                wait_for(lambda: 'The checkpoint is complete.' in '\n'.join(screen().values()), 'broadcast reply')
                current='\n'.join(screen().values())
                assert 'RECIPIENTS' in current and 'REPLY' in current and 'The checkpoint is complete.' in current, current
                assert b'\x1b[38;5;183m' in output and b'\x1b[38;5;117m' in output
                (evidence/'broadcast-frame.txt').write_text(current)
                # Grouped view and narrow conversation list retain broadcasts.
                os.write(master,b'4')
                wait_for(lambda: 'BROADCASTS / b' in '\n'.join(screen().values()), 'grouped broadcast view')
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH',24,80,0,0))
                os.kill(int(pidfile.read_text()),signal.SIGWINCH)
                drain(.3)
                os.write(master,b'2jj1q')
            elif mode == 'native':
                for key,label in [(b'\x1bOR',b'Line topology'),(b'\x1bOS',b'Relays'),(b'\x1b[15~',b'Broadcasts'),(b'\x1b[17~',b'Roadmaps'),(b'\x1b[18~',b'Configuration')]:
                    os.write(master,key)
                    def window_open():
                        return any(label.decode() in row for row in terminal_rows(output, 160, 44))
                    wait_for(window_open, f'{label.decode()} to open')
                    os.write(master,key)
                    drain(.15)
                def click_label(label, row_offset=0):
                    rows = terminal_rows(output, 160, 44)
                    y, row = next((y, row) for y, row in enumerate(rows) if label in row)
                    x = row.index(label) + len(label) // 2 + 1
                    for suffix in ('M', 'm'):
                        os.write(master, f'\x1b[<0;{x};{y+1+row_offset}{suffix}'.encode())
                        drain(.12)

                for title, field in [('Set up a relay', 'Public HTTPS URL'),
                                     ('Invite a workstation', 'Workstation name'),
                                     ('Join a line', 'Invitation from operator')]:
                    click_label('Actions')
                    wait_for(lambda: any(title in row for row in terminal_rows(output,160,44)),
                             f'{title} menu entry')
                    click_label(title)
                    wait_for(lambda: any(field in row for row in terminal_rows(output,160,44)),
                             f'{title} first step')
                    (evidence/(title.replace(' ', '-')+'.txt')).write_text(
                        '\n'.join(terminal_rows(output,160,44)))
                    if title == 'Set up a relay':
                        click_label(field, row_offset=1)
                        os.write(master, b'https://localhost:8443')
                        wait_for(lambda: any('localhost:8443' in row for row in terminal_rows(output,160,44)),
                                 'host URL to appear')
                        click_label('Review')
                        wait_for(lambda: any('Apply' in row for row in terminal_rows(output,160,44)),
                                 'host identity review')
                        click_label('Apply')
                        bundle = root/'.yip-ldr/relay-host/share/host.yip'
                        wait_for(bundle.exists, 'host identity bundle')
                        assert json.loads(bundle.read_text())['url'] == 'https://localhost:8443'
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
