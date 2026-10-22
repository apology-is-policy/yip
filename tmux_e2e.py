#!/usr/bin/env python3
"""Private tmux server and a passive fake 'claude' executable, never a live agent."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

binary=Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='yip-tmux-') as temp:
    root=Path(temp)
    socket=root/'server.sock'
    helper=root/'claude'
    received=root/'received'
    source=root/'fake.go'
    source.write_text('''package main
import("bufio";"os";"fmt")
func main(){fmt.Println("FAKE READY");s:=bufio.NewScanner(os.Stdin);s.Buffer(make([]byte,4096),1024*1024);for s.Scan(){f,e:=os.OpenFile(os.Args[1],os.O_CREATE|os.O_APPEND|os.O_WRONLY,0600);if e!=nil{panic(e)};fmt.Fprintln(f,s.Text());f.Close()}}
''')
    subprocess.run([os.environ.get('GO','go'),'build','-o',str(helper),str(source)],check=True)
    env=dict(os.environ,YIP_ROOT=str(root/'line'),YIP_HOME=str(root/'home'))
    def tmux(*args):
        return subprocess.check_output(['tmux','-S',str(socket),'-f','/dev/null',*args],text=True,cwd=root)
    def run(*args,body=None,ok=True):
        p=subprocess.run([str(binary),*args],input=body,env=env,cwd=root,text=True,capture_output=True,timeout=10)
        if ok:assert p.returncode==0,(args,p.stdout,p.stderr)
        return p
    command='exec '+shlex.quote(str(helper))+' '+shlex.quote(str(received))
    pane=tmux('new-session','-d','-P','-F','#{pane_id}','-s','fixture',command).strip()
    try:
        tmux('set-option','-g','remain-on-exit','on')
        deadline=time.monotonic()+5
        while 'FAKE READY' not in tmux('capture-pane','-p','-t',pane):
            assert time.monotonic()<deadline
            time.sleep(.05)
        run('install','--as','a')
        run('delivery','register-tmux','--socket',str(socket),'--pane',pane)
        body='Literal $(touch SHOULD_NOT_EXIST) `touch ALSO_NOT_CREATED` ; no shell execution.'
        run('broadcast','announcement','--to','a',body=body)
        assert run('delivery','dispatch-tmux',ok=False).returncode!=0
        assert not received.exists()
        run('delivery','pause')
        run('delivery','dispatch-tmux','--confirm-idle')
        assert not received.exists()
        run('delivery','resume')
        run('delivery','dispatch-tmux','--confirm-idle')
        deadline=time.monotonic()+5
        while not received.exists():
            assert time.monotonic()<deadline
            time.sleep(.05)
        text=received.read_text()
        assert '$(touch SHOULD_NOT_EXIST)' in text and not (root/'SHOULD_NOT_EXIST').exists()
        assert not (root/'ALSO_NOT_CREATED').exists()
        run('delivery','dispatch-tmux','--confirm-idle')
        assert received.read_text()==text,'duplicate send'
        status=json.loads(run('delivery','status').stdout)
        assert status['events'][0]['status']=='sent'
        run('broadcast','announcement','--to','a',body='must not reach replacement process')
        tmux('respawn-pane','-k','-t',pane,command)
        deadline=time.monotonic()+5
        while 'FAKE READY' not in tmux('capture-pane','-p','-t',pane):
            assert time.monotonic()<deadline
            time.sleep(.05)
        assert run('delivery','dispatch-tmux','--confirm-idle',ok=False).returncode!=0
        assert received.read_text()==text,'sent to replacement process'
        status=json.loads(run('delivery','status').stdout)
        assert status['events'][-1]['status']=='unknown'
        print('PASS private tmux: explicit idle assertion, pause/resume, literal keys, no shell expansion, duplicate suppression, changed-process refusal')
    finally:
        # This unique socket belongs only to this disposable fixture.
        subprocess.run(['tmux','-S',str(socket),'kill-server'],capture_output=True)
