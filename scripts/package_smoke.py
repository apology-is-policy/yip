#!/usr/bin/env python3
"""Clean install/configure/uninstall in disposable paths, preserving resource state."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

repo=Path(__file__).resolve().parent.parent
source=Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='yip-package-') as temporary:
    root=Path(temporary)
    binary=root/'install path'/'yip'
    subprocess.run(['sh',str(repo/'scripts/install-binary.sh'),str(source),str(binary)],check=True)
    # Exercise safe replacement while the old inode has a running stdio reader.
    env=dict(os.environ,YIP_ROOT=str(root/'line'),YIP_HOME=str(root/'home'))
    running=subprocess.Popen([str(binary),'serve','--as','owner'],cwd=root,env=env,
                             stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
        subprocess.run(['sh',str(repo/'scripts/install-binary.sh'),str(source),str(binary)],check=True)
        assert list(binary.parent.glob('yip.backup.*'))
    finally:
        running.stdin.close()
        assert running.wait(timeout=5)==0
    def run(*args,body=None,ok=True):
        p=subprocess.run([str(binary),*args],cwd=root,env=env,input=body,text=True,capture_output=True,timeout=10)
        if ok: assert p.returncode==0,(args,p.stdout,p.stderr)
        return p
    run('config','init','--clients-restarted')
    config=root/'proposed.json'
    config.write_text(json.dumps({'version':1,'resources':[{'name':'builder','description':'fixture build host','machine':'fixture-machine'}]}))
    run('config','validate',str(config))
    run('config','apply',str(config),'--clients-restarted')
    (root/'.mcp.json').write_text('{"mcpServers":{"other":{"command":"preserve-me"}}}')
    run('install','--runtime','claude-channels','--as','owner')
    run('hold','builder','fixture','--as','owner','--now')
    queued=run('api','request','{"resource":"builder","reason":"fixture wait"}','--as','waiter')
    assert 'QUEUED' in queued.stdout
    lease=root/'line/resources/builder.lease'
    queue=root/'line/resources/builder.queue/waiter.json'
    before=(lease.read_bytes(),queue.read_bytes())
    config.write_text('{"version":1,"resources":[]}')
    assert run('config','apply',str(config),'--clients-restarted',ok=False).returncode!=0
    run('uninstall')
    assert before==(lease.read_bytes(),queue.read_bytes())
    assert json.loads((root/'.mcp.json').read_text())['mcpServers']=={'other':{'command':'preserve-me'}}
    run('install','--runtime','codex','--as','owner')
    run('uninstall')
    assert before==(lease.read_bytes(),queue.read_bytes())
    assert (root/'line/resources.json').exists()
    print('PASS clean binary install/replacement, resource config, both runtime installs/uninstalls, unrelated MCP entry, live fixture lease and queue preservation')
