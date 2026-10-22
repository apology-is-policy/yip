#!/usr/bin/env python3
"""Build reproducible offline release archives. Does not publish or install."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--version', required=True)
parser.add_argument('--out', required=True)
parser.add_argument('--targets', default='darwin/arm64,darwin/amd64,linux/arm64,linux/amd64')
args = parser.parse_args()
if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', args.version):
    parser.error('version must be a safe archive component')
repo = Path(__file__).resolve().parent.parent
out = Path(args.out).resolve()
out.mkdir(parents=True, exist_ok=True)
if (out/'SHA256SUMS').exists():
    raise SystemExit('refusing to replace existing SHA256SUMS; use a new output directory')
if shutil.disk_usage(out).free < 9 * 1024**3:
    raise SystemExit('release build needs at least 9 GiB free; preserve the 8 GiB floor')
targets = args.targets.split(',')
allowed = {'darwin/arm64','darwin/amd64','linux/arm64','linux/amd64'}
if len(set(targets)) != len(targets) or any(t not in allowed for t in targets):
    parser.error('supported targets: '+','.join(sorted(allowed)))
go = os.environ.get('GO', 'go')
sha = lambda data: hashlib.sha256(data).hexdigest()
source_files = sorted([*repo.glob('*.go'),repo/'go.mod'])
source = {str(p.relative_to(repo)): sha(p.read_bytes()) for p in source_files}
metadata = {'version': args.version, 'go': subprocess.check_output([go,'version'],text=True).strip(),
            'source_sha256':source, 'targets':targets,
            'runtime_qualification':'See docs/RELEASE.md; cross-compilation is not runtime qualification.'}
files = ['README.md','LICENSE','docs/RELEASE.md','docs/RESOURCE-CONFIG.md','docs/delivery-and-broadcasts.md',
         'examples/resources.json','scripts/install-binary.sh']
checksums = []
with tempfile.TemporaryDirectory(prefix='yip-release-') as tmp:
    tmp = Path(tmp)
    for target in targets:
        if shutil.disk_usage(out).free < 8.5 * 1024**3:
            raise SystemExit('stopped before disk floor; completed archives retained')
        goos, arch = target.split('/')
        binary = tmp / ('yip-'+goos+'-'+arch)
        env = dict(os.environ, GOOS=goos, GOARCH=arch, CGO_ENABLED='0')
        subprocess.run([go,'build','-trimpath','-buildvcs=false','-ldflags',
                        '-s -w -X main.serverVersion='+args.version,'-o',str(binary),'.'],
                       cwd=repo,env=env,check=True)
        name = f'yip-{args.version}-{goos}-{arch}'
        archive = out / (name+'.tar.gz')
        if archive.exists():
            raise SystemExit(f'refusing to replace existing archive: {archive}')
        content = {'yip':binary.read_bytes(), **{f:(repo/f).read_bytes() for f in files},
                   'BUILD.json':(json.dumps(metadata,indent=2)+'\n').encode()}
        # Fixed metadata and gzip timestamp make repeated builds comparable.
        staged = tmp / archive.name
        with staged.open('wb') as raw:
            with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as gz:
                with tarfile.open(fileobj=gz,mode='w') as tar:
                    for path,data in sorted(content.items()):
                        info=tarfile.TarInfo(name+'/'+path)
                        info.size=len(data); info.mtime=0
                        info.mode=0o755 if path in ('yip','scripts/install-binary.sh') else 0o644
                        tar.addfile(info,io.BytesIO(data))
        # Output may be on another filesystem; copy to a sibling temporary file
        # and rename, never publish a partial archive under its final name.
        stage_out=out/(archive.name+'.partial')
        if stage_out.exists():
            raise SystemExit(f'refusing to overwrite incomplete artifact: {stage_out}')
        shutil.copyfile(staged,stage_out)
        os.rename(stage_out,archive)
        checksums.append(f'{sha(archive.read_bytes())}  {archive.name}\n')
        print('built',archive,flush=True)
checksum_path=out/'SHA256SUMS'
with checksum_path.open('x') as stream:
    stream.writelines(checksums)
