#!/usr/bin/env python3
"""Two real containers/restic/rest-server; compile-time injected network only.
Run from app/: python3 integration/run.py [--no-build]
All fixtures and secrets stay under app/.integration; containers/network are removed.
"""
import http.cookiejar
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

APP = Path(__file__).resolve().parents[1]
IMAGE = 'buddybackup:integration'
RUN = 'buddy-it-' + uuid.uuid4().hex[:10]
ROOT = APP / '.integration' / RUN
containers = []

def docker(*args, check=True):
    return subprocess.run(['docker', *map(str,args)], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()

class API:
    def __init__(self, port):
        self.base = f'http://127.0.0.1:{port}/api/v1/'
        self.jar = http.cookiejar.CookieJar()
        self.client = urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ''
        deadline = time.monotonic() + 30
        while True:
            try:
                self.csrf = self.get('auth')['csrf_token'];break
            except (OSError, urllib.error.URLError):
                if time.monotonic() > deadline: raise
                time.sleep(.1)
    def call(self, method, path, data=None, expected=200):
        raw = None if data is None else json.dumps(data).encode()
        headers = {'Content-Type':'application/json','X-CSRF-Token':self.csrf}
        req = urllib.request.Request(self.base+path,raw,headers,method=method)
        try:
            with self.client.open(req,timeout=45) as res:
                status,body=res.status,json.load(res)
        except urllib.error.HTTPError as e:
            status,body=e.code,json.load(e)
        if status != expected:
            # Only error envelopes, never export/invitation secrets, appear in logs.
            raise AssertionError(f'{method} {path}: expected {expected}, got {status}: {body.get("error",{})}')
        return body
    def get(self,path):return self.call('GET',path)
    def post(self,path,data=None,expected=200):return self.call('POST',path,data or {},expected)
    def operation(self,kind,success=True,**kw):
        op=self.post('operations',dict(kind=kind,**kw),202)
        deadline=time.monotonic()+180
        while op['state']=='running':
            if time.monotonic()>deadline:raise AssertionError(f'{kind} timed out')
            time.sleep(.15);op=self.get('operations/current')
        if success and op['state']!='success':raise AssertionError(f'{kind}: {op["error"]}')
        if not success and op['state']!='error':raise AssertionError(f'{kind}: expected failure')
        return op

def settings(source, upload=0):
    return dict(sources=[f'/sources/{source}'], interval_hours=24, keep_daily=7,
                keep_weekly=4,keep_monthly=12,direct_only=True, upload_kib=upload,
                ntfy_url='', stale_hours=48)
def ack(api):
    export=api.post('recovery/export')
    api.post('recovery/ack',dict(fingerprint=export['fingerprint'],connection_fingerprint=export['connection_fingerprint'],confirm='SAVED_OFFLINE'))
    return export

def start(name, peer, data=None):
    base=ROOT/name
    for p in ['data','photos','docs','restore']:(base/p).mkdir(parents=True,exist_ok=True)
    data=data or base/'data'
    name_id=f'{RUN}-{name}';containers.append(name_id)
    n=1 if name=='a' else 2
    docker('run','-d','--name',name_id,'--network',RUN,'--network-alias',name,
           '--read-only','--cap-drop','ALL','--cap-add','DAC_READ_SEARCH',
           '--cap-add','CHOWN','--cap-add','FOWNER','--security-opt','no-new-privileges:true',
           '--stop-timeout','60','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777',
           '-p','127.0.0.1::8080','-v',f'{data}:/data',
           '-v',f'{base/"photos"}:/sources/photos:ro','-v',f'{base/"docs"}:/sources/docs:ro',
           '-v',f'{base/"restore"}:/restore',
           '-e','BUDDY_TEST_TRANSPORT=1','-e',f'BUDDY_TEST_IP=100.64.0.{n}',
           '-e',f'BUDDY_TEST_NODE=node-{name}','-e',f'BUDDY_TEST_PEER_NODE=node-{peer}',
           '-e',f'BUDDY_TEST_PEER_IP=100.64.0.{3-n}','-e',f'BUDDY_TEST_PEER_HOST={peer}',IMAGE)
    port=int(docker('port',name_id,'8080/tcp').rsplit(':',1)[1])
    api=API(port);api.post('setup',dict(name=name,password='local-integration-password',quota_bytes=128<<20))
    return name_id,api

def assert_restored(name,folder,source,filename):
    expected=(ROOT/name/source/filename).read_bytes()
    actual=docker('exec',f'{RUN}-{name}','sha256sum',f'/restore/{folder}/sources/{source}/{filename}').split()[0]
    assert actual==hashlib.sha256(expected).hexdigest(), 'restored bytes differ'

def main():
    ROOT.mkdir(parents=True)
    if '--no-build' not in sys.argv:
        print('Building pinned integration image…',flush=True)
        subprocess.run(['docker','build','--build-arg','BUILD_TAGS=integration','-t',IMAGE,str(APP)],check=True)
    docker('network','create',RUN)
    for name in ['a','b']:
        for source in ['photos','docs']:
            p=ROOT/name/source;p.mkdir(parents=True,exist_ok=True)
            (p/'sample.bin').write_bytes(os.urandom(65536))
    ca,a=start('a','b');cb,b=start('b','a')
    ia,ib=a.get('invitation'),b.get('invitation')
    for api,invite in [(a,ib),(b,ia)]:
        api.post('peer',dict(invitation=invite['invitation'],fingerprint=invite['fingerprint'],replace=False))
        api.post('settings',settings('photos'));ack(api)
    print('PASS setup, CSRF sessions, mutual invitation and recovery acknowledgement',flush=True)
    for name,api in [('a',a),('b',b)]:
        result=api.operation('backup')['result'];snapshot=result['snapshot_id']
        rows=api.operation('snapshots')['result']
        assert len(rows)==1 and 'buddybackup-complete' in rows[0]['tags'] and 'buddybackup-pending' not in rows[0]['tags']
        api.operation('restore',snapshot=snapshot,folder='restored')
        assert_restored(name,'restored','photos','sample.bin')
        api.operation('restore',snapshot=snapshot,folder='restored',success=False)
        api.operation('restore',snapshot=snapshot,folder='../escape',success=False)
        api.operation('restore-test');api.operation('check',read_data=True)
        api.operation('maintenance',low_space=True)
    print('PASS bidirectional encrypted backups, complete tags, synthetic restore, verified restore, no-overwrite, check, zero-repack maintenance',flush=True)
    # Retired source group is explicit and never merged with the new path set.
    a.post('settings',settings('docs'))
    retired=[x for x in a.get('source-sets')['source_sets'] if x['retired']]
    assert len(retired)==1
    a.operation('backup')
    a.post('source-sets/retire',dict(id=retired[0]['id'],confirm='DELETE_RETIRED_SNAPSHOTS'),202)
    deadline=time.monotonic()+60
    while True:
        op=a.get('operations/current')
        if op['state']!='running':break
        assert time.monotonic()<deadline;time.sleep(.1)
    assert op['state']=='success' and op['result']['deleted_snapshots']==1
    assert len(a.operation('snapshots')['result'])==1
    print('PASS explicit retired source-set deletion preserves current set',flush=True)
    # Enforce receiver auth and private repos over the isolated bridge.
    ip=docker('inspect','-f',f'{{{{(index .NetworkSettings.Networks "{RUN}").IPAddress}}}}',cb)
    client=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for path in ['/', '/someone-else/config']:
        req=urllib.request.Request(f'http://{ip}:8787{path}')
        try:client.open(req,timeout=10);raise AssertionError('unauthenticated receiver accessible')
        except urllib.error.HTTPError as e:assert e.code==401
    print('PASS receiver authentication and private repository isolation',flush=True)
    # Real SIGTERM during throttled restic: process must exit before the grace period.
    (ROOT/'a'/'docs'/'large.bin').write_bytes(os.urandom(4<<20))
    a.post('settings',settings('docs',64));a.post('operations',dict(kind='backup'),202)
    a.post('operations',dict(kind='unlock',confirm='UNLOCK_STALE_LOCKS'),409)
    deadline=time.monotonic()+20
    while not docker('exec',ca,'pidof','restic',check=False):
        if time.monotonic()>=deadline:
            op=a.get('operations/current');raise AssertionError(f'restic did not stay active: {op["state"]}: {op["error"]}')
        time.sleep(.1)
    began=time.monotonic();docker('stop','-t','60',ca);elapsed=time.monotonic()-began
    assert elapsed<40, f'SIGTERM cleanup took {elapsed:.1f}s'
    docker('start',ca);port=int(docker('port',ca,'8080/tcp').rsplit(':',1)[1]);a=API(port)
    a.post('login',dict(password='local-integration-password'));a.operation('unlock',confirm='UNLOCK_STALE_LOCKS')
    a.operation('check')
    print(f'PASS guarded unlock and SIGTERM restic cleanup ({elapsed:.1f}s); repository check after restart',flush=True)
    # Export/import into a fresh app without initializing a replacement repository.
    export=a.post('recovery/export');docker('rm','-f',ca);containers.remove(ca)
    fresh=ROOT/'a'/'recovery-data';fresh.mkdir()
    ca,a=start('a','b',fresh)
    a.post('recovery/import',dict(kit=export['kit'],fingerprint=export['fingerprint'],confirm='IMPORT_RECOVERY'))
    rows=a.operation('snapshots')['result'];assert rows
    a.operation('restore',snapshot=rows[0]['id'],folder='recovered')
    assert_restored('a','recovered','docs','sample.bin')
    assert not a.get('status')['recovery_acknowledged']
    print('PASS fresh recovery import, existing-repository pinning, recovery-only restore',flush=True)
    print('INTEGRATION PASS (two containers, real restic 0.19.1, embedded rest-server 0.14.0; no real tailnet)',flush=True)

if __name__=='__main__':
    try:main()
    finally:
        for c in reversed(containers):docker('rm','-f',c,check=False)
        docker('network','rm',RUN,check=False)
        if ROOT.exists():
            # Container-created private state directories need root for cleanup.
            docker('run','--rm','--network','none','--entrypoint','/bin/sh',
                   '-v',f'{ROOT}:/cleanup',IMAGE,'-c','rm -rf /cleanup/*',check=False)
            shutil.rmtree(ROOT,ignore_errors=True)
