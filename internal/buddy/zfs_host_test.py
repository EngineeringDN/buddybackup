"""Host logic tests with a fake middleware and ZFS; never touch a NAS."""
import copy
import struct
import zlib
import base64
import os
import datetime
import json
from pathlib import Path
import subprocess
import stat
import shutil
import socket
import time
import tempfile
import unittest
from unittest.mock import patch

BODY = Path(__file__).with_name('zfs_host.py').read_text()
DEFINITIONS = BODY.split('\ndef interrupted(')[0]


class HostProgramTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scope = {'BODY': BODY, 'CONFIG': {}}
        exec(compile(DEFINITIONS, '<host-functions>', 'exec'), self.scope)
        self.offer = {'id': 'a' * 32, 'name': 'alice', 'datasets': ['tank/a', 'tank/b'],
                      'hour': 3, 'retention_days': 30,
                      'public_key': 'ssh-ed25519 ' + base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' + b'a' * 32).decode(), 'created': '2026-11-08T00:00:00Z'}
        self.config = {'side': 'sender', 'offer': self.offer, 'pool': 'tank',
                       'directory': str(self.root), 'parent': 'other/buddy-zfs-' + 'a' * 16,
                       'username': 'bz' + 'a' * 16, 'host_key': 'ssh-ed25519 TEST-HOST',
                       'private_key': 'SECRET-PRIVATE-KEY'}
        self.journal = {'id': self.offer['id'], 'resources': {}}
        self.rows = {}
        self.calls = []
        self.zfs_calls = []
        self.props = {}
        self.scope.update(CONFIG=self.config, offer=self.offer, side='sender',
                          prefix='buddy-zfs-' + 'a' * 32, username=self.config['username'],
                          parent=self.config['parent'], journal=self.journal,
                          manifest=self.root / 'sender.json', script=self.root / 'sender.py',
                          complete=self.root / 'sender-complete.json', status_file=self.root / 'status.json',
                          probe_file=self.root / 'probe.json', guard_file=self.root / 'guard.json', call=self.call,
                          run=self.zrun, zget=self.zget, EXEC_WRAPPER='exec(BODY)\n',
                          key_file=self.root / 'sender.key', hosts_file=self.root / 'sender.hosts')
        self.scope['check_private_key'] = lambda: None

    def call(self, method, *args, **kwargs):
        self.calls.append((method, args, kwargs))
        if method == 'ssh.config':
            return {'passwordauth': False, 'password_login_groups': [], 'options': ''}
        service, action = method.rsplit('.', 1)
        table = self.rows.setdefault(service, [])
        if action == 'query':
            rows = copy.deepcopy(table)
            for key, op, value in args[0] if args else []:
                self.assertEqual(op, '=')
                rows = [r for r in rows if r[key] == value]
            return rows
        if action == 'create':
            row = copy.deepcopy(args[0])
            row['id'] = len(table) + 100
            table.append(row)
            return copy.deepcopy(row)
        if action == 'get_instance':
            return copy.deepcopy(next(r for r in table if r['id'] == args[0]))
        if action == 'update':
            row = next(r for r in table if r['id'] == args[0])
            row.update(copy.deepcopy(args[1]))
            return copy.deepcopy(row)
        if action == 'run':
            self.assertTrue(kwargs.get('job'))
            return None
        if action == 'delete':
            table[:] = [r for r in table if r['id'] != args[0]]
            return True
        if method == 'pool.dataset.export_key':
            self.assertEqual(args, ('tank/encryption-root', False))
            return None
        raise AssertionError((method, args))

    def zrun(self, *args, **kwargs):
        self.zfs_calls.append(args)
        return ''

    def zget(self, dataset, prop):
        return self.props.get((dataset, prop), {
            'encryption': 'aes-256-gcm', 'type': 'filesystem', 'origin': '-',
            'keystatus': 'available', 'encryptionroot': 'tank/encryption-root',
            'org.buddybackup:probe': self.offer['id'], 'guid': '123456',
            'referenced': str(1024 ** 3), 'available': str(100 * 1024 ** 3),
        }.get(prop, '-'))

    def fake_snapshot_exists(self, *args, **kwargs):
        return subprocess.CompletedProcess(args, 1)

    def test_sender_idempotent_cron_and_private_file(self):
        with patch('subprocess.run', self.fake_snapshot_exists):
            self.scope['sender_setup']()
            self.scope['sender_setup']()
        self.assertFalse(self.rows.get('replication'))
        self.assertFalse(self.rows.get('keychaincredential'))
        self.assertEqual(len(self.rows['pool.snapshottask']), 2)
        self.assertEqual(len(self.rows['cronjob']), 2)
        cron = next(r for r in self.rows['cronjob'] if r['description'].endswith('-run'))
        self.assertEqual(cron['schedule']['hour'], '*')
        self.assertEqual(cron['user'], 'root')
        key = self.scope['key_file']
        self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
        self.assertEqual(key.read_text(), 'SECRET-PRIVATE-KEY')
        for path in self.root.iterdir():
            if path != key:
                self.assertNotIn('SECRET-PRIVATE-KEY', path.read_text())
        self.assertEqual(json.loads(self.scope['complete'].read_text())['id'], self.offer['id'])
        compile(self.scope['script'].read_text(), '<persisted-runner>', 'exec')
        self.assertFalse(any('send' in c for c in self.zfs_calls))
        self.assertIn("systemd-run", BODY)

    def test_refuses_modified_owned_resource_and_name_collision(self):
        with patch('subprocess.run', self.fake_snapshot_exists):
            self.scope['sender_setup']()
            self.rows['pool.snapshottask'][0]['enabled'] = False
            with self.assertRaises(self.scope['BuddyError']):
                self.scope['sender_setup']()

    def test_removal_preserves_data_and_is_repeatable(self):
        with patch('subprocess.run', self.fake_snapshot_exists):
            self.scope['sender_setup']()
        self.scope['sys'].argv = ['sender.py', 'remove']
        self.scope['remove']()
        self.scope['remove']()
        self.assertTrue(all(not rows for rows in self.rows.values()))
        self.assertFalse(any(args[:2] == ('zfs', 'destroy') for args in self.zfs_calls))
        self.assertFalse((self.root / 'sender-complete.json').exists())

    def test_receiver_delegation_fixed_scope_and_ssh_restrictions(self):
        self.config.update(side='receiver', quota_gib=50)
        self.scope['side'] = 'receiver'
        self.scope['parent'] = 'tank/buddy-zfs-' + 'a' * 16
        original_call = self.scope['call']
        users = []

        def receiver_call(method, *args, **kwargs):
            if method == 'user.query':
                return copy.deepcopy([u for u in users if all(u[k] == v for k, op, v in args[0])])
            if method == 'user.create':
                row = dict(args[0], id=123, uid=321, group={'gid': 321}, groups=[], roles=[])
                users.append(row)
                return copy.deepcopy(row)
            if method == 'user.get_instance':
                return copy.deepcopy(users[0])
            if method == 'user.update':
                users[0].update(args[1])
                return copy.deepcopy(users[0])
            if method == 'service.query':
                return [{'enable': False, 'state': 'STOPPED'}]
            if method in ('service.update', 'service.control'):
                if method == 'service.control':
                    self.assertTrue(kwargs['job'])
                return True
            return original_call(method, *args, **kwargs)

        self.scope['call'] = receiver_call
        self.scope['receive_status'] = lambda: None
        original_dir = self.scope['directory_fd_close']
        def test_dir(path, **kwargs):
            self.assertTrue(kwargs['protected'])
            return original_dir(path, create=True)
        self.scope['directory_fd_close'] = test_dir
        with patch('os.chown') as chown, patch('subprocess.run', self.fake_snapshot_exists):
            self.scope['receiver_setup']()
            self.scope['receiver_setup']()
        self.assertEqual(len(users), 1)
        self.assertTrue(users[0]['password_disabled'])
        self.assertFalse(users[0]['ssh_password_enabled'])
        self.assertFalse(users[0]['sudo_commands_nopasswd'])
        home = Path(users[0]['home'])
        chown.assert_called_with(str(home), 0, 0)
        self.assertFalse(home.stat().st_mode & 0o022)
        auth = home / '.ssh' / 'authorized_keys'
        self.assertEqual(auth.stat().st_uid, os.getuid())
        self.assertTrue(auth.read_text().startswith('restrict,command="'))
        self.assertNotIn('sshpubkey', users[0])
        self.assertFalse(any(m == 'user.update' for m, _, _ in self.calls))
        gate = self.root / ('gate-' + self.offer['id'] + '.py')
        compile(gate.read_text(), '<gate>', 'exec')
        delegation = [args for args in self.zfs_calls if args[:2] == ('zfs', 'allow')]
        for args in delegation:
            self.assertEqual(args[-1], self.scope['parent'])
            self.assertEqual(set(args[-2].split(',')), {'create', 'mount', 'receive', 'destroy', 'send'})
        self.assertTrue(any('filesystem_limit=128' in c and 'snapshot_limit=8192' in c for c in self.zfs_calls))
        self.assertEqual(len(self.rows['cronjob']), 1)

    def test_changed_encryption_root_type_and_plain_sources_fail_before_send(self):
        with patch('subprocess.run', self.fake_snapshot_exists):
            self.scope['sender_setup']()
        for prop, value in [('encryption', 'off'), ('type', 'volume'), ('encryptionroot', 'tank/other')]:
            with self.subTest(prop=prop):
                self.props[('tank/a', prop)] = value
                sent = []
                self.scope['transfer'] = lambda *args: sent.append(args)
                with self.assertRaises(self.scope['BuddyError']):
                    self.scope['sender_run']()
                self.assertEqual(sent, [])
                status = json.loads(self.scope['status_file'].read_text())
                self.assertEqual(status['datasets'][0]['state'], 'error')
                self.assertTrue(status['datasets'][0]['error'])
                self.props.pop(('tank/a', prop))

    def test_setup_retry_without_app_private_key(self):
        with patch('subprocess.run', self.fake_snapshot_exists):
            self.scope['sender_setup']()
            self.config.pop('private_key')
            self.scope['sender_setup']()
        self.assertEqual(len(self.rows['pool.snapshottask']), 2)

    def test_account_deletion_attempted_when_auth_directory_is_symlink(self):
        self.journal['resources']['user'] = {'id': 123, 'method': 'user.create', 'identity': 'username',
                                             'payload': {'username': self.config['username']}}
        outside = self.root / 'outside'; outside.mkdir()
        home = self.root / 'linked-home'; home.symlink_to(outside, target_is_directory=True)
        self.journal['home'] = str(home)
        self.rows['user'] = [{'id': 123, 'username': self.config['username']}]
        self.scope['side'] = 'receiver'
        self.scope['sys'].argv = ['receiver.py', 'remove']
        self.scope['remove']()
        self.assertEqual(self.rows['user'], [])
        self.assertTrue(any(method == 'user.delete' and args[0] == 123 for method, args, kw in self.calls))

    def test_probe_key_inherited_root_and_absent_key(self):
        root = 'tank/encryption-root'
        self.props[(root, 'keyformat')] = 'hex'
        seen = []
        def keys(method, *args, **kwargs):
            seen.append((method, args, kwargs))
            if method.endswith('encryption_summary'):
                return [{'name': root, 'key_present_in_database': True}]
            return '12' * 32
        self.scope['call'] = keys
        self.assertEqual(self.scope['probe_key'](root), ('12' * 32 + '\n').encode())
        self.assertEqual(seen[0][1], (root, {}))
        self.assertEqual(seen[1][1], (root, False))
        self.assertTrue(all(item[2]['job'] for item in seen))
        self.scope['call'] = lambda *args, **kw: [{'name': root, 'key_present_in_database': False}]
        self.assertIsNone(self.scope['probe_key'](root))
        self.props[(root, 'keyformat')] = 'passphrase'
        self.scope['call'] = lambda *args, **kw: self.fail('must not request passphrase')
        self.assertIsNone(self.scope['probe_key'](root))

    def test_status_atomic_and_newest_per_dataset(self):
        self.scope['run'] = lambda *args, **kwargs: (
            self.config['parent'] + '/d0@new\t200\n' + self.config['parent'] + '/d1@only\t150'
            if 'snapshot' in args else self.config['parent'] + '\t-\t10\n' +
            self.config['parent'] + '/d0\tunavailable\t123\n' + self.config['parent'] + '/d1\tavailable\t456')
        self.scope['receive_status']()
        data = json.loads((self.root / 'status.json').read_text())
        self.assertEqual(len(data['datasets']), 2)
        self.assertEqual(data['datasets'][0]['snapshot_time'], '1970-01-01T00:03:20+00:00')
        self.assertEqual(data['datasets'][1]['keystatus'], 'available')
        self.assertEqual(list(self.root.glob('.buddy-*')), [])

    def test_probe_failure_cleans_temporary_dataset_and_records_error(self):
        # Fail after the temporary parent has been created, during SSH send.
        self.scope['remote_run'] = lambda *args: (
            self.config['parent'] + '/d0@bz-' + 'a' * 16 + '-d0-2026-11-08_03-00' if args[0] == 'list' else '123456')
        with patch('subprocess.Popen', side_effect=OSError('injected send failure')):
            with self.assertRaises(self.scope['BuddyError']):
                self.scope['probe']()
        destroys = [args for args in self.zfs_calls if args[:2] == ('zfs', 'destroy')]
        self.assertEqual(len(destroys), 1)
        self.assertTrue(destroys[0][-1].startswith('tank/buddy-probe-'))
        self.assertTrue(any(args[:2] == ('zfs', 'release') for args in self.zfs_calls))
        self.assertEqual(json.loads((self.root / 'probe.json').read_text())['state'], 'error')
        self.assertFalse(any(self.root.glob('key')))

    def test_public_key_exact_and_line_injection(self):
        validate = self.scope['validate_public_key']
        validate(self.offer['public_key'])
        for value in [self.offer['public_key'] + c for c in ('\n', '\r', ' ', '\nssh-ed25519 evil')]:
            with self.subTest(value=repr(value)), self.assertRaises(self.scope['BuddyError']):
                validate(value)

    def test_safe_report_io_rejects_symlink_directory_and_nonregular_targets(self):
        outside = self.root / 'outside'
        outside.mkdir()
        (outside / 'target').write_text('untouched')
        link = self.root / 'link'
        link.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.scope['atomic'](link / 'target', {'bad': True})
        path = self.root / 'target'
        path.symlink_to(outside / 'target')
        with self.assertRaises(self.scope['BuddyError']):
            self.scope['atomic'](path, {'bad': True})
        with self.assertRaises(self.scope['BuddyError']):
            self.scope['safe_unlink'](path)
        self.assertEqual((outside / 'target').read_text(), 'untouched')
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(self.scope['BuddyError']):
            self.scope['atomic'](path, {})

    def test_report_directory_swap_uses_original_fd(self):
        report = self.root / 'reports'; report.mkdir()
        outside = self.root / 'outside'; outside.mkdir()
        (outside / 'status').write_text('untouched')
        original_replace = os.replace
        def swap(src, dst, **kw):
            report.rename(self.root / 'old-reports')
            report.symlink_to(outside, target_is_directory=True)
            return original_replace(src, dst, **kw)
        with patch('os.replace', swap):
            self.scope['atomic'](report / 'status', {'ok': True})
        self.assertEqual((outside / 'status').read_text(), 'untouched')
        self.assertEqual(json.loads((self.root / 'old-reports' / 'status').read_text()), {'ok': True})

    def test_removal_revokes_user_despite_parent_missing_changed_or_held(self):
        for parent_state in ('missing', 'changed', 'held'):
            with self.subTest(parent_state=parent_state):
                self.journal['resources'] = {'user': {'id': 123, 'method': 'user.create', 'identity': 'username',
                                                      'payload': {'username': self.config['username']}}}
                self.journal['parent_guid'] = '123456'
                self.rows['user'] = [{'id': 123, 'username': self.config['username']}]
                self.scope['side'] = 'receiver'
                self.scope['sys'].argv = ['receiver.py', 'remove', '--destroy-received-data']
                self.scope['atomic'](self.scope['complete'], {'id': self.offer['id']})
                def parent_guid(*a):
                    if parent_state == 'missing':
                        raise subprocess.CalledProcessError(1, ['zfs', 'get'])
                    return 'wrong' if parent_state == 'changed' else '123456'
                self.scope['zget'] = parent_guid
                self.scope['run'] = lambda *a, **kw: 'snapshot\ttag\t0' if 'holds' in a else ''
                with self.assertRaises(self.scope['BuddyError']):
                    self.scope['remove']()
                self.assertEqual(self.rows['user'], [])
                self.assertTrue(self.scope['complete'].exists())

    def test_removal_revokes_account_before_delegation_failure_then_retries(self):
        self.journal['resources']['user'] = {'id': 123, 'method': 'user.create', 'identity': 'username',
                                             'payload': {'username': self.config['username']}}
        self.journal.update(parent_guid='123456', user_uid=321)
        self.rows['user'] = [{'id': 123, 'username': self.config['username']}]
        self.scope['side'] = 'receiver'
        self.scope['sys'].argv = ['receiver.py', 'remove']
        self.scope['atomic'](self.scope['complete'], {'id': self.offer['id']})
        def fail_unallow(*args, **kw):
            if 'unallow' in args:
                self.assertEqual(self.rows['user'], [])
                self.assertEqual(args[-2], '321')
                raise subprocess.CalledProcessError(1, args)
            return self.zrun(*args, **kw)
        self.scope['run'] = fail_unallow
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0)) as proc:
            with self.assertRaises(self.scope['BuddyError']):
                self.scope['remove']()
            self.assertTrue(self.scope['complete'].exists())
            self.assertEqual(self.rows['user'], [])
            self.assertEqual(proc.call_args.args[0], ['/usr/bin/pkill', '-KILL', '-u', '321'])
        self.scope['run'] = self.zrun
        self.scope['remove']()
        self.assertFalse(self.scope['complete'].exists())
        self.assertIn(('zfs', 'unallow', '-u', '321', self.config['parent']), self.zfs_calls)

    def test_probe_space_refused_before_create_and_quota_bounded(self):
        self.scope['remote_run'] = lambda *args: (self.config['parent'] + '/d0@bz-' + 'a' * 16 + '-d0-2026-11-08_03-00' if args[0] == 'list' else '123456')
        self.props[('tank', 'available')] = '1'
        with self.assertRaises(self.scope['BuddyError']):
            self.scope['probe']()
        self.assertFalse(any('create' in c for c in self.zfs_calls))
        self.props[('tank', 'available')] = str(100 * 1024 ** 3)
        with patch('subprocess.Popen', side_effect=OSError('stop')):
            with self.assertRaises(self.scope['BuddyError']):
                self.scope['probe']()
        creates = [c for c in self.zfs_calls if 'create' in c]
        self.assertEqual(len(creates), 1)
        self.assertIn('quota=' + str(2 * 1024 ** 3), creates[0])


    def test_setup_launches_detached_after_marker_and_unlock_without_sending(self):
        from types import SimpleNamespace
        class Client:
            def __enter__(self): return self
            def __exit__(self, *args): pass
        tail = BODY[BODY.index('def interrupted('):]
        directory = self.root / 'control'
        tail = tail.replace("directory = Path('/mnt') / CONFIG['pool'] / 'buddy-zfs-control'", 'directory = Path(' + repr(str(directory)) + ')')
        tail = tail.replace('protected=True', 'protected=False')
        self.scope['control_dataset'] = lambda *args: directory.mkdir()
        self.scope['sys'].argv = ['setup.py']
        def start(args, **kwargs):
            self.assertEqual(args[0], 'systemd-run')
            self.assertEqual(args[-1], 'run')
            self.assertTrue(self.scope['complete'].exists())
            with open(str(self.scope['script']) + '.lock') as fd:
                self.assertTrue(self.scope['acquire_lock'](fd.fileno()))
            self.assertFalse(any('send' in e for e in self.zfs_calls))
        launched = []
        def wraps_run(args, **kwargs):
            if args[0] == 'systemd-run':
                launched.append(args)
                start(args, **kwargs)
                return subprocess.CompletedProcess(args, 0)
            return self.fake_snapshot_exists(args, **kwargs)
        with patch.dict('sys.modules', {'truenas_api_client': SimpleNamespace(Client=Client)}), patch('os.geteuid', return_value=0), patch('subprocess.run', wraps_run):
            exec(compile(tail, '<setup-main>', 'exec'), self.scope)
        self.assertEqual(len(launched), 1)

    def test_metadata_output_is_bounded_and_exact(self):
        self.scope['run'] = self.zrun
        original = self.scope['ssh_command']
        try:
            self.scope['ssh_command'] = lambda *args: ['python3', '-c', 'print("exact-token")']
            self.assertEqual(self.scope['remote_run']('get'), 'exact-token')
            self.scope['ssh_command'] = lambda *args: ['python3', '-c', 'import os; os.write(1,b"a"*1000000)']
            with self.assertRaises(ValueError):
                self.scope['remote_run']('get')
        finally:
            self.scope['ssh_command'] = original

    def test_key_file_ownership_mode_and_public_key_match(self):
        real = {}
        exec(compile(DEFINITIONS, '<key-check>', 'exec'), real)
        real.update(key_file=self.scope['key_file'], offer=self.offer, run=lambda *args: self.offer['public_key'])
        self.scope['private_write'](real['key_file'], 'test-key')
        with patch('os.lstat', return_value=SimpleStat(0, stat.S_IFREG | 0o600)):
            real['check_private_key']()
        for uid, mode in [(1000, stat.S_IFREG | 0o600), (0, stat.S_IFREG | 0o644), (0, stat.S_IFLNK | 0o600)]:
            with patch('os.lstat', return_value=SimpleStat(uid, mode)):
                with self.assertRaises(real['BuddyError']): real['check_private_key']()
        real['run'] = lambda *args: 'ssh-ed25519 wrong'
        with patch('os.lstat', return_value=SimpleStat(0, stat.S_IFREG | 0o600)):
            with self.assertRaises(real['BuddyError']): real['check_private_key']()


class SimpleStat:
    def __init__(self, uid, mode):
        self.st_uid, self.st_mode = uid, mode


def resume_token(values, *, suffix=b'', duplicate=None):
    """Independent encoder for OpenZFS's native nvpair layout, not production code."""
    pairs = list(values.items())
    if duplicate:
        pairs.append(duplicate)
    packed = b'\x00\x01\x00\x00' + struct.pack('<II', 0, 1)
    for name, value in pairs:
        rawname = name.encode() + b'\0'
        offset = (16 + len(rawname) + 7) // 8 * 8
        if value is True:
            kind, nelem, data = 1, 0, b''
        elif isinstance(value, int):
            kind, nelem, data = 8, 1, struct.pack('<Q', value)
        else:
            kind, nelem, data = 9, 1, value.encode() + b'\0'
            data += b'\0' * (-len(data) % 8)
        packed += struct.pack('<ihhii', offset + len(data), len(rawname), 0, nelem, kind)
        packed += rawname + b'\0' * (offset - 16 - len(rawname)) + data
    packed += b'\0' * 4 + suffix
    compressed = zlib.compress(packed)
    checksum = sum(int.from_bytes(compressed[n:n+4], 'little') for n in range(0, len(compressed) // 4 * 4, 4)) % (2 ** 64)
    return '1-%x-%x-%s' % (checksum, len(packed), compressed.hex())


class SenderTest(unittest.TestCase):
    call = HostProgramTest.call
    zrun = HostProgramTest.zrun
    zget = HostProgramTest.zget

    def setUp(self):
        HostProgramTest.setUp(self)
        self.offer['datasets'] = ['tank/a']
        self.journal['source_roots'] = [['tank/a', 'tank/encryption-root']]
        self.base = 'bz-' + 'a' * 16 + '-d0-2026-01-01_03-00'
        self.new = 'bz-' + 'a' * 16 + '-d0-2026-11-08_03-00'
        self.local = {self.base: {'guid': 101, 'creation': 100},
                      self.new: {'guid': 202, 'creation': 200}}
        self.peer = {self.base: 101}
        self.exists = True
        self.token = '-'
        self.holds = set()
        self.events = []
        self.scope['local_snapshots'] = lambda index: copy.deepcopy(self.local)
        self.scope['remote_run'] = self.remote
        self.scope['run'] = self.local_run
        self.scope['transfer'] = self.transfer
        self.scope['syslog'].syslog = lambda *args: None

    def local_run(self, *args, **kwargs):
        self.events.append(args)
        if args[:3] == ('zfs', 'holds', '-H'):
            targets = args[3:]
            return '\n'.join(s + '\t' + tag + '\t0' for s, tag in sorted(self.holds) if s in targets)
        if args[:5] == ('zfs', 'list', '-H', '-t', 'snapshot') and '-r' in args:
            return '\n'.join(sorted({s for s, _ in self.holds if s.startswith(args[-1] + '@')}))
        if args[:2] == ('zfs', 'hold'):
            self.holds.add((args[3], args[2]))
        if args[:2] == ('zfs', 'release'):
            self.holds.remove((args[3], args[2]))
        return ''

    def remote(self, *args):
        self.events.append(('remote', *args))
        if args[0] == 'list':
            if 'filesystem' in args:
                return self.config['parent'] + ('\n' + self.target if self.exists else '')
            return '\n'.join(self.target + '@' + n for n in self.peer)
        if args[0] == 'get':
            if 'receive_resume_token' in args:
                return self.token
            return str(self.peer[args[-1].split('@')[1]])
        if args[:2] == ('recv', '-A'):
            self.token = '-'
            if not self.peer:
                self.exists = False
            return ''
        if args[0] == 'destroy':
            self.peer.pop(args[-1].split('@')[1])
            return ''
        raise AssertionError(args)

    @property
    def target(self):
        return self.config['parent'] + '/d0'

    def transfer(self, args, target):
        self.events.append(('transfer', args, target))
        self.assertEqual(target, self.target)
        name = self.new if '-t' in args else args[-1].split('@')[1]
        self.peer[name] = self.local[name]['guid']
        self.exists = True
        self.token = '-'

    def prepare_resume(self, full=False):
        self.journal.pop('verified_base', None)  # independent pre-success resume scenario
        self.peer = {} if full else {self.base: 101}
        base = None if full else self.base
        self.journal['pending'] = {'0': {'snapshot': self.new, 'guid': 202, 'base': base,
                                         'base_guid': 101 if base else None, 'initial_full': full}}
        for name, kind in [(self.new, 'pending')] + ([] if full else [(self.base, 'base')]):
            self.holds.add(('tank/a@' + name, self.scope['hold_tag'](0, kind)))
        values = {'toname': 'tank/a@' + self.new, 'toguid': 202, 'object': 1,
                  'offset': 0, 'bytes': 123, 'rawok': True, 'largeblockok': True, 'compressok': True}
        if base:
            values['fromguid'] = 101
        return values

    def sends(self):
        return [e for e in self.events if e[0] == 'transfer']

    def test_forged_token_table_never_reaches_resume_send(self):
        original = self.prepare_resume()
        cases = {
            'missing rawok': dict(original, rawok=None),
            'wrong toname': dict(original, toname='tank/a@' + self.base),
            'another local dataset': dict(original, toname='tank/b@' + self.new),
            'wrong toguid': dict(original, toguid=999),
            'wrong fromguid': dict(original, fromguid=999),
            'missing fromguid': dict(original, fromguid=None),
            'unknown flag': dict(original, savedok=True),
            'embed flag': dict(original, embedok=True),
            'fromname': dict(original, fromname='tank/a@' + self.base),
            'wrong schema': dict(original, toname='tank/a@manual'),
            'rawok wrong type': dict(original, rawok=1),
            'diagnostic injection': dict(original, toname='tank/a@bad\n\trawok = 1\n'),
        }
        tokens = {label: resume_token({k: v for k, v in value.items() if v is not None}) for label, value in cases.items()}
        tokens.update(malformed='garbage', oversized='1-' + 'a' * 17000,
                      duplicate=resume_token(original, duplicate=('rawok', 0)),
                      trailing=resume_token(original, suffix=b'evil'),
                      bad_checksum=resume_token(original).replace('1-', '1-f', 1),
                      invalid_hex='1-0-10-xx', wrong_version='2-0-10-00')
        for label, token in tokens.items():
            with self.subTest(label=label):
                self.prepare_resume()
                self.events.clear()
                self.token = token
                self.scope['sender_run']()
                self.assertTrue(self.sends())  # restarted normally
                self.assertFalse(any('-t' in e[1] for e in self.sends()))
                abort = next(i for i, e in enumerate(self.events) if e[:3] == ('remote', 'recv', '-A'))
                first_send = next(i for i, e in enumerate(self.events) if e[0] == 'transfer')
                self.assertLess(abort, first_send)
                state = json.loads(self.scope['status_file'].read_text())['datasets'][0]
                self.assertIn('Sicherheitswarnung', state['security_warning'])

    def test_valid_full_and_incremental_resume_exact_token(self):
        for full in (False, True):
            with self.subTest(full=full):
                self.token = resume_token(self.prepare_resume(full))
                expected = self.token
                self.events.clear()
                self.scope['sender_run']()
                self.assertEqual(self.sends()[0][1], ['-t', expected])
                self.assertEqual(self.holds, {('tank/a@' + self.new, self.scope['hold_tag'](0, 'base'))})

    def test_token_requires_held_base_and_local_intent(self):
        for kind in ('base', 'pending', 'intent'):
            with self.subTest(kind=kind):
                self.token = resume_token(self.prepare_resume())
                if kind == 'intent':
                    self.journal.pop('pending')
                else:
                    self.holds = {(s, t) for s, t in self.holds if not t.endswith('-' + kind)}
                self.events.clear()
                self.scope['sender_run']()
                self.assertFalse(any('-t' in e[1] for e in self.sends()))
                self.assertTrue(any(e[:3] == ('remote', 'recv', '-A') for e in self.events))

    def test_peer_guid_mismatch_and_existing_no_common_never_full(self):
        self.peer[self.base] = 999
        with self.assertRaises(self.scope['BuddyError']):
            self.scope['sender_run']()
        self.assertEqual(self.sends(), [])
        self.assertFalse(any(e[:2] == ('remote', 'destroy') for e in self.events))

    def test_full_only_when_absent(self):
        self.exists, self.peer = False, {}
        self.scope['sender_run']()
        self.assertEqual(self.sends()[0][1], ['-p', 'tank/a@' + self.new])

    def test_newest_name_and_guid_common_selection(self):
        self.peer[self.new] = 999  # a matching name alone must not become the base
        self.scope['sender_run']()
        self.assertEqual(self.sends()[0][1][:3], ['-p', '-i', 'tank/a@' + self.base])

    def test_hostile_snapshot_names(self):
        for name in ('-option', '$(id)', 'x;id', 'x\nother', '../evil', 'manual', self.new + '@extra'):
            with self.subTest(name=name):
                self.peer = {name: 101}
                self.events.clear()
                with self.assertRaises(self.scope['BuddyError']):
                    self.scope['sender_run']()
                self.assertEqual(self.sends(), [])

    def test_verification_failure_preserves_base_and_pending_hold(self):
        self.scope['transfer'] = lambda *args: self.events.append(('transfer', *args))
        with self.assertRaises(self.scope['BuddyError']):
            self.scope['sender_run']()
        self.assertIn(('tank/a@' + self.base, self.scope['hold_tag'](0, 'base')), self.holds)
        self.assertIn(('tank/a@' + self.new, self.scope['hold_tag'](0, 'pending')), self.holds)
        state = json.loads(self.scope['status_file'].read_text())['datasets'][0]
        self.assertIsNone(state['last_success'])
        self.assertEqual(state['state'], 'error')
        self.assertTrue(self.journal['pending']['0'])

    def test_hold_movement_retention_and_remove(self):
        self.scope['sender_run']()
        held = ('tank/a@' + self.new, self.scope['hold_tag'](0, 'base'))
        self.assertEqual(self.holds, {held})
        self.assertNotIn(self.base, self.peer)
        self.assertIn(self.new, self.peer)  # both snapshots expired; latest remains
        acquire = next(i for i, e in enumerate(self.events) if e == ('zfs', 'hold', held[1], held[0]))
        release = next(i for i, e in enumerate(self.events) if e[:2] == ('zfs', 'release'))
        self.assertLess(acquire, release)
        self.scope['sys'].argv = ['sender.py', 'remove']
        self.scope['remove']()
        self.assertEqual(self.holds, set())

    def test_retention_uses_journal_for_snapshots_no_longer_local(self):
        self.journal['known_snapshots'] = {'0': copy.deepcopy(self.local)}
        self.local.pop(self.base)
        self.peer[self.new] = 202
        self.scope['sender_run']()
        self.assertEqual(self.peer, {self.new: 202})

    def test_overlap_lock_and_release(self):
        path = self.root / 'lock'
        with path.open('w') as first, path.open('w') as second:
            self.assertTrue(self.scope['acquire_lock'](first.fileno()))
            self.assertFalse(self.scope['acquire_lock'](second.fileno()))
            self.scope['fcntl'].flock(first.fileno(), self.scope['fcntl'].LOCK_UN)
            self.assertTrue(self.scope['acquire_lock'](second.fileno()))

    def test_transfer_always_raw_including_resume(self):
        transfer = {}
        exec(compile(DEFINITIONS, '<real-transfer>', 'exec'), transfer)
        transfer.update(key_file=self.root / 'key', hosts_file=self.root / 'hosts', username='bztest')
        calls = []
        transfer['stream'] = lambda *args: calls.append(args)
        for args in (['-p', 'tank/a@' + self.new], ['-t', 'validated-exact-token']):
            transfer['transfer'](args, self.target)
            send, recv = calls[-1]
            self.assertEqual(send, ['/usr/sbin/zfs', 'send', '-w', *args])
            gate = {}
            exec(transfer['GATE'], gate)
            gate['gate_command'](recv[-1], self.config['parent'])


    def test_sigterm_stops_before_another_dataset(self):
        self.offer['datasets'].append('tank/b')
        self.journal['source_roots'].append(['tank/b', 'tank/encryption-root'])
        calls = []
        def interrupted(index, state):
            calls.append(index)
            raise self.scope['BuddyInterrupted']('interrupted')
        self.scope['send_dataset'] = interrupted
        with self.assertRaises(self.scope['BuddyError']):
            self.scope['sender_run']()
        self.assertEqual(calls, [0])
        self.assertEqual(json.loads(self.scope['status_file'].read_text())['datasets'][0]['state'], 'error')

    def test_schema_checked_even_for_an_existing_local_manual_snapshot(self):
        values = self.prepare_resume()
        values['toname'] = 'tank/a@manual'
        self.local['manual'] = {'guid': 202, 'creation': 200}
        self.journal['pending']['0']['snapshot'] = 'manual'
        self.token = resume_token(values)
        with self.assertRaises(ValueError):
            self.scope['validate_resume'](self.token, 0, self.local, self.journal['pending']['0'])

    def test_retention_stops_if_peer_changes_claim_after_verification(self):
        original = self.scope['remote_snapshots']
        calls = 0
        def changed(index):
            nonlocal calls
            calls += 1
            result = original(index)
            if calls == 3:  # initial, verify, before hold movement/retention
                result.pop(self.new, None)
            return result
        self.scope['remote_snapshots'] = changed
        with self.assertRaises(self.scope['BuddyError']):
            self.scope['sender_run']()
        self.assertFalse(any(e[:2] == ('remote', 'destroy') for e in self.events))
        self.assertIn(('tank/a@' + self.base, self.scope['hold_tag'](0, 'base')), self.holds)

    def test_verification_rejects_guid_mismatch_and_a_newer_snapshot(self):
        for fault in ('guid', 'newer'):
            with self.subTest(fault=fault):
                self.peer = {self.base: 101}
                def wrong(args, target):
                    self.transfer(args, target)
                    if fault == 'guid': self.peer[self.new] = 999
                    else: self.peer[self.new.replace('11-08', '11-09')] = 303
                self.scope['transfer'] = wrong
                with self.assertRaises(self.scope['BuddyError']):
                    self.scope['sender_run']()
                self.assertIsNone(self.journal['sender_states']['0']['last_success'])

    def test_overlap_main_exits_quietly_before_loading_journal(self):
        path = self.root / 'control'
        path.mkdir()
        script = path / ('sender-' + self.offer['id'] + '.py')
        code = BODY.replace("directory = Path('/mnt') / CONFIG['pool'] / 'buddy-zfs-control'", 'directory = Path(' + repr(str(path)) + ')')
        code = code.replace('protected=True', 'protected=False')  # test temp ancestors owned by test user
        with open(str(script) + '.lock', 'w') as lock:
            self.scope['fcntl'].flock(lock.fileno(), self.scope['fcntl'].LOCK_EX)
            with patch('os.geteuid', return_value=0), patch('sys.argv', ['runner', 'run']):
                with self.assertRaises(SystemExit) as result:
                    exec(compile(code.replace("control_dataset(directory, action == 'setup')", 'pass'), '<overlap>', 'exec'), {'CONFIG': self.config})
            self.assertEqual(result.exception.code, 0)
        self.assertFalse(script.with_suffix('.json').exists())


class FinalSecurityTest(unittest.TestCase):
    setUp = HostProgramTest.setUp
    call = HostProgramTest.call
    zrun = HostProgramTest.zrun
    zget = HostProgramTest.zget
    fake_snapshot_exists = HostProgramTest.fake_snapshot_exists
    def test_control_requires_own_mounted_filesystem_and_rejects_bind_source(self):
        directory = self.root / 'buddy-zfs-control'
        self.config['bind_datasets'] = ['tank/buddy-zfs-control']
        with patch('subprocess.run') as proc:
            with self.assertRaises(self.scope['BuddyError']):
                self.scope['control_dataset'](directory, True)
            proc.assert_not_called()
        self.config['bind_datasets'] = []
        self.scope['directory_fd_close'] = lambda *args, **kw: None
        self.props.update({('tank/buddy-zfs-control', 'mounted'): 'yes',
                           ('tank/buddy-zfs-control', 'mountpoint'): str(directory)})
        def create(*args, **kw):
            self.zrun(*args, **kw)
            if args[:2] == ('zfs', 'create'):
                directory.mkdir(mode=0o755)
        self.scope['run'] = create
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 1)), patch('os.path.ismount', return_value=True), patch('os.chown'):
            self.scope['control_dataset'](directory, True)
        self.assertIn(('zfs', 'create', '-o', 'mountpoint=/tank/buddy-zfs-control', '-o', 'setuid=off',
                       '-o', 'devices=off', '-o', 'exec=on', '-o', 'snapdir=hidden', 'tank/buddy-zfs-control'), self.zfs_calls)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0)), patch('os.path.ismount', return_value=False):
            with self.assertRaises(self.scope['BuddyError']):
                self.scope['control_dataset'](directory, True)
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 1)):
            with self.assertRaises(self.scope['BuddyError']):
                self.scope['control_dataset'](directory, True)  # no plain-folder adoption

    def test_ssh_password_auth_groups_and_auxiliary_overrides_abort_before_mutation(self):
        for ssh in ({'passwordauth': True}, {'passwordauth': False, 'password_login_groups': ['admins']},
                    {'passwordauth': False, 'options': 'Match User root\nPasswordAuthentication yes'}, {}):
            with self.subTest(ssh=ssh):
                self.scope['call'] = lambda method, *args, **kw: ssh if method == 'ssh.config' else self.fail('mutation before SSH check')
                with patch('subprocess.run') as proc:
                    with self.assertRaisesRegex(self.scope['BuddyError'], 'Password Login Groups'):
                        self.scope['receiver_setup']()
                    proc.assert_not_called()
                self.assertEqual(self.zfs_calls, [])

    def test_probe_queries_use_bounded_remote_path_and_raw_only_is_not_verification(self):
        queries, streams = [], []
        def query(*args):
            queries.append(args)
            return self.config['parent'] + '/d0@bz-' + 'a' * 16 + '-d0-2026-11-08_03-00' if args[0] == 'list' else '123456'
        self.scope['remote_run'] = query
        self.scope['stream'] = lambda *args: streams.append(args)
        self.scope['probe_key'] = lambda *args: None
        self.scope['probe']()
        self.assertEqual([q[0] for q in queries], ['list', 'get'])
        result = json.loads(self.scope['probe_file'].read_text())
        self.assertEqual(result['state'], 'raw_only')
        self.assertEqual(result['message'], 'Freund hat einen Stream geliefert; Inhalt nicht geprüft. Entschlüsselung benötigt den Benutzerschlüssel.')
        self.assertNotIn('geprüft;', result['message'])
        self.assertTrue(any('volmode=none' in c and 'dedup=off' in c and 'copies=1' in c for c in self.zfs_calls))
        self.assertEqual(streams[0][1], ['/usr/sbin/zfs', 'recv', '-u', *self.scope['RECEIVE_EXCLUDES'], streams[0][1][-1]])
        self.assertNotIn('TemporaryFile', DEFINITIONS)
        self.assertFalse(any(c and c[0] == 'ssh' for c in self.zfs_calls))

    def test_probe_reconciles_only_its_stale_deterministic_hold(self):
        tag = self.scope['hold_tag'](0, 'probe')
        self.scope['dataset_holds'] = lambda source: ('tank/a@old\t' + tag + '\t0\n' +
            'tank/a@base\t' + self.scope['hold_tag'](0, 'base') + '\t0\n' +
            'tank/a@unrelated\tmanual\t0')
        self.scope['remote_run'] = lambda *args: (self.config['parent'] + '/d0@bz-' + 'a' * 16 + '-d0-2026-11-08_03-00' if args[0] == 'list' else '123456')
        self.scope['stream'] = lambda *args: None
        self.scope['probe_key'] = lambda *args: None
        self.scope['probe']()
        releases = [c for c in self.zfs_calls if c[:2] == ('zfs', 'release')]
        self.assertIn(('zfs', 'release', tag, 'tank/a@old'), releases)
        self.assertEqual(len(releases), 2)  # stale probe, then current probe in finally
        self.assertTrue(all(c[2] == tag for c in releases))

    def test_remote_query_discards_hostile_stderr_and_bounds_both_probe_queries(self):
        for method in ('list', 'get'):
            self.scope['ssh_command'] = lambda *args: ['python3', '-c', 'import os; os.write(2, b"E"*1000000); print("123")']
            self.assertEqual(self.scope['remote_query'](method), '123')
            self.scope['ssh_command'] = lambda *args: ['python3', '-c', 'import os; os.write(1,b"X"*1000000)']
            with self.assertRaises(ValueError):
                self.scope['remote_query'](method)

    def test_stream_watchdog_stalled_sender_receiver_and_eof(self):
        self.scope['STREAM_IDLE_SECONDS'] = .15
        python = self.scope['sys'].executable
        for sender, receiver in (
            ('import time; time.sleep(30)', 'import sys; sys.stdin.buffer.read()'),
            ('import os; os.write(1,b"X"*1000000)', 'import time; time.sleep(30)'),
            ('pass', 'import sys,time; sys.stdin.buffer.read(); time.sleep(30)'),
        ):
            start = time.monotonic()
            with self.subTest(sender=sender), self.assertRaises(self.scope['BuddyError']):
                self.scope['stream']([python, '-c', sender], [python, '-c', receiver])
            self.assertLess(time.monotonic() - start, 2)

    def test_slow_moving_stream_outlives_idle_timeout(self):
        self.scope['STREAM_IDLE_SECONDS'] = .3
        python = self.scope['sys'].executable
        sender = 'import os,time\nfor i in range(12): os.write(1,b"X"*65536); time.sleep(.06)'
        receiver = 'import sys\nassert len(sys.stdin.buffer.read()) == 12*65536'
        start = time.monotonic()
        self.scope['stream']([python, '-c', sender], [python, '-c', receiver])
        self.assertGreater(time.monotonic() - start, .6)

    def test_lock_pid_cancellation_and_abnormal_skip_report(self):
        lock = self.root / 'lock'
        # A real independent process holds flock and records its PID/start time.
        code = DEFINITIONS + "\nguard_file=Path(" + repr(str(self.scope['guard_file'])) + ")\nfd=os.open(" + repr(str(lock)) + ",os.O_CREAT|os.O_RDWR,0o600)\nenter_lock(fd,'run')\nprint('ready',flush=True)\ntime.sleep(30)\n"
        child = subprocess.Popen([self.scope['sys'].executable, '-c', code], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            self.assertEqual(child.stdout.readline(), b'ready\n')
            with lock.open('r+') as second:
                owner = self.scope['lock_owner'](second.fileno())
                self.assertEqual(owner['pid'], child.pid)
                with patch('time.time', return_value=time.time() + 7*3600):
                    self.assertFalse(self.scope['enter_lock'](second.fileno(), 'run'))
                self.assertIn('6 Stunden', json.loads(self.scope['guard_file'].read_text())['message'])
                start = time.monotonic()
                self.assertTrue(self.scope['enter_lock'](second.fileno(), 'remove'))
                self.assertLess(time.monotonic() - start, 2)
                self.assertEqual(self.scope['lock_owner'](second.fileno())['pid'], os.getpid())
            self.assertEqual(child.wait(timeout=2), -15)
        finally:
            if child.poll() is None: child.kill()
            child.wait()
            child.stdout.close()

    def test_missing_first_sender_dataset_does_not_block_other_cleanup(self):
        with patch('subprocess.run', self.fake_snapshot_exists):
            self.scope['sender_setup']()
        cleaned = []
        def release(index, source, keep):
            cleaned.append(source)
            if source == 'tank/a': raise subprocess.CalledProcessError(1, [])
        self.scope['release_holds'] = release
        with patch('sys.argv', ['runner', 'remove']), patch('subprocess.run', self.fake_snapshot_exists):
            self.scope['remove']()
        self.assertEqual(cleaned, ['tank/a', 'tank/b'])
        self.assertFalse(self.scope['key_file'].exists())
        self.assertFalse(self.scope['complete'].exists())
        self.assertFalse(self.rows['cronjob'])


class HoldBoundTest(unittest.TestCase):
    setUp = SenderTest.setUp
    call = HostProgramTest.call
    zrun = HostProgramTest.zrun
    zget = HostProgramTest.zget
    local_run = SenderTest.local_run
    remote = SenderTest.remote
    transfer = SenderTest.transfer
    sends = SenderTest.sends
    target = SenderTest.target
    def test_failed_new_intents_cannot_accumulate_offer_holds(self):
        self.scope['transfer'] = lambda *args: None  # peer keeps reporting the old base
        for day in range(8, 18):
            name = self.new.replace('11-08', '11-%02d' % day)
            self.local[name] = {'guid': 200 + day, 'creation': 200 + day}
            self.holds.add(('tank/a@stale', 'buddy-' + self.offer['id'] + '-old-tag'))
            with self.assertRaises(self.scope['BuddyError']):
                self.scope['sender_run']()
            self.assertEqual(self.holds, {('tank/a@' + self.base, self.scope['hold_tag'](0, 'base')),
                                          ('tank/a@' + name, self.scope['hold_tag'](0, 'pending'))})
            self.assertEqual(self.journal['pending']['0']['snapshot'], name)

    def test_peer_cannot_move_intent_away_from_last_verified_base(self):
        self.journal['verified_base'] = {'0': self.base}
        self.peer = {self.new: 202}
        self.holds = {('tank/a@' + self.base, self.scope['hold_tag'](0, 'base'))}
        with self.assertRaises(self.scope['BuddyError']): self.scope['sender_run']()
        self.assertEqual(self.holds, {('tank/a@' + self.base, self.scope['hold_tag'](0, 'base'))})
        self.assertEqual(self.sends(), [])


class NativeTokenTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('BUDDY_ZFS_NVPAIR_TEST') == '1', 'libnvpair differential test requires zfs-libs')
    def test_decoder_matches_real_libnvpair_native_packing(self):
        import ctypes as c
        lib = c.CDLL('libnvpair.so.3')
        lib.fnvlist_alloc.restype = c.c_void_p
        lib.fnvlist_add_string.argtypes = [c.c_void_p, c.c_char_p, c.c_char_p]
        lib.fnvlist_add_uint64.argtypes = [c.c_void_p, c.c_char_p, c.c_uint64]
        lib.fnvlist_add_boolean.argtypes = [c.c_void_p, c.c_char_p]
        lib.fnvlist_pack.argtypes = [c.c_void_p, c.POINTER(c.c_size_t)]
        lib.fnvlist_pack.restype = c.c_void_p
        lib.fnvlist_pack_free.argtypes = [c.c_void_p, c.c_size_t]
        lib.fnvlist_free.argtypes = [c.c_void_p]
        values = {'toname': 'tank/a@bz-aaaaaaaaaaaaaaaa-d0-2026-11-08_03-00',
                  'toguid': 0xffffffffffffffff, 'fromguid': 123456789, 'object': 22,
                  'offset': 1048576, 'bytes': 9999999, 'rawok': True,
                  'largeblockok': True, 'compressok': True}
        nv = lib.fnvlist_alloc()
        packed_ptr = None
        try:
            for key, value in values.items():
                if value is True:
                    lib.fnvlist_add_boolean(nv, key.encode())
                elif isinstance(value, str):
                    lib.fnvlist_add_string(nv, key.encode(), value.encode())
                else:
                    lib.fnvlist_add_uint64(nv, key.encode(), value)
            size = c.c_size_t()
            packed_ptr = lib.fnvlist_pack(nv, c.byref(size))
            packed = c.string_at(packed_ptr, size.value)
            compressed = zlib.compress(packed)
            checksum = sum(v[0] for v in struct.iter_unpack('<I', compressed[:len(compressed) // 4 * 4]))
            token = '1-%x-%x-%s' % (checksum, len(packed), compressed.hex())
            scope = {}
            exec(compile(DEFINITIONS, '<native-token>', 'exec'), scope)
            self.assertEqual(scope['decode_resume_token'](token), values)
            self.assertEqual(scope['decode_resume_token'](resume_token(values)), values)
        finally:
            if packed_ptr: lib.fnvlist_pack_free(packed_ptr, size.value)
            lib.fnvlist_free(nv)


class GateTest(unittest.TestCase):
    def setUp(self):
        scope = {}
        exec(compile(DEFINITIONS, '<functions>', 'exec'), scope)
        self.gate = {}
        exec(compile(scope['GATE'], '<gate>', 'exec'), self.gate)
        self.parent = 'tank/buddy-zfs-' + 'a' * 16

    def test_explicit_command_table(self):
        p = self.parent
        wrapped = lambda s: "sh -c 'PATH=$PATH:/usr/local/sbin:/usr/sbin:/sbin zfs " + s + " 2>&1'"
        recv = "sh -c 'PATH=$PATH:/usr/local/sbin:/usr/sbin:/sbin zfs recv -s -F -x xattr -x sharesmb -x mountpoint -x sharenfs " + p + "/d0'"
        allowed = [
            '/usr/sbin/zfs recv -s -u -x mountpoint -x sharenfs -x sharesmb -x xattr -x volmode -x dedup -x copies -x reservation -x refreservation ' + p + '/d0',
            '/usr/sbin/zfs recv -A ' + p + '/d0',
            '/usr/sbin/zfs destroy ' + p + '/d0@snap',
            '/usr/sbin/zfs list -H -p -t filesystem -d 1 -o name ' + p,
            '/usr/sbin/zfs get -H -o value receive_resume_token ' + p + '/d0',
            '/usr/sbin/zfs send -w ' + p + '/d0@snap',
            '/usr/sbin/zfs list -H -p -t snapshot -d 1 -o name -s creation ' + p + '/d0',
            '/usr/sbin/zfs get -H -o value guid ' + p + '/d0@snap',
        ]
        refused = [
            *[allowed[0].replace('-x ' + prop + ' ', '') for prop in ('volmode', 'dedup', 'copies', 'reservation', 'refreservation')],
            '', 'bash', 'sftp', recv, wrapped('recv -x'),
            wrapped('list -t snapshot -H -o name -s name -d 1 ' + p + '/d0'),
            *[c.replace(p + '/d0', ds) for c in allowed if p + '/d0' in c
              for ds in (p, p + '/d32', p + '/d0/child', 'tank/outside')],
            *[c.replace('recv -s -u', form) for c in allowed if 'recv -s -u' in c
              for form in ('recv -s -F', 'recv -s', 'recv -u', 'receive -s -u')],
            '/usr/sbin/zfs destroy ' + p + '/d0@snap1,snap2', '/usr/sbin/zfs send ' + p + '/d0@snap',
            '/usr/sbin/zfs send -t 1-abc-def', '/usr/sbin/zfs send -w tank/other@snap',
            '/usr/sbin/zfs send -w ' + p + 'evil/d0@snap',
            '/usr/sbin/zfs send -w ' + p + '/../../other@snap',
            '/usr/sbin/zfs send -w ' + p + '/d0@snap;id',
            '/usr/sbin/zfs send -w ' + p + '/d0@$(id)',
            '/usr/sbin/zfs load-key ' + p + '/d0', '/usr/sbin/zfs set quota=none ' + p,
            '/usr/sbin/zfs allow root ' + p, 'sh -c "cat </dev/tcp/host/22"',
            wrapped('destroy ' + p), wrapped('destroy ' + p + '/d0'),
            wrapped('destroy ' + p + '/d0@snap,tank/other@snap'),
            wrapped('set filesystem_limit=none ' + p), wrapped('recv -A ' + p),
            recv.replace(p + '/d0', p), recv.replace(p, 'tank/outside'),
            recv.replace('-x mountpoint', '-x quota'), recv + '; id',
            wrapped('load-key ' + p + '/d0'), wrapped('allow root ' + p),
            wrapped('get -H -p -t filesystem,volume type tank/other'),
            wrapped('recv -x; id'), wrapped('recv -x $(id)'),
            wrapped('recv -x /dev/tcp/host/22'),
            recv.replace('PATH=$PATH:', 'PATH=/tmp:'),
            recv.replace("sh -c '", 'sh -c "').replace("'", '"'),
        ]
        for command in allowed:
            with self.subTest(allowed=command):
                args = self.gate['gate_command'](command, p)
                self.assertEqual(args[0], '/usr/sbin/zfs')
        for command in refused:
            with self.subTest(refused=command), self.assertRaises(ValueError):
                self.gate['gate_command'](command, p)


class OpenSSHStrictModesTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('BUDDY_ZFS_SSHD_TEST') == '1' and os.geteuid() == 0 and shutil.which('sshd'), 'root + OpenSSH required (pinned Go test image)')
    def test_root_owned_home_keys_and_forced_gate_with_strictmodes(self):
        # Runs only in the disposable test container. No NAS paths are touched.
        with tempfile.TemporaryDirectory(prefix='buddy-sshd-') as tmp:
            root = Path(tmp); root.chmod(0o755)
            home = root / 'home'; home.mkdir(mode=0o755)
            sshdir = home / '.ssh'; sshdir.mkdir(mode=0o755)
            user = 'bztest' + str(os.getpid())
            subprocess.run(['adduser', '-D', '-H', '-h', str(home), '-s', '/bin/sh', user], check=True)
            try:
                # Alpine locks new accounts; permit keys while sshd denies passwords.
                subprocess.run(['chpasswd'], input=(user + ':test-only-disposable-password\n').encode(), check=True)
                key = root / 'key'; hostkey = root / 'hostkey'
                for path in (key, hostkey):
                    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)], check=True)
                scope = {}; exec(compile(DEFINITIONS, '<host-functions>', 'exec'), scope)
                parent = 'tank/buddy-zfs-' + 'a' * 16
                fake = root / 'fake-zfs'
                fake.write_text('#!/bin/sh\nprintf "RAW-GATE-OK\\n"\n'); fake.chmod(0o755)
                gate = root / 'gate.py'
                gate.write_text(scope['GATE'].replace('import os\n', 'import os\nPARENT = ' + repr(parent) + '\n', 1)
                                .replace("os.execve('/usr/sbin/zfs'", 'os.execve(' + repr(str(fake))))
                gate.chmod(0o755)
                auth = sshdir / 'authorized_keys'
                auth.write_text('restrict,command="' + str(gate) + '" ' + key.with_suffix('.pub').read_text())
                auth.chmod(0o644)
                self.assertTrue(all(p.stat().st_uid == 0 and not p.stat().st_mode & 0o022 for p in (home, sshdir, auth, gate)))
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
                config = root / 'sshd_config'
                config.write_text('Port ' + str(port) + '\nListenAddress 127.0.0.1\nHostKey ' + str(hostkey) +
                                  '\nPidFile ' + str(root / 'pid') + '\nStrictModes yes\nPasswordAuthentication no\n'
                                  'KbdInteractiveAuthentication no\nUsePAM no\nPermitRootLogin no\nLogLevel VERBOSE\n')
                log = root / 'log'
                with log.open('wb') as error_log:
                    server = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(config)], stderr=error_log)
                try:
                    for _ in range(100):
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                break
                        except OSError:
                            if server.poll() is not None:
                                self.fail(log.read_text())
                            time.sleep(.01)
                    hosts = root / 'hosts'
                    hosts.write_text('[127.0.0.1]:' + str(port) + ' ' + hostkey.with_suffix('.pub').read_text())
                    ssh = ['ssh', '-T', '-oBatchMode=yes', '-oIdentitiesOnly=yes', '-oStrictHostKeyChecking=yes',
                           '-oUserKnownHostsFile=' + str(hosts), '-i', str(key), '-p', str(port), user + '@127.0.0.1']
                    allowed = subprocess.run(ssh + ['/usr/sbin/zfs send -w ' + parent + '/d0@snap'], capture_output=True, timeout=10)
                    self.assertEqual(allowed.returncode, 0, (allowed.stderr.decode(), log.read_text()))
                    self.assertEqual(allowed.stdout, b'RAW-GATE-OK\n')
                    for cmd in ('id', '/usr/sbin/zfs send ' + parent + '/d0@snap', 'cat /etc/passwd', ''):
                        refused = subprocess.run(ssh + [cmd], capture_output=True, timeout=10)
                        self.assertNotEqual(refused.returncode, 0, cmd)
                        self.assertIn('SSH-Befehl abgelehnt', refused.stderr.decode())
                finally:
                    server.terminate(); server.wait(timeout=5)
            finally:
                subprocess.run(['deluser', user], check=True, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    unittest.main()
