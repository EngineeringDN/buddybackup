# Executed only on the TrueNAS host, never in the app. CONFIG/BODY are supplied
# through a quoted heredoc, not process argv. The persisted runner has no keys.
import datetime
import fcntl
import hashlib
import json
import re
import os
from pathlib import Path
import shlex
import stat
import signal
import subprocess
import sys
import tempfile
import traceback
import uuid
import struct
import zlib
import syslog
import select
import time


class BuddyError(Exception):
    pass


class BuddyInterrupted(BuddyError):
    pass


def fail(message):
    raise BuddyError(message)


def run(*args, input=None):
    if args and args[0] == 'zfs':
        args = ('/usr/sbin/zfs', *args[1:])
    return subprocess.run(args, input=input, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True).stdout.decode().strip()


def zget(dataset, prop):
    return run('/usr/sbin/zfs', 'get', '-H', '-p', '-o', 'value', prop, dataset)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def directory_fd_close(*args, **kwargs):
    os.close(directory_fd(*args, **kwargs))


def directory_fd(path, create=False, protected=False):
    # Walk from / using directory handles: no symlink in ANY path component.
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        fail('Unsicherer Kontrollpfad.')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            if create:
                try:
                    os.mkdir(part, 0o755 if protected else 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            st = os.fstat(fd)
            if protected and (st.st_uid != 0 or st.st_mode & 0o022):
                fail('Kontrollpfad muss root gehören und darf nicht fremd beschreibbar sein.')
        return fd
    except BaseException:
        os.close(fd)
        raise


def regular_target(fd, name):
    try:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(st.st_mode):
        fail('ZFS-Dateiziel ist keine reguläre Datei.')


def atomic(path, value):
    fd = directory_fd(path.parent, create=True)
    name = '.buddy-' + uuid.uuid4().hex
    try:
        regular_target(fd, path.name)
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(out, 'w') as f:
            json.dump(value, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path.name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def safe_unlink(path):
    try:
        fd = directory_fd(path.parent)
    except FileNotFoundError:
        return
    try:
        regular_target(fd, path.name)
        try:
            os.unlink(path.name, dir_fd=fd)
        except FileNotFoundError:
            pass
    finally:
        os.close(fd)


def private_write(path, text, mode=0o600):
    fd = directory_fd(path.parent)
    name = '.buddy-' + uuid.uuid4().hex
    try:
        regular_target(fd, path.name)
        out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=fd)
        os.fchmod(out, mode)
        with os.fdopen(out, 'w') as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path.name, src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        try:
            os.unlink(name, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def validate_public_key(key):
    # The SSH ed25519 wire format is a fixed 51-byte blob. No comments/options,
    # leading/trailing whitespace or second authorized_keys line are accepted.
    import base64
    if not isinstance(key, str) or '\r' in key or '\n' in key:
        fail('Ungültiger öffentlicher SSH-Schlüssel.')
    try:
        kind, encoded = key.split(' ')
        raw = base64.b64decode(encoded, validate=True)
        if (kind != 'ssh-ed25519' or raw[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'
                or len(raw) != 51 or base64.b64encode(raw).decode() != encoded):
            raise ValueError()
    except (ValueError, TypeError):
        fail('Ungültiger öffentlicher SSH-Schlüssel.')


# Exact runner/restore grammar. No shell, wrappers, rollback or token send.
GATE = r'''#!/usr/bin/python3 -I
import os
import re
import sys
import syslog


def gate_command(command, parent):
    if not command or len(command) > 262000 or any(c in command for c in '\r\n\x00'):
        raise ValueError('command')
    args = command.split(' ')
    if not args or args[0] != '/usr/sbin/zfs' or '' in args:
        raise ValueError('binary')
    a = args[1:]
    def dataset(value, child=False):
        return (re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*(/[A-Za-z0-9][A-Za-z0-9_.-]*)*', value)
                and all(p not in ('.', '..') for p in value.split('/'))
                and (value.startswith(parent + '/') or not child and value == parent))
    def snapshot(value):
        pieces = value.split('@')
        return (len(pieces) == 2 and dataset(pieces[0], True)
                and ',' not in pieces[1]
                and all(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]*', x)
                        and x not in ('.', '..') for x in pieces[1].split(',')))
    def target(value):
        return re.fullmatch(re.escape(parent) + r'/d(?:[0-9]|[12][0-9]|3[01])', value)
    allowed = False
    if len(a) == 3 and a[:2] == ['send', '-w']:
        allowed = snapshot(a[2]) and target(a[2].split('@')[0])
    if len(a) == 12 and a[:11] == ['list', '-H', '-p', '-t', 'snapshot', '-d', '1', '-o', 'name', '-s', 'creation']:
        allowed = target(a[11])
    if a == ['list', '-H', '-p', '-t', 'filesystem', '-d', '1', '-o', 'name', parent]:
        allowed = True
    if len(a) == 6 and a[:4] == ['get', '-H', '-o', 'value']:
        allowed = (a[4] == 'guid' and snapshot(a[5]) and target(a[5].split('@')[0])
                   or a[4] == 'receive_resume_token' and target(a[5]))
    if len(a) == 22 and a[:21] == ['recv', '-s', '-u', '-x', 'mountpoint', '-x', 'sharenfs', '-x', 'sharesmb', '-x', 'xattr', '-x', 'volmode', '-x', 'dedup', '-x', 'copies', '-x', 'reservation', '-x', 'refreservation']:
        allowed = target(a[21])
    if len(a) == 3 and a[:2] == ['recv', '-A']:
        allowed = target(a[2])
    if len(a) == 2 and a[0] == 'destroy':
        allowed = snapshot(a[1]) and target(a[1].split('@')[0])
    if not allowed:
        raise ValueError('form or scope')
    return ['/usr/sbin/zfs'] + a


if __name__ == '__main__':
    try:
        argv = gate_command(os.environ.get('SSH_ORIGINAL_COMMAND', ''), PARENT)
    except ValueError:
        syslog.openlog('buddy-zfs-gate')
        syslog.syslog(syslog.LOG_WARNING, 'SSH-Befehl abgelehnt (uid=%d)' % os.getuid())
        sys.exit('SSH-Befehl abgelehnt.')
    os.execve('/usr/sbin/zfs', argv, {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
'''


def call(method, *args, job=False):
    # Official TrueNAS local client; job=True is midclt call -j semantics.
    return client.call(method, *args, job=job)


def save():
    atomic(manifest, journal)


def resource(label, method, payload, identity):
    # Persist intent BEFORE middleware mutation, so a crash is resumable.
    entry = journal['resources'].get(label)
    query = method.rsplit('.', 1)[0] + '.query'
    if entry:
        if entry['payload'] != payload:
            fail('Einrichtung geändert; zuerst vorhandene Aufgaben entfernen.')
    else:
        if call(query, [[identity, '=', payload[identity]]]):
            fail('Namenskollision; vorhandene TrueNAS-Ressource bleibt unverändert.')
        entry = {'method': method, 'payload': payload, 'identity': identity, 'id': None}
        journal['resources'][label] = entry
        save()
    rows = call(query, [[identity, '=', payload[identity]]])
    if rows:
        row = rows[0]
        if entry['id'] is not None and row['id'] != entry['id']:
            fail('TrueNAS-Ressource wurde ersetzt; Abbruch.')
        # Never silently reuse an unrelated or subsequently modified resource.
        for key, value in payload.items():
            actual = row.get(key)
            if actual != value:
                fail('TrueNAS-Ressource wurde verändert: ' + label + '/' + key)
    else:
        if entry['id'] is not None:
            fail('TrueNAS-Ressource fehlt; erst entfernen/zurücksetzen.')
        row = call(method, payload)
    entry['id'] = row['id'] if isinstance(row, dict) else row
    save()
    return entry['id']


def write_runner():
    public = {k: v for k, v in CONFIG.items() if k != 'private_key'}
    runner = ('import base64, json\nCONFIG = json.loads(' + repr(json.dumps(public)) +
              ')\nBODY = ' + repr(BODY) + '\n' + EXEC_WRAPPER)
    runner = 'EXEC_WRAPPER = ' + repr(EXEC_WRAPPER) + '\n' + runner
    private_write(script, runner)


def install_runner(action, schedule):
    write_runner()
    resource('cron-' + action, 'cronjob.create', {
        'description': prefix + '-' + action, 'user': 'root',
        'command': '/usr/bin/python3 -I ' + shlex.quote(str(script)) + ' ' + action,
        'schedule': schedule, 'enabled': True, 'stdout': True, 'stderr': False,
    }, 'description')


def receive_status():
    rows = run('zfs', 'list', '-H', '-p', '-r', '-t', 'filesystem,volume',
               '-o', 'name,keystatus,used', parent).splitlines()
    snapshots = run('zfs', 'list', '-H', '-p', '-r', '-t', 'snapshot',
                    '-o', 'name,creation', '-s', 'creation', parent).splitlines()
    newest = {}
    for line in snapshots:
        name, creation = line.split('\t')
        newest[name.split('@')[0]] = (name, int(creation))
    datasets = []
    for line in rows:
        name, key, used = line.split('\t')
        if name == parent:
            continue
        snap, created = newest.get(name, ('', 0))
        datasets.append({'name': name, 'keystatus': key, 'used_bytes': int(used),
                         'snapshot': snap, 'snapshot_time': (
                             datetime.datetime.fromtimestamp(created, datetime.timezone.utc).isoformat()
                             if created else '0001-01-01T00:00:00Z')})
    atomic(status_file, {'updated': utc(), 'datasets': datasets})


def receiver_setup():
    validate_public_key(offer['public_key'])
    ssh = call('ssh.config')
    if ssh.get('passwordauth') is not False or ssh.get('password_login_groups', []) or ssh.get('options', '').strip():
        fail('TrueNAS-SSH muss für alle Benutzer Passwortauthentifizierung deaktivieren: Dienste > SSH > Password Authentication ausschalten, Password Login Groups leeren und Auxiliary Parameters entfernen; danach erneut einrichten.')
    # A unique parent is app-owned; no existing dataset is adopted.
    if 'parent_created' not in journal:
        if subprocess.run(['/usr/sbin/zfs', 'list', '-H', parent], stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0:
            fail('Ziel-Dataset existiert bereits; Abbruch ohne Übernahme.')
        journal['parent_created'] = 'planned'
        save()
    if subprocess.run(['/usr/sbin/zfs', 'list', '-H', parent], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode != 0:
        run('zfs', 'create', '-o', 'encryption=off', '-o', 'mountpoint=none',
            '-o', 'canmount=off', '-o', 'volmode=none', parent)
        journal['parent_guid'] = zget(parent, 'guid')
        save()
    if not journal.get('parent_guid') or zget(parent, 'guid') != journal['parent_guid']:
        fail('Ziel-Dataset-GUID stimmt nicht mit dem Journal überein.')
    journal['parent_created'] = True
    save()
    run('zfs', 'set', 'quota=' + str(CONFIG['quota_gib']) + 'G', parent)
    run('zfs', 'set', 'filesystem_limit=128', 'snapshot_limit=8192', 'volmode=none',
        'dedup=off', 'copies=1', parent)
    home = str(script.parent / ('home-' + offer['id'][:16]))
    if 'home' not in journal:
        if os.path.lexists(home):
            fail('Benutzer-Home existiert bereits; Abbruch.')
        journal['home'] = home
        save()
    # TrueNAS treats home as a parent directory when home_create is set, so create the real home here.
    directory_fd_close(home, create=True, protected=True)
    # user.create makes a real, owned home. Explicitly no admin/sudo/SMB rights.
    user_payload = {'username': username, 'full_name': prefix, 'group_create': True,
                    'home': home, 'home_create': False,
                    'shell': '/usr/bin/bash', 'smb': False, 'password_disabled': True,
                    'ssh_password_enabled': False, 'sudo_commands': [],
                    'sudo_commands_nopasswd': []}
    # User result contains group IDs/home_create defaults not creation-only fields.
    user_resource(user_payload)
    st = os.lstat(home)
    if not stat.S_ISDIR(st.st_mode):
        fail('Benutzer-Home ist kein echter Ordner.')
    # StrictModes permits uid 0 ownership; all ancestors, home, .ssh and
    # authorized_keys are root-owned and have no group/other write permission.
    os.chown(home, 0, 0)
    os.chmod(home, 0o755)
    sshdir = Path(home) / '.ssh'
    directory_fd_close(sshdir, create=True, protected=True)
    os.chmod(sshdir, 0o755)
    gate = script.parent / ('gate-' + offer['id'] + '.py')
    private_write(gate, GATE.replace("import os\n", "import os\nPARENT = " + repr(parent) + "\n", 1), 0o755)
    # Never ask middleware to write sshpubkey: that would give ownership to user.
    private_write(sshdir / 'authorized_keys', 'restrict,command="' + str(gate) + '" ' + offer['public_key'] + '\n', 0o644)
    run('zfs', 'allow', '-u', username, 'create,mount,receive,destroy,send', parent)
    # No shell, userprop, hold/release, snapshot, limits, key or property rights.
    # Shared SSH intentionally remains enabled on removal. No restoration state.
    journal.pop('ssh_before', None)
    call('service.update', 'ssh', {'enable': True})
    if not call('service.control', 'START', 'ssh', {'silent': False}, job=True):
        fail('SSH-Dienst konnte nicht gestartet werden.')
    install_runner('status', {'minute': '*/5', 'hour': '*', 'dom': '*', 'month': '*', 'dow': '*'})
    receive_status()
    atomic(complete, {'id': offer['id'], 'quota_gib': CONFIG['quota_gib']})


def user_resource(payload):
    entry = journal['resources'].get('user')
    if not entry:
        if call('user.query', [['username', '=', username]]):
            fail('Benutzername existiert bereits.')
        entry = {'method': 'user.create', 'payload': payload, 'identity': 'username', 'id': None}
        journal['resources']['user'] = entry
        save()
    rows = call('user.query', [['username', '=', username]])
    if rows:
        row = rows[0]
        if (entry['id'] is not None and entry['id'] != row['id']) or row['full_name'] != prefix or row['home'] != payload['home']:
            fail('Benutzer gehört nicht zu diesem Auftrag.')
        if row.get('sudo_commands') or row.get('sudo_commands_nopasswd') or row.get('roles') or row.get('groups'):
            fail('Empfangsbenutzer hat unerwartete Rechte.')
    else:
        if entry['id'] is not None:
            fail('Empfangsbenutzer fehlt.')
        row = call('user.create', payload)
    if not isinstance(row.get('uid'), int) or row['uid'] <= 0:
        fail('Ungültige Empfangsbenutzer-UID.')
    journal['user_uid'] = row['uid']
    entry['id'] = row['id']
    save()
    return row['id']


def snapshot_schema(index):
    return 'bz-' + offer['id'][:16] + '-d' + str(index) + '-%Y-%m-%d_%H-%M'


def validate_sources():
    # Entire selection is checked BEFORE mkdir, tasks, keys or snapshots.
    sources = []
    for index, source in enumerate(offer['datasets']):
        names = [source]
        for name in names:
            if len(name.encode()) + 1 + len(datetime.datetime.now().strftime(snapshot_schema(index))) > 255:
                fail('Datasetname lässt keinen sicheren Snapshotnamen zu: ' + name)
            if zget(name, 'encryption') == 'off':
                fail('Unverschlüsseltes Dataset abgelehnt: ' + name)
            if zget(name, 'type') != 'filesystem':
                fail('Für die Wiederherstellungsprobe sind nur Dateisysteme erlaubt: ' + name)
            root = zget(name, 'encryptionroot')
            if root == '-' or zget(name, 'keystatus') != 'available':
                fail('Verschlüsselungswurzel muss lokal entsperrt sein: ' + name)
            sources.append((name, root))
    return sources


def acquire_lock(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False


def schema_snapshot(name, index):
    if not isinstance(name, str):
        return False
    schema = snapshot_schema(index)
    try:
        return datetime.datetime.strptime(name, schema).strftime(schema) == name
    except ValueError:
        return False


def guid(value):
    if not re.fullmatch(r'[1-9][0-9]{0,19}', value) or int(value) >= 2 ** 64:
        fail('Ungültige Snapshot-GUID.')
    return int(value)


def decode_resume_token(token):
    # OpenZFS 2.3.x/2.4: dsl_dataset.c get_receive_resume_token_impl,
    # fnvpair.c fnvlist_pack (NATIVE), nvpair.c nvs_native_nvp_op, and
    # libzfs_sendrecv.c zfs_send_resume_token_to_nvlist. Only the exact native
    # little-endian format generated on supported amd64 TrueNAS is accepted.
    # Never parse nvlist_print: strings can contain spoofed diagnostic lines.
    if not isinstance(token, str) or len(token) > 16384:
        raise ValueError('token size')
    match = re.fullmatch(r'1-([0-9a-f]{1,16})-([0-9a-f]{1,4})-([0-9a-f]+)', token)
    if not match or len(match[3]) % 2:
        raise ValueError('token header')
    packed_len = int(match[2], 16)
    if not 16 <= packed_len <= 8192 or sys.byteorder != 'little':
        raise ValueError('token payload size/architecture')
    compressed = bytes.fromhex(match[3])
    # Fletcher4 word[0] sums complete native uint32 words (trailing bytes ignored).
    checksum = sum(v[0] for v in struct.iter_unpack('<I', compressed[:len(compressed) // 4 * 4])) % (2 ** 64)
    if checksum != int(match[1], 16):
        raise ValueError('token checksum')
    decoder = zlib.decompressobj()
    packed = decoder.decompress(compressed, packed_len + 1)
    if (len(packed) != packed_len or not decoder.eof or decoder.unused_data
            or decoder.unconsumed_tail or packed[:12] != b'\x00\x01\x00\x00' + struct.pack('<II', 0, 1)):
        raise ValueError('token encoding')
    values = {}
    pos = 12
    while pos + 4 <= len(packed):
        size = struct.unpack_from('<i', packed, pos)[0]
        if size == 0:
            if pos + 4 != len(packed):
                raise ValueError('trailing data')
            return values
        if size < 24 or size % 8 or pos + size > len(packed):
            raise ValueError('nvpair size')
        _, namesize, reserved, nelem, kind = struct.unpack_from('<ihhii', packed, pos)
        if reserved or namesize < 2 or 16 + namesize > size:
            raise ValueError('nvpair header')
        namebytes = packed[pos + 16:pos + 16 + namesize]
        if namebytes[-1:] != b'\0' or b'\0' in namebytes[:-1]:
            raise ValueError('nvpair name')
        name = namebytes[:-1].decode('ascii')
        if name in values:
            raise ValueError('duplicate key')
        offset = (16 + namesize + 7) & ~7
        data = packed[pos + offset:pos + size]
        if kind == 1 and nelem == 0 and not data:  # DATA_TYPE_BOOLEAN, presence flag
            value = True
        elif kind == 8 and nelem == 1 and len(data) == 8:  # UINT64
            value = struct.unpack('<Q', data)[0]
        elif kind == 9 and nelem == 1 and b'\0' in data:  # STRING
            value, padding = data.split(b'\0', 1)
            if any(padding) or len(data) != ((len(value) + 1 + 7) & ~7):
                raise ValueError('string padding')
            value = value.decode('ascii')
        else:
            raise ValueError('nvpair type')
        values[name] = value
        pos += size
    raise ValueError('missing terminator')


def validate_resume(token, index, local, pending):
    values = decode_resume_token(token)
    required = {'toname', 'toguid', 'object', 'offset', 'bytes', 'rawok'}
    # OpenZFS generates no fromname. Reject it, saved/embed/redaction flags and
    # all unknown keys/types rather than accepting future semantics implicitly.
    if not required <= values.keys() or values.keys() - (required | {'fromguid', 'largeblockok', 'compressok'}):
        raise ValueError('token fields/flags')
    if any(values.get(k) is not True for k in ('rawok',) + tuple(k for k in ('largeblockok', 'compressok') if k in values)):
        raise ValueError('token raw flag')
    if any(type(values[k]) is not int for k in ('toguid', 'object', 'offset', 'bytes')):
        raise ValueError('token numeric types')
    name = pending.get('snapshot', '')
    if (not schema_snapshot(name, index) or name not in local
            or values['toname'] != offer['datasets'][index] + '@' + name
            or values['toguid'] != local[name]['guid'] or pending.get('guid') != local[name]['guid']):
        raise ValueError('token destination')
    base = pending.get('base')
    if base:
        if (base not in local or type(values.get('fromguid')) is not int
                or values['fromguid'] != local[base]['guid'] or pending.get('base_guid') != local[base]['guid']
                or not has_hold(index, offer['datasets'][index] + '@' + base, 'base')):
            raise ValueError('token incremental base')
    elif 'fromguid' in values or not pending.get('initial_full'):
        raise ValueError('token full base')
    if not has_hold(index, values['toname'], 'pending'):
        raise ValueError('token target hold')
    return name


def check_private_key():
    st = os.lstat(key_file)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
        fail('SSH-Privatschlüssel muss eine root-eigene 0600-Datei sein.')
    if run('/usr/bin/ssh-keygen', '-y', '-f', str(key_file)) != offer['public_key']:
        fail('SSH-Privatschlüssel stimmt nicht mit dem Angebot überein.')


def remote_run(*args):
    # A fresh tunnel can drop the very first connection; one quiet retry avoids a false alarm.
    try:
        return remote_query(*args)
    except BuddyError:
        time.sleep(10)
        return remote_query(*args)


def remote_query(*args):
    # Bound peer metadata, runtime and errors; never expose hostile output as a
    # root exception/log message. Streams use a separate no-progress watchdog.
    process = subprocess.Popen(ssh_command(key_file, hosts_file, 'zfs', *args),
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    data = bytearray()
    deadline = time.monotonic() + 60
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                fail('Zeitüberschreitung bei ZFS-Abfrage beim Freund.')
            block = os.read(process.stdout.fileno(), min(4096, 65537 - len(data)))
            if not block:
                break
            data.extend(block)
            if len(data) > 65536:
                raise ValueError('peer metadata size')
        if process.wait(timeout=max(0.01, deadline - time.monotonic())):
            fail('ZFS-Abfrage beim Freund fehlgeschlagen.')
    finally:
        process.stdout.close()
        if process.poll() is None:
            process.kill()
        process.wait()
    return data.decode('ascii').removesuffix('\n')


def local_snapshots(index):
    source = offer['datasets'][index]
    rows = run('zfs', 'list', '-H', '-p', '-t', 'snapshot', '-d', '1', '-o',
               'name,guid,creation', '-s', 'creation', source)
    result = {}
    for row in rows.splitlines():
        full, identity, created = row.split('\t')
        if not full.startswith(source + '@'):
            fail('Unerwarteter lokaler Snapshot.')
        name = full[len(source) + 1:]
        if schema_snapshot(name, index):
            result[name] = {'guid': guid(identity), 'creation': int(created)}
    return result


def remote_exists(target):
    rows = remote_run('list', '-H', '-p', '-t', 'filesystem', '-d', '1', '-o', 'name', parent).splitlines()
    if parent not in rows or len(rows) != len(set(rows)):
        fail('Ungültige Datasetliste vom Freund.')
    if any(row != parent and not re.fullmatch(re.escape(parent) + r'/d(?:[0-9]|[12][0-9]|3[01])', row) for row in rows):
        fail('Ungültiger Datasetname vom Freund.')
    return target in rows


def remote_snapshots(index):
    target = parent + '/d' + str(index)
    rows = remote_run('list', '-H', '-p', '-t', 'snapshot', '-d', '1', '-o', 'name', '-s', 'creation', target)
    result = {}
    for full in rows.splitlines():
        if not full.startswith(target + '@') or not schema_snapshot(full[len(target) + 1:], index):
            fail('Ungültiger Snapshotname vom Freund.')
        name = full[len(target) + 1:]
        if name in result:
            fail('Doppelter Snapshot vom Freund.')
        result[name] = guid(remote_run('get', '-H', '-o', 'value', 'guid', full))
    return result


def hold_tag(index, kind):
    return 'buddy-' + offer['id'] + '-d' + str(index) + '-' + kind


def has_hold(index, snapshot, kind):
    return any(row.split('\t')[1] == hold_tag(index, kind)
               for row in run('zfs', 'holds', '-H', snapshot).splitlines())


def ensure_hold(index, snapshot, kind):
    if not has_hold(index, snapshot, kind):
        run('zfs', 'hold', hold_tag(index, kind), snapshot)


def dataset_holds(dataset):
    # `zfs holds` only accepts snapshots, so list them first; -r on a filesystem is an error.
    snapshots = run('zfs', 'list', '-H', '-t', 'snapshot', '-o', 'name', '-r', dataset).splitlines()
    rows = [run('zfs', 'holds', '-H', *snapshots[i:i + 200]) for i in range(0, len(snapshots), 200)]
    return '\n'.join(row for row in rows if row)


def release_holds(index, source, keep):
    tag_prefix = 'buddy-' + offer['id'] + '-'
    for row in dataset_holds(source).splitlines():
        snapshot, tag, _ = row.split('\t')
        if snapshot.startswith(source + '@') and tag.startswith(tag_prefix) and (snapshot, tag) not in keep:
            run('zfs', 'release', tag, snapshot)


# No total duration limit: even a multi-day stream survives while bytes move.
STREAM_IDLE_SECONDS = 30 * 60
ABNORMAL_LOCK_SECONDS = 6 * 60 * 60
RECEIVE_EXCLUDES = ['-x', 'mountpoint', '-x', 'sharenfs', '-x', 'sharesmb', '-x', 'xattr',
                    '-x', 'volmode', '-x', 'dedup', '-x', 'copies', '-x', 'reservation', '-x', 'refreservation']


def stream(send_argv, recv_argv):
    processes = []
    try:
        send = subprocess.Popen(send_argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        processes.append(send)
        recv = subprocess.Popen(recv_argv, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        processes.append(recv)
        os.set_blocking(send.stdout.fileno(), False)
        os.set_blocking(recv.stdin.fileno(), False)
        pending = b''  # at most 64 KiB, never peer-controlled buffering on disk
        eof = False
        deadline = time.monotonic() + STREAM_IDLE_SECONDS
        while not eof or pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                fail('ZFS-Stream seit 30 Minuten ohne Fortschritt; abgebrochen.')
            readable, writable, _ = select.select(
                [] if eof or pending else [send.stdout], [recv.stdin] if pending else [], [], remaining)
            if readable:
                pending = os.read(send.stdout.fileno(), 65536)
                eof = not pending
            if writable:
                count = os.write(recv.stdin.fileno(), pending)
                pending = pending[count:]
                if count:
                    deadline = time.monotonic() + STREAM_IDLE_SECONDS
        recv.stdin.close()
        for process in processes:
            try:
                code = process.wait(timeout=max(.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                fail('ZFS-Stream seit 30 Minuten ohne Fortschritt; abgebrochen.')
            if code:
                fail('Raw-Übertragung fehlgeschlagen; stündlicher Wiederholungsversuch.')
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
        for process in processes:
            process.wait()
            for pipe in (process.stdin, process.stdout):
                if pipe:
                    pipe.close()


def transfer(send_args, target):
    # Raw mode is explicit even for a validated resume token.
    stream(['/usr/sbin/zfs', 'send', '-w', *send_args],
           ssh_command(key_file, hosts_file, 'zfs', 'recv', '-s', '-u', *RECEIVE_EXCLUDES, target))


def send_dataset(index, state):
    source, target = offer['datasets'][index], parent + '/d' + str(index)
    local = local_snapshots(index)
    if not local:
        fail('Kein passender lokaler Snapshot vorhanden.')
    exists = remote_exists(target)
    try:
        token = remote_run('get', '-H', '-o', 'value', 'receive_resume_token', target) if exists else '-'
    except (ValueError, UnicodeError):
        token = 'invalid-token'
    known = journal.setdefault('known_snapshots', {}).setdefault(str(index), {})
    known.update(local)
    save()
    pending = journal.setdefault('pending', {}).get(str(index), {})
    resumed = False
    if token != '-':
        try:
            name = validate_resume(token, index, local, pending)
            peer = remote_snapshots(index)
            if pending.get('base') and peer.get(pending['base']) != pending['base_guid']:
                raise ValueError('resume base no longer common')
            resumed = True
        except (ValueError, UnicodeError, struct.error, zlib.error):
            state['security_warning'] = 'Sicherheitswarnung: manipuliertes oder unerwartetes Resume-Token verworfen.'
            save()
            syslog.syslog(syslog.LOG_WARNING, state['security_warning'])
            sender_report()
            remote_run('recv', '-A', target)
            exists = remote_exists(target)
    if not resumed:
        peer = remote_snapshots(index) if exists else {}
        common = [n for n in local if peer.get(n) == local[n]['guid']]
        base = max(common, key=lambda n: (local[n]['creation'], n)) if common else None
        verified_base = journal.get('verified_base', {}).get(str(index))
        if verified_base:
            if verified_base not in common:
                fail('Letzte bestätigte Basis fehlt beim Freund; keine neue Transferabsicht.')
            base = verified_base
        if not base and exists:
            fail('Kein gemeinsamer Snapshot; vorhandenes Empfangsziel bleibt unverändert.')
        name = max(local, key=lambda n: (local[n]['creation'], n))
        keep = {(source + '@' + name, hold_tag(index, 'pending'))}
        if base:
            keep.add((source + '@' + base, hold_tag(index, 'base')))
        release_holds(index, source, keep)
        if base:
            ensure_hold(index, source + '@' + base, 'base')
        if base == name:
            # Re-check newest: a peer may have additional, divergent snapshots.
            verify_received(index, name, local[name]['guid'])
            finish_dataset(index, name, local, state)
            return
        ensure_hold(index, source + '@' + name, 'pending')
        pending = {'snapshot': name, 'guid': local[name]['guid'], 'base': base,
                   'base_guid': local[base]['guid'] if base else None, 'initial_full': not exists}
        journal['pending'][str(index)] = pending
        save()  # crash-safe intent and both holds precede any stream
    args = ['-t', token] if resumed else ['-p'] + (['-i', source + '@' + pending['base']] if pending['base'] else []) + [source + '@' + name]
    transfer(args, target)
    verify_received(index, name, local[name]['guid'])
    finish_dataset(index, name, local, state)


def verify_received(index, name, identity):
    peer = remote_snapshots(index)
    # The gate fixes list ordering to creation; validate the newest row too.
    if not peer or next(reversed(peer)) != name or peer[name] != identity:
        fail('Empfangsprüfung fehlgeschlagen: neuester Snapshot oder GUID weicht ab.')


def finish_dataset(index, name, local, state):
    # Reconfirm before hold movement/retention; changed peer claims cannot make
    # the previous common base a retention victim.
    peer = remote_snapshots(index)
    if not peer or next(reversed(peer)) != name or peer[name] != local[name]['guid']:
        fail('Empfangsprüfung vor Retention fehlgeschlagen.')
    source, target = offer['datasets'][index], parent + '/d' + str(index)
    ensure_hold(index, source + '@' + name, 'base')
    journal.setdefault('verified_base', {})[str(index)] = name
    journal.setdefault('pending', {}).pop(str(index), None)
    save()  # acquire new base before releasing old or pending holds
    release_holds(index, source, {(source + '@' + name, hold_tag(index, 'base'))})
    cutoff = datetime.datetime.now(datetime.timezone.utc).timestamp() - offer['retention_days'] * 86400
    # Only local creation times and matching local identities authorize deletion.
    for old, item in journal.get('known_snapshots', {}).get(str(index), local).items():
        if old != name and item['creation'] < cutoff and peer.get(old) == item['guid']:
            remote_run('destroy', target + '@' + old)
    state.update(last_success=utc(), last_sent_snapshot=source + '@' + name, error='', state='success')
    sender_report()


def sender_report():
    atomic(status_file, {'updated': utc(), 'scheduler': 'cron',
                        'datasets': list(journal.get('sender_states', {}).values())})


def sender_run():
    states = journal.setdefault('sender_states', {})
    failed = False
    for index, source in enumerate(offer['datasets']):
        state = states.setdefault(str(index), {'name': source, 'state': 'pending',
                      'last_attempt': None, 'last_success': None, 'last_sent_snapshot': '',
                      'error': '', 'security_warning': '', 'bytes': None})
        stopping = False
        state.update(last_attempt=utc(), state='running', error='')
        sender_report()
        try:
            roots = validate_sources()
            if roots != [tuple(item) for item in journal.get('source_roots', [])]:
                fail('Verschlüsselungswurzel stimmt nicht mit der Einrichtung überein.')
            check_private_key()
            send_dataset(index, state)
        except Exception as exc:
            failed = True
            stopping = isinstance(exc, BuddyInterrupted)
            # The status file stays generic; this root-only log is what makes a failure diagnosable.
            traceback.print_exc()
            if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
                print(exc.stderr.decode(errors='replace')[:2000], file=sys.stderr, flush=True)
            state.update(state='error', error=str(exc) if isinstance(exc, BuddyError) else 'ZFS-Sender fehlgeschlagen; Quelle, Tunnel und Empfang prüfen.')
        finally:
            save()
            sender_report()
        if stopping:
            break
    atomic(guard_file, {'updated': utc(), 'state': 'error' if failed else 'ok',
                       'message': 'ZFS-Sender fehlgeschlagen; Status prüfen.' if failed else 'Raw-Sender geprüft.'})
    if failed:
        fail('ZFS-Sender fehlgeschlagen; stündlicher Wiederholungsversuch.')


def sender_setup():
    validate_public_key(offer['public_key'])
    roots = validate_sources()
    if 'source_roots' in journal and journal['source_roots'] != [list(item) for item in roots]:
        fail('Verschlüsselungswurzel wurde verändert; neue Einrichtung erforderlich.')
    journal['source_roots'] = [list(item) for item in roots]
    save()
    if not key_file.exists():
        if not CONFIG.get('private_key'):
            fail('SSH-Schlüssel fehlt; neue Einrichtung erforderlich.')
        private_write(key_file, CONFIG['private_key'])
    check_private_key()
    private_write(hosts_file, '[127.0.0.1]:2288 ' + CONFIG['host_key'] + '\n')
    for index, source in enumerate(offer['datasets']):
        naming = snapshot_schema(index)
        resource('snapshot-' + str(index), 'pool.snapshottask.create', {
            'dataset': source, 'recursive': False, 'exclude': [],
            'lifetime_value': offer['retention_days'], 'lifetime_unit': 'DAY',
            'naming_schema': naming, 'enabled': True,
            'schedule': {'minute': '0', 'hour': str(offer['hour']), 'dom': '*',
                         'month': '*', 'dow': '*', 'begin': '00:00', 'end': '23:59'},
            'allow_empty': True,
        }, 'naming_schema')
        snap = source + '@' + datetime.datetime.now().strftime(naming)
        if subprocess.run(['/usr/sbin/zfs', 'list', '-H', '-t', 'snapshot', snap],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            run('zfs', 'snapshot', snap)
    install_runner('run', {'minute': '1', 'hour': '*', 'dom': '*', 'month': '*', 'dow': '*'})
    install_runner('probe', {'minute': '17', 'hour': '4', 'dom': '1', 'month': '*', 'dow': '*'})
    sender_report()
    atomic(complete, {'id': offer['id']})


def ssh_command(key_file, hosts_file, *remote):
    return ['ssh', '-T', '-oBatchMode=yes', '-oStrictHostKeyChecking=yes',
            '-oIdentitiesOnly=yes', '-oConnectTimeout=15', '-oUserKnownHostsFile=' + str(hosts_file),
            '-i', str(key_file), '-p', '2288', username + '@127.0.0.1',
            # Non-interactive SSH sessions have no /usr/sbin in PATH on TrueNAS.
            shlex.join(('/usr/sbin/zfs' if remote[0] == 'zfs' else remote[0], *remote[1:]))]


def content_digest(root):
    # Deterministic content/type/symlink inventory; don't follow symlinks or cross
    # into child mounts. Metadata permissions are not a content verification.
    h = hashlib.sha256()
    def walk_error(error):
        raise error  # os.walk hides errors otherwise, and two unreadable trees would compare equal

    for current, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if d != '.zfs')
        for name in sorted(dirs + files):
            path = os.path.join(current, name)
            st = os.lstat(path)
            h.update(os.fsencode(os.path.relpath(path, root)) + b'\0')
            h.update(str(stat.S_IFMT(st.st_mode)).encode() + b'\0')
            if stat.S_ISLNK(st.st_mode):
                h.update(os.fsencode(os.readlink(path)) + b'\0')
            elif stat.S_ISREG(st.st_mode):
                h.update(str(st.st_size).encode() + b'\0')
                with open(path, 'rb') as f:
                    for block in iter(lambda: f.read(1024 * 1024), b''):
                        h.update(block)
            elif not stat.S_ISDIR(st.st_mode):
                fail('Spezialdatei kann nicht durch Inhaltsprobe geprüft werden.')
    return h.hexdigest()


def probe_key(root):
    key_format = zget(root, 'keyformat')
    if key_format == 'passphrase':
        return None
    summary = call('pool.dataset.encryption_summary', root, {}, job=True)
    if not any(item['name'] == root and item['key_present_in_database'] for item in summary):
        return None
    secret = call('pool.dataset.export_key', root, False, job=True)
    if not secret:
        return None
    return bytes.fromhex(secret) if key_format == 'raw' else (secret + '\n').encode()


def probe():
    result = {'updated': utc(), 'state': 'error', 'message': 'ZFS-Probe fehlgeschlagen.'}
    # Only this unique parent is ever destroyed; no -F on an existing dataset.
    temporary = CONFIG['pool'] + '/buddy-probe-' + offer['id'][:16] + '-' + uuid.uuid4().hex
    created = False
    held = False
    local_snapshot = None
    probe_tag = hold_tag(0, 'probe')
    try:
        check_private_key()
        with tempfile.TemporaryDirectory(prefix='buddy-probe-', dir='/tmp') as tmp:
            hosts_file = Path(tmp) / 'hosts'
            private_write(hosts_file, '[127.0.0.1]:2288 ' + CONFIG['host_key'] + '\n')
            remote = parent + '/d0'
            rows = remote_run('list', '-H', '-p', '-t', 'snapshot', '-d', '1',
                              '-o', 'name', '-s', 'creation', remote).splitlines()
            if not rows:
                fail('Kein empfangener Snapshot vorhanden.')
            snapshot = rows[-1]
            if not snapshot.startswith(remote + '@') or not schema_snapshot(snapshot.split('@', 1)[1], 0):
                fail('Ungültiger Snapshot vom Freund.')
            local_snapshot = offer['datasets'][0] + '@' + snapshot.split('@', 1)[1]
            # Keep source snapshot stable throughout comparison; local hold is
            # released even if raw receive or decryption fails.
            # A prior SIGKILL must not accumulate random probe holds. The offer
            # lock excludes live probes; retain sender base/pending holds.
            for row in dataset_holds(offer['datasets'][0]).splitlines():
                old, tag, _ = row.split('\t')
                if old.startswith(offer['datasets'][0] + '@') and tag == probe_tag and old != local_snapshot:
                    run('zfs', 'release', tag, old)
            ensure_hold(0, local_snapshot, 'probe')
            held = True
            remote_guid = remote_run('get', '-H', '-o', 'value', 'guid', snapshot)
            guid(remote_guid)
            if remote_guid != zget(local_snapshot, 'guid'):
                fail('Snapshot-GUID stimmt nicht mit dem Original überein.')
            # Mark ownership BEFORE receive; trap/finally always attempts cleanup
            # including a failed/partial receive.
            referenced = int(zget(local_snapshot, 'referenced'))
            budget = referenced + max(referenced // 4, 1024 ** 3)
            if int(zget(CONFIG['pool'], 'available')) < budget + 1024 ** 3:
                fail('Zu wenig freier Poolplatz für die begrenzte ZFS-Probe.')
            run('zfs', 'create', '-o', 'mountpoint=none', '-o', 'canmount=off',
                '-o', 'volmode=none', '-o', 'dedup=off', '-o', 'copies=1', '-o', 'filesystem_limit=1', '-o', 'snapshot_limit=1',
                '-o', 'org.buddybackup:probe=' + offer['id'], '-o', 'quota=' + str(budget), temporary)
            created = True
            received = temporary + '/data'
            stream(ssh_command(key_file, hosts_file, 'zfs', 'send', '-w', snapshot),
                   ['/usr/sbin/zfs', 'recv', '-u', *RECEIVE_EXCLUDES, received])
            if zget(received + '@' + snapshot.split('@', 1)[1], 'guid') != remote_guid:
                fail('Empfangene Snapshot-GUID stimmt nicht überein.')
            source = offer['datasets'][0]
            root = zget(source, 'encryptionroot')
            secret = probe_key(root)
            if not secret:
                result.update(state='raw_only', message='Freund hat einen Stream geliefert; Inhalt nicht geprüft. Entschlüsselung benötigt den Benutzerschlüssel.')
            else:
                run('zfs', 'load-key', '-L', 'file:///dev/stdin', received, input=secret)
                # Keep mounts OUTSIDE TemporaryDirectory: its cleanup must never
                # traverse a mounted filesystem when verification raises.
                run('zfs', 'set', 'canmount=noauto', received)
                # TrueNAS pools use altroot=/mnt, so the property is relative to it; read back the real path.
                run('zfs', 'set', 'mountpoint=/' + received, received)
                run('zfs', 'mount', received)
                mount = zget(received, 'mountpoint')
                source_mount = zget(source, 'mountpoint')
                if source_mount in ('none', 'legacy') or zget(source, 'mounted') != 'yes':
                    fail('Original-Dataset muss für den Inhaltsvergleich gemountet sein.')
                original = os.path.join(source_mount, '.zfs', 'snapshot', snapshot.split('@', 1)[1])
                if content_digest(original) != content_digest(mount):
                    fail('Inhaltsvergleich ist fehlgeschlagen.')
                run('zfs', 'unmount', received)
                result.update(state='verified', message='Raw-Transfer, Entschlüsselung und Dateiinhalte geprüft.')
    except Exception:
        # Never include a traceback or middleware response that might carry keys.
        result.update(state='error', message='ZFS-Probe fehlgeschlagen; TrueNAS-Aufgaben und Schlüssel prüfen.')
    finally:
        try:
            if created:
                if zget(temporary, 'org.buddybackup:probe') != offer['id']:
                    fail('Temporäres Dataset gehört nicht zu dieser Probe; keine Löschung.')
                run('zfs', 'destroy', '-r', temporary)
        except Exception:
            result.update(state='error', message='Sicherheitswarnung: temporäres Probe-Dataset konnte nicht entfernt werden: ' + temporary)
        try:
            if held:
                run('zfs', 'release', probe_tag, local_snapshot)
        except Exception:
            result.update(state='error', message='Snapshot-Haltepunkt der Probe konnte nicht entfernt werden.')
        atomic(probe_file, result)
    if result['state'] == 'error':
        fail(result['message'])


def remove():
    flag = sys.argv[2] if len(sys.argv) > 2 else ''
    if flag not in ('', '--destroy-received-data'):
        fail('Unbekannte Entfernungsoption.')
    if flag and side != 'receiver':
        fail('--destroy-received-data ist nur auf dem Empfänger erlaubt.')
    errors = []
    # Revoke access FIRST, even if parent is absent/replaced/held or task cleanup
    # fails. Peer cannot veto account deletion using dataset properties or holds.
    entry = journal['resources'].get('user')
    if entry and entry.get('id') is not None and not entry.get('removed'):
        home = journal.get('home')
        try:
            if home:
                safe_unlink(Path(home) / '.ssh' / 'authorized_keys')
        except Exception:
            print('SSH-Schlüsseldatei nicht entfernbar; Account wird trotzdem entfernt.', file=sys.stderr)
        uid = journal.get('user_uid')
        if isinstance(uid, int) and uid > 0:
            try:
                # Dedicated account only. Terminate already authenticated gates,
                # Numeric UID delegation can also be revoked after NSS deletion.
                killed = subprocess.run(['/usr/bin/pkill', '-KILL', '-u', str(uid)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if killed.returncode not in (0, 1):
                    errors.append('Empfangsprozesse konnten nicht beendet werden.')
            except Exception:
                errors.append('Empfangsprozesse konnten nicht beendet werden.')
        try:
            call('user.delete', entry['id'], {'delete_group': True})
            entry['removed'] = True
            save()
        except Exception:
            # A missing account is already revoked. Query by journaled ID only.
            if call('user.query', [['id', '=', entry['id']]]):
                errors.append('Empfangskonto konnte nicht entfernt werden.')
            else:
                entry['removed'] = True
                save()
    if side == 'receiver':
        try:
            same_parent = bool(journal.get('parent_guid')) and zget(parent, 'guid') == journal['parent_guid']
        except Exception:
            same_parent = False
            print('Hinweis: Parent fehlt oder ist nicht prüfbar; Zugang wurde separat entzogen.', file=sys.stderr)
        if same_parent:
            try:
                run('zfs', 'unallow', '-u', str(journal['user_uid']), parent)
            except Exception:
                errors.append('Delegation der gespeicherten UID konnte nicht entfernt werden; Account ist bereits entzogen.')
    order = sorted(journal['resources'], key=lambda key: 0 if key.startswith('cron-') else 1)
    for label in order:
        entry = journal['resources'][label]
        if label == 'user' or entry.get('removed') or entry['id'] is None:
            continue
        try:
            service = entry['method'].rsplit('.', 1)[0]
            rows = call(service + '.query', [['id', '=', entry['id']]])
            if rows:
                if rows[0].get(entry['identity']) != entry['payload'][entry['identity']]:
                    fail('Ressource wurde verändert: ' + label)
                call(service + '.delete', entry['id'])
            entry['removed'] = True
            save()
        except Exception:
            errors.append('TrueNAS-Ressource konnte nicht entfernt werden: ' + label)
    if flag and not journal.get('data_destroyed'):
        try:
            if not journal.get('parent_guid') or zget(parent, 'guid') != journal['parent_guid']:
                fail('Parent-GUID stimmt nicht überein; keine Datenlöschung.')
            holds = dataset_holds(parent)
            if holds:
                fail('Haltepunkte verhindern Löschung; als Eigentümer mit /usr/sbin/zfs holds -r prüfen und freigeben.')
            run('zfs', 'destroy', '-r', parent)
            journal['data_destroyed'] = True
            save()
        except Exception as exc:
            errors.append(str(exc) if isinstance(exc, BuddyError) else 'Empfangsdaten nicht gelöscht; Haltepunkte mit /usr/sbin/zfs holds -r prüfen.')
    if side == 'sender':
        for index, source in enumerate(offer['datasets']):
            try:
                release_holds(index, source, set())
            except Exception:
                # A deleted source has no holds left. Other datasets still need cleanup.
                if subprocess.run(['/usr/sbin/zfs', 'list', '-H', source],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    errors.append('Eigene Haltepunkte konnten nicht entfernt werden: ' + source)
        for path in (key_file, hosts_file):
            try:
                safe_unlink(path)
            except Exception:
                errors.append('Sender-Transportdatei konnte nicht entfernt werden: ' + str(path))
        # Missing sources are already clean; other cleanup failures stay visible.
    # Retained source/receiver snapshots may still carry native replication or
    # administrator holds. Report exact names/tags; never release unrelated holds.
    for dataset in ([parent] if side == 'receiver' else offer['datasets']):
        try:
            holds = dataset_holds(dataset)
            if holds:
                print('Verbleibende Haltepunkte (mit /usr/sbin/zfs release als Eigentümer prüfen): ' + json.dumps(holds), file=sys.stderr)
        except Exception:
            print('Haltepunkte nicht prüfbar: ' + dataset + '; /usr/sbin/zfs holds -r prüfen.', file=sys.stderr)
    if errors:
        fail(' '.join(errors))
    journal['removed'] = True
    save()
    # Completion marker is removed LAST and only after successful removal.
    for path in (status_file, probe_file, guard_file, complete):
        safe_unlink(path)
    print('BuddyBackup-ZFS-Aufgaben entfernt. Empfangsdaten bleiben ohne ausdrückliches Löschflag erhalten.')



def control_dataset(directory, setup):
    dataset = CONFIG['pool'] + '/buddy-zfs-control'
    if dataset in CONFIG.get('bind_datasets', []):
        fail('Kontroll-Dataset darf kein App-Bind-Mount sein.')
    exists = subprocess.run(['/usr/sbin/zfs', 'list', '-H', dataset],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    if not exists:
        if not setup:
            fail('Kontroll-Dataset fehlt.')
        # Never adopt an existing plain directory, even if root-owned.
        if directory.exists():
            fail('Kontrollpfad existiert ohne eigenes Dataset; manuell prüfen.')
        directory_fd_close(directory.parent, protected=True)
        run('zfs', 'create', '-o', 'mountpoint=/' + dataset, '-o', 'setuid=off',
            '-o', 'devices=off', '-o', 'exec=on', '-o', 'snapdir=hidden', dataset)
    if (zget(dataset, 'type') != 'filesystem' or zget(dataset, 'mounted') != 'yes'
            or zget(dataset, 'mountpoint') != str(directory)
            or not os.path.ismount(directory)):
        fail('Kontrollpfad muss das gemountete eigene ZFS-Dataset sein.')
    directory_fd_close(directory, protected=True)
    os.chown(directory, 0, 0)
    os.chmod(directory, 0o755)


def lock_owner(fd):
    try:
        data = json.loads(os.pread(fd, 1024, 0))
        pid = data['pid']
        if type(pid) is not int or pid <= 1:
            return None
        if Path('/proc/%d/stat' % pid).read_text().split(') ', 1)[1].split()[19] != data['start']:
            return None
        return data
    except (OSError, ValueError, KeyError, TypeError):
        return None


def enter_lock(fd, action):
    if not acquire_lock(fd):
        owner = lock_owner(fd)
        if action == 'remove':
            if not owner:
                fail('Laufenden ZFS-Prozess nicht sicher identifiziert; Root-Prozess prüfen.')
            os.kill(owner['pid'], signal.SIGTERM)
            deadline = time.monotonic() + 10
            while not acquire_lock(fd):
                if time.monotonic() >= deadline:
                    # Kill only the same recorded process, never a reused PID.
                    if lock_owner(fd) == owner:
                        os.kill(owner['pid'], signal.SIGKILL)
                    deadline = time.monotonic() + 5
                    while not acquire_lock(fd):
                        if time.monotonic() >= deadline:
                            fail('ZFS-Prozess lässt sich nicht beenden; Host-Prozess prüfen.')
                        time.sleep(.05)
                    break
                time.sleep(.05)
        elif action == 'run':
            if not owner or time.time() - owner.get('since', 0) > ABNORMAL_LOCK_SECONDS:
                message = 'ZFS-Stundenlauf übersprungen: Sperre seit über 6 Stunden belegt oder Laufzeit unbekannt.'
                atomic(guard_file, {'updated': utc(), 'state': 'error', 'message': message})
                syslog.syslog(syslog.LOG_WARNING, message)
                print(message, file=sys.stderr)
            return False
        else:
            fail('ZFS-Auftrag läuft bereits; später erneut versuchen.')
    data = {'pid': os.getpid(), 'start': Path('/proc/self/stat').read_text().split(') ', 1)[1].split()[19],
            'since': time.time(), 'action': action}
    os.ftruncate(fd, 0)
    os.pwrite(fd, json.dumps(data).encode(), 0)
    os.fsync(fd)
    return True


def interrupted(signum, frame):
    raise BuddyInterrupted('ZFS-Aktion unterbrochen.')

signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)

if os.geteuid() != 0:
    fail('Diesen Befehl als root ausführen (als Admin: sudo bash).')
side, offer = CONFIG['side'], CONFIG['offer']
action = sys.argv[1] if len(sys.argv) > 1 else 'setup'
parent = CONFIG.get('parent', CONFIG['pool'] + '/buddy-zfs-' + offer['id'][:16])
username = CONFIG.get('username', 'bz' + offer['id'][:16])
prefix = 'buddy-zfs-' + offer['id']
validate_public_key(offer['public_key'])
# A separate filesystem is required against open_by_handle_at from container root.
directory = Path('/mnt') / CONFIG['pool'] / 'buddy-zfs-control'
script = directory / (side + '-' + offer['id'] + '.py')
manifest = script.with_suffix('.json')
report_directory = Path(CONFIG['directory'])
complete = report_directory / (side + '-' + offer['id'] + '-complete.json')
status_file = report_directory / (side + '-' + offer['id'] + '-status.json')
probe_file = report_directory / (side + '-' + offer['id'] + '-probe.json')
guard_file = report_directory / (side + '-' + offer['id'] + '-guard.json')
key_file = script.with_suffix('.key')
hosts_file = script.with_suffix('.hosts')
if side == 'sender' and action == 'setup':
    validate_sources()
control_dataset(directory, action == 'setup')
lock_fd = os.open(str(script) + '.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
if not enter_lock(lock_fd, action):
    sys.exit(0)
if manifest.is_symlink():
    fail('ZFS-Journal darf kein symbolischer Link sein.')
journal = json.loads(manifest.read_text()) if manifest.exists() else {'id': offer['id'], 'resources': {}}
if journal['id'] != offer['id'] or journal.get('removed') and action != 'remove':
    fail('ZFS-Auftrag wurde entfernt oder gehört zu einem anderen Angebot.')
if side == 'sender' and any(k.startswith('replication-') or v.get('method', '').startswith('keychaincredential.') for k, v in journal['resources'].items()):
    fail('Alte native ZFS-Aufgaben zuerst mit dem ursprünglichen Runner entfernen; keine automatische Übernahme.')
public_config = {k: v for k, v in CONFIG.items() if k not in ('private_key', 'quota_gib', 'bind_datasets')}
if journal.get('config', public_config) != public_config:
    fail('Konfiguration stimmt nicht mit dem ZFS-Journal überein.')
journal['config'] = public_config
save()
from truenas_api_client import Client
if action == 'setup':
    write_runner()
with Client() as client:
    if action == 'setup':
        if side == 'receiver':
            receiver_setup()
        else:
            sender_setup()
        print('BuddyBackup-ZFS eingerichtet. Abschluss jetzt in der App bestätigen.')
    elif action == 'status' and side == 'receiver':
        receive_status()
    elif action == 'run' and side == 'sender':
        sender_run()
    elif action == 'probe' and side == 'sender':
        probe()
    elif action == 'remove':
        remove()
    else:
        fail('Unbekannte ZFS-Aktion.')

# Setup must return promptly even when the first upstream transfer takes days.
# Release the per-offer lock before launching the independent root process.
if action == 'setup' and side == 'sender':
    fcntl.flock(lock_fd, fcntl.LOCK_UN)
    # A transient service survives the end of the login session that pasted this command.
    # If it cannot be started, the hourly cron job performs the first transfer instead.
    log = script.with_suffix('.log')
    subprocess.run(['systemd-run', '--quiet', '--collect', '--unit=buddy-zfs-first-' + offer['id'][:16],
                    '--property=StandardOutput=append:' + str(log), '--property=StandardError=append:' + str(log),
                    '/usr/bin/python3', '-I', str(script), 'run'],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
