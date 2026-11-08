# BuddyBackup API v1

Contract for the independently implemented frontend. All UI messages are German.
Base `/api/v1`, JSON UTF-8. Responses and downloads carry `Cache-Control: no-store`.
Unknown fields and bodies over 1 MiB are rejected. No secrets appear in status.

## Authentication

`GET /auth` → `{"initialized":false,"csrf_token":"..."}`. This creates an HttpOnly,
SameSite=Strict cookie (Secure on HTTPS). Send the token as `X-CSRF-Token` for EVERY
POST, including setup/login. Requests must be same-origin; no CORS is enabled.
Passwords must be 12–72 UTF-8 bytes. Sessions expire after 12 hours or restart; successful login rotates the cookie.
`POST /setup` with `{"name":"alice","password":"at-least-12-characters","quota_bytes":107374182400}`
sets the bcrypt admin password once and logs in. `POST /login` with `{"password":"..."}`
logs in; `POST /logout` logs out. Successful responses: `{"ok":true}`.
Login attempts are limited per remote IP. Refresh `/auth` after cookie expiry.
Protected GET requests without authentication return 401. POST requests first require a valid session CSRF token (403 when absent).

## Errors

`{"error":{"code":"invalid_request","message":"Ungültige Anfrage."}}`.
Codes: `invalid_request` (400), `unauthorized` (401), `csrf` (403), `not_found` (404),
`conflict` (409; operation running or stale fingerprint), `rate_limited` (429),
`internal` (500). Validation/conflict errors on authenticated mutations use 409; malformed JSON uses 400. Background operation failures are returned in the polled operation object. Unsupported methods use 405; shutdown returns 503.

## Wizard and status (poll every 2 seconds)

`GET /status` → `{"wizard":"network","name":"alice","network":{"ready":false,"auth_url":"https://login.tailscale.com/...","node_id":"","ip":""},"peer_fingerprint":"","recovery_acknowledged":false,"settings":{},"operation":null,"warnings":[],"next_run":"...","last_success":"...","receiver":{"quota_bytes":107374182400},"snapshot_instructions":"..."}`.
Wizard order: `setup` → `network` → `peer` → `sources` → `recovery` → `ready`.
Recovery-only imports may list/restore snapshots without sources or acknowledgement.
Status warnings include stale backups, missing mounts, interrupted operations, Tailscale
and expiry. Receiver ZFS snapshot instructions are in `snapshot_instructions`; no ZFS task detection is claimed.
`POST /network/login` `{}` starts interactive tsnet login; poll status for auth_url.
Only private LAN/loopback client IPs are accepted by the UI. DNS Host headers require
`BUDDY_UI_HOST` (IP access and localhost work by default).
The app node must be shared in BOTH directions across the two separate tailnets.
`GET /sources` → `{"sources":[{"path":"/sources/photos","valid":true,"message":""}]}`
lists only individually mounted source roots; empty/missing/changed mounts are invalid.

`POST /peer/check` `{}` → `{"reachable":true,"route":"direct","message":""}` tests the saved friend. `POST /password` `{"old_password":"...","new_password":"..."}` changes the admin password. `POST /quota` `{"quota_bytes":1073741824}` changes the friend's limit at runtime. Status also carries `recovery_only`: true after a kit import until sources are saved, when main views are available without the wizard.

## Pairing

`GET /invitation` → `{"invitation":{"schema":1,"name":"alice","ip":"100.64.0.1","node_id":"n123","port":8787,"username":"buddy-0123456789abcdef","password":"..."},"fingerprint":"64-lowercase-hex"}`.
Contains incoming HTTP credentials, NEVER the restic encryption key. Treat as secret.
`POST /peer` with `{"invitation":{...},"fingerprint":"...","replace":false}`.
Fingerprint is SHA-256 over canonical JSON (sorted keys, compact, ASCII names/values).
Both friends must compare the full displayed fingerprint out of band BEFORE import.
A different peer requires `replace:true`; replacement creates a new encryption key and
backup identity and invalidates the exported recovery kit and acknowledgement.
No old repository is removed. Retain its kit to recover it later.

## Configuration

`POST /settings` with
`{"sources":["/sources/photos"],"interval_hours":24,"keep_daily":7,"keep_weekly":4,"keep_monthly":12,"direct_only":false,"upload_kib":0,"ntfy_url":"","stale_hours":48}`.
This is a full replacement; sources may be empty for recovery. Source mount identities
are captured and verified before backups. Source changes create a distinct source set.
ntfy_url is optional HTTPS (HTTP allowed for local ntfy), no embedded credentials.
Notifications contain generic failure/staleness text without repository credentials.
`snapshots` operations also discover source sets from decrypted snapshot tags after recovery.
`GET /source-sets` → `{"source_sets":[{"id":"...","paths":["/sources/photos"],"retired":true}]}`.
`POST /source-sets/retire` `{"id":"...","confirm":"DELETE_RETIRED_SNAPSHOTS"}`
queues removal of snapshots for an inactive set; active sets cannot be retired.
It returns the same HTTP 202 operation object as `/operations`; poll `/operations/current`.
`deleted:true` records a retired set whose snapshots were explicitly removed.
Retention never merges different source sets or complete/pending snapshot groups.
Independent maintenance keeps the newest pending attempt separately, to bound crash remnants.

## Recovery kit (download and explicit acknowledgement)

`POST /recovery/export` `{}` → `{"kit":{"schema":1,"peer":{...},"repository_key":"...","repository_id":"...","backup_id":"...","backup_host":"..."},"fingerprint":"...","connection_fingerprint":"..."}`.
Save the entire response securely offline. The kit is plaintext and decrypts backups.
`POST /recovery/ack` `{"fingerprint":"...","connection_fingerprint":"...","confirm":"SAVED_OFFLINE"}`
acknowledges exactly that export for the current connection. Replacement/export/ack
are serialized atomically. A stale export cannot acknowledge a replaced connection.
`POST /recovery/import` `{"kit":{...},"fingerprint":"...","confirm":"IMPORT_RECOVERY"}`
validates integrity and installs recovery credentials; fails when already paired.
Recovery mode NEVER initializes a repository, including if it is absent.

## Operations and progress

`POST /operations` `{"kind":"backup"}` → HTTP 202 `{"id":"...","kind":"backup","state":"running","started":"...","progress":{},"result":null,"error":""}`.
Kinds: `backup`, `snapshots`, `files`, `check`, `maintenance`, `restore-test`, `restore`, `unlock`.
Optional fields: `read_data:true` for check; `low_space:true` for maintenance (prune
`--max-repack-size 0`); `snapshot:"full-64-hex-id",folder:"restore-2026"` for restore;
`paths:["/sources/photos/a.jpg"]` optionally limits a restore to those files or folders; `snapshot` selects the version for `files`, whose result is `{"entries":[{"path":"...","type":"file","size":1}],"truncated":false}` (20000 entries at most). `confirm:"UNLOCK_STALE_LOCKS"` for unlock. Unlock refuses while any operation runs;
only restic's normal stale-lock cleanup is used, never `--remove-all`.
Restore creates a NEW directory under the individually mounted `/restore`; existing
paths, traversal, symlinks and absent mounts are refused; partial restores remain for review.
`GET /operations/current` → operation or `null`. Poll every 1–2 seconds. `progress`
contains the most recent restic JSON progress event, sanitized. `state` is `running`,
`success`, or `error`; `result` contains snapshots, restored path, or operation details.
`POST /operations/cancel` `{}` interrupts the running subprocess gracefully.
Only one operation runs at once; configuration/pairing cannot change underneath it.
Backup success requires restic exit 0, a valid snapshot, and final tag promotion.
Every newly created snapshot starts `buddybackup-pending`; interrupted/partial ones
remain pending and are never treated as complete. Independent maintenance is available
even after a storage-full failure. Maintenance is also scheduled independently every seven days
after kit acknowledgement. Status includes `next_maintenance`, `last_maintenance`, and receiver
`used_bytes` / `filesystem_free_bytes` (usage cached for at most 30 seconds).
Schedule slots are anchored and missed slots coalesced.

## Optional encrypted ZFS replication

Restic remains the default. All `/zfs/*` endpoints require the normal admin session
and CSRF token on POST. Successful mutations return `{"ok":true}` unless specified;
invalid JSON/unknown fields return 400, state/precondition failures 409. GET is
read-only; other methods cannot mutate ZFS state. No changes to `web/` are included.
Dataset paths use ASCII letters/numbers, `_`, `-`, `.`, `/`, no empty/`.`/`..`
components, maximum 200 bytes, 1–32 non-overlapping explicitly named filesystems.
The `recursive` field has been removed from offer requests, peer offers, persisted
offers and status. Supplying it is a 400 unknown-field error, including `false`.
Descendants are never automatically selected, including descendants created later.

- `POST /zfs/receive` `{"enabled":true,"quota_gib":500}` opens only the pinned
  peer's inbound TCP 8788 tunnel. Quota: 1–1048576 GiB, separate from restic.
  Disabling closes listeners/connections immediately; NAS tasks/account/data still
  require the removal command. Quota changes require receiver setup again.
- `POST /zfs/offer` `{"datasets":["tank/photos"],"hour":3,"retention_days":30}`
  creates an ed25519 transport key and sends the public offer. Hour: 0–23 local
  TrueNAS time; retention: 1–3650 days. Identical retries reuse offer/key; changed
  selections require removal/reset. Offers are refused in imported rescue mode.
- `POST /zfs/sync` `{}` refreshes receiver readiness and advisory received status.
- `GET /zfs/status` returns `receive`, `incoming`, `outgoing`, `receiver_ready`,
  `sender_complete`, `peer_status`, `local_status`, `sender_status`, `probe`, `guard`,
  `rescue_acknowledged` (bool), `rescue_mode` (bool), `warnings` (string array).
  Offers contain exactly `id`, `name`, `datasets`, `hour`, `retention_days`,
  `public_key`, `created`. Peer status: `offer_id`, `ready`, `username`, `parent`,
  `report`. Reports: `updated`, `datasets` with `name`, `snapshot`, `snapshot_time`,
  `keystatus`, `used_bytes`. Times are UTC. `probe` and `guard` each contain
  `updated`, `state`, `message`; empty reports have zero time/empty strings.
  Probe states: `verified`, `raw_only`, `error`; guard states: `ok`, `error`.
  Guard errors report sender failure and appear in warnings and generic ntfy
  alerts. `sender_status` is the local root runner report:
  `{"updated":"<UTC RFC3339>","scheduler":"cron","datasets":[{"name":"tank/photos","state":"running","last_attempt":"<UTC RFC3339>","last_success":null,"last_sent_snapshot":"","error":"","security_warning":"","bytes":null}]}`.
  Dataset states: `pending`, `running`, `success`, `error`. `last_attempt` changes
  before each attempted run; `last_success` and `last_sent_snapshot` change only
  after remote newest-name/GUID verification and retention complete. Previous
  success survives failure. Attempt/success times and bytes are nullable; bytes
  is currently always null (the direct stream pipe does not count bytes).
  An untouched sender report has zero `updated`, empty `scheduler`, null `datasets`;
  successful setup writes `scheduler:"cron"`, `datasets:[]` before first run.
  `error` and persistent `security_warning` are added to app warnings and the
  existing daily-rate-limited generic ntfy alerts. A sender report older than two
  hours after confirmation also warns; long transfers may therefore warn while
  still running. `security_warning` survives later success and setup retries;
  remove/reset the offer after investigating to clear it. Status (also embedded in
  `/status`) NEVER includes SSH private keys,
  rescue contents or HTTP passwords. Peer reports can be falsified by the friend.
- `GET /zfs/commands/receiver`, `/sender`, `/remove-receiver`, `/remove-sender`
  return `{"command":"...","sensitive":false,"zfs_host_sha256":"<64hex>","root_trust_warning":"<warning>"}`; sender setup is sensitive.
  Receiver requires an incoming offer, enabled receive and writable ZFS `/data`.
  Sender requires matching ready receiver, then captures/pins its SSH host key on
  first use through the authenticated node-pinned tunnel. There is no human host
  key confirmation. Later changes are refused. Generate sender command BEFORE
  rescue export so its host key is pinned. Command generation does not execute it.
- `POST /zfs/confirm` `{"side":"sender","offer_id":"<32hex>"}` requires the
  side's matching successful setup marker. Sender additionally requires the exact
  current rescue export acknowledged offline (below); the marker means setup
  installed successfully, NOT that a first transfer has completed. Confirmation
  works while the background first transfer is still running; then sets completion and
  removes the private key from app state. Repeated confirmations succeed.
  Receiver accepts `side:"receiver"`; its marker must also match current quota.
  Sender command and rescue export are unavailable after sender completion.
- `POST /zfs/reset`
  `{"side":"sender","offer_id":"<32hex>","confirm":"REMOVED_ON_NAS"}`
  forgets that side only if its completion marker is absent. ANY existing marker
  (even malformed, stale quota, symlink or unreadable path) refuses reset. Receiver
  reset also disables receive. This endpoint cannot remove NAS resources; removal
  deletes its marker last, only after successful cleanup. Ordinary `/peer`
  replacement remains refused while ZFS offers or receive are configured.

### ZFS rescue file and replacement node

- `POST /zfs/rescue/export` `{}` returns
  `{"rescue":{"schema":1,"offer_id":"<32hex>","peer":{<Invitation>},"datasets":["tank/photos"],"username":"bz<16hex>","parent":"tank/buddy-zfs-<16hex>","host_key":"ssh-ed25519 ...","private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\n..."},"fingerprint":"<64hex>"}`.
  Export AFTER receiver readiness and sender command generation, BEFORE sender
  confirmation. Save the entire plaintext response securely offline once. It
  contains the friend's existing invitation (including its HTTP password), the
  sender's SSH private key, pinned receiver host key, fixed receiver account/parent
  and ordered source-to-`d0`, `d1`, … mapping. It contains NO ZFS decryption key.
  Identical retries return the same rescue and retain its acknowledgement; this
  is not a later export from the root-only key file. App state retains the key until confirmation.
- `POST /zfs/rescue/ack`
  `{"fingerprint":"<export fingerprint>","confirm":"SAVED_OFFLINE"}`
  acknowledges exactly the exported current rescue/connection under the state lock.
  A stale fingerprint cannot acknowledge another key, offer or connection.
- `POST /zfs/rescue/import`
  `{"rescue":{<exact exported rescue>},"fingerprint":"<export fingerprint>","confirm":"IMPORT_ZFS_RESCUE"}`
  installs rescue mode on a replacement NAS and opens ONLY the outbound host
  tunnel at 127.0.0.1:2288, without an active offer or new NAS replication task.
  Requires working network login/verified Docker host gateway, no configured ZFS
  receive/offer/rescue, and no different saved peer. An unpaired app adopts the
  saved peer; an identical peer from a Restic kit is allowed. It disables Restic
  repository initialization and sets recovery-only mode. Imported SSH secrets are
  persisted mode 0600 in app state, never returned in status. Restore SSH uses the
  file's pinned host key and original account, never a new offer or account removal.
- `POST /zfs/rescue/close` `{"confirm":"CLOSE_ZFS_RESCUE"}` clears imported rescue
  credentials and closes the outbound tunnel; retains the saved peer/Restic state.
- On the SURVIVING friend's app, `POST /zfs/peer/repin`
  `{"invitation":{<replacement device Invitation>},"fingerprint":"<its canonical SHA-256>","previous_node_id":"<old pinned node id>","confirm":"REPIN_REPLACED_ZFS_PEER"}`
  explicitly replaces only the saved peer's node ID and IP, after out-of-band
  fingerprint comparison with the replacement owner. Requires an existing incoming
  ZFS offer, same friend name, a different non-self node and exact previous node ID.
  Incoming offer, root journal, receiver account, authorized SSH key, parent/data,
  existing HTTP credentials and Restic identity are kept. Active streams close and
  reconnect to the new pin. It neither creates a new receive account nor trusts a
  new NAS SSH host key. Any opposite-direction replication into the lost NAS needs
  separate repair; re-pin alone does not recover that lost data/account.

### Host execution and security contract

Setup/removal commands are quoted bash pastes invoking root `sudo bash` and isolated
`/usr/bin/python3 -I` using TrueNAS's local middleware socket. No API key is used.
The sender paste contains its private SSH key (base64 is NOT encryption) and can
appear in shell history. See [ZFS recovery](ZFS-RECOVERY.md) for rotation/recovery.
Receiver setup enables the shared TrueNAS SSH service on ALL configured/default
interfaces, not just the tunnel; it remains enabled after removal. Setup first
queries `ssh.config` and aborts if `passwordauth` is enabled,
`password_login_groups` is nonempty, or auxiliary `options` are present. Disable
Allow Password Authentication, clear Password Login Groups and Auxiliary
Parameters in TrueNAS Services > SSH, arrange key-based admin access, then retry.
No SSH settings are silently changed and no unused restoration state is saved.

Runner, root-owned journal and forced-command gate live in the dedicated ZFS
dataset `<pool>/buddy-zfs-control`, mounted root-owned 0755 at
`/mnt/<pool>/buddy-zfs-control`, outside the receiver quota parent. Setup refuses
plain-folder adoption, an unmounted/wrong filesystem, and any app bind whose
source is this dataset (even a different folder on it). Root-only journal/runner files are 0600; gate is root-owned 0755. Sender
SSH private key `sender-<offer-id>.key`, pinned hosts file `.hosts` and background
log `.log` are root-owned 0600 in the same control directory. The runner and
journal contain no private key. Every run checks key ownership/mode and derives
its public key with ssh-keygen to compare with the offer. No sender middleware
SSH keychain credentials are created.
The receive home/.ssh are root-owned 0755 and authorized_keys root-owned 0644,
written by setup itself with `restrict,command="<fixed gate>"`. OpenSSH StrictModes
accepts uid 0 ownership. No user.update SSH key writing is used. Non-root-writable
ancestors are required; no symlink component is allowed. Do not bind-mount a pool
root or this directory into any container or grant NAS users write access there.
The account has no password/sudo/SMB access. Its only delegated ZFS permissions
are `create,mount,receive,destroy,send` on the fixed parent; the gate further limits
them to the audited command forms and forbids destruction/receive of the parent.
Parent limits: quota, `filesystem_limit=128`, `snapshot_limit=8192`. Counts include
all received descendants/snapshots; exhaustion fails replication, never removes
these limits. No property/limit, key-loading, hold, shell, forwarding or SFTP right
is exposed. Only `/usr/sbin/zfs send -w <child@snapshot>` may send remotely.
Remote `send -t` is always refused. The gate executes zfs directly with a fixed
PATH/LANG; all shell wrappers, including `sh -c 'PATH=...'`, are refused.
Exact allowed forms (literal option ordering; `P` is the fixed parent,
`T=P/d0` … `P/d31`, `S=T@<single safe snapshot name>`):

- `/usr/sbin/zfs recv -s -u -x mountpoint -x sharenfs -x sharesmb -x xattr -x volmode -x dedup -x copies -x reservation -x refreservation T`
- `/usr/sbin/zfs recv -A T`
- `/usr/sbin/zfs send -w S` (restore/probe)
- `/usr/sbin/zfs list -H -p -t filesystem -d 1 -o name P`
- `/usr/sbin/zfs list -H -p -t snapshot -d 1 -o name -s creation T`
- `/usr/sbin/zfs get -H -o value guid S`
- `/usr/sbin/zfs get -H -o value receive_resume_token T`
- `/usr/sbin/zfs destroy S` (one snapshot only)

There is no `-F`, dataset destroy, batch destroy, create, umount, capability probe,
property update, recursive operation, token/non-raw send, or shell syntax in the
gate. Receive/abort cannot target P, ancestors, arbitrary children or descendants
of a `dN`. The stream always stays unmounted and excludes mountpoint, sharenfs,
sharesmb, xattr, volmode, dedup, copies, reservation and refreservation, including
during probe receive. Both receive parents enforce `volmode=none`, `dedup=off` and
`copies=1`; the probe also limits filesystem/snapshot counts to one each.

Only JSON status/guard/probe/completion reports go under `/data/buddy-zfs`. Root
walks every directory with O_NOFOLLOW and performs all file operations using pinned
dir_fd handles; non-regular existing targets are refused. Root never loads code or
journals from `/data`. Removal revokes the journaled SSH account first even if the
parent is absent/replaced/held, compares immutable parent GUID for optional data
cleanup, reports remaining holds, removes owned middleware resources and deletes
the completion marker last. Default removal preserves data and SSH service; only
`BUDDY_ZFS_REMOVE_FLAG=--destroy-received-data` opts into GUID-checked data deletion.

Native TrueNAS periodic snapshot tasks remain non-recursive and run daily at
hour:00 with the selected DAY retention and schema
`bz-<first16-offer-id>-d<index>-%Y-%m-%d_%H-%M` in local TrueNAS time.
The sender creates NO native Replication Task and calls no replication service.
A root cron runs `python3 -I <sender-runner> run` at minute :01 EVERY hour;
the monthly probe is another root cron. Transfers appear under TrueNAS Cron Jobs
and `sender_status` in the app, never under Replication Tasks. Setup creates an
initial schema snapshot if absent, installs the runner/key/crons, writes completion,
releases its lock and starts the first transfer detached in the background. The
setup command returns promptly even if first sync takes days. Overlapping `run`
invocations use a non-blocking per-offer flock. After six hours (or unknown
ownership), a skipped hourly run writes an error guard, syslog and stderr warning.
The root-only lock records PID, Linux process start time and acquisition time.
Removal validates that identity, sends SIGTERM, waits at most ten seconds, then
SIGKILL and at most five more seconds before acquiring the lock and loading the
journal. Setup/probe still report busy. An unkillable host process is reported
instead of concurrently editing its journal. Streams have a 30-minute no-progress
watchdog, measured on bytes actually written from the sending pipe to the receiving
pipe. Any progress renews it, so moving transfers may run for days. Sender and
probe use the same bounded 64 KiB relay; SSH stdout is discarded except for stream
bytes or metadata, and SSH stderr is always DEVNULL. Both probe metadata calls use
the 64 KiB/60-second remote-query path (with the existing single quiet retry).

Before every run the sender verifies ALL selected sources are natively encrypted,
locally unlocked filesystems with exactly the encryption roots captured during
setup. Root changes, plaintext and volumes stop sending and write errors. It lists
only local snapshots of the source, accepts only exact round-trip matches of its
schema, and builds `zfs send -w -p [-i <local-base>] <local-target>` locally.
`-p` preserves the properties previously preserved by native replication; receive
exclusions above remain mandatory. Peer names are strictly checked; decimal GUIDs
must be nonzero uint64. For the first intent, the newest local snapshot whose name AND GUID match the
peer is the incremental base. Later intents retain the journaled successfully
confirmed base; its absence at the peer stops the run. With no common base a full send is allowed only if
a successful parent listing proves T absent. Existing targets are never destroyed
or rolled back to recover. Target naming is unchanged: `P/d<index>`.

The base has a persistent local `buddy-<offer-id>-d<index>-base` hold. The in-flight
snapshot also has a `...-pending` hold so days-long first syncs outlive retention.
Root journal intent records exact snapshot/GUID/base/GUID and whether the transfer
began with an absent target BEFORE sending. After send, the peer's newest schema
snapshot name and GUID must equal the sent snapshot. Only then does the runner
acquire the new base hold, persist completion and release old owned base/pending
holds. Before every new pending intent, all holds belonging to this offer on
that dataset except the new pending and selected verified base are released.
The last successfully confirmed base is journaled; a peer cannot replace it by
withholding it. At most two persistent offer holds remain per dataset (at most
three during crash-safe base handover or while the single probe hold is active);
repeated failed intents do not accumulate holds. Probe holds use a deterministic
offer tag; retries release stale probe holds without dropping sender base/pending
holds, and removal releases them too. Re-runs reconcile holds after a crash. Failed receives retain pending intent
and holds for next hour. Remote retention destroys only matching name/GUID entries
whose creation time was recorded from a LOCAL snapshot and is older than configured
retention_days, never the current common base, never any dataset or outside T.
The journal remembers identities/times after local retention removes a snapshot.
Unknown remote snapshots are retained. Removal deletes crons/tasks, releases only
this offer's holds, deletes the transport key/hosts, and removes the
completion marker even if a source dataset is gone. Each source is cleaned
independently; a missing source never skips the other sources, key or cron cleanup.
Completion is removed after cleanup succeeds; a missing source counts as already
clean, while real task/key/hold cleanup failures retain the marker for retry. Existing experimental native-task journals must be removed
using their original runner before installing this new sender; there is no silent
adoption/migration of native replication resources.

The monthly probe pulls the newest first-source snapshot raw, compares GUID and,
when the local root hex/raw key is stored, loads it via stdin and compares contents.
No passphrase is requested. Its temporary parent quota is local snapshot referenced
bytes + max(25%, 1 GiB). Pool available must cover that budget plus 1 GiB reserve.
The bounded parent is destroyed in finally; quota/space/send/cleanup failures are
reported. A full pool can still interrupt other operations; quotas reserve no space.

### Hostile receiver resume tokens

A malicious friend with root on their NAS can forge resume-token checksums and
return any metadata. The old zettarepl sender trusted token flags and could send a
decrypted stream after the peer omitted `rawok`. The purpose-built sender removes
that daemon path. EVERY send explicitly includes `-w`, including resume:
`zfs send -w -t <exact validated token>`; no receiver value can request a non-raw send.

The decoder is based on OpenZFS [2.3.4 libzfs_sendrecv.c](https://github.com/openzfs/zfs/blob/zfs-2.3.4/lib/libzfs/libzfs_sendrecv.c),
[dsl_dataset.c](https://github.com/openzfs/zfs/blob/zfs-2.3.4/module/zfs/dsl_dataset.c),
[fnvpair.c](https://github.com/openzfs/zfs/blob/zfs-2.3.4/module/nvpair/fnvpair.c) and
[nvpair.c](https://github.com/openzfs/zfs/blob/zfs-2.3.4/module/nvpair/nvpair.c).
The corresponding token generation, packing and send paths were also checked in
[2.4.0](https://github.com/openzfs/zfs/blob/zfs-2.4.0/lib/libzfs/libzfs_sendrecv.c).
It deliberately decodes binary native nvlists instead of parsing `send -nv -t`
printed output, where attacker-controlled strings can impersonate fields/lines.
Supported format: v1, lowercase hex, native little endian (TrueNAS amd64), checksum
Fletcher4 word[0] over complete native uint32 compressed words, zlib, nvlist version
0 / NV_UNIQUE_NAME. Maximum token 16384 characters and expanded payload 8192 bytes.
Bounds, full zlib consumption, exact pair sizes, field types, NUL termination,
unique field names and end-of-list/no trailing data are required. Alternative
encodings/new semantics fail closed and cause an aborted/restarted transfer.

Required fields: `toname` string, `toguid`, `object`, `offset`, `bytes` uint64 and
`rawok` presence boolean. Optional only `fromguid` uint64, `largeblockok` and
`compressok` presence booleans. All others, including `fromname`, `savedok`,
`embedok` and redaction fields, are refused; these raw non-redacted streams do not
produce them. `toname` must be exactly the journaled local dataset@snapshot with
an extant schema snapshot and local GUID equal to both `toguid` and journal GUID.
Incrementals require `fromguid` equal to the locally held, journaled base GUID and
a freshly matched peer name/GUID for that base. Full resumes require `fromguid`
ABSENT and a journaled initial full send begun while the target was absent. A
pending hold must still protect the target. The token is never normalized or
reconstructed: only the exact string validated here reaches `send -w -t`.

Invalid tokens cause NO resume send: log a persistent security warning, abort the
remote partial state with `recv -A T`, re-query existence/common snapshots and
restart by the ordinary rules. Abort failure stops the run. The checksum is only
a corruption check, not authentication. Peer claims can still fake receipt, delete
backups, cause denial of service or lie during restore. They cannot choose a
plaintext send; raw-stream confidentiality is bounded by locally selected content
and properties and the secrecy/strength of the owner's ZFS key/passphrase.

## Deployment constraints

The LAN UI port 8080 and host-loopback-only TCP 2288 are published. Tailnet TCP
8787 serves authenticated rest-server and isolated ZFS signalling; optional 8788
forwards the pinned peer only to `host.docker.internal:22`, whose single IPv4 address must match the directly connected Docker default-route gateway. Compose uses `extra_hosts: host.docker.internal:host-gateway` and Docker's default bridge so both addresses agree. Missing/mismatching resolution refuses both tunnels. No generic HTTP/SOCKS proxy, arbitrary host port forwarding, Funnel or Serve is used.
The local outbound forwarder is loopback-only with a fixed peer destination and requires
per-operation credentials. Restic encryption happens locally. Receiver storage limit
uses rest-server's `MaxRepoSize` over the entire incoming repository tree (not a filesystem/ZFS quota).
Setup accepts a quota from 1 MiB to 1 EiB. Settings require interval_hours 1–168,
stale_hours 1–87600, upload_kib 0–10000000, and each retention count 0–3650; at least
one retention count must be positive. Source mount names follow `[A-Za-z0-9][A-Za-z0-9-]{0,30}`.


### Root paste trust and source filesystem exposure

Command results additionally return `zfs_host_sha256` (SHA-256 of the exact decoded
`zfs_host.py` bytes) and `root_trust_warning`. Before any host mutation the paste
prints that hash and a readable decoded config: usernames, source datasets, control
dataset, receiver parent, quota and public/host key SHA256 fingerprints. Private
keys are not printed. It then requires `RUN` on `/dev/tty`; abort to inspect first.
Removal prints the review before invoking the root-owned installed runner; the
release hash identifies the embedded helper, not the installed runner wrapper.

**The entire pasted shell/Python wrapper is a root trust boundary.** A compromised
app can replace the paste, its reported hash and config summary. The hash returned
by that same app is not independent authentication. Obtain the release source and
`docs/ZFS-HOST-SHA256.txt` through an independently trusted release channel; compare
the first field against `sha256sum internal/buddy/zfs_host.py` from that release.
Decode the paste without executing it, hash the decoded BODY separately, and
inspect the wrapper and decoded config too. `make zfs-host-hash` prints the release
hash and writes the file; maintainers must publish it with each release. A matching
helper hash does not authenticate the config or wrapper and cannot make an already
compromised root host trustworthy.

With uid 0 and CAP_DAC_READ_SEARCH, `open_by_handle_at` can access other inodes on
any filesystem from which a container has a bind mount. A folder bind therefore
exposes the rest of its source dataset even outside every bind path. Use dedicated
ZFS datasets for each source and `/data` (and restore destinations), never plain
folders on a shared dataset. This applies equally to Restic file backups.
`GET /sources` adds a top-level `warnings` string array; `/status.warnings` includes
the same warning for each source or `/data` mount that is not a ZFS dataset root.

`raw_only` means only that the friend delivered a stream; content was not checked.
Its exact message is `Freund hat einen Stream geliefert; Inhalt nicht geprüft. Entschlüsselung benötigt den Benutzerschlüssel.`
Only `verified` means decryption and file-content comparison succeeded.
Crafted streams still reach OpenZFS's kernel parser and can consume CPU/I/O or
exploit implementation bugs. Quotas, count limits, excluded costly properties and
`volmode=none` reduce exposure; they do not sandbox a hostile stream. The friend
can lie about GUIDs, delete data, throttle transfers or deny service. Maintain
independent copies and test recovery; no protocol guarantees the friend's honesty.
