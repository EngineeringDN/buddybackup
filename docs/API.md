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

## Deployment constraints

Only the LAN UI port 8080 is published. Tailnet TCP 8787 serves authenticated rest-server
only. No generic HTTP/SOCKS proxy, host port forwarding, Funnel or Serve is used.
The local outbound forwarder is loopback-only with a fixed peer destination and requires
per-operation credentials. Restic encryption happens locally. Receiver storage limit
uses rest-server's `MaxRepoSize` over the entire incoming repository tree (not a filesystem/ZFS quota).
Setup accepts a quota from 1 MiB to 1 EiB. Settings require interval_hours 1–168,
stale_hours 1–87600, upload_kib 0–10000000, and each retention count 0–3650; at least
one retention count must be positive. Source mount names follow `[A-Za-z0-9][A-Za-z0-9-]{0,30}`.
