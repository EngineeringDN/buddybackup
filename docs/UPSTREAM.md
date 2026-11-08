# Primary upstream evidence (checked 2026-11-08)

Dependencies are pinned in go.mod/go.sum. The following were inspected directly,
including the downloaded source of the exact pinned Go modules.

- [tsnet README](https://github.com/tailscale/tailscale/blob/v1.102.5/tsnet/README.md)
  and [tsnet source](https://github.com/tailscale/tailscale/blob/v1.102.5/tsnet/tsnet.go):
  Server.Listen registers a tailnet-only listener, Server.Dial uses the embedded
  stack, LocalClient uses an in-memory listener. `getTCPHandlerForFlow` returns
  `(nil,true)` for unregistered ports: no default forwarding to host loopback.
- [netstack dispatch](https://github.com/tailscale/tailscale/blob/v1.102.5/wgengine/netstack/netstack.go)
  calls LocalBackend.TCPHandlerForDst BEFORE tsnet's flow handler. This is why merely
  registering one listener is insufficient if built-in PeerAPI remains enabled.
  The build uses `ts_omit_peerapiserver`, `ts_omit_webclient`, `ts_omit_ssh`,
  `ts_omit_drive`, and `ts_omit_taildrop`; startup checks the buildfeature constants.
  Serve omission is currently incompatible with tsnet's unconditional references
  to Serve/ACME methods; the app instead refuses Serve state with a Store wrapper.
- [PeerStatus](https://github.com/tailscale/tailscale/blob/v1.102.5/ipn/ipnstate/ipnstate.go)
  defines stable `ID`, `TailscaleIPs`, `Online`, `AltSharerUserID`, `ShareeNode`,
  `Expired` and `KeyExpiry`. `Online` means connected to the control plane; it is not
  an authenticated reachability test. `ShareeNode` describes nodes belonging to a
  shared-to user which might connect to this node, not a generic shared-in indicator.
- [LocalBackend.populatePeerStatusLocked / peerStatusFromNode](https://github.com/tailscale/tailscale/blob/v1.102.5/ipn/ipnlocal/local.go)
  walks all control-plane peers and fills ID from StableID(), addresses from the
  node's Tailscale prefixes, AltSharerUserID from Sharer(), Online from the optional
  control field's Get(). An absent Online thus becomes false. There is no shared-in
  exception removing stable ID or IP from this path. The API uses LocalClient.Status
  (not StatusWithoutPeers) to obtain this list. Pinning compares ID AND the exact
  invitation IPv4, never silently switches addresses. Authentication is then tried
  before a route probe, irrespective of Online=false. Real cross-tailnet behavior
  still needs the planned live validation; this conclusion is from source inspection.
- [Sharing docs](https://tailscale.com/docs/features/sharing): node sharing makes
  a particular node available across tailnets; both friends share their app nodes
  to support reciprocal backups. ACL policy can still restrict port 8787.
- [rest-server handler](https://github.com/restic/rest-server/blob/v0.14.0/mux.go)
  exposes NewHandler(*Server); [Server options](https://github.com/restic/rest-server/blob/v0.14.0/handlers.go)
  include HtpasswdPath, PrivateRepos and MaxRepoSize. The handler uses the upstream
  bcrypt htpasswd parser and quota implementation. Upload requests are serialized
  by BuddyBackup so the upstream check/write quota sequence cannot race uploads.
  The maximum covers incoming repository files under the configured receiver root,
  including subrepositories; it excludes external ZFS snapshots and app state.
- [restic prune documentation](https://restic.readthedocs.io/en/stable/060_forget.html):
  low-space prune can use `--max-repack-size 0`. The pinned 0.19.1 binary's own
  backup/tag/restore/prune help was also checked. Local integration verifies the
  actual JSON summary/tag output and `restore --verify --overwrite never` behavior.
- [TrueNAS 25.10 Custom App screen](https://www.truenas.com/docs/scale/25.10/scaleuireference/apps/installcustomappscreens/)
  and [TrueNAS 27 Custom App screen](https://cdn.truenas.com/docs/scale/scaleuireference/apps/installcustomappscreens/):
  Install via YAML accepts Docker Compose. The example uses services/networks,
  bind mounts, explicit published host IP, and standard Compose security settings.
  Docker Compose parses the example locally; actual TrueNAS installation is deferred.


## Optional ZFS mode (checked 2026-11-08)

- TrueNAS versioned API schemas were read for both
  [25.10 replication.create](https://api.truenas.com/v25.10.0/api_methods_replication.create.html)
  and [27 replication.create](https://api.truenas.com/v27.0/api_methods_replication.create.html),
  plus `keychaincredential.create`, `pool.snapshottask.create`, `user.create/update`,
  `cronjob.create`, `pool.dataset.export_key`, `service.update/control` under both
  versioned API paths. SSH credentials take a keychain pair ID, custom port and raw
  `remote_host_key` (algorithm/base64, without known_hosts hostname prefix).
  Replication has no `raw` API flag; `encryption` configures replacement encryption,
  and is deliberately false for preservation of existing encrypted raw streams.
- [zettarepl raw selection](https://github.com/truenas/zettarepl/blob/master/zettarepl/replication/run.py)
  selects raw when properties are included and the source dataset is encrypted.
  [ZFS command generation](https://github.com/truenas/zettarepl/blob/master/zettarepl/transport/zfscli/__init__.py)
  adds `-w`; receive suppresses mounting and applies property exclusions.
  [SSH transport](https://github.com/truenas/zettarepl/blob/master/zettarepl/transport/ssh.py)
  uses remote exec without a PTY, agent forwarding or port forwarding; therefore
  `no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding` do not obstruct it.
  [OpenSSH authorized_keys](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT)
  defines those restrictions.
- [OpenZFS 2.3 send](https://openzfs.github.io/openzfs-docs/man/v2.3/8/zfs-send.8.html)
  and [receive](https://openzfs.github.io/openzfs-docs/man/v2.3/8/zfs-receive.8.html)
  specify raw preservation and restrictions. Standalone raw sends do not require
  sending the encryption-root ancestor; received children use the original root
  key material. Raw/non-raw incrementals must not be mixed. Native unencrypted
  sources (and unencrypted descendants in a recursive selection) are refused
  before creating host resources. Locked sources are refused consistently with
  [TrueNAS encrypted replication](https://www.truenas.com/docs/scale/25.10/scaletutorials/dataprotection/replication/advancedreplication/replicationwithencryptionscale/).
- [TrueNAS local API client](https://github.com/truenas/api_client/blob/master/truenas_api_client/__init__.py)
  documents `Client()` as local Unix-socket IPC and `call(..., job=True)` waits for
  job completion (the Python counterpart of `midclt call -j`). This keeps private
  keys and exported ZFS keys off argv. No host client is imported by the app itself.
  [user home writer](https://github.com/truenas/middleware/blob/master/src/middlewared/middlewared/plugins/account/user_home.py)
  writes `sshpubkey` into the real home authorized_keys; the options are preserved.
- The exact pinned tsnet 1.102.5 `Listen`, `Dial`, LocalClient.Status and
  `ipnstate.PeerStatus` implementation was inspected from the downloaded module.
  Optional 8788 has no fallback target, and source IP is checked against the pinned
  stable node ID/IP in the control-plane peer list before a host SSH dial.
  Host-side 2288 accepts only the Docker gateway source; Compose publishes it on
  127.0.0.1. Real tsnet tests verify 8788 closed/off and 8787+8788 only/on.
- The exact pinned x/crypto 0.54.0 `MarshalPrivateKey`, `NewClientConn`,
  `HostKeyCallback`, and handshake implementation were inspected. Host-key
  discovery aborts authentication after signature verification in the callback;
  the discovered key is then pinned in TrueNAS credentials and OpenSSH probes.

The restricted receive/raw-return experiment in the task brief is supplied evidence
from TrueNAS 25.10.8/OpenZFS 2.3.9, not a test rerun by this implementation. Generated
middleware payloads, permissions, custom bridge gateway SSH reachability and probe
mounting/key export still require actual TrueNAS 25.10/27 acceptance testing.
