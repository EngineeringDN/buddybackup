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
