# Relay folders extension (version 1)

Mercury Relay exposes an optional, Mercury-owned folder browser over the
existing encrypted controller channel. It is not a new Hermes HTTP route and
never opens a loopback listener or sends a Hermes bearer token through the router.

## Capability negotiation

A host advertises the extension in the result of `relay.status` only when the
installed Hermes managed-files policy and the plugin's secure directory adapter
are available:

```json
{
  "capabilities": {
    "folders": {
      "version": 1,
      "list_method": "relay.folders.list",
      "create_method": "relay.folders.create"
    }
  }
}
```

An older host, a host without the managed-files policy, or a host whose secure
filesystem adapter cannot be loaded omits `capabilities.folders`. Clients must
show their normal upgrade/unsupported-host path and must not attempt the
methods based on a version guess.

## Methods

### `relay.folders.list`

Parameters:

```json
{"profile":"default","path":"/workspace"}
```

`profile` is required. `path` is optional; omitting it lists the policy's
initial directory. Paths are absolute canonical paths without `..`; a locked
managed root may also accept `/` as its root alias.

### `relay.folders.create`

Parameters:

```json
{"profile":"default","parent_path":"/workspace","name":"new folder"}
```

All three fields are required. `name` is one directory component, not a path;
slashes, control characters, `.` and `..` are rejected. The response is the
listing of the newly created directory, so clients can render the canonical
path without constructing one locally. Creating an already existing directory
is idempotent; an existing regular file is an error.

Both methods return the same relay listing shape. `entries` contains only
subdirectories; every entry uses `is_dir: true`:

```json
{
  "path":"/workspace",
  "parent":null,
  "root":"/workspace",
  "locked_root":"/workspace",
  "can_change_path":false,
  "entries":[
    {"name":"docs","path":"/workspace/docs","is_dir":true}
  ]
}
```

`root` and `locked_root` are `null` for an unlocked policy. A locked root has
no `parent` entry above that root. Entry ordering is case-insensitive name
order.

## Bounds and errors

The service returns stable, non-oracular error messages only:

- `invalid_params` — malformed profile/path/name or wrong fields;
- `profile_not_available` — the selected profile is not authorized or does not
  exist;
- `folders_unavailable` — the host policy/adapter cannot be used;
- `folder_not_available` — the directory is missing, unreadable, outside the
  managed policy, sensitive, or linked through a symlink;
- `folder_exists` — creation found a non-directory at the requested name;
- `folder_create_failed` — the host could not complete the directory mutation;
- `response_too_large` — the listing exceeds the explicit bounds.

Paths are capped at 1,024 UTF-16 code units (matching the shared mobile contract),
including derived child paths checked before directory creation. Folder names
are capped at 255 UTF-8 bytes. A listing JSON response is capped at
1 MiB to match the shared mobile contract. A listing contains at most 500
visible directory entries and scans only one additional directory entry before
returning `response_too_large`; it is never silently truncated. The normal
relay logical-message bound applies as a second cap.

## Security and retry behavior

The adapter obtains the official Hermes managed-files policy and sensitive-path
predicate from the installed host. It does not reproduce or weaken the
policy's locked-root behavior. It refuses sensitive basenames and credential
directory trees, skips symlink/non-directory entries, and walks directories
with `O_NOFOLLOW`/descriptor-relative operations on POSIX. The folder
capability is deliberately omitted on hosts without those POSIX descriptor
primitives; the plugin does not advertise a weaker path-based Windows mode.
Creation uses a single validated parent and a descriptor-relative `mkdir`; it
does not create arbitrary parent trees.
The target is reopened through the secure walk before its listing is returned
so a path swap cannot turn the response into an escape.

Profile authorization is performed by the existing `SessionReads` gate. The
admission service performs its existing device authorization and epoch fence
before and after the dispatcher, so pairing, revocation, and E2EE router
opacity remain unchanged.

Folder creation is a local relay mutation, not a Hermes request. The retained
session lease uses the namespaced JSON-RPC request identity as the retry key and
stores the request's method/params fingerprint to reject accidental reuse of
that identity with different payloads. A new socket namespace therefore runs a
new idempotent create operation; the same identity after an outer reconnect
returns the successful original outcome without replaying the mutation.
Failures are not retained, so a later namespaced request can retry a transient
host error. The ledger is bounded; if a successful entry is evicted, the
filesystem operation is still idempotent for an existing directory.
