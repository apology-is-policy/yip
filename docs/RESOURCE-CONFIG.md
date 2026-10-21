# Line-specific resources

Yip's resources are exclusive contention classes. A physical host and all VMs
sharing its CPUs should be one resource. Two names for the same machine must
not grant independent permission to saturate it.

Definitions live in `$YIP_ROOT/resources.json`, or the active line directory
under `$YIP_HOME/lines`. Ownership, queues, runner identities, recovery events and
history stay in their existing files. An absent config retains the original
`mac`/`pi` definitions for backward compatibility; a malformed config fails
closed rather than silently restoring defaults.

## First-time setup

For a new line with no resource state:

```sh
yip config init --clients-restarted
yip config validate examples/resources.json
yip config apply examples/resources.json --clients-restarted
yip config show
yip resources
```

Use `--line NAME` consistently when grouping separate repositories. Empty
`resources: []` is valid. `config validate` checks the schema; `apply` additionally
checks the current state while holding the registry lock.

For an existing unconfigured line:

```sh
yip config migrate --clients-restarted
```

This writes the existing mac/pi definitions without modifying leases, queue
entries, runner registrations or history. Coordinate client upgrades/restarts
before running it. `--clients-restarted` is an operator assertion, not automatic
process discovery. Old binaries do not honor the new registry lock or custom
names; running mixed versions is unsupported. No command kills/restarts peers.

## Schema

```json
{
  "version": 1,
  "resources": [
    {
      "name": "builder",
      "description": "The physical build host and its VMs",
      "machine": "physical-host-01",
      "host": "exact-output-of-hostname",
      "disk_path": "/absolute/build/filesystem/path",
      "min_free_gib": 8
    }
  ]
}
```

`name` is a unique lowercase identifier using letters, digits, `_` or `-`.
`description` and `machine` are required. Machine identifiers must be unique in
a line; use stable canonical values, not aliases for the same host. Yip cannot
infer physical topology or detect differently spelled aliases automatically.

`host` is optional unless a disk guard is present. A disk guard requires both an
absolute `disk_path` and positive `min_free_gib`. Yip checks the actual available
bytes on that filesystem immediately before a new grant/recovery. If the caller
is not on the exact configured hostname, admission fails rather than measuring
the wrong host. Remote disk inspection is not implemented. Host association
without a disk guard is descriptive; runner records retain their own host.

Disk guards are admission checks, not disk reservations or continuous monitors.
Existing holders may renew and release when free space subsequently drops. All
external deployment rules still apply, including the existing 8 GiB runner floor
and stricter checkpoint-specific guards. Migration does not invent a path or
replace those external guards. Explicitly configure the real path/host during a
coordinated idle boundary if you want Yip itself to enforce an additional guard.

`disabled: true` prevents new grants while retaining a retired definition and
its history. It may be set only when the lease and queued requests have cleared.
Expiration alone does not clear a lease or authorize its removal.

## Safe updates and restoration

Use `config show` to obtain a proposed file, edit that file, then validate/apply
it. Do not edit the active config in place while clients run. Resource operations
hold the shared registry lock before their individual resource lock; config edits
hold it exclusively. A held/queued resource allows description changes only.
Resources with recorded lease/queue/history/recovery state cannot be removed or
renamed. Historical machine identities remain immutable. Existing disk floors
cannot be lowered or redirected through `apply`.

Every successful apply first records the before/after definitions under
`config-history`. That immutable record is a restoration source, not a receipt
that the active rename necessarily succeeded: compare it with `config show`.
The apply path validates both the schema and the current resource references.
No config edit deletes resource files or cleans a queue. Unknown or corrupt
state must be investigated rather than discarded to force an update.

If an active config was manually damaged, stop all line clients, preserve the
bad file, and restore a reviewed prior definition from config-history before
resuming. Never restore lease/queue snapshots over current coordination state.
