# Durable logical workspace state

`workspace_state` provides a reusable, versioned checkpoint for the logical
model. A checkpoint contains:

- the Carrier and Parking desktop GUIDs;
- every monitor's opaque stable key, active workspace, and workspace IDs; and
- each live `WindowIdentity` tuple mapped to its logical `WorkspaceId`.

The checkpoint does not claim that a saved HWND is still current. After load,
the host must compare each full identity tuple (HWND, PID, and process creation
time) with a fresh authoritative discovery snapshot before restoring ownership.
Native Carrier/Parking roles are derived from the active workspace after that
reconciliation; they are not independently persisted.

## File safety and validation

The schema-2 binary format uses fixed-width little-endian fields, canonical
monitor/identity ordering, explicit count and file-size limits, and a CRC-32
over the payload. `SaveWorkspaceState` validates the complete candidate before
touching the destination, writes a uniquely created temporary file in the same
directory, flushes it with `FlushFileBuffers`, and replaces the destination with
`MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`. A failed
validation or write leaves the prior checkpoint intact.

`LoadWorkspaceState` rejects unsupported schemas, truncation, checksum errors,
duplicate/empty stable monitor keys, duplicate/zero workspace IDs, active
workspaces outside their monitor, duplicate/invalid window identities, and
ownership referencing an unknown workspace. The caller's output object is
assigned only after the whole file passes validation. Schema 1 is deliberately
rejected because it persisted process-local raw `HMONITOR` values.

`CaptureWorkspaceState` requires caller-supplied stable-key/runtime bindings
and copies a valid `WorkspaceEngine` model into the durable representation.
The runtime `MonitorId` is never serialized. After load it is zero until
`RemapWorkspaceStateTopology` resolves every saved stable key against the
current startup's bindings; missing or duplicate bindings reject the whole
candidate. Saving is not coupled to switch/journal transactions yet, so
checkpoint cadence and startup reconciliation can be added at the host
boundary without changing the transaction engine's crash semantics.

## Fresh-engine seeding

`SeedWorkspaceEngineFromState` is a reusable, observation-only startup
component. It accepts a fully validated and remapped checkpoint, the caller's
current monitor/workspace topology (including the caller-authoritative active
workspace), and a fresh authoritative window snapshot. It builds a separate
`WorkspaceEngine` candidate and replaces the caller's `unique_ptr` only after
the complete topology, snapshot, ownership mapping, and engine invariant pass.
No failure can partially change the caller's existing output engine.

An exact `WindowIdentity` retains its saved workspace only when the live
monitor still owns that workspace and the observed native role is Carrier for
the active workspace or Parking for an inactive workspace. Missing identities
are omitted. An HWND reused by a different PID/process creation time is a new
window and never inherits the old generation's ownership: a new Carrier window
joins the caller's active workspace, while a new Parking window remains
unassigned.

The seeder never uses a stable monitor key as an engine identifier. Both
`WorkspaceStateMonitor::runtime_monitor` and the caller topology's `MonitorId`
are raw process-local values and must refer to the same startup scope. A loaded
state has no such mapping (`runtime_monitor == 0`) and is rejected until
`RemapWorkspaceStateTopology` binds its durable stable keys for this startup.
This is explicitly not a claim that raw `MonitorId` values survive restart.

Run the deterministic, non-mutating validation with:

```powershell
.\build\vdprobe.exe workspace-state-test
```
