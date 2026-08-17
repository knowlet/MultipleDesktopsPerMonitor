# Durable logical workspace state

`workspace_state` provides a reusable, versioned checkpoint for the logical
model. A checkpoint contains:

- the Carrier and Parking desktop GUIDs;
- every monitor's active workspace and ordered workspace IDs; and
- each live `WindowIdentity` tuple mapped to its logical `WorkspaceId`.

The checkpoint does not claim that a saved HWND is still current. After load,
the host must compare each full identity tuple (HWND, PID, and process creation
time) with a fresh authoritative discovery snapshot before restoring ownership.
Native Carrier/Parking roles are derived from the active workspace after that
reconciliation; they are not independently persisted.

## File safety and validation

The schema-1 binary format uses fixed-width little-endian fields, canonical
monitor/identity ordering, explicit count and file-size limits, and a CRC-32
over the payload. `SaveWorkspaceState` validates the complete candidate before
touching the destination, writes a uniquely created temporary file in the same
directory, flushes it with `FlushFileBuffers`, and replaces the destination with
`MoveFileExW(MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`. A failed
validation or write leaves the prior checkpoint intact.

`LoadWorkspaceState` rejects unsupported schemas, truncation, checksum errors,
duplicate/zero monitor and workspace IDs, active workspaces outside their
monitor, duplicate/invalid window identities, and ownership referencing an
unknown workspace. The caller's output object is assigned only after the whole
file passes validation.

`CaptureWorkspaceState` is the deliberately narrow production integration: it
copies a valid `WorkspaceEngine` model into the durable representation. Saving
is not coupled to switch/journal transactions yet, so checkpoint cadence and
startup reconciliation can be added at the host boundary without changing the
transaction engine's crash semantics.

Run the deterministic, non-mutating validation with:

```powershell
.\build\vdprobe.exe workspace-state-test
```
