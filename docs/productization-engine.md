# Productization engine — stateful Carrier/Parking core

## Decision

The representative compatibility gate is not yet complete. Windows Terminal
and the Edge semantics contract have been observed, but the latest Edge run
must still prove that the isolated temporary profile fully drains and is
removed before the strict gate can be promoted:

| Behavior type | Representative | Result |
|---|---|---|
| Classic Win32 | controlled vdprobe child | `GO-WITH-LIMITATIONS` |
| Shell/shared process | Explorer | `GO-WITH-LIMITATIONS` |
| Chromium multi-process | isolated Microsoft Edge | `GO-WITH-LIMITATIONS` |
| Packaged/modern Windows app | Windows Terminal | `GO-WITH-LIMITATIONS` |

This is a **pending `GO-PRODUCTIZATION` checkpoint**, not a completed
decision. The Edge top-level semantics are valid, but the last evidence still
ends in `INCONCLUSIVE-CLEANUP`; a clean interactive rerun is required before
claiming the strict gate. The engine must remain capability-driven; it must not
grow an executable whitelist.

## Engine milestone

`src/workspace_engine.{h,cpp}` contains the first non-mutating productization
core. The core itself invokes no native shell calls; its first live use is the
callback-backed `logical-workspace-test` adapter. It keeps logical workspace
identity separate from native desktop GUIDs:

```text
HMONITOR/MonitorId × WorkspaceId -> logical ownership
active workspace window         -> Carrier
inactive workspace window       -> shared Parking
```

The engine accepts a `WindowCapabilities` record instead of an application
name:

```cpp
has_application_view
can_move_desktops
independent_top_level
desktop_state_observable
owner_state_observable
```

Unsupported or ambiguous windows are retained as records but are excluded from
mutating switch plans. A switch touching an unsupported/ambiguous affected
workspace fails closed. Unrelated unsupported windows on another workspace do
not block a monitor-local switch.

Window identity is generation-safe for the current model: HWND, PID, and
process creation time are stored together. Re-observing the same HWND with a
different process generation produces `Recreated`; a close removes the record
and a later observation adds a fresh record.

## Transaction and recovery boundary

`PrepareSwitch()` only produces operations for the outgoing and incoming
logical workspaces on one monitor. Operations are ordered Carrier -> Parking
before Parking -> Carrier. `ExecuteSwitch()`:

1. validates the current logical/native invariant;
2. writes a `BEGIN` journal record when configured;
3. verifies the observed native role before each move;
4. invokes the caller-supplied move callback;
5. verifies the resulting native role;
6. rolls back applied operations in reverse order on failure;
7. commits the logical active workspace only after all operations succeed.

If a journal commit or native move fails, rollback is attempted immediately.
If rollback cannot be verified, the result is marked
`recovery_required=true`; startup can call `RecoverPending()` with the pending
plan before accepting new workspace operations.

The journal is deliberately generic and does not call `SwitchDesktop`, create
desktops, remove desktops, or terminate processes. It is a transaction
boundary, not persistence of a native desktop identity.

## Deterministic evidence

Run:

```powershell
.\build\vdprobe.exe workspace-engine-test
```

This test performs no COM calls and no native desktop/window mutation. It
currently verifies:

- two monitors with independent active workspaces;
- Carrier/Parking invariant enforcement;
- one monitor-local switch and round-trip restoration;
- HWND reuse as a new generation;
- close and recreate lifecycle;
- generation-safe lifecycle observations, including stale-generation
  suppression and fail-closed handling of identity-less close events;
- complete discovery-snapshot reconciliation with HWND-generation checks;
- read-only complete-window discovery through an injected backend, including
  runtime capability classification and fail-closed duplicate/exception
  handling;
- deterministic Z-order capture and fail-closed presentation restore planning;
- identity-checked presentation execution ordering for probe-owned windows;
- unsupported capability fail-closed behavior;
- interrupted transaction recovery;
- durable journal `BEGIN` replacement and terminal-marker flushing.

All checks passed on August 12, 2026 after the engine was added.

The discovery and presentation APIs remain callback boundaries, not a claim
that the product already tracks every desktop window. The controlled
`logical-workspace-test` supplies a probe-owned native presentation adapter
that revalidates HWND generation and capability immediately before applying
placement, non-activating Z-order, and confirmation-gated foreground
operations. `window_lifecycle.{h,cpp}` adds a bounded read-only
`SetWinEventHook` source for window-object create/show/destroy hints and a separate
model-neutral adapter. The hook callback queues window-object hints without
doing COM or model mutation; capability/native-role resolution happens later
in a caller-supplied observer. Native out-of-context destroy hints
intentionally carry no identity because a dispatch-time PID/process-time lookup
is not an event-time generation. Close hints never remove records directly;
they set a sticky full-snapshot reconciliation requirement. The authoritative
batch boundary deduplicates event hints, counts invalid/stale generations, and
passes only the complete scoped
observation to `ReconcileDiscoverySnapshot()`; events themselves never remove
or replace model records. Hook installation/removal is RAII-managed, including
cleanup when only part of registration succeeds. The hook source requires
same-thread start/stop, bounded queue storage, and reports unhook failure
through `shutdown_ok()`. `ReconcileDiscoverySnapshot()` requires a complete,
point-in-time observation and treats omitted tracked windows as closed;
generation changes are recorded as recreation. `PreparePresentationRestore()`
emits placement, Z-order, and foreground operations only when the snapshot is
 complete, managed, capability-safe, and identity-consistent.

The read-only `window_discovery.{h,cpp}` layer is the next productization
boundary. Its `WindowDiscoveryBackend` accepts complete HWND enumeration and
per-window observation callbacks, so platform-specific identity, monitor,
desktop-role, presentation, and `IApplicationView` capability reads remain
outside the state model. `WindowDiscovery::Discover()` sorts and validates a
complete snapshot, rejects duplicate HWNDs or generations, and leaves the
previous result unchanged on observation failure or callback exception. It
classifies only proven Carrier/Parking top-level records as `Managed`;
unsupported capability or tool/owned windows are retained as `Unsupported`,
while missing identity, monitor, desktop state, or a valid native role is
`Ambiguous`. It deliberately does not assign logical workspaces, mutate native
state, or branch on executable names. Run:

```powershell
.\build\vdprobe.exe workspace-discovery-test
```

This deterministic test covers managed/unsupported/ambiguous classification,
incomplete and duplicate enumeration, tool/ownership limits, invalid native
roles, and enumeration/observation exception containment. A live all-window
discovery adapter and assignment policy remain separate milestones.

## Deliberate next boundaries

The controlled `logical-workspace-test` now provides live integration
evidence: it captures three vdprobe-owned top-level HWNDs, resolves and
re-resolves `IApplicationView` with `GetViewForHwnd`, supplies
identity-checked move/observe callbacks to `WorkspaceEngine`, executes the
probe-only presentation restore path, and verifies the transaction with
notification events and documented desktop state. Its interrupted-operation
check hands the journal to a fresh engine/coordinator pair and then performs
an authoritative complete reconciliation; this is still a bounded simulation,
not a process-restart bootstrap. It is not yet the user-facing workspace
manager. Remaining work is:

- production wiring of lifecycle observations to full window discovery and a
  periodic/recovery full-snapshot policy;
- durable crash-journal placement and startup recovery policy;
- production focus/Z-order policy and foreground-lock failure handling;
- minimal hotkey/UI integration.

The serialized `WorkspaceCoordinator` boundary is now covered by the
non-mutating `workspace-coordinator-test`. It owns an owner-thread operation
boundary, drains lifecycle hints atomically with overflow state, retries
complete discovery until the input is quiet, rejects late lifecycle changes
before native mutation, and delegates stale-plan validation, rollback, and
journal recovery to `WorkspaceEngine`. It is intentionally not yet a
long-running manager: the caller still supplies complete discovery and native
move/observe callbacks, pumps the WinEvent owner thread, and chooses the
production journal/bootstrap policy.

The live command was also attempted on the current host. `GetImmersiveShell`
returned `E_ACCESSDENIED` before any probe window was spawned, so the command
reported `ENVIRONMENT-BLOCKED`, `mutation_started = no`, and exit status `77`.
That is an environment limitation, not a logical-workspace semantics result.

These layers should call the capability-driven engine and preserve its
fail-closed behavior. They should not add app-name branches unless a concrete
runtime anomaly demonstrates that a capability is insufficient.
