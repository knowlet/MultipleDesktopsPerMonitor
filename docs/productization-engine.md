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
.\build\vdprobe.exe workspace-assignment-test
.\build\vdprobe.exe workspace-live-lifecycle-test
```

`WorkspaceAssignmentAdapter` is the read-only boundary between complete
`DiscoveredWindow` snapshots and engine-scoped `WindowRecord` values.  Its
monitor workspace membership must match the engine, while the engine's current
active workspace remains authoritative after each switch. Exact tracked managed identities keep
their workspace only when the observed Carrier/Parking role still matches;
monitor migration or a role mismatch rejects the entire candidate without
changing either the caller's output or the engine.  A new Carrier window joins
the monitor's active workspace, while a new Parking window remains unassigned.
Unsupported and ambiguous observations remain outside managed scope.  An HWND
with a new process generation is evaluated as a new candidate and never
inherits the prior generation's workspace.

`workspace-live-lifecycle-test` composes the read-only discovery, lifecycle,
assignment, engine, and coordinator boundaries without native window or
desktop mutation. Deterministic injected probe identities exercise appeared,
close-hint, authoritative close, reappearance, and same-HWND new-generation
reconciliation. The explicit test registry is keyed by full `WindowIdentity`,
so a new generation must be assigned independently. Complete snapshots are the
sole close authority; lifecycle hints only cause bounded reconciliation. The
candidate snapshot is rejected intact on missing assignment, monitor mismatch,
capability loss, unstable identity, or lifecycle input that does not become
quiet. The command uses the injectable Win32 discovery factory seam to avoid
enumerating user HWNDs; `workspace-live-coordinator-bootstrap-test` separately
validates the system discovery factory against the live shell.

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

The read-only `window_discovery.{h,cpp}` layer now implements the next
productization boundary. `CreateSystemWindowDiscoveryBackend()` supplies
complete `EnumWindows` enumeration plus documented identity, monitor,
owner/style, presentation, foreground/Z-order, DWM-cloak, and
`IVirtualDesktopManager` observations. An injectable
`CreateWin32WindowDiscoveryBackend()` seam keeps the platform reads testable,
while optional `IApplicationView` capability augmentation can establish only
`has_application_view` and `can_move_desktops`; it cannot relax the documented
HWND safety checks. `WindowDiscovery::Discover()` sorts and validates a
complete snapshot, rejects duplicate HWNDs or generations, and leaves the
previous result unchanged on observation failure or callback exception. It
classifies only proven Carrier/Parking top-level records as `Managed`;
unsupported capability or tool/owned windows are retained as `Unsupported`,
while missing identity, monitor, desktop state, or a valid native role is
`Ambiguous`. It deliberately does not assign logical workspaces, mutate native
state, or branch on executable names. Run:

```powershell
.\build\vdprobe.exe workspace-discovery-test
.\build\vdprobe.exe workspace-live-discovery-test
.\build\vdprobe.exe workspace-live-bootstrap-test
.\build\vdprobe.exe workspace-live-coordinator-bootstrap-test
```

This deterministic test covers the injected backend and managed/unsupported/
ambiguous classification, incomplete and duplicate enumeration, tool/ownership
limits, invalid native roles, HWND-generation changes, and enumeration/
observation exception containment. The system backend is read-only and ready
for caller integration. `workspace-live-discovery-test` performs one bounded
live bootstrap: it selects the existing current desktop as Carrier and one
existing inactive desktop as Parking, augments eligible top-level HWNDs through
gated read-only `GetViewForHwnd` and `CanViewMoveDesktops` calls, and reports
managed/unsupported/ambiguous counts. It assigns no logical workspace and
performs no native mutation. `E_ACCESSDENIED` is emitted as the stable
`RESULT=ENVIRONMENT-BLOCKED` status with exit code 77. Production coordinator
wiring, assignment policy, and lifecycle-driven rescan remain separate
milestones.

`workspace-live-bootstrap-test` reuses that live read-only discovery and
private capability augmentation, then converts the complete snapshot into
`WindowRecord` values and reconciles them into a fresh `WorkspaceEngine`. For
this validation only, it creates two synthetic in-memory workspace IDs per
observed monitor and assigns Carrier/Parking observations accordingly. This is
not a workspace assignment policy: the command installs no move callback,
persists nothing, and performs no native mutation. It reports machine-readable
snapshot, monitor, engine-window, invariant, and result status.

`workspace-live-coordinator-bootstrap-test` takes the next narrow integration
step without enabling product mutation. It starts `WinEventLifecycleSource` on
the command's owner thread, pumps the owner-thread queue around each complete
discovery callback, and runs bounded quiet reconciliation through
`WindowLifecycleAdapter` and `WorkspaceCoordinator`. Monitor/workspace mapping
is explicitly synthetic and in-memory, the coordinator has no move callback,
and the lifecycle source is stopped and checked before `RESULT=OK` is emitted.
Environmental access denial, unavailable lifecycle hooks, or a snapshot that
cannot become quiet within the bound reports `RESULT=ENVIRONMENT-BLOCKED` and
`mutation_started=no`; all other failures report `RESULT=ERROR` with the same
non-mutation marker.

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
- production process hosting, journal-path selection, and startup invocation
  policy around the reusable startup boundary;
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

`workspace_startup.{h,cpp}` adds the bounded reusable `RecoverAtStartup`
ordering boundary. Its caller supplies the normal engine/coordinator,
authoritative discovery callback, lifecycle source, stable journal path, and a
factory for the fresh recovery runtime. It starts and verifies the WinEvent
source, reads the journal before enabling operations, requires a complete quiet
snapshot, and for a pending transaction bootstraps a fresh model, recovers it,
then requires full reconciliation. Journal parse errors, unproven identities,
lifecycle instability, and every recovery failure block operations and retain
the journal. `workspace-startup-test` is deterministic and uses only
in-memory move/observation callbacks; it does not mutate native windows or
desktops. This is a boundary, not a claim that a long-running product host or
journal-location policy is complete.

The live command was also attempted on the current host. `GetImmersiveShell`
returned `E_ACCESSDENIED` before any probe window was spawned, so the command
reported `ENVIRONMENT-BLOCKED`, `mutation_started = no`, and exit status `77`.
That is an environment limitation, not a logical-workspace semantics result.

These layers should call the capability-driven engine and preserve its
fail-closed behavior. They should not add app-name branches unless a concrete
runtime anomaly demonstrates that a capability is insufficient.
