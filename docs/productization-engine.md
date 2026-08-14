# Productization engine — stateful Carrier/Parking core

## Decision

The representative compatibility gate is complete as
`GO-PRODUCTIZATION`. The post-hardening Edge rerun proved that the isolated
temporary profile fully drains and is removed, and Windows Terminal completed
its probe-owned cleanup contract:

| Behavior type | Representative | Result |
|---|---|---|
| Classic Win32 | controlled vdprobe child | `GO-WITH-LIMITATIONS` |
| Shell/shared process | Explorer | `GO-WITH-LIMITATIONS` |
| Chromium multi-process | isolated Microsoft Edge | `GO-WITH-LIMITATIONS` |
| Packaged/modern Windows app | Windows Terminal | `GO-WITH-LIMITATIONS` |

This is a completed representative decision, not an application whitelist.
Edge and Terminal prove the top-level Carrier/Parking contract for their
representative application architectures, with internal/owned windows kept
observation-only. The engine must remain capability-driven; it must not grow
an executable whitelist.

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
.\build\vdprobe.exe workspace-readonly-host-test
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

`WorkspaceReadOnlyHost` composes `WindowDiscovery`,
`WorkspaceAssignmentAdapter`, `WinEventLifecycleSource`,
`WindowLifecycleAdapter`, `WorkspaceCoordinator`, and `WorkspaceStartup` into
one owner-thread observation boundary. The caller injects Carrier/Parking
GUIDs, monitor/workspace topology, a complete discovery backend, a stable
journal path, and optionally the WinEvent hook seams. `Start()` requires a
quiet authoritative startup snapshot, `Reconcile()` requests another bounded
complete snapshot, and `Stop()` verifies lifecycle cleanup.

`workspace-readonly-host-test` is deterministic and non-mutating. It uses
synthetic HWND identities and injected discovery/hook functions, performs no
COM or native window calls, and installs no move, observe, or recovery
callback. It checks initial population, idle polling, event-triggered and
forced complete rescans, subsequent Carrier-window discovery, preservation of
the last valid model after discovery failure, owner-thread hook shutdown, and
startup blocking when a durable transaction is pending.
Because recovery requires mutation-capable callbacks, this host deliberately
leaves a pending journal blocked and unchanged.

This is a composition/test host, not a production process or live-shell host.
Its `Poll()` boundary pumps the owner thread's out-of-context WinEvent queue
and requests only complete authoritative rescans when a lifecycle epoch
changes, the caller-supplied interval expires, or the caller forces a rescan.
It does not choose the system capability provider, persistent monitor/workspace
configuration, production journal location, or the application's outer
message-loop policy. Focus/Z-order policy, hotkeys, and UI remain separate.
Its test is not compatibility evidence and does not support a
`GO-PRODUCTIZATION` claim.

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
operations; foreground activation is best-effort because the foreground lock
can deny `SetForegroundWindow` even for an owned window, and the executor
records such denials (`best_effort_failed`) instead of failing the restore,
while placement and Z-order remain strict. `window_lifecycle.{h,cpp}` adds a bounded read-only
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
`Ambiguous`. Per-window observation limits are contained: a protected process
whose identity cannot be opened, or a HWND that vanishes mid-scan, is retained
as an `Ambiguous` record and the complete scan continues. Only enumeration
failure, duplicate HWNDs/identities, identity instability during an
observation, and callback exceptions remain scan-fatal. The layer deliberately
does not assign logical workspaces, mutate native state, or branch on
executable names. Run:

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

`workspace-live-manager-test --confirm-mutate` is the first bounded mutable
composition of these boundaries. It creates exactly three disposable
vdprobe-owned top-level windows (A1, A2, and B1), promotes only their exact
HWND/PID/process-generation identities to `Managed`, and performs one
monitor-local A1 -> A2 -> A1 round-trip through the assignment, lifecycle,
coordinator, and journal layers. Each native move revalidates the window
generation, monitor, `GetViewForHwnd`, and `CanViewMoveDesktops`; Monitor B
and the session-global Carrier are verified after each switch. The command
never calls `SwitchDesktop`, creates/removes a native desktop, or promotes
an existing user window. Probe windows are restored before lifecycle shutdown
and journal cleanup, and pending or malformed stable journals are preserved.

This is a bounded integration probe, not a long-running user-facing manager.
It does not provide automatic application assignment, persistent workspace
configuration, production journal-path selection, focus/Z-order policy,
hotkeys, or UI. The command requires `--confirm-mutate`; without it, mutation
is refused. If ImmersiveShell access is denied before probe creation, it emits
`RESULT=ENVIRONMENT-BLOCKED`, `mutation_started=no`, and exit status `77`.
That status is an environment limitation, not live semantics evidence.

The interactive run on the live shell completed the full gate with
`RESULT=PASS`:

```text
RESULT=PASS
mutation_started=yes

spawned vdprobe probes A1/A2 on Monitor A, B1 on Monitor B
setup:  A2 -> Parking                      verified
initial authoritative reconcile           PASS
A1 -> A2: A1 -> Parking, A2 -> Carrier     PASS
A2 -> A1: A2 -> Parking, A1 -> Carrier     PASS
restore: A2 -> Carrier                     verified
probe window close                         PASS
monitor B unchanged                        PASS
stable journal pending                     no
stable journal cleanup                     PASS
probe cleanup/restoration                  PASS
```

Every native move revalidated the HWND generation, monitor, `GetViewForHwnd`,
and `CanViewMoveDesktops`; Monitor B and the session-global Carrier stayed
unchanged throughout, no `CurrentVirtualDesktopChanged` was reported, and the
stable journal contained no pending transaction at exit. This closes the live
probe-owned manager gate: the composed discovery, assignment, lifecycle,
coordinator, and journal boundaries execute a complete monitor-local
A1 -> A2 -> A1 round-trip on the live shell.

`workspace-live-focus-test` is the deterministic focus/Z-order boundary. It
composes injected discovery, assignment, and the engine, then derives each
workspace's `last_foreground` and top-to-bottom Z-order from the complete
snapshot presentation state. After an A1 -> A2 -> A1 switch, it verifies that
`PreparePresentationRestore` emits placements first, then relative Z-order
bottom-to-top, with the incoming workspace's foreground activation last, and
that `ExecutePresentationRestore` applies those operations in that order with
an identity check before every native call. Fail-closed cases are covered: an
identity/capability mismatch stops before the failing operation, an altered
plan is rejected before mutation, and an incomplete Z-order snapshot cannot
produce a restore plan. Monitor B control windows never appear in the plan.
The command performs no COM, native window, desktop, or foreground mutation.

`workspace-live-focus-restore-test --confirm-mutate` is the live focus gate.
It spawns four vdprobe-owned windows (A1 top/bottom, A2, and B1), derives
per-workspace Z-order and a confirmation-gated foreground target, and runs one
monitor-local A1 -> A2 -> A1 switch through the coordinator. After each switch
it executes `PreparePresentationRestore` and `ExecutePresentationRestore`
with an identity-checked native adapter that applies `SetWindowPlacement`,
non-activating `SetWindowPos(HWND_TOP)`, and best-effort
`SetForegroundWindow` to the real probe HWNDs. Placement is re-verified with
`GetWindowRect` and the relative Z-order of the two-window A1 workspace is
re-verified with `GetWindow` ordering; foreground denials are recorded as
best-effort failures. Monitor B and the session-global Carrier stay unchanged,
the stable journal has no pending transaction, and all probe windows are
restored and closed before cleanup. The live run reports `RESULT=PASS`.

`workspace-manager-test` and `workspace-manager --confirm-mutate` form the
minimal hotkey/UI boundary. The deterministic test parses the line-based
manager config (`hotkey <mods>+<key> <monitor> <workspace>`, `journal`,
`tray`), rejects duplicate hotkeys, unknown modifiers/keys, zero
monitor/workspace values, and unknown directives, and resolves WM_HOTKEY
modifier/key pairs to monitor/workspace targets. The live self-test registers
real `RegisterHotKey` bindings (Ctrl+Alt+F9 -> monitor A workspace A2,
Ctrl+Alt+F10 -> monitor A workspace A1) on a message-only window, adds a tray
icon with `Shell_NotifyIcon`, and posts WM_HOTKEY messages that the window
procedure resolves through the same binding table and hands to
`WorkspaceCoordinator::Switch`; both probe-owned switches commit, Monitor B
and the session-global Carrier stay unchanged, and hotkeys, tray icon,
lifecycle source, and journal are all cleaned up. The live run reports
`RESULT=PASS`. This is a bounded self-test, not yet a long-running user
manager: production assignment policy, config-file discovery, focus policy,
and process hosting remain separate work.

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
journal recovery to `WorkspaceEngine`. Pre-commit lifecycle validation
tolerates window-object events for the windows the switch itself moves (the
native moves can emit SHOW-style events for those same windows); a lifecycle
event for any other window invalidates the attempt, which is rolled back
without mutation and retried with a fresh authoritative snapshot (bounded,
default three attempts); persistent noise exhausts the bound and fails
closed, overflow always fails closed, and any rollback that cannot be
verified stops immediately. It is intentionally not yet a long-running
manager: the caller still supplies complete discovery and native
move/observe callbacks, pumps the WinEvent owner thread, and chooses the
production journal/bootstrap policy.

`workspace_startup.{h,cpp}` adds the bounded reusable `RecoverAtStartup`
ordering boundary. Its caller supplies the normal engine/coordinator,
authoritative discovery callback, lifecycle source, stable journal path, and a
factory for the fresh recovery runtime. It starts and verifies the WinEvent
source and reads the journal before enabling operations.

The journal is a two-state WAL. `BEGIN` + `MOVE` records describe the
prepared switch; the terminal `COMMIT` record now carries the logical switch
itself (`COMMIT <monitor> <from> <to>`), so a crash between the durable
COMMIT flush and the in-memory commit leaves a replayable logical state
instead of an unreadable vacuum window (`ReadJournalState` returns
`pending` or `committed`; `ReadPending` keeps its old contract). At startup:

- a pending transaction bootstraps a fresh model
  (`BootstrapPendingRecoveryModel`), rolls it back, then requires full
  reconciliation;
- a committed transaction replays the logical ownership into the already
  configured normal engine (`ReplayCommitted`: monitor active = to,
  Carrier-moved windows in `to`, Parking-moved windows in `from`) with no
  native moves, then reconciles.

The recovery snapshot is deliberately assignment-neutral: the production
host feeds `RecoverAtStartup` a raw discovery mapping (workspace left
unassigned) instead of the assignment adapter output, because the adapter
drops untracked Parking-native windows and would make a partially-moved
transaction unprovable. Logical ownership is derived from the journal plan,
never from a snapshot guess. Journal parse errors, unproven identities,
lifecycle instability, and every recovery failure block operations and retain
the journal.

The production host (`workspace-manager --run --confirm-mutate`) wires
`RecoverAtStartup` with a recovery-runtime factory that rebuilds the
discovery/assignment stack against the fresh engine, so a recovered runtime
keeps managing the full configured monitor topology. Startup reports
`startup recovery: pending transaction rolled back and reconciled` or
`startup recovery: committed switch replayed and reconciled`. The
deterministic `workspace-startup-test` covers clean, pending, committed
replay, malformed, missing-identity, unstable, and unavailable-lifecycle
paths with in-memory move/observation callbacks; a live crash-after-COMMIT
injection (journal copied mid-switch from the live manager gate, then
restarted through the production host) verified the committed replay and
reconciliation on the interactive host.

The live command was also attempted on the current host. `GetImmersiveShell`
returned `E_ACCESSDENIED` before any probe window was spawned, so the command
reported `ENVIRONMENT-BLOCKED`, `mutation_started = no`, and exit status `77`.
That is an environment limitation, not a logical-workspace semantics result.

These layers should call the capability-driven engine and preserve its
fail-closed behavior. They should not add app-name branches unless a concrete
runtime anomaly demonstrates that a capability is insufficient.
