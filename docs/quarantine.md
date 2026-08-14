# Compatibility quarantine

A window or application group that violates expected Carrier/Parking
semantics is quarantined so it can never repeatedly destabilize workspace
state.

## Triggers

`WorkspaceEngine::ExecuteSwitch` auto-quarantines a window when, with
auto-quarantine enabled (the default):

- a native move fails or post-move verification fails (the transaction
  rolls back), and the failing operation can be attributed to exactly that
  window;
- post-move revalidation observes a per-window native mismatch, again
  attributed to exactly the mismatched window.

Each quarantine records the `WindowIdentity` and a diagnostic reason in the
engine's quarantine log.

## Non-triggers

Quarantine is deliberately narrow. The following never quarantine any
window, because they are environmental rather than window semantics:

- pre-commit invalidation (transient external noise observed between the
  last move and the commit);
- journal begin/commit I/O failure;
- rollback failure (the transaction is left pending for journal recovery,
  not blamed on a specific window);
- an unrelated window's lifecycle event inside the transaction window (the
  coordinator retries those with a fresh authoritative snapshot).

The `TransactionResult` carries `culprit_identified`/`culprit` so callers
can distinguish a proven semantic offender from environmental noise.

## Semantics

Quarantined windows are assigned `WindowDisposition::Quarantined` and:

- are excluded from all future switch plans (a switch never moves them);
- are excluded from presentation restore plans and the Carrier/Parking
  invariant;
- are never re-promoted to `Managed` by authoritative discovery snapshots
  (quarantine is sticky) and are not closed by snapshots either;
- are skipped by the assignment adapter, so they cannot re-enter managed
  scope through assignment.

Because presentation membership is defined as present + `Managed` +
manageable + owner-state-observable, one quarantined window cannot make
the workspace's Z-order or restore plan unsatisfiable: the remaining
eligible members keep their placement/Z-order/foreground restore, and a
quarantined foreground slot is dropped rather than failing the whole
workspace.

Anomalies therefore roll back once and then leave the affected window
unmanaged, preserving the rest of the workspace.

## User override

The config directive `quarantine on|off` (schema v1) enables or disables
automatic quarantine. With `quarantine off`, anomalies still roll back and
are recorded, but windows are not automatically quarantined. The directive is
validated and round-trips through save/load.

## Diagnostics

The long-running host reports the current quarantine log size
(`quarantine entries`) on shutdown; the tray Diagnostics command reports
workspace/reconcile/switch counters.

## Deterministic coverage

`workspace-engine-test` verifies: quarantined windows are excluded from
 switch plans, a rolled-back switch auto-quarantines only the culprit,
 post-state mismatch quarantines only the mismatched window, pre-commit
 invalidation quarantines nothing, a quarantined window keeps the
 presentation model satisfiable, auto-quarantine can be disabled, and
 quarantine persists across reconciliation snapshots.
 `workspace-assignment-test` verifies quarantined windows are omitted from
 assignment, and `workspace-manager-test` verifies the `quarantine` config
 directive.
