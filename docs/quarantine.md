# Compatibility quarantine

A window or application group that violates expected Carrier/Parking
semantics is quarantined so it can never repeatedly destabilize workspace
state.

## Triggers

`WorkspaceEngine::ExecuteSwitch` auto-quarantines the windows of a switch
when, with auto-quarantine enabled (the default):

- a native move fails or post-move verification fails (the transaction rolls
  back);
- the switch is invalidated before commit;
- journal commit fails after mutation.

Each quarantine records the `WindowIdentity` and a diagnostic reason in the
engine's quarantine log.

## Semantics

Quarantined windows are assigned `WindowDisposition::Quarantined` and:

- are excluded from all future switch plans (a switch never moves them);
- are excluded from presentation restore plans and the Carrier/Parking
  invariant;
- are never re-promoted to `Managed` by authoritative discovery snapshots
  (quarantine is sticky) and are not closed by snapshots either;
- are skipped by the assignment adapter, so they cannot re-enter managed
  scope through assignment.

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
switch plans, a rolled-back switch auto-quarantines all affected windows,
auto-quarantine can be disabled, and quarantine persists across
reconciliation snapshots. `workspace-assignment-test` verifies quarantined
windows are omitted from assignment, and `workspace-manager-test` verifies
the `quarantine` config directive.
