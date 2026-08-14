# Production window assignment policy

This document defines how the production workspace manager answers the
question "which logical workspace does a newly discovered window belong to?".
The policy is deterministic, capability-driven, and fails closed whenever
attribution cannot be proven.

## New independently manageable top-level windows

```text
new independently manageable top-level window
    -> monitor containing the window
    -> that monitor's active logical workspace
```

A window observed on the Carrier desktop with a valid
`GetViewForHwnd`/`CanViewMoveDesktops` capability set joins the active
workspace of the monitor that contains it. A window observed on the shared
Parking desktop is retained as an observation but is not assigned: its
workspace cannot be proven, so it stays outside managed scope.

## Owned and transient windows

Owned, modal, and tool windows are never promoted to independent workspace
entities. `WorkspaceAssignmentAdapter::DeriveInheritedOwnership()` resolves
the root owner chain and, when the root owner is a managed window, records the
inherited `WorkspaceId` as observation-only registry metadata. The adapter
never mutates an owned window; when ownership state is unreliable the window
is observation-only.

## Recreated windows and HWND reuse

A window whose HWND is reused with a different PID or process creation time is
a new generation and never inherits the previous generation's workspace. The
recreated window is classified and assigned with the normal new-window
policy.

## Cross-monitor movement

When a tracked window is observed on a different configured monitor, the
default policy (`MonitorMigrationPolicy::ReassignToDestinationActive`)
reassigns ownership:

```text
ownership.monitor    = destination monitor
ownership.workspace  = destination monitor's currently active workspace
```

Reassignment is applied only when the observed native role is Carrier on the
destination (a visible window); a window observed parked on the destination,
or on an unconfigured monitor, fails the conversion closed. The
`FailClosed` policy rejects any monitor change instead of guessing.

## Unsupported and ambiguous windows

Protected, elevated/inaccessible, view-less, ambiguous-identity, and
capability-missing windows remain outside managed scope. They are retained in
the complete snapshot for diagnostics but never participate in normal
Carrier/Parking reconciliation or mutation.

## Deterministic coverage

`workspace-assignment-test` verifies: new Carrier windows join the active
workspace, new Parking windows stay unassigned, tracked parked workspaces are
preserved, native-role mismatches fail closed, unsupported/ambiguous and
unobservable-identity windows are omitted, recreated generations do not
inherit, assignment follows switched active workspaces, monitor migration
reassigns to the destination active workspace, the fail-closed migration
policy rejects monitor changes, and owned windows inherit their root owner's
workspace only when that owner is managed.
