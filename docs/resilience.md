# Runtime resilience

The long-running host converges back to a valid Carrier/Parking state after
common environmental disruptions instead of corrupting logical ownership.

## Monitor topology changes

`MonitorTopologyMapper` (src/workspace_host_resilience.{h,cpp}) tracks the
configured monitors. Bindings prefer device identity (the monitor device
string) and fall back to enumeration order, so re-ordering by Windows does not
reassign workspaces to the wrong physical monitor.

- A configured monitor that disappears is removed from the binding list and
  its workspaces are suspended: the host skips switches for that monitor and
  records the host as degraded instead of silently losing ownership.
- A monitor that returns is re-bound by device identity; its workspaces
  recover automatically.
- A new monitor takes the lowest missing config index, so a binding set
  where only a higher index survived a suspend never collides with the
  newcomer.
- If a surviving monitor's real handle differs from the handle the engine
  was configured with, the host degrades until a restart: the engine and
  assignment registry are keyed by the startup MonitorId and cannot be
  rebound at runtime.

The host handles `WM_DISPLAYCHANGE` by re-enumerating and re-running the
mapper.

## Sleep / resume

The host handles `WM_POWERBROADCAST` with `PBT_APMRESUMESUSPEND`: it
re-enumerates the monitor topology and revalidates the Shell. If the current
desktop can no longer be read, it marks the shell lost, retries
`GetImmersiveShell`/manager acquisition, and only resumes when the
re-acquired Carrier identity matches the engine's; otherwise the host stays
degraded and stops native mutations.

## Explorer / Shell loss

Shell loss surfaces as failed reads or RPC disconnects. The host treats them
as degraded (stop mutations, retain logical state, keep retrying on the
periodic reconcile timer) and never keeps invoking stale interface pointers.
Full Explorer-restart convergence is exercised through the same
re-acquire path.

Re-acquisition rebuilds the whole `ShellRuntimeBundle` atomically:
`IServiceProvider`, `IVirtualDesktopManagerInternal` plus its layout and
`CanViewMoveDesktops` entry, `IApplicationViewCollection` plus
`GetViewForHwnd`, the documented `IVirtualDesktopManager`, and both
Carrier/Parking desktop objects. Every mutation lambda reads from the live
bundle, so no stale COM object or method entry survives a swap. A
re-acquired bundle is only adopted when it still names the same current
Carrier desktop and the same Parking desktop; a changed desktop layout
keeps the host degraded until a restart can re-adopt it. The degraded
state gates `do_switch` and reconciliation, and the 3 s reconcile timer
keeps retrying the bundle re-acquisition.

## Reconciliation after event loss

Periodic authoritative reconciliation (3 s timer) plus the coordinator's
bounded retry and quiet-boundary checks converge the registry back to the
Carrier/Parking invariant even when individual WinEvent hints are missed or
reordered. HWND reuse and process restarts remain generation-safe in the
engine/lifecycle layers.

## Automated validation

`workspace-host-resilience-test` verifies deterministically: initial order
binding, suspension when a monitor disappears, recovery when it returns, and
device-identity preservation across enumeration order changes, and lowest
missing-index assignment for a newly added monitor.

`workspace-manager --run --self-resilience --seconds N` posts
`WM_DISPLAYCHANGE` and a resume broadcast to the host's own message window
(the same message path as external delivery) and reports the handled counts;
the live run reports `RESULT=PASS` with clean shutdown.
