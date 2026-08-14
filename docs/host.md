# Long-running host

`workspace-manager --run` is the long-running per-user interactive host. It
is not a Windows service: it operates on interactive-session windows and
Shell COM objects and must run as the logged-in user.

## Startup

The primary startup mechanism is the per-user HKCU Run value
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\VdprobeWorkspaceManager`:

```powershell
vdprobe.exe workspace-manager --install-startup [--config PATH]
vdprobe.exe workspace-manager --remove-startup
```

The installed command launches `workspace-manager --run` (optionally with the
same `--config`) at sign-in. No administrator privileges are required.

## Single instance

The host holds a per-session named mutex (`Local\vdprobe-workspace-manager`).
A second launch detects the mutex, prints that another instance is already
running, and exits cleanly without touching windows.

## Host loop

The host owns a hidden message window that:

- dispatches `WM_HOTKEY` through the configured binding table to
  `WorkspaceCoordinator::Switch`;
- runs a periodic authoritative reconciliation (`WM_TIMER`, 3 s interval);
- serves a tray icon whose menu exposes switch commands, diagnostics, and
  exit (Switch monitor A -> A2/A1, Status, Diagnostics, Reload configuration,
  Exit);
- handles `WM_QUERYENDSESSION` and `WM_CLOSE` for graceful shutdown.

## Configuration reload

`workspace-manager --reload` (or the tray Reload item) asks the host to
reload the config file transactionally: the new file is parsed and validated
and mapped to the current monitors before anything changes. An invalid file is
rejected and the previous configuration stays fully in effect with a clear
message; a valid file re-registers hotkeys and applies the migration and
quarantine policy. Monitor/workspace topology changes still require a restart.

## Status and diagnostics

The tray Status item prints the current active workspace per monitor plus
reconcile/switch/quarantine counters; Diagnostics prints the same counters
with the hotkey dispatch total. The shutdown summary includes uptime
reconciliations, hotkey dispatches, committed switches, quarantine entries,
display-change and resume events, and shell re-acquire attempts.

## Graceful shutdown

On `workspace-manager --stop`, tray Exit, session end, or (for automated
validation) the `--seconds N` bound, the host stops accepting mutations,
stops the lifecycle source, unregisters hotkeys, removes the tray icon,
destroys the message window, restores and closes its managed probe windows,
and verifies the stable journal has no pending transaction. Parked windows are
not force-unparked on shutdown; that is a deliberate policy.

## Automated validation

- `workspace-manager --run --seconds N` runs a bounded host session and
  reports `RESULT=PASS` after clean shutdown (verified live with periodic
  reconciliations counted).
- Single-instance behavior is verified live by launching a second instance
  while one runs.
- `--install-startup` and `--remove-startup` are verified live (install,
  remove, idempotent remove).

The automated host gate manages only probe-owned windows. Production
user-window management uses the same coordinator/assignment layers with the
assignment policy in docs/assignment-policy.md and is progressively covered
by the resilience and quarantine milestones.
