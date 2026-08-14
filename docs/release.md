# Release notes and operations

## Version

`vdprobe --version` reports the manager version. This release is 0.1.0.

## Supported Windows builds

The private Shell interfaces are validated against the registered vtable
layouts in src/vdlayout.cpp. The interface layouts were verified on Windows
11 23H2 (22631.3085+), 24H2 (26100), and 25H2 (26200) families. On an unknown
or unsupported layout the manager reports the host capability state and
refuses unsafe native mutation instead of making speculative vtable calls.

## Install

The manager is a per-user interactive process and does not require
administrator privileges:

```powershell
vdprobe.exe workspace-manager --install-startup [--config PATH]
```

This adds the HKCU Run value that launches `workspace-manager --run` at
sign-in. The optional config path is embedded in the startup command; the
default config is `%APPDATA%\vdprobe\workspace-manager.conf`.

## Configure

Create the schema-v1 config file (see docs/configuration.md):

```text
version 1
monitor 1 workspaces A1,A2 active A1
monitor 2 workspaces B1 active B1
hotkey Ctrl+Alt+F9 1 A2
hotkey Ctrl+Alt+F10 1 A1
assignment monitor-migration reassign
log-level info
quarantine on
tray on
```

Config monitor N maps to the N-th enumerated monitor. The manager validates
the file at startup and on every reload; invalid files are rejected and the
previous configuration stays in effect.

## Operate

- `workspace-manager --run` runs the host (tray icon, hotkeys, periodic
  reconciliation). Use `--seconds N` only for bounded automated runs.
- Tray menu: switch monitor A workspaces, Status, Diagnostics, Reload
  configuration, Exit.
- `workspace-manager --stop` / `--reload` control a running instance from
  a console.
- `workspace-manager --diagnostics [--config PATH]` prints a standalone
  bundle: version, Windows build, monitor topology, config status, journal
  status.

## Recovery

Interrupted switches are journaled and recovered at startup (see
docs/productization-engine.md). The host converges back to the Carrier/Parking
invariant after display changes, sleep/resume, and Shell loss (see
docs/resilience.md). Anomalous windows are quarantined and excluded from
further mutation (see docs/quarantine.md).

## Uninstall

```powershell
vdprobe.exe workspace-manager --remove-startup
```

Removing the HKCU Run entry stops auto-start; the process can be stopped with
`--stop` or the tray Exit item. No native desktops, user windows, or
profiles are modified by the manager or its removal.

## Upgrade / migration

Configuration is schema-versioned (currently 1). Files with an unsupported
schema version are refused with a clear message rather than reinterpreted;
migrate the file explicitly. Durable state is limited to the config file and
the transaction journal; individual HWND state is never persisted because
HWNDs are transient.

## Known limitations

- Foreground restoration is best-effort: the Windows foreground lock can
  reject `SetForegroundWindow` even for an owned window; denials are recorded
  (`best_effort_failed`) and placement/Z-order still restore.
- Monitor identity across reboots is order/device-based; extreme topology
  changes suspend affected workspaces until the monitor returns.
- Owned/internal HWNDs of shared-process applications may be unobservable and
  are kept observation-only.
- Representative compatibility (Win32, Explorer, Edge, Windows Terminal) is
  evidence, not a universal guarantee; capability detection and quarantine
  cover other applications.
- The manager is not a Windows service and must run in the interactive user
  session.

## Validation evidence

Run the deterministic suites and the live gates listed in the README command
table from a fresh build; the final tree keeps `develop` buildable and the
working tree clean.
