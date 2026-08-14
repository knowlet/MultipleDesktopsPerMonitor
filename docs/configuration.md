# Workspace manager configuration

The manager configuration is a human-readable, schema-versioned text file.
The default per-user path is
`%APPDATA%\vdprobe\workspace-manager.conf`; an explicit file can be passed
with `--config PATH` to `workspace-manager`.

## Schema version 1

Every file starts with the schema version:

```text
version 1
```

Unsupported or missing versions are rejected with the exact field and
expected form; no partial configuration is applied.

## Directives

```text
# comment
version 1
monitor 1 workspaces A1,A2,A3 active A1
monitor 2 workspaces B1,B2 active B1
hotkey Ctrl+Alt+F9 1 A2
hotkey Ctrl+Alt+F10 1 A1
hotkey Ctrl+Alt+Shift+F9 2 B2
assignment monitor-migration reassign
log-level info
journal C:/Users/me/AppData/Roaming/vdprobe/workspace-manager.journal
tray on
```

- `monitor <id> workspaces <name1,name2,...> active <name>` defines one
  configured monitor. The i-th workspace name maps to `WorkspaceId i` within
  that monitor. Workspace names must be non-empty and unique per monitor, and
  the active workspace must be one of the defined names.
- `hotkey <mods>+<key> <monitor> <workspace>` binds a global hotkey to a
  workspace switch. Modifiers are `Ctrl`, `Alt`, `Shift`, `Win` (one or
  more, separated by `+`); keys are `Q`..`Z`, `0`..`9`, `F1`..`F24`,
  `Left`, `Right`, `Up`, `Down`, `Home`, `End`, `Space`, `Tab`,
  `Enter`, `Escape`. Duplicate hotkeys, undefined monitors, and undefined
  workspace names are rejected.
- `assignment monitor-migration <reassign|fail-closed>` selects the
  cross-monitor assignment policy (see docs/assignment-policy.md).
- `log-level <debug|info|warn|error>` selects the diagnostic verbosity.
- `journal <path>` selects the durable transaction journal path.
- `tray <on|off>` controls the tray icon.

## Monitor mapping and stable ids

At runtime the i-th configured monitor maps to the i-th enumerated real
monitor (by `EnumDisplayMonitors` order). Logical `WorkspaceId` values are
derived per monitor with a disjoint global range (monitor i starts at
`i*1000+1`), so ids stay stable across restarts and never collide between
monitors. Monitor identity across reboots/re-enumeration is order-based;
topology changes are handled by the runtime reconciliation layers.

## Persistence and restart semantics

`SaveManagerConfig` and `LoadManagerConfig` round-trip the full schema-v1
text canonically. A manager restart with the same file reproduces the same
monitors, workspace definitions, hotkeys, assignment policy, and journal path;
the last-active workspace per monitor is persisted as `active <name>`.
Invalid files fail safe: the previous configuration is never partially
applied.

## Runtime reload

`workspace-manager --reload` (or the tray Reload item) reloads the config
file transactionally: parse, validate, and map to the current monitors first;
only then are hotkeys re-registered and the migration/quarantine policy
applied. An invalid file keeps the previous configuration in full effect and
reports the exact field/value problem. Monitor/workspace topology changes
require a restart.

## Validation summary

`workspace-manager-test` covers: valid v1 parsing, hotkey dispatch
resolution, unbound hotkeys, duplicate hotkeys, missing/unsupported schema
versions, duplicate monitors, undefined active workspaces, undefined hotkey
workspaces, invalid migration policies, invalid log levels, unknown
directives, config save/load round-trip, runtime topology derivation, and
extra-monitor rejection.

The live `workspace-manager --config <file> --confirm-mutate` self-test loads
a persisted config, maps it to the real monitors, registers the configured
hotkeys, and completes one probe-owned A1 -> A2 -> A1 switch with
`RESULT=PASS`.
