# Phase 4B-1 — Explorer semantics

## Scope

This milestone is a narrow application-family probe. It does not change the
Carrier/Parking architecture and does not attempt to build a general
application tracker.

`vdprobe explorer-semantics-test --confirm-mutate`:

- requires an existing current Carrier and at least one existing inactive
  Parking desktop;
- launches two Explorer windows using `explorer.exe`;
- attributes each launch against a pre-launch snapshot using HWND, PID, and
  process-creation-time identity;
- accepts only processes whose complete normalized image path is the system
  `%WINDIR%\explorer.exe`, not an arbitrary executable with the same basename;
- moves only one newly observed top-level Explorer view from Carrier to
  Parking;
- observes the sibling top-level window, owned descendants, and notification
  callbacks;
- verifies that the session-global current desktop remains Carrier;
- restores changed probe windows to Carrier before unregistering notifications;
- sends `WM_CLOSE` only to HWNDs attributable to this probe.

The shared `explorer.exe` process is never terminated. The command does not
create or remove native desktops, call `SwitchDesktop`, manipulate existing
user-selected Explorer windows, or add lifecycle/focus/hotkey behavior.

## Result categories

The command emits machine-readable outcomes:

| Result | Meaning |
|---|---|
| `EXPLORER-SEMANTICS-OBSERVED` | The controlled Explorer move/restore contract passed; this is a `GO-WITH-LIMITATIONS` observation, not a complete real-app matrix result. |
| `INCONCLUSIVE-ENVIRONMENT` | Explorer launch attribution or window discovery was not deterministic in the host session; rerun rather than infer a semantics failure. |
| `INCONCLUSIVE-PRECONDITION` | A required top-level target or sibling snapshot/view precondition was unavailable before mutation; no Explorer view was moved and the probe returns exit status `77`. |
| `INCONCLUSIVE-CONTAMINATED` | An unrelated `ViewVirtualDesktopChanged` callback entered the observation window; rerun in a quiet session. |
| `ENVIRONMENT-BLOCKED` | ImmersiveShell access was denied before any Explorer window was launched (`mutation_started = no`, exit status `77`). |
| `SEMANTICS-FAILED` | A target move, global-current-desktop invariant, callback contract, restoration, or cleanup assertion failed. |

If a launch produces multiple plausible new primary windows, or otherwise
cannot be uniquely attributed, the command reports
`cleanup_scope = incomplete` and `unattributed_new_windows = N`. Those HWNDs
are intentionally retained because ownership cannot be proven; the probe never
closes ambiguous windows merely to make cleanup appear complete. A future
Phase 4B-1.1 can strengthen attribution with folder identity via
`IShellWindows`/Explorer location data.

Owned Explorer windows are observation-only when they do not expose an
independent `IApplicationView`; their HWND desktop state is still recorded to
characterize owner/group behavior. `GUID_NULL` is accepted only on this
owned-window observation/recovery path when `IsWindowOnCurrentVirtualDesktop`
confirms the Carrier-side state. Top-level target and sibling windows still
require a real Carrier GUID.

Owned/internal Explorer HWND snapshot failures are non-blocking observation
limits throughout the baseline, post-move, restore, and final-verification
paths. The probe reports owned-window totals, observable counts, moved counts,
and a tri-state semantic summary (`unavailable`, `partially-observed`,
`grouped`, or `independent`) so unavailable state is never reported as
independent behavior. Target and sibling top-level snapshots remain strict:
without them the command reports `INCONCLUSIVE-PRECONDITION` before mutation.

## Validation in this checkout

The source and dispatch path build successfully:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

The no-consent safety gate rejects mutation:

```text
vdprobe explorer-semantics-test
  gate REFUSED: method mutates shell state
```

The available non-interactive run is host-blocked before child-window
creation:

```text
IServiceProvider FAILED 0x80070005 (E_ACCESSDENIED)
result = ENVIRONMENT-BLOCKED
reason = ImmersiveShell E_ACCESSDENIED
mutation_started = no
exit = 77
```

Therefore this checkout contains the Phase 4B-1 implementation and safety
validation, but does not claim an interactive Explorer semantics PASS yet.
The next evidence-bearing run must be performed in a session where the
ImmersiveShell service is accessible.
