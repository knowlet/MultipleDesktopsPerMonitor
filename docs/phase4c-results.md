# Phase 4C — Representative compatibility gate

## Decision

Phase 4C narrows application compatibility research to representative Windows
window/application-view behavior rather than an executable-by-executable
matrix. The tested representatives are:

| Behavior type | Representative | Result |
|---|---|---|
| Classic Win32 | controlled vdprobe child | `GO-WITH-LIMITATIONS` |
| Shell-hosted/shared process | Explorer | `GO-WITH-LIMITATIONS` |
| Chromium multi-process | Microsoft Edge, isolated profile | `GO-WITH-LIMITATIONS` |
| Packaged/modern Windows app | Windows Terminal | `GO-WITH-LIMITATIONS` |

The representative compatibility gate is complete:
`GO-PRODUCTIZATION`. The post-hardening Edge rerun proved complete
temporary-profile process drain and removal, while Windows Terminal also
completed its probe-owned cleanup contract. These results do not create an
application whitelist and do not claim that every application has identical
owner, popup, or grouping behavior.
The production path is capability-driven:

```text
discover top-level HWND
    -> GetViewForHwnd
    -> CanViewMoveDesktops
    -> move to Carrier/Parking
    -> verify target and global desktop invariants
    -> rollback immediately on an anomaly
```

Unsupported or anomalous windows are left unmanaged rather than forced through
an app-specific policy.

## Contract tested

Each representative probe uses the existing current desktop as Carrier and an
existing inactive desktop as shared Parking. It performs one target-window
round trip:

```text
Carrier -> Parking -> Carrier
```

The evidence-bearing contract is:

- `MoveViewToDesktop` returns `S_OK`;
- the target's desktop assignment becomes Parking and
  `IsWindowOnCurrentVirtualDesktop` becomes false;
- `ViewVirtualDesktopChanged` is observed for the target;
- the sibling top-level window remains on Carrier with unchanged identity,
  rectangle, and monitor;
- the session-global current desktop remains Carrier;
- `CurrentVirtualDesktopChanged` count remains zero;
- restoration succeeds before notification unregister and cleanup.

Callback latency is recorded as an observation only. It is not a product
latency promise for workspace switching.

## Edge evidence

The command is:

```powershell
.\build\vdprobe.exe chromium-semantics-test --browser edge --confirm-mutate
```

The probe creates a unique temporary `--user-data-dir`, launches two
same-profile top-level Edge windows, and attributes them using pre/post HWND
observation, the canonical Edge executable path, and the profile-bearing
process command line. It never uses an existing profile, closes an
unattributed browser HWND, or terminates an Edge process.

The post-hardening interactive rerun on August 14, 2026 observed:

```text
target Carrier -> Parking     S_OK
target on current             false
ViewVirtualDesktopChanged     observed (36.855 ms)
sibling top-level moved       no
CurrentVirtualDesktopChanged  0
restore                       PASS
Unregister                    S_OK
probe-owned roots cleanup     passed
temporary profile process drain passed
temporary profile cleanup     passed
```

Nine internal/popup HWNDs were not sufficiently observable and remained
observation-only. The parked target reported `IsWindowVisible = true` while
DWM reported `cloaked = 2`; product visibility decisions must therefore use
desktop assignment and cloaking, not `IsWindowVisible` alone.

The post-hardening run retained launch-process handles, combined the scoped
launch tree with a pre-launch Edge baseline, waited for attributed profile
windows to quiesce, and then removed the temporary profile. Only unchanged
baseline identities are ignored; new, reused, or opaque Edge identities remain
fail-closed. No `taskkill`, `TerminateProcess`, or existing-profile mutation is
allowed. The Edge result is therefore `GO-WITH-LIMITATIONS` with cleanup
complete.

## Windows Terminal evidence

The command is:

```powershell
.\build\vdprobe.exe terminal-semantics-test --confirm-mutate
```

The interactive run on August 14, 2026 observed:

```text
Carrier -> Parking                  S_OK
target desktop                      Parking
target on_current                   false
ViewVirtualDesktopChanged           observed (34.606 ms)
sibling top-level moved             no
CurrentVirtualDesktopChanged        0
target restore                      PASS
Unregister                          S_OK
probe-owned Terminal cleanup        passed
```

Two probe-attributed top-level Terminal windows were characterized. Auxiliary
or owned HWNDs were observation-only; two were observable and none moved with
the target. The result was:

```text
result   = TERMINAL-SEMANTICS-OBSERVED
GO/NO-GO = GO-WITH-LIMITATIONS
```

## Scope boundary after Phase 4C

The following are deliberately deferred to productization and beta validation:

- automatic window tracking and lifecycle/recreation handling;
- focus and Z-order restoration;
- transaction journaling and crash recovery;
- GUI, hotkeys, persistence, and user-facing workspace management;
- Chrome, Electron, and additional packaged applications as separate probes;
- stress, benchmark, and latency characterization.

Chrome, Electron, and other applications are not silently assumed identical;
they are handled by runtime capability detection and rollback. A future
real-world anomaly can add a narrowly scoped compatibility policy, but Phase 4C
does not pre-build an executable whitelist.
