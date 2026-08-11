# Phase 4 validation results

## Phase 4A — controlled Win32 process semantics gate

The first Phase 4 probe is intentionally limited to a controlled ordinary
Win32 child process created by `vdprobe` itself. The child exposes:

- two independent top-level windows;
- one owned popup window;
- stable PID and process-creation-time identity for every HWND.

`vdprobe real-app-semantics-test --confirm-mutate` is designed to move one
top-level `IApplicationView` from the current Carrier desktop to the existing
inactive Parking desktop. It records the target, sibling, and owned-popup
desktop assignments, `ViewVirtualDesktopChanged` callbacks, global current
desktop state, HWND/PID identity, owner, rectangle, and monitor. It never
creates or removes a native desktop and never touches existing user windows.

The child process has its own `--confirm-mutate` requirement as a defense in
depth. The parent passes that gate explicitly when it launches the child.
Notification callbacks are also checked to ensure every reported view HWND is
within the probe-owned child window set. An unrelated view callback during the
move is reported as `INCONCLUSIVE-CONTAMINATED`, not as a Carrier/Parking
semantics failure. The owned popup is observation-only: it is not required to
expose an independent `IApplicationView`; owner/group restoration is verified
from its HWND-level desktop state.

## Headless host result

Build validation succeeded with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

The no-consent command was correctly rejected:

```text
vdprobe real-app-semantics-test
  refusing to launch or move a real-app child without --confirm-mutate
```

The consented command stopped before child creation because this execution
environment denied the ImmersiveShell service lookup:

```text
IServiceProvider FAILED 0x80070005 (E_ACCESSDENIED)
```

The command now emits a machine-readable outcome and uses exit status `77` for
this host-level skip:

```text
result = ENVIRONMENT-BLOCKED
reason = ImmersiveShell E_ACCESSDENIED
mutation_started = no
```

The same access denial is observable in the existing read-only private-shell
commands on this host. Therefore this run performed no window mutation:

- no child process or test window was launched;
- no `IApplicationView` was moved;
- no native desktop state changed;
- no existing user window was touched.

This is recorded as **ENVIRONMENT-BLOCKED / SKIP**, not `GO-REAL-APPS`,
`GO-WITH-LIMITATIONS`, or `NO-GO`. The test must be rerun in an interactive
session with ImmersiveShell access before making a Phase 4A semantics claim.

## Interactive Phase 4A rerun

The same binary was then run from an elevated interactive Windows session:

```powershell
.\build\vdprobe.exe real-app-semantics-test --confirm-mutate
```

The controlled Win32 gate completed with exit status `0`:

```text
Register hr                 0x00000000 (S_OK)
MoveViewToDesktop            Carrier -> Parking
  HRESULT                    0x00000000 (S_OK)
  current desktop            Carrier
  window desktop              Parking
  IsWindowOnCurrentVirtualDesktop false
  ViewVirtualDesktopChanged observed
  CurrentVirtualDesktopChanged count 0
target moved to Parking       yes
sibling top-level moved       no
owned popup moved with owner  no (independent)
callback HWND scope           probe-owned only
Unregister hr                0x00000000 (S_OK)
probe-owned child closed      yes
result                        GROUPING-OBSERVED
GO/NO-GO                      GO-WITH-LIMITATIONS
```

This is a **Phase 4A controlled Win32 result**, not a claim about the
Phase 4B Edge/Chrome, Explorer, Terminal, Electron, or WinUI/UWP matrix.
The result proves that a top-level ordinary Win32 view can move from Carrier
to shared Parking while the sibling top-level window and session-global
current desktop remain unchanged. The owned popup stayed independent in this
run; grouped propagation remains a valid behavior to characterize for other
application families.

On this host the documented window-desktop API may report `GUID_NULL` for an
owned popup even while `IsWindowOnCurrentVirtualDesktop` is true. The probe
treats that as an observation-only popup state, uses the current-desktop
boolean for movement/recovery correlation, and continues to require a real
Carrier GUID for target and sibling top-level views.

The broader Phase 4B matrix (Edge/Chrome, Explorer, Terminal, Electron,
WinUI/UWP), lifecycle tracking, focus/Z-order behavior, and crash recovery are
separate follow-up gates.
