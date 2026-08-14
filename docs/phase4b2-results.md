# Phase 4B-2A — Isolated Chromium / Edge semantics

## Scope

This milestone is a narrow application-family probe. It keeps the validated
Carrier/Parking architecture unchanged and asks one question:

> Can two top-level windows in the same isolated Chromium instance be treated
> with window granularity, moving only one view from Carrier to Parking while
> the sibling and the session-global current desktop remain unchanged?

The command is:

```powershell
.\build\vdprobe.exe chromium-semantics-test --browser edge --confirm-mutate
```

The probe:

- resolves the canonical installed Microsoft Edge executable and uses that
  absolute path for launch and attribution;
- creates a unique temporary profile directory owned by the probe;
- launches two `--new-window about:blank` requests against the same profile
  with Chromium background mode disabled;
- attributes each new normal browser root by pre/post HWND observation, full
  executable path, and a command line containing the unique profile path;
- treats the Chromium class name (`Chrome_WidgetWin_*`) as evidence, not as an
  ownership boundary;
- moves one attributable top-level view Carrier -> Parking -> Carrier;
- verifies the sibling HWND, PID, process generation, RECT, and monitor;
- observes `ViewVirtualDesktopChanged` and requires zero
  `CurrentVirtualDesktopChanged` events;
- closes only probe-attributed browser roots with `WM_CLOSE`;
- closes only probe-attributed browser roots, then requires a fail-closed
  process-drain check before removing the temporary profile.  The drain
  combines retained launch-tree handles with a pre-launch Edge baseline:
  unchanged PID + valid process-creation identities are ignored, while any
  new/reused or opaque Edge identity keeps the profile retained.

The probe never uses an existing browser profile, never closes an
unattributed browser HWND, never calls `SwitchDesktop`, and never terminates an
existing browser process. Internal, popup, and utility windows are
observation-only.

## Result categories

| Result | Meaning |
|---|---|
| `CHROMIUM-SEMANTICS-OBSERVED` | Target move/restore, sibling isolation, callback, and global-current-desktop contract passed. This is a `GO-WITH-LIMITATIONS` observation, not a complete browser matrix result. |
| `INCONCLUSIVE-ATTRIBUTION` | A launch did not yield exactly one attributable top-level window, or the final same-profile set was ambiguous. Unattributed HWNDs are intentionally retained. |
| `INCONCLUSIVE-PRECONDITION` | A required target/sibling snapshot or target view precondition was unavailable before mutation. |
| `INCONCLUSIVE-CONTAMINATED` | An unrelated `ViewVirtualDesktopChanged` callback entered the observation window. |
| `ENVIRONMENT-BLOCKED` | ImmersiveShell access, canonical Edge discovery, or temporary profile creation was unavailable before the semantics mutation. |
| `INCONCLUSIVE-CLEANUP` | The semantics observation completed, but safe cleanup could not prove the temporary profile was fully released/removed. |
| `SEMANTICS-FAILED` | A mutation occurred and violated the target, sibling, callback, global-current-desktop, restoration, or hard cleanup contract. |

Exit status `77` means inconclusive/environment-blocked and is not a
semantics PASS or FAIL. A cleanup state that is safe but incomplete must not be
reported as a clean semantics pass.

## Validation in this checkout

The source and dispatch path build successfully:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

The mutation gate rejects launch without explicit consent:

```text
vdprobe chromium-semantics-test
  gate REFUSED: method mutates shell state
```

The first supported browser is Edge; unsupported browser selection is
machine-readable and does not launch a profile:

```text
vdprobe chromium-semantics-test --browser chrome --confirm-mutate
  result = INCONCLUSIVE-ATTRIBUTION
  reason = Phase 4B-2A supports only --browser edge
  mutation_started = no
```

The available non-interactive run is host-blocked before Edge/profile
creation:

```text
.\build\vdprobe.exe chromium-semantics-test --browser edge --confirm-mutate
  IServiceProvider FAILED 0x00000005 (E_ACCESSDENIED)
  result = ENVIRONMENT-BLOCKED
  reason = ImmersiveShell E_ACCESSDENIED
  mutation_started = no
  exit = 77
```

## Interactive Edge evidence (August 14, 2026)

The post-hardening interactive rerun completed the semantics and cleanup
contract on the tested Windows 11 host. It measured a 36.855 ms callback
latency:

```text
target Carrier -> Parking     S_OK
target desktop                Parking
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

The evidence-bearing semantics result is:

```text
result                        CHROMIUM-SEMANTICS-OBSERVED
GO/NO-GO                      GO-WITH-LIMITATIONS
exit                          0
```

The target and sibling were two top-level `Chrome_WidgetWin_1` windows from
the same isolated Edge profile and shared the same Edge PID. Nine additional
internal/popup HWNDs were not sufficiently observable for desktop assignment;
they remained observation-only and did not block the top-level semantics gate.
The parked target reported `IsWindowVisible = true` while DWM reported
`cloaked = 2`, so product visibility decisions must use virtual-desktop
assignment and cloaking state rather than `IsWindowVisible` alone.

The successful cleanup used `--disable-background-mode`, retained launch-process
handles, a pre-launch Edge baseline, and a bounded profile-window quiescence
wait. The process drain completed and the unique temporary profile was removed.
Opaque or PID-reused Edge identities remain fail-closed; the probe never
terminates Edge or touches an existing profile. This completes the
representative Chromium gate as `GO-WITH-LIMITATIONS`.

The remaining limitations are unchanged: internal, popup, and utility windows
are observation-only, and the result does not claim Chrome equivalence, browser
lifecycle support, focus/Z-order recovery, or a complete browser matrix.
