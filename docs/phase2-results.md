# Phase 2 validation results

Probe host: Windows 11 build `10.0.26200.8875` (25H2), with two existing
native virtual desktops.

## Phase 2A — notification callback pipeline

`vdprobe notify-watch --confirm-register --self-trigger --confirm-mutate`
completed the one-shot existing-desktop round trip:

```text
Register                                   S_OK
Switch carrier -> other                   S_OK
GetCurrentDesktop                         confirmed other GUID
CurrentVirtualDesktopChanged              observed
Switch other -> carrier                   S_OK
GetCurrentDesktop                         confirmed carrier GUID
CurrentVirtualDesktopChanged              observed
Unregister                                S_OK
```

The observed callback old/new GUIDs matched the corresponding real
`SwitchDesktop` operations.  The measured callback latencies were about
96 ms and 129 ms.  These values describe global desktop switching plus the
Shell callback and are not a Carrier/Parking latency target.

## Phase 2B — Carrier/Parking primitive

`vdprobe carrier-parking-test --confirm-mutate` completed:

```text
carrier -> parking -> carrier
```

using the existing current desktop as Carrier and the existing non-current
desktop as Parking.  No native desktop was created or removed, and
`SwitchDesktop` was not called.

The result was **GO-CARRIER**:

- `MoveViewToDesktop` succeeded in both directions.
- `GetCurrentDesktop` stayed on the original Carrier GUID throughout.
- `ViewVirtualDesktopChanged` was observed for the moved probe view.
- `CurrentVirtualDesktopChanged` count remained zero.
- The probe-owned window was restored and the process exited cleanly.

The test host GUIDs were:

```text
Carrier  {8D5C0D20-FC61-4107-B42B-DEC7CBF6A983}
Parking  {B8ED750C-D162-48CF-B578-EC74E81746C0}
```

This establishes the architecture boundary for later work: native virtual
desktops provide visible Carrier and hidden Parking storage; logical
per-monitor workspace identity must live in application state.
