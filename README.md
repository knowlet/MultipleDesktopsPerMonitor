# per-monitor-vd

A gated feasibility probe that answers two related questions: **does current
Windows 11 still contain a usable native per-monitor virtual desktop
implementation, and can its ordinary desktops serve as Carrier/Parking storage
for a logical per-monitor workspace model?**

Short answer for build 10.0.26200.8875: **no — the monitor-aware interface
revision was removed from the shipping binaries, not merely disabled.** Full
reasoning and evidence in [`docs/findings.md`](docs/findings.md).

This repository contains only the probe. It is deliberately *not* a complete
virtual desktop manager: it has no GUI, hotkeys, persistence, automatic window
tracking, or desktop lifecycle management.

## Build

Requires a C++20 compiler and CMake. A no-admin toolchain is provisioned into
`.toolchain/` (portable CMake + winlibs MinGW-w64), which `build.ps1` uses:

```powershell
.\build.ps1              # -> build\vdprobe.exe
.\build.ps1 -Clean
.\build.ps1 -Msvc        # use an installed Visual Studio toolchain instead
```

The result is statically linked, so `vdprobe.exe` can be copied to another
machine and run on its own.

## Subcommands

Phase 1 uses documented APIs only:

| Command | What it shows |
|---|---|
| `vdprobe system` | exact build via `RtlGetVersion` + UBR, and shell module versions |
| `vdprobe monitors` | `HMONITOR` enumeration with device name, bounds, work area, DPI |
| `vdprobe windows` | top-level HWNDs, HWND→HMONITOR, desktop GUID via the documented `IVirtualDesktopManager`, and a desktop-GUID × monitor cross-tab |

Phase 2 probes the private ImmersiveShell COM surface:

| Command | What it shows |
|---|---|
| `vdprobe private-status` | which private interfaces and which per-build IIDs this machine accepts (QueryService/QueryInterface only — no method is called) |
| `vdprobe desktops` | enumerates virtual desktops with GUID and name |
| `vdprobe current-desktop` | identifies the current desktop and cross-checks it against the documented API |
| `vdprobe per-monitor-status` | whether any monitor-aware desktop API still exists, including a raw scan of the shipped binaries for the removed IIDs |

Plus one documentation helper:

| Command | What it shows |
|---|---|
| `vdprobe matrix` | emits the vtable layout registry as markdown (this is how `docs/interface-matrix.md` is produced) |

Gated feasibility tests:

| Command | What it shows |
|---|---|
| `vdprobe notify-watch --confirm-register [--self-trigger --confirm-mutate]` | registers the notification sink; the optional one-shot self-trigger validates `CurrentVirtualDesktopChanged` against a real switch |
| `vdprobe carrier-parking-test --confirm-mutate` | moves one probe-owned window Carrier -> Parking -> Carrier without `SwitchDesktop` |
| `vdprobe logical-workspace-test --confirm-mutate` | creates three probe-owned windows, performs one monitor-local logical A1 -> A2 -> A1 round-trip, and verifies that the other monitor and global current desktop are unchanged |
| `vdprobe real-app-semantics-test --confirm-mutate` | Phase 4A: launches a probe-owned ordinary Win32 child with two top-level windows and one owned popup, then characterizes view grouping/ownership for one Carrier -> Parking move |
| `vdprobe explorer-semantics-test --confirm-mutate` | Phase 4B-1: launches two newly attributable Explorer top-level windows, moves one view Carrier -> Parking, observes sibling/owned-window behavior, and restores only probe-created HWNDs |
| `vdprobe chromium-semantics-test --browser edge --confirm-mutate` | Phase 4C: launches one isolated temporary Edge profile, attributes two same-profile top-level windows, moves one view Carrier -> Parking -> Carrier, and restores/cleans up only probe-attributed state |
| `vdprobe terminal-semantics-test --confirm-mutate` | Phase 4C: launches two probe-owned Windows Terminal top-level windows, moves one view Carrier -> Parking -> Carrier, and restores/cleans up only probe-attributed state |
| `vdprobe workspace-discovery-test` | productization boundary: deterministic, non-mutating capability-driven complete-window discovery and fail-closed classification |
| `vdprobe workspace-live-discovery-test` | productization bootstrap: one complete, non-mutating live Carrier/Parking snapshot with `GetViewForHwnd` and `CanViewMoveDesktops` capability checks |
| `vdprobe workspace-live-bootstrap-test` | validates that same read-only live snapshot in `WorkspaceEngine` using an explicitly synthetic, in-memory-only workspace assignment |
| `vdprobe workspace-live-coordinator-bootstrap-test` | starts the read-only WinEvent source and reconciles bounded complete live discovery through `WorkspaceCoordinator`; assignment remains synthetic/in-memory and no move callback is installed |
| `vdprobe workspace-live-lifecycle-test` | deterministic read-only integration of injected discovery, an explicit generation-keyed assignment registry, owner-thread lifecycle hints, and bounded authoritative coordinator snapshots; no real HWND or move callback is used |
| `vdprobe workspace-engine-test` | productization core: deterministic, non-mutating capability-driven monitor/workspace state, lifecycle, rollback, and journal-recovery checks |
| `vdprobe workspace-assignment-test` | productization boundary: deterministic, non-mutating discovery-to-workspace assignment with identity preservation and fail-closed Carrier/Parking checks |
| `vdprobe workspace-coordinator-test` | productization boundary: deterministic, non-mutating serialized discovery, lifecycle quiet-boundary, stale-safe switching, and recovery checks |
| `vdprobe workspace-startup-test` | productization boundary: deterministic, non-mutating fail-closed lifecycle/journal startup ordering and fresh-model pending recovery |

`--all` makes `windows` include invisible and untitled HWNDs. Add `--help` for
the full usage text.

## Safety model

Undocumented COM methods are never reached by declaring a speculative C++
interface and calling a member function. Every private call goes through
`InvokeSlot()` in [`src/vdlayout.h`](src/vdlayout.h), which refuses unless all of
the following hold:

- the method is in the layout registry for the IID that was actually accepted;
- the slot index is agreed (an entry whose sources disagree is stored as
  `kUnknownSlot` and can be reported but never invoked);
- confidence is `high` or `VERIFIED`;
- the method is marked read-only, unless mutation is explicitly unlocked;
- the vtable pointer is readable, and the slot holds an executable pointer inside
  a mapped image (checked with `VirtualQuery` immediately before the call).

On refusal it returns `E_ABORT` and a reason, which the subcommands print.
`SwitchDesktop` is reachable only through the explicitly double-gated
`notify-watch --self-trigger` path. The Carrier/Parking and logical-workspace
tests unlock only `MoveViewToDesktop`; they never create/remove native desktops
and never call `SwitchDesktop`.

## Where the layout data comes from

The registry in [`src/vdlayout.cpp`](src/vdlayout.cpp) records, per method: build
family, IID, vtable index, signature, evidence, confidence and read-only status.
`docs/interface-matrix.md` is generated from it, so the documentation cannot drift
from what the binary will do.

Slots marked `VERIFIED` were confirmed against the probe host's own binaries:

```powershell
# derive the PDB identity from the PE debug directory, fetch from the symbol server
python tools\vdsym.py pdbid C:\Windows\System32\twinui.pcshell.dll
python tools\vdsym.py fetch C:\Windows\System32\twinui.pcshell.dll

# per-monitor symbol search for the running build
python tools\vdsym.py report C:\Windows\System32\twinui.pcshell.dll <pdb>

# dump a real vtable, slot -> public symbol
python tools\vdsym.py vtable C:\Windows\System32\twinui.pcshell.dll <pdb> `
    '\?\?_7CVirtualDesktopManager@@6B\?\$ImplementsHelper.*ChainInterfaces'

# independent method count from the MIDL proxy
python tools\vdsym.py proxyinfo C:\Windows\System32\actxprxy.dll `
    '{53F5CA0B-158F-4124-900C-057158060B27}'

# is a removed IID still in the binaries at all?
python tools\vdsym.py findguid '{B2F925B9-5A0F-4D2E-9F4D-2B1507593C10}' `
    C:\Windows\System32\twinui.pcshell.dll C:\Windows\explorer.exe
```

`tools/vdsym.py` implements its own PE parser and MSF/PDB reader, so no DIA SDK,
dbghelp or Visual Studio installation is needed. `tools/extract_refs.py`
summarises the downloaded reference implementations in `research/ref/`.

## Regenerating the docs

```powershell
.\regen-docs.ps1
```

Rewrites `docs/interface-matrix.md` and `docs/test-results.md` from live runs.
`docs/findings.md` is hand-written and is left alone.

## Layout

```
CMakeLists.txt        build.ps1        regen-docs.ps1
src/
  main.cpp            subcommand dispatch
  util.{h,cpp}        console, strings, GUID/HRESULT formatting, version info
  comraw.{h,cpp}      COM pointer wrappers, pointer validation, raw slot dispatch
  vdids.{h,cpp}       CLSIDs, service IDs, per-build IID candidate table
  vdlayout.{h,cpp}    vtable layout registry + the invocation gate
  phase1.{h,cpp}      system / monitors / windows
  phase2.{h,cpp}      private COM probing
tools/
  vdsym.py            PE + PDB reader, vtable dumper, GUID scanner
  extract_refs.py     per-build IID/slot extraction from reference sources
docs/
  findings.md         the feasibility report (hand-written)
  interface-matrix.md generated from the layout registry
  test-results.md     verbatim transcripts of every subcommand
research/
  ref/                downloaded reference implementations
  symbols/            downloaded PDBs (not checked in)
```

## Scope

Phase 4C is the representative compatibility gate. Controlled Win32,
Explorer, isolated Edge, and Windows Terminal probes have reached
`GO-WITH-LIMITATIONS` for the tested top-level Carrier/Parking semantics.
The strict gate remains pending until Edge also proves complete temporary
profile process drain and cleanup. Evidence and limitations are recorded in
[`docs/phase4c-results.md`](docs/phase4c-results.md).

The project now moves from app-by-app compatibility research to productization
with runtime capability detection:

```text
GetViewForHwnd
    -> CanViewMoveDesktops
    -> move and verify target/global state
    -> rollback immediately on an anomaly
```

The probe never maintains an executable whitelist. Chrome, Electron, other
packaged applications, and unusual owner/popup behavior remain beta validation
inputs rather than separate prebuilt compatibility claims.

Productization work still excludes production automatic lifecycle tracking,
persistence, GUI, hotkeys, tray icon, installer, Rust port, stress, latency
benchmarking, and any form of faked or emulated native desktop lifecycle until
those milestones are explicitly implemented. The controlled
`logical-workspace-test` now exercises identity-checked placement,
non-activating Z-order, and confirmation-gated foreground restoration for its
probe-owned windows; this is not yet a user-facing presentation manager.

The first productization core is in
[`src/workspace_engine.{h,cpp}`](src/workspace_engine.h). It models
`MonitorId × WorkspaceId` independently from native desktop GUIDs, accepts
runtime `WindowCapabilities`, rejects unsupported/ambiguous affected windows,
and provides a callback-based switch transaction with rollback and optional
journal recovery. Run `workspace-engine-test` for deterministic, non-mutating
evidence. The controlled `logical-workspace-test` is now the first live use of
that engine: it discovers three vdprobe-owned HWNDs, performs generation-safe
`GetViewForHwnd` resolution before each move, and verifies the callback-backed
transaction against live desktop state. The engine also provides deterministic
generation-safe discovery reconciliation and fail-closed presentation restore
planning/execution. The live command hands a journal to a fresh
engine/coordinator pair and performs complete snapshot reconciliation after
recovery; this is a bounded same-process simulation, not fresh-process startup
bootstrap. A bounded read-only `window_lifecycle.{h,cpp}` source collects
window-object
WinEvent hints for owner-thread draining; native destroy hints remain
non-authoritative and require a complete snapshot before model closure.
The new `window_discovery.{h,cpp}` boundary performs complete, deterministic
read-only discovery and now also exposes a system backend built from
`EnumWindows`, generation-safe HWND identity, documented desktop/presentation
reads, and optional capability augmentation. It captures monitor/owner/tool
state, desktop role, presentation, and runtime capabilities, then classifies
records as `Managed`, `Unsupported`, or `Ambiguous` without assigning logical
workspaces or using executable names. Incomplete enumeration, duplicate
identity, unstable observation, invalid desktop role, or backend exceptions
fail closed and preserve the prior snapshot. `workspace-discovery-test`
exercises the injected seam without COM or native mutation; the system backend
is wired into `workspace-live-discovery-test` for a single bounded bootstrap
snapshot, but is not yet wired into the long-running
coordinator. Production assignment/lifecycle policy, durable journal/bootstrap
policy, focus/Z-order execution, and UI integration remain separate milestones.

`workspace-live-coordinator-bootstrap-test` is the narrow live coordinator
bootstrap check: it starts `WinEventLifecycleSource` on the command's owner
thread, pumps callbacks around each complete read-only discovery attempt, and
uses `WorkspaceCoordinator::ReconcileDiscovery()` to require a quiet bounded
snapshot. The resulting `WindowRecord` assignments use only synthetic
in-memory workspace IDs. No move callback is installed, no switch is requested,
and the lifecycle source is stopped before the command reports success.

`workspace-live-lifecycle-test` advances that boundary through a complete
appeared/closed/reappeared/HWND-generation lifecycle without inspecting or
mutating a user window. It uses the injectable documented-Win32 discovery seam
with deterministic probe-owned identities, an explicit in-memory assignment
registry keyed by the full HWND/PID/process-generation tuple, a real
owner-thread `WinEventLifecycleSource` drain boundary, and
`WorkspaceCoordinator` bounded reconciliation. A close hint alone leaves the
record present; only omission from a complete snapshot closes it. Missing
assignment, monitor mismatch, capability loss, identity instability, and a
lifecycle stream that does not become quiet all fail closed. The preceding
live coordinator command remains the proof that the same `WindowDiscovery`
pipeline can be built by `CreateSystemWindowDiscoveryBackend`; the deterministic
lifecycle command deliberately does not enumerate unrelated user HWNDs.

The serialized coordinator boundary is in
[`src/workspace_coordinator.{h,cpp}`](src/workspace_coordinator.h). It keeps
complete discovery snapshots and lifecycle hints on one owner thread, retries
until the lifecycle input is quiet, rejects stale plans before native mutation,
and blocks new operations while a journal transaction is pending. Run
`workspace-coordinator-test` for deterministic, non-mutating evidence. This is
still a library boundary, not a long-running user-facing manager: production
discovery policy, WinEvent message pumping, startup bootstrap, and
presentation/focus policy remain separate. `workspace_startup.{h,cpp}` now
adds a reusable caller-composed `RecoverAtStartup` gate: it starts/verifies the
owner-thread WinEvent source, reads an injected stable journal path before
enabling operations, requires an authoritative complete snapshot, and, for a
pending transaction, bootstraps a fresh recovery engine, recovers it, then
requires a second full reconciliation. Malformed journals, missing pending
identities, unavailable/unstable lifecycle input, and recovery failures remain
blocked with the journal retained. The boundary does not choose discovery or
native move policy; its deterministic test uses only in-memory callbacks.

On hosts where ImmersiveShell access is denied, either gated test prints
`result = ENVIRONMENT-BLOCKED`, reports `mutation_started = no`, and exits with
status `77` (inconclusive/skip); that is not a semantics PASS or FAIL. The
same exit status is used for non-deterministic attribution, callback
contamination, and cleanup that is safe but incomplete; those outcomes must be
rerun or investigated rather than treated as a semantics failure.
