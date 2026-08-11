# Findings — read-only feasibility of native per-monitor virtual desktops

**Probe host:** Windows 11 25H2, `RtlGetVersion` 10.0.26200, UBR 8875 → **10.0.26200.8875**
`explorer.exe`, `twinui.pcshell.dll`, `twinui.dll` = 10.0.26100.8875 · `actxprxy.dll` = 10.0.26100.8328
Two physical monitors attached (`\\.\DISPLAY1` 2048×1280 primary, `\\.\DISPLAY5` 1920×1080).
Two real virtual desktops existed during testing.

> Two registry/resource oddities on this machine, both benign, both worth naming
> so they are not mistaken for probe errors:
>
> - `ProductName` reads "Windows 10 Pro for Workstations". That value is a
>   well-known stale string; `RtlGetVersion` and `DisplayVersion` (25H2) are
>   authoritative and are what the probe uses.
> - The shell modules report **two** different versions. Their StringFileInfo
>   `FileVersion` string is `10.0.26100.8875`, while the binary
>   `VS_FIXEDFILEINFO` fields say `6.2.26100.8875` — Windows keeps the fixed
>   fields at 6.2.x on many shell binaries for compatibility. `vdprobe system`
>   prints both. Where this document names a module version it uses the
>   `10.0.x` string form; earlier revisions of these notes quoted the `6.2.x`
>   form, and the evidence strings compiled into `src/vdlayout.cpp` still do.
>   They refer to the same file.

---

## Verdict

**Windows 11 build 26200 does not contain a usable native per-monitor virtual
desktop implementation.** The monitor-aware interface revision that existed in
Windows 11 21H2/22H2 (and Windows Server 2022) has been removed from the shipping
binaries — not merely disabled, and not left behind as dormant code. There is
nothing to re-enable.

macOS "Displays have separate Spaces" has no equivalent surface on this build.

---

## Answers to the eight questions

### 1. Can `IVirtualDesktopManagerInternal` be obtained?

**Yes.**

```
CoCreateInstance(CLSID_ImmersiveShell {C2F03A33-21F5-47FA-B4BB-156362A2F239})
    -> IServiceProvider {6D5140C1-7436-11CE-8034-00AA006009FA}   [vtable in OneCoreCommonProxyStub.dll]
QueryService(SID_VirtualDesktopManager {C5E0CDCA-7B6E-41B2-9FC4-D93975CC467B},
             IID {53F5CA0B-158F-4124-900C-057158060B27})          -> S_OK
```

Only that one IID is accepted. Every other historical IID is rejected with
`E_NOINTERFACE` (0x80004002):

| IID | Build family | Monitor-aware layout | Result on 26200.8875 |
|---|---|---|---|
| `{53F5CA0B-158F-4124-900C-057158060B27}` | Win11 23H2 22631.3085+ / 24H2 / 25H2 | no | **ACCEPT** |
| `{A3175F2D-239C-4BD2-8AA0-EEBA8B0B138E}` | Win11 22H2 22621.2215+ / 23H2 pre-3085 | no | E_NOINTERFACE |
| `{B2F925B9-5A0F-4D2E-9F4D-2B1507593C10}` | Win11 21H2 22000 / 22H2 pre-2215 | **YES** | E_NOINTERFACE |
| `{094AFE11-44F2-4BA0-976F-29A97E263EE0}` | Windows Server 2022 20348 | **YES** | E_NOINTERFACE |
| `{F31574D6-B682-4CDC-BD56-1827860ABEC6}` | Win10 1607–21H2 / Server 2016 | no | E_NOINTERFACE |

The other private interfaces are also reachable: `IApplicationViewCollection`
`{1841C6D7-…}`, `IVirtualDesktopNotificationService` `{0CD45E71-…}` and
`IVirtualDesktopPinnedApps` `{4CE81583-…}` all return S_OK. `IVirtualDesktop`
`{3F07F4BE-…}` is not a service; it is obtained from the manager and was
confirmed by `QueryInterface` on the returned desktop objects.

### 2. Can desktops be enumerated?

**Yes.** `GetDesktops` at verified vtable slot 7 returns an `IObjectArray`:

```
GetCount  (slot 3) -> 2
GetDesktops (slot 7) -> IObjectArray, count 2
  [0] {8D5C0D20-FC61-4107-B42B-DEC7CBF6A983}
  [1] {B8ED750C-D162-48CF-B578-EC74E81746C0}
```

The GUIDs are read with `IVirtualDesktop::GetId` at verified slot 4. They match,
exactly, both the documented `IVirtualDesktopManager::GetWindowDesktopId` results
for live windows and the persisted `VirtualDesktopIDs` value in
`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VirtualDesktops`. Three
independent sources agreeing is what makes this result trustworthy rather than a
lucky vtable hit.

### 3. Can the current desktop be identified?

**Yes.** `GetCurrentDesktop` at verified slot 6 returns
`{8D5C0D20-FC61-4107-B42B-DEC7CBF6A983}`, which equals the registry's
`CurrentVirtualDesktop` value and the desktop GUID that the documented API
reports for every window it marks as being on the current desktop.

The signature is `GetCurrentDesktop(IVirtualDesktop**)` — **one** out-parameter
and no monitor discriminator. There is exactly one current desktop per session;
the API has no shape in which "current desktop on monitor N" could be asked.

### 4. Is a monitor-aware virtual desktop interface still present?

**No.** Four independent checks agree:

1. **Live QueryService** — both monitor-aware IIDs (`{B2F925B9-…}`,
   `{094AFE11-…}`) return `E_NOINTERFACE`.
2. **Symbols of the running build** — not one method of the implementation class
   `CVirtualDesktopManager` has `HMONITOR` in its decorated signature (regex
   `@CVirtualDesktopManager@@.*HMONITOR` over 82 913 public symbols: 0 matches).
3. **The actual vtable** — dumped slot-by-slot from `twinui.pcshell.dll`; all 22
   methods take desktop/view pointers only.
4. **The marshalled contract** — `actxprxy.dll`'s `CInterfaceStubHeader` for
   `{53F5CA0B-…}` reports `DispatchTableCount = 25`. That field counts every
   vtable entry including the three `IUnknown` slots, so it implies 22 methods.
   That reading is not assumed: it matches the independent slot-by-slot vtable
   dump, which resolves exactly 22 named methods at slots 3–24 and then runs into
   the next vtable. Two different mechanisms bounding the interface at the same
   size leaves no room for hidden monitor-aware entries.

Two near-misses are worth recording so nobody rediscovers them as false hope:

- **`CPerMonitorDesktopVisibilityService`** exists in `twinui.pcshell.dll`. It
  implements `IDesktopVisibilityService` / `IFullScreenPositionerNotification`
  and its methods are `IsDesktopVisible(IImmersiveMonitor*, BOOL*)`,
  `FullScreenVisibilityChanged`, `RegisterForDesktopVisibilityChanges`. This is
  per-monitor tracking of whether *the desktop (Program Manager) is visible* —
  the show-desktop / full-screen state — and has nothing to do with virtual
  desktops.
- **`VirtualDesktopGestureWindow`**, **`VirtualDesktopHotKeyWindow`** and
  **`CAppThumbnailWindow`** do take `HMONITOR__*`. These are per-monitor UI host
  windows for gestures, hotkeys and thumbnails. Per-monitor *chrome* for a
  session-global desktop model.

### 5. Does `GetDesktopIsPerMonitor` still exist?

**No.** Zero matches among the 82 913 public symbols in `twinui.pcshell.pdb` for
the exact running build (`twinui.pcshell.pdb`, GUID
`06D692620003180BB9EE4DE2222CB6CF`, age 1, fetched from
`msdl.microsoft.com`). It is absent from the 22-slot vtable, and absent from
every published layout for the live IID.

Historically it existed at slot 19 (Win11 21H2), slot 20 (Win11 22H2 pre-2215)
and slot 16 (Windows Server 2022).

### 6. Does `SetDesktopIsPerMonitor` still exist?

**No.** Same result: zero symbol matches, absent from the vtable. Historically at
slot 20 (21H2) and slot 21 (22H2 pre-2215). Windows Server 2022 had the getter
but never the setter.

Broader spellings were also searched and found nothing: `IsPerMonitor` (0 hits),
`DesktopPerMonitor` (0 hits).

### 7. Is the implementation live or apparently legacy/dead code?

**Neither — it is removed.** This is a stronger statement than "disabled", and it
is the finding that determines what is worth doing next.

A raw 16-byte scan for each historical IID across `twinui.pcshell.dll`,
`twinui.dll`, `explorer.exe`, `actxprxy.dll`, `OneCoreCommonProxyStub.dll`,
`combase.dll`, `Windows.Internal.Shell.Broker.dll` and
`Windows.UI.Immersive.dll`:

| IID | Occurrences |
|---|---|
| `{53F5CA0B-…}` live | 2 — `twinui.pcshell.dll` .rdata rva 0x7B8F38, `actxprxy.dll` .rdata rva 0x596D0 |
| `{B2F925B9-…}` per-monitor | **0** |
| `{094AFE11-…}` per-monitor | **0** |
| `{A3175F2D-…}` | **0** |
| `{F31574D6-…}` | **0** |

If the per-monitor revision were dormant-but-present, its IID would still appear
in the QueryInterface comparison tables. It does not appear anywhere. The
interface, its vtable slots, and its symbols are all gone.

The *remaining* implementation is emphatically live, not legacy: `GetCount`,
`GetDesktops` and `GetCurrentDesktop` returned correct, cross-validated data on
the first call.

What is genuinely present but unexplored is a wider private surface on the same
object. `CVirtualDesktopManager` chains three interfaces
(`IVirtualDesktopManagerPrivate` → `IVirtualDesktopManagerInternal2` →
`IVirtualDesktopManagerInternal`), and slots 25+ of the chain vtable hold
`GetCountInternal`, `GetCurrentDesktopInternal`, `GetDesktopsInternal`,
`SwitchDesktop2`, `CreateRecoveredDesktopInternal`,
`MoveViewToDesktopNoGroupPropagateInternal` and others. None of these takes an
`HMONITOR` either, so none of them restores per-monitor behaviour — but the
`IVirtualDesktopManagerPrivate` IID was not identified in this milestone and its
17-method sibling vtable at rva 0x00787F90 is a loose end (see
`docs/test-results.md`).

### 8. What is the safest next experiment?

Per-monitor virtual desktops cannot be obtained from the shell on this build. So
the next experiment should not be "find the hidden API" — that question is
answered. It should establish whether an *emulation* is viable, and the safest
first step is still read-only.

**Recommended next step: a passive notification-sink observer.**

Register an `IVirtualDesktopNotification` sink through
`IVirtualDesktopNotificationService::Register` (slot 3, already confirmed
obtainable) and log `CurrentVirtualDesktopChanged`, `VirtualDesktopCreated`,
`VirtualDesktopDestroyed` and `ViewVirtualDesktopChanged` for a normal working
session. Rationale:

- It is the last piece of state an emulation would need and the only one not yet
  observed. Everything else (desktop list, current desktop, window→desktop,
  window→monitor) is already proven readable.
- Registering a sink is the smallest possible mutation: it adds a callback
  registration, changes no desktop or window state, and is undone by
  `Unregister` or process exit. Note this is a genuine (if small) state change,
  which is why the current gate refuses it — `read_only = false` for
  `Register`. It needs an explicit unlock, not a silent one.
- It tells us whether an emulator can react to desktop switches promptly, or
  whether it would have to poll — which decides whether the whole approach is
  even pleasant to use.

Order of the experiments after that, cheapest and most reversible first:

1. **Timing measurement (read-only).** Measure `SwitchDesktop` latency and
   whether `WaitForAnimationToComplete` (slot 24, verified) gives a usable
   completion signal. An emulation that must hide/show windows per monitor lives
   or dies on this number.
2. **Single-window move, one desktop, manual revert.** `MoveViewToDesktop`
   (slot 4, verified) on one window the tester owns, on a test account, with the
   window moved back by hand. This is the first genuinely destructive step, so it
   should be the first thing done behind the gate's `allow_mutating` unlock and
   should never run by default.
3. Only then consider whether an emulation (cloak/uncloak windows per monitor on
   desktop switch) is worth building. Be aware up front that this approach
   cannot reproduce per-monitor Task View, per-monitor switch animations, or
   per-monitor taskbar grouping, because those are shell-owned.

Explicitly **not** recommended: patching `twinui.pcshell.dll`, injecting into
`explorer.exe`, or trying to synthesise the removed interface. The IID is absent
from the binary, so there is no dormant code path that such an approach could
reach — the cost is high and the ceiling is zero.

---

## How the interface generations evolved

Reconstructed from sources that were downloaded and are cited in
`docs/interface-matrix.md`, not from recollection.

| Build family | `IVirtualDesktopManagerInternal` IID | Methods | HMONITOR params | `GetDesktopIsPerMonitor` | `SetDesktopIsPerMonitor` |
|---|---|---|---|---|---|
| Win10 1607–21H2, Server 2016 | `{F31574D6-…}` | 10 | no | — | — |
| Windows Server 2022 (20348) | `{094AFE11-…}` | 14 | **yes** | slot 16 | — |
| Win11 21H2 (22000) | `{B2F925B9-…}` | 18 | **yes** | slot 19 | slot 20 |
| Win11 22H2 (22621 < .2215) | `{B2F925B9-…}` *(same IID)* | 19 | **yes** | slot 20 | slot 21 |
| Win11 22621.2215+ / 23H2 pre-3085 | `{A3175F2D-…}` | 21 | no | removed | removed |
| Win11 23H2 22631.3085+ / 24H2 / **25H2 26200** | `{53F5CA0B-…}` | **22 (verified)** | no | absent | absent |

Two hazards this table makes visible, and the reason the probe never trusts an
IID alone:

- **21H2 and 22H2 share `{B2F925B9-…}` but have different layouts.** 22H2
  inserted `GetAllCurrentDesktops` at slot 7, shifting all ten later methods by
  one. Code that matched the IID and used the 21H2 indices would have called the
  wrong function with the wrong arguments.
- **The live IID `{53F5CA0B-…}` has two published layouts too** — 21 methods with
  `CreateDesktop` at slot 10, versus 22 methods with
  `SwitchDesktopAndMoveForegroundView` at slot 10. The vtable dump settles it for
  this build: `SwitchDesktopAndMoveForegroundView` is at 10 and `CreateDesktopW`
  at 11.

## Verified layout on this build

`CVirtualDesktopManager` in `twinui.pcshell.dll` 6.2.26100.8875. Chain vtable at
`.rdata` rva `0x00788030`; every entry resolved to a public symbol.

| Slot | Method | Interface |
|---|---|---|
| 3 | `GetCount(UINT*)` | Internal |
| 4 | `MoveViewToDesktop(IApplicationView*, IVirtualDesktop*)` | Internal |
| 5 | `CanViewMoveDesktops(IApplicationView*, BOOL*)` | Internal |
| 6 | `GetCurrentDesktop(IVirtualDesktop**)` | Internal |
| 7 | `GetDesktops(IObjectArray**)` | Internal |
| 8 | `GetAdjacentDesktop(IVirtualDesktop*, UINT, IVirtualDesktop**)` | Internal |
| 9 | `SwitchDesktop(IVirtualDesktop*)` | Internal |
| 10 | `SwitchDesktopAndMoveForegroundView(IVirtualDesktop*)` | Internal |
| 11 | `CreateDesktopW(IVirtualDesktop**)` | Internal |
| 12 | `MoveDesktop(IVirtualDesktop*, UINT)` | Internal |
| 13 | `RemoveDesktop(IVirtualDesktop*, IVirtualDesktop*)` | Internal |
| 14 | `FindDesktop(const GUID*, IVirtualDesktop**)` | Internal |
| 15 | `GetDesktopSwitchIncludeExcludeViews(...)` | Internal |
| 16 | `SetDesktopName(IVirtualDesktop*, HSTRING)` | Internal |
| 17 | `SetDesktopWallpaper(IVirtualDesktop*, HSTRING)` | Internal |
| 18 | `UpdateWallpaperPathForAllDesktops(HSTRING)` | Internal |
| 19 | `CopyDesktopState(IApplicationView*, IApplicationView*)` | Internal |
| 20 | `CreateRemoteDesktop(HSTRING, IVirtualDesktop**)` | Internal2 |
| 21 | `SwitchRemoteDesktop(IVirtualDesktop*, void*)` | Internal2 |
| 22 | `SwitchDesktopWithAnimation(IVirtualDesktop*)` | Internal2 |
| 23 | `GetLastActiveDesktop(IVirtualDesktop**)` | Internal2 |
| 24 | `WaitForAnimationToComplete()` | Internal2 |

`IVirtualDesktop` = `CVirtualDesktop`, chain vtable rva `0x00747DD0`,
`DispatchTableCount = 7` → 4 methods (7 vtable entries less the 3 `IUnknown`
slots, again corroborated by the dump): slot 3 `IsViewVisible`, slot 4 `GetID`,
slot 5 `GetName`, slot 6 `GetWallpaper`. Slot 7 `IsRemote` belongs to
`IVirtualDesktop2` and is *not* reachable through the `{3F07F4BE-…}` contract, so
the probe refuses it.

## Observable behaviour, independent of any API

Even ignoring interfaces entirely, the shell behaves as session-global:

- Both desktop GUIDs are found on windows on **both** monitors
  (`vdprobe windows` cross-tab). A per-monitor model would partition them.
- `HKCU\…\Explorer\VirtualDesktops` holds one flat `VirtualDesktopIDs` list and
  one `CurrentVirtualDesktop` GUID. No value anywhere is keyed by monitor or
  display id. A per-monitor implementation would have to persist a desktop list
  per display; there is no such structure.
- `Desktops\{guid}\Wallpaper` subkeys exist for five GUIDs, of which three are
  not in `VirtualDesktopIDs` — stale entries from deleted desktops, not
  per-monitor state.

## Service and interface IDs confirmed against this build

Read back from `twinui.pcshell.dll`'s own `.rdata` at its public data symbols, so
these are not taken on trust from a third party:

| Symbol | Value |
|---|---|
| `SID_VirtualDesktopManager` | `{C5E0CDCA-7B6E-41B2-9FC4-D93975CC467B}` |
| `SID_VirtualDesktopPinnedApps` | `{B5A399E7-1C87-46B8-88E9-FC5747B171BD}` |
| `SID_VirtualDesktopNotificationService` | `{A501FDEC-4A09-464C-AE4E-1B9C21B84918}` |
| `IID_IVirtualDesktopManager` | `{A5CD92FF-29BE-454C-8D04-D82879FB3F1B}` |

## Limits of these findings

- One machine, one build (10.0.26200.8875), x64, single session, two monitors.
  The IID-acceptance result is a property of the build; the behavioural
  observations are a property of this session.
- Microsoft ships **public** PDBs. A private method could exist without a public
  symbol. That is why the symbol search is corroborated by the vtable dump and by
  `actxprxy.dll`'s `DispatchTableCount`, which bound the interface size
  independently of symbol availability.
- The GUID byte scan covered eight modules. It is not the whole OS. It does cover
  every module that participates in serving or marshalling this interface on this
  build.
- `IVirtualDesktopManagerPrivate`'s IID was not determined, and the 17-method
  vtable at rva 0x00787F90 is not fully explained. Neither affects the answers
  above, since neither contains an `HMONITOR` parameter.
- No mutating method was called at any point. `SwitchDesktop`, `CreateDesktopW`,
  `MoveViewToDesktop`, `SetDesktopName` and the rest are recorded with verified
  slots but are refused by the gate.
