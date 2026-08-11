#include "vdlayout.h"

#include <cstring>
#include <iterator>
#include <vector>

namespace vd {
namespace {

constexpr const char* kAgree3 =
    "MScholtes 23H2/24H2 + Ciantic VDA agree; slot identical in both";
constexpr const char* kHist21 = "MScholtes @V1.15 VirtualDesktop11-21H2.cs";
constexpr const char* kHist22 = "MScholtes @V1.17 VirtualDesktop11-22H2.cs";
constexpr const char* kHistBoth =
    "MScholtes @V1.15 21H2 + @V1.17 22H2 (slot differs between them)";

// ===========================================================================
// IVirtualDesktopManagerInternal {53F5CA0B-...}
// Win11 23H2 22631.3085+ / 24H2 26100 / 25H2 26200.
//
// VERIFIED against the probe host's own binary, not inferred:
//   * implementation class is CVirtualDesktopManager in twinui.pcshell.dll
//     6.2.26100.8875;
//   * vftable ??_7CVirtualDesktopManager@@6B?$ImplementsHelper@...
//     ChainInterfaces<IVirtualDesktopManagerPrivate, IVirtualDesktopManager-
//     Internal, IVirtualDesktopManagerInternal2>... at .rdata rva 0x00788030
//     was dumped slot-by-slot and each entry resolved to a public symbol from
//     twinui.pcshell.pdb (GUID 06D692620003180BB9EE4DE2222CB6CF, age 1);
//   * actxprxy.dll's CInterfaceStubHeader for this IID reports
//     DispatchTableCount = 25, i.e. 3 IUnknown + 22 methods, which matches the
//     dump exactly (slots 3..24).
// Reproduce with: tools/vdsym.py vtable / proxyinfo (see docs/test-results.md).
//
// Slots 3..19 are IVirtualDesktopManagerInternal's own methods; 20..24 come
// from the chained IVirtualDesktopManagerInternal2 and are reachable on the
// marshalled proxy because the RPC contract for this IID covers all 22.
// ===========================================================================
constexpr const char* kVerified =
    "vtable dump of CVirtualDesktopManager in twinui.pcshell.dll 6.2.26100.8875 "
    "+ actxprxy.dll DispatchTableCount=25; agrees with MScholtes 24H2 and VDA";

constexpr MethodEntry kVDMI_53F5CA0B_Methods[] = {
    {"GetCount", 3, "HRESULT GetCount(UINT* pCount)", Confidence::Verified, kVerified,
     true, "NO HMONITOR parameter on this build"},
    {"MoveViewToDesktop", 4,
     "HRESULT MoveViewToDesktop(IApplicationView* pView, IVirtualDesktop* pDesktop)",
     Confidence::Verified, kVerified, false, nullptr},
    {"CanViewMoveDesktops", 5,
     "HRESULT CanViewMoveDesktops(IApplicationView* pView, BOOL* pfCanMove)",
     Confidence::Verified, kVerified, true, nullptr},
    {"GetCurrentDesktop", 6, "HRESULT GetCurrentDesktop(IVirtualDesktop** ppDesktop)",
     Confidence::Verified, kVerified, true, "NO HMONITOR parameter on this build"},
    {"GetDesktops", 7, "HRESULT GetDesktops(IObjectArray** ppDesktops)",
     Confidence::Verified, kVerified, true, "NO HMONITOR parameter on this build"},
    {"GetAdjacentDesktop", 8,
     "HRESULT GetAdjacentDesktop(IVirtualDesktop* pFrom, UINT direction, "
     "IVirtualDesktop** ppDesktop)",
     Confidence::Verified, kVerified, true, nullptr},
    {"SwitchDesktop", 9, "HRESULT SwitchDesktop(IVirtualDesktop* pDesktop)",
     Confidence::Verified, kVerified, false, "NO HMONITOR parameter on this build"},
    {"SwitchDesktopAndMoveForegroundView", 10,
     "HRESULT SwitchDesktopAndMoveForegroundView(IVirtualDesktop* pDesktop)",
     Confidence::Verified, kVerified, false,
     "resolves the slot-10 ambiguity between the two published layouts"},
    {"CreateDesktopW", 11, "HRESULT CreateDesktopW(IVirtualDesktop** ppNewDesktop)",
     Confidence::Verified, kVerified, false,
     "binary symbol is CreateDesktopW; NO HMONITOR parameter"},
    {"MoveDesktop", 12, "HRESULT MoveDesktop(IVirtualDesktop* pDesktop, UINT nIndex)",
     Confidence::Verified, kVerified, false, "NO HMONITOR parameter on this build"},
    {"RemoveDesktop", 13,
     "HRESULT RemoveDesktop(IVirtualDesktop* pRemove, IVirtualDesktop* pFallback)",
     Confidence::Verified, kVerified, false, nullptr},
    {"FindDesktop", 14,
     "HRESULT FindDesktop(const GUID* pId, IVirtualDesktop** ppDesktop)",
     Confidence::Verified, kVerified, true, nullptr},
    {"GetDesktopSwitchIncludeExcludeViews", 15,
     "HRESULT GetDesktopSwitchIncludeExcludeViews(IVirtualDesktop*, IObjectArray**, "
     "IObjectArray**)",
     Confidence::Verified, kVerified, true, nullptr},
    {"SetDesktopName", 16, "HRESULT SetDesktopName(IVirtualDesktop*, HSTRING name)",
     Confidence::Verified, kVerified, false, nullptr},
    {"SetDesktopWallpaper", 17,
     "HRESULT SetDesktopWallpaper(IVirtualDesktop*, HSTRING path)",
     Confidence::Verified, kVerified, false, nullptr},
    {"UpdateWallpaperPathForAllDesktops", 18,
     "HRESULT UpdateWallpaperPathForAllDesktops(HSTRING path)", Confidence::Verified,
     kVerified, false, nullptr},
    {"CopyDesktopState", 19,
     "HRESULT CopyDesktopState(IApplicationView* pFrom, IApplicationView* pTo)",
     Confidence::Verified, kVerified, false,
     "last method of IVirtualDesktopManagerInternal proper"},
    {"CreateRemoteDesktop", 20,
     "HRESULT CreateRemoteDesktop(HSTRING path, IVirtualDesktop** ppDesktop)",
     Confidence::Verified, kVerified, false,
     "IVirtualDesktopManagerInternal2 range (slots 20..24)"},
    {"SwitchRemoteDesktop", 21,
     "HRESULT SwitchRemoteDesktop(IVirtualDesktop*, void* switchType)",
     Confidence::Verified, kVerified, false, "IVirtualDesktopManagerInternal2"},
    {"SwitchDesktopWithAnimation", 22,
     "HRESULT SwitchDesktopWithAnimation(IVirtualDesktop*)", Confidence::Verified,
     kVerified, false, "IVirtualDesktopManagerInternal2"},
    {"GetLastActiveDesktop", 23, "HRESULT GetLastActiveDesktop(IVirtualDesktop**)",
     Confidence::Verified, kVerified, true, "IVirtualDesktopManagerInternal2"},
    {"WaitForAnimationToComplete", 24, "HRESULT WaitForAnimationToComplete()",
     Confidence::Verified, kVerified, false,
     "IVirtualDesktopManagerInternal2; last slot, matches DispatchTableCount=25"},
    // Explicit negative results.  Recorded so per-monitor-status reports an
    // evidenced absence rather than silence.
    {"GetDesktopIsPerMonitor", kUnknownSlot, "HRESULT GetDesktopIsPerMonitor(BOOL*)",
     Confidence::Unknown,
     "ABSENT: 0 matches for 'GetDesktopIsPerMonitor' among the 82913 public symbols "
     "of twinui.pcshell.pdb for this build; not in the 22-slot vtable",
     true, "removed after Win11 22621.2215"},
    {"SetDesktopIsPerMonitor", kUnknownSlot, "HRESULT SetDesktopIsPerMonitor(BOOL)",
     Confidence::Unknown,
     "ABSENT: 0 matches for 'SetDesktopIsPerMonitor' among the 82913 public symbols "
     "of twinui.pcshell.pdb for this build; not in the 22-slot vtable",
     false, "removed after Win11 22621.2215"},
    {"GetAllCurrentDesktops", kUnknownSlot,
     "HRESULT GetAllCurrentDesktops(IObjectArray**)", Confidence::Unknown,
     "ABSENT from the verified 22-slot vtable for this IID", true,
     "existed only in the monitor-aware 22H2 layout"},
};

// ===========================================================================
// IVirtualDesktopManagerInternal {A3175F2D-...} - 22H2 22621.2215+ / 23H2.
// First revision where the per-monitor surface was gone.
// ===========================================================================
constexpr MethodEntry kVDMI_A3175F2D_Methods[] = {
    {"GetCount", 3, "HRESULT GetCount(UINT* pCount)", Confidence::Medium,
     "MScholtes @V1.15 VirtualDesktop11-23H2.cs", true, "no HMONITOR parameter"},
    {"GetCurrentDesktop", 6, "HRESULT GetCurrentDesktop(IVirtualDesktop**)",
     Confidence::Medium, "MScholtes @V1.15 VirtualDesktop11-23H2.cs", true,
     "no HMONITOR parameter"},
    {"GetDesktops", 7, "HRESULT GetDesktops(IObjectArray**)", Confidence::Medium,
     "MScholtes @V1.15 VirtualDesktop11-23H2.cs", true, "no HMONITOR parameter"},
    {"GetDesktopIsPerMonitor", kUnknownSlot, "HRESULT GetDesktopIsPerMonitor(BOOL*)",
     Confidence::Unknown, "ABSENT from the published layout for this IID", true,
     "per-monitor surface removed at 22621.2215"},
    {"SetDesktopIsPerMonitor", kUnknownSlot, "HRESULT SetDesktopIsPerMonitor(BOOL)",
     Confidence::Unknown, "ABSENT from the published layout for this IID", false,
     "per-monitor surface removed at 22621.2215"},
};

// ===========================================================================
// IVirtualDesktopManagerInternal {B2F925B9-...} - Win11 21H2 22000 and
// 22H2 pre-2215.  THE PER-MONITOR LAYOUT.  Retained purely as the historical
// reference the probe compares the current build against.
//
// Same IID, two layouts: 22H2 inserted GetAllCurrentDesktops at slot 7, which
// shifts everything after it by one.  This is exactly why an IID match is not
// treated as proof of layout anywhere in this project.
// ===========================================================================
constexpr MethodEntry kVDMI_B2F925B9_Methods[] = {
    {"GetCount", 3, "HRESULT GetCount(HMONITOR hMonitorOrHwnd, UINT* pCount)",
     Confidence::High, "identical slot in both 21H2 and 22H2 layouts", true,
     "MONITOR-AWARE"},
    {"MoveViewToDesktop", 4, "HRESULT MoveViewToDesktop(IApplicationView*, IVirtualDesktop*)",
     Confidence::High, kHistBoth, false, nullptr},
    {"CanViewMoveDesktops", 5, "HRESULT CanViewMoveDesktops(IApplicationView*, BOOL*)",
     Confidence::High, kHistBoth, true, nullptr},
    {"GetCurrentDesktop", 6,
     "HRESULT GetCurrentDesktop(HMONITOR hMonitorOrHwnd, IVirtualDesktop** ppDesktop)",
     Confidence::High, "identical slot in both 21H2 and 22H2 layouts", true,
     "MONITOR-AWARE"},
    {"GetAllCurrentDesktops", kUnknownSlot,
     "HRESULT GetAllCurrentDesktops(IObjectArray** ppDesktops)", Confidence::Low,
     "slot 7 in 22H2 layout only; absent in 21H2", true,
     "its presence is what shifts the rest of the 22H2 vtable"},
    {"GetDesktops", kUnknownSlot,
     "HRESULT GetDesktops(HMONITOR hMonitorOrHwnd, IObjectArray** ppDesktops)",
     Confidence::Low, "slot 7 in 21H2, slot 8 in 22H2", true,
     "MONITOR-AWARE; slot ambiguous"},
    {"SwitchDesktop", kUnknownSlot,
     "HRESULT SwitchDesktop(HMONITOR hMonitorOrHwnd, IVirtualDesktop*)",
     Confidence::Low, "slot 9 in 21H2, slot 10 in 22H2", false,
     "MONITOR-AWARE; slot ambiguous"},
    {"CreateDesktop", kUnknownSlot,
     "HRESULT CreateDesktop(HMONITOR hMonitorOrHwnd, IVirtualDesktop** ppDesktop)",
     Confidence::Low, "slot 10 in 21H2, slot 11 in 22H2", false,
     "MONITOR-AWARE; slot ambiguous"},
    {"MoveDesktop", kUnknownSlot,
     "HRESULT MoveDesktop(IVirtualDesktop*, HMONITOR hMonitorOrHwnd, int nIndex)",
     Confidence::Low, "slot 11 in 21H2, slot 12 in 22H2", false,
     "MONITOR-AWARE; slot ambiguous"},
    {"GetDesktopIsPerMonitor", kUnknownSlot, "HRESULT GetDesktopIsPerMonitor(BOOL* pfPerMonitor)",
     Confidence::Medium, "slot 19 in 21H2 layout, slot 20 in 22H2 layout", true,
     "THE per-monitor feature switch getter"},
    {"SetDesktopIsPerMonitor", kUnknownSlot, "HRESULT SetDesktopIsPerMonitor(BOOL fPerMonitor)",
     Confidence::Medium, "slot 20 in 21H2 layout, slot 21 in 22H2 layout", false,
     "THE per-monitor feature switch setter"},
};

// ===========================================================================
// IVirtualDesktopManagerInternal {094AFE11-...} - Windows Server 2022 (20348).
// Monitor-aware, getter present, setter absent.
// ===========================================================================
constexpr MethodEntry kVDMI_094AFE11_Methods[] = {
    {"GetCount", 3, "HRESULT GetCount(HMONITOR hMonitorOrHwnd, UINT* pCount)",
     Confidence::Medium, "MScholtes VirtualDesktopServer2022.cs", true, "MONITOR-AWARE"},
    {"GetCurrentDesktop", 6,
     "HRESULT GetCurrentDesktop(HMONITOR hMonitorOrHwnd, IVirtualDesktop**)",
     Confidence::Medium, "MScholtes VirtualDesktopServer2022.cs", true, "MONITOR-AWARE"},
    {"GetDesktops", 7,
     "HRESULT GetDesktops(HMONITOR hMonitorOrHwnd, IObjectArray**)", Confidence::Medium,
     "MScholtes VirtualDesktopServer2022.cs", true, "MONITOR-AWARE"},
    {"GetDesktopIsPerMonitor", 16, "HRESULT GetDesktopIsPerMonitor(BOOL*)",
     Confidence::Medium, "MScholtes VirtualDesktopServer2022.cs (last slot, 14 methods)",
     true, "getter present, setter absent on this SKU"},
};

// ===========================================================================
// IVirtualDesktopManagerInternal {F31574D6-...} - Windows 10 / Server 2016.
// ===========================================================================
constexpr MethodEntry kVDMI_F31574D6_Methods[] = {
    {"GetCount", 3, "HRESULT GetCount(UINT* pCount)", Confidence::High,
     "MScholtes VirtualDesktop.cs + many independent Win10 implementations", true,
     "no monitor parameter"},
    {"GetCurrentDesktop", 6, "HRESULT GetCurrentDesktop(IVirtualDesktop**)",
     Confidence::High, "MScholtes VirtualDesktop.cs", true, "no monitor parameter"},
    {"GetDesktops", 7, "HRESULT GetDesktops(IObjectArray**)", Confidence::High,
     "MScholtes VirtualDesktop.cs", true, "no monitor parameter"},
};

// ===========================================================================
// IVirtualDesktop {3F07F4BE-...}
//
// VERIFIED: CVirtualDesktop in twinui.pcshell.dll 6.2.26100.8875, vftable
// ??_7CVirtualDesktop@@6B?$ChainInterfaces@UIVirtualDesktop2@@UIVirtualDesktop@@...
// at .rdata rva 0x00747dd0; actxprxy.dll CInterfaceStubHeader for this IID
// reports DispatchTableCount = 7, i.e. 3 IUnknown + 4 methods.
// ===========================================================================
constexpr const char* kVerifiedVD =
    "vtable dump of CVirtualDesktop in twinui.pcshell.dll 6.2.26100.8875 "
    "+ actxprxy.dll DispatchTableCount=7";

constexpr MethodEntry kVD_3F07F4BE_Methods[] = {
    {"IsViewVisible", 3, "HRESULT IsViewVisible(IApplicationView*, BOOL*)",
     Confidence::Verified, kVerifiedVD, true, nullptr},
    {"GetId", 4, "HRESULT GetId(GUID* pId)", Confidence::Verified, kVerifiedVD, true,
     "binary symbol is CVirtualDesktop::GetID"},
    {"GetName", 5, "HRESULT GetName(HSTRING* pName)", Confidence::Verified, kVerifiedVD,
     true, nullptr},
    {"GetWallpaperPath", 6, "HRESULT GetWallpaperPath(HSTRING* pPath)",
     Confidence::Verified, kVerifiedVD, true,
     "binary symbol is CVirtualDesktop::GetWallpaper; last slot of this IID"},
    {"IsRemote", kUnknownSlot, "HRESULT IsRemote(BOOL*)", Confidence::Low,
     "occupies slot 7 of the CVirtualDesktop chain vtable, but belongs to "
     "IVirtualDesktop2: the marshalled contract for 3F07F4BE stops at 4 methods",
     true, "not invocable through this IID"},
};

// ===========================================================================
// IVirtualDesktop {536D3495-...} - Win11 21H2/22H2 (per-monitor era).
// ===========================================================================
constexpr MethodEntry kVD_536D3495_Methods[] = {
    {"IsViewVisible", 3, "HRESULT IsViewVisible(IApplicationView*, BOOL*)",
     Confidence::Medium, kHist22, true, nullptr},
    {"GetId", 4, "HRESULT GetId(GUID* pId)", Confidence::Medium, kHist22, true, nullptr},
    {"Unknown1", 5, "HRESULT Unknown1(void** )", Confidence::Low, kHist22, true,
     "unnamed slot present in this era only"},
    {"GetName", 6, "HRESULT GetName(HSTRING*)", Confidence::Medium, kHist22, true,
     nullptr},
    {"GetWallpaperPath", 7, "HRESULT GetWallpaperPath(HSTRING*)", Confidence::Medium,
     kHist21, true, nullptr},
};

// ===========================================================================
// Support interfaces.  Only what the probe needs, read-only.
// ===========================================================================
// ===========================================================================
// IApplicationViewCollection {1841C6D7-...}
//
// VERIFIED against the probe host's own binary: CApplicationViewManager chains
// IApplicationViewCollectionManagement -> IApplicationViewCollection in
// twinui.pcshell.dll 6.2.26100.8875, vftable rva 0x0075ca70.  actxprxy.dll has
// no marshalling stub for this IID (0 CInterfaceStubHeader references found),
// so the DispatchTableCount cross-check used elsewhere is not available here;
// the vtable dump against a live implementation class is the sole evidence,
// which is why this is Verified rather than something stronger.
// ===========================================================================
constexpr const char* kVerifiedAVC =
    "vtable dump of CApplicationViewManager (chain IApplicationViewCollectionManagement"
    " -> IApplicationViewCollection) in twinui.pcshell.dll 6.2.26100.8875";

constexpr MethodEntry kAppViewCollection_Methods[] = {
    {"GetViews", 3, "HRESULT GetViews(IObjectArray**)", Confidence::Verified,
     kVerifiedAVC, true, nullptr},
    {"GetViewsByZOrder", 4, "HRESULT GetViewsByZOrder(IObjectArray**)",
     Confidence::Verified, kVerifiedAVC, true, nullptr},
    {"GetViewsByAppUserModelId", 5,
     "HRESULT GetViewsByAppUserModelId(HSTRING, IObjectArray**)", Confidence::Verified,
     kVerifiedAVC, true, nullptr},
    {"GetViewForHwnd", 6, "HRESULT GetViewForHwnd(HWND, IApplicationView**)",
     Confidence::Verified, kVerifiedAVC, true, nullptr},
    {"GetViewInFocus", 9, "HRESULT GetViewInFocus(IApplicationView**)",
     Confidence::Verified, kVerifiedAVC, true, nullptr},
    {"RefreshCollection", 11, "HRESULT RefreshCollection()", Confidence::Verified,
     kVerifiedAVC, false, "mutates the collection cache; not a desktop mutation"},
};

// ===========================================================================
// IApplicationView {372E1D3B-...}
//
// VERIFIED: CWin32ApplicationView in twinui.pcshell.dll 6.2.26100.8875, vftable
// rva 0x0073E6E0.  IApplicationView derives from IInspectable, so slots 3..5
// are IInspectable's GetIids/GetRuntimeClassName/GetTrustLevel, not part of
// IApplicationView's own contract.
// ===========================================================================
constexpr const char* kVerifiedAV =
    "vtable dump of CWin32ApplicationView in twinui.pcshell.dll 6.2.26100.8875";

constexpr MethodEntry kAppView_Methods[] = {
    {"SetFocus", 6, "HRESULT SetFocus()", Confidence::Verified, kVerifiedAV, false,
     "IApplicationView derives from IInspectable; slots 3..5 are IInspectable"},
    {"SwitchTo", 7, "HRESULT SwitchTo()", Confidence::Verified, kVerifiedAV, false,
     "switches the current desktop to this view's desktop"},
    {"GetThumbnailWindow", 9, "HRESULT GetThumbnailWindow(HWND*)", Confidence::Verified,
     kVerifiedAV, true, nullptr},
    {"GetMonitor", 10, "HRESULT GetMonitor(IImmersiveMonitor**)", Confidence::Verified,
     kVerifiedAV, true, nullptr},
    {"GetVisibility", 11, "HRESULT GetVisibility(int*)", Confidence::Verified,
     kVerifiedAV, true, nullptr},
    {"GetVirtualDesktopId", 25, "HRESULT GetVirtualDesktopId(GUID*)",
     Confidence::Verified, kVerifiedAV, true, nullptr},
    {"SetVirtualDesktopId", 26, "HRESULT SetVirtualDesktopId(const GUID*)",
     Confidence::Verified, kVerifiedAV, false,
     "moves the view directly; distinct code path from "
     "IVirtualDesktopManagerInternal::MoveViewToDesktop"},
};

constexpr MethodEntry kNotifSvc_Methods[] = {
    {"Register", 3, "HRESULT Register(IVirtualDesktopNotification*, DWORD* pCookie)",
     Confidence::High, "Ciantic/VDA + MScholtes-era sources agree", false,
     "registering a sink mutates shell state; requires --confirm-register"},
    {"Unregister", 4, "HRESULT Unregister(DWORD cookie)", Confidence::High,
     "Ciantic/VDA", false, "undoes Register; also requires --confirm-register"},
};

// ===========================================================================
// IVirtualDesktopNotification {B9E5E94D-233E-49AB-AF5C-2B4541C3AADE}
//
// This is NOT a table of methods vdprobe calls through the gate.  It is the
// sink interface vdprobe *implements* so the shell can call back into it after
// IVirtualDesktopNotificationService::Register.  It is recorded here purely as
// documentation of the verified layout our sink class must match exactly.
//
// VERIFIED against a live, unchained implementer:
// CVirtualDesktopNotificationsDerived's pure-interface vtable slice in
// twinui.pcshell.dll 6.2.26100.8875, vftable rva 0x0074B4A0.  Every slot
// resolved to a distinctly-named method (no shared-thunk ambiguity), which is
// why this is Verified.  This layout DIFFERS from the published VDA Rust
// binding in two places: VirtualDesktopMoved takes two 32-bit UINTs here, not
// two 64-bit indices, and slot 9 (ViewVirtualDesktopChanged) sits after
// VirtualDesktopNameChanged rather than immediately after VirtualDesktopMoved.
// ===========================================================================
constexpr const char* kVerifiedNotif =
    "vtable dump of CVirtualDesktopNotificationsDerived (pure IVirtualDesktopNotification "
    "slice) in twinui.pcshell.dll 6.2.26100.8875, rva 0x0074B4A0";

constexpr MethodEntry kNotifSink_Methods[] = {
    {"VirtualDesktopCreated", 3, "HRESULT VirtualDesktopCreated(IVirtualDesktop*)",
     Confidence::Verified, kVerifiedNotif, true, "sink method, not called by vdprobe"},
    {"VirtualDesktopDestroyBegin", 4,
     "HRESULT VirtualDesktopDestroyBegin(IVirtualDesktop* destroyed, "
     "IVirtualDesktop* fallback)",
     Confidence::Verified, kVerifiedNotif, true, "sink method, not called by vdprobe"},
    {"VirtualDesktopDestroyFailed", 5,
     "HRESULT VirtualDesktopDestroyFailed(IVirtualDesktop* destroyed, "
     "IVirtualDesktop* fallback)",
     Confidence::Verified, kVerifiedNotif, true, "sink method, not called by vdprobe"},
    {"VirtualDesktopDestroyed", 6,
     "HRESULT VirtualDesktopDestroyed(IVirtualDesktop* destroyed, "
     "IVirtualDesktop* fallback)",
     Confidence::Verified, kVerifiedNotif, true, "sink method, not called by vdprobe"},
    {"VirtualDesktopMoved", 7,
     "HRESULT VirtualDesktopMoved(IVirtualDesktop*, UINT oldIndex, UINT newIndex)",
     Confidence::Verified, kVerifiedNotif, true,
     "sink method; two UINT32 (not i64) on this build"},
    {"VirtualDesktopNameChanged", 8,
     "HRESULT VirtualDesktopNameChanged(IVirtualDesktop*, HSTRING)", Confidence::Verified,
     kVerifiedNotif, true, "sink method, not called by vdprobe"},
    {"ViewVirtualDesktopChanged", 9,
     "HRESULT ViewVirtualDesktopChanged(IApplicationView*)", Confidence::Verified,
     kVerifiedNotif, true,
     "fires when a view's desktop assignment changes; central to Phase 2B"},
    {"CurrentVirtualDesktopChanged", 10,
     "HRESULT CurrentVirtualDesktopChanged(IVirtualDesktop* old, IVirtualDesktop* new)",
     Confidence::Verified, kVerifiedNotif, true,
     "fires on a GLOBAL desktop switch; the Phase 2B pass criterion is that this "
     "does NOT fire"},
    {"VirtualDesktopWallpaperChanged", 11,
     "HRESULT VirtualDesktopWallpaperChanged(IVirtualDesktop*, HSTRING)",
     Confidence::Verified, kVerifiedNotif, true, "sink method, not called by vdprobe"},
    {"VirtualDesktopSwitched", 12,
     "HRESULT VirtualDesktopSwitched(IVirtualDesktop*, VirtualDesktopSwitchType)",
     Confidence::Verified, kVerifiedNotif, true,
     "also indicates a global switch; monitored alongside CurrentVirtualDesktopChanged"},
    {"RemoteVirtualDesktopConnected", 13,
     "HRESULT RemoteVirtualDesktopConnected(IVirtualDesktop*)", Confidence::Verified,
     kVerifiedNotif, true, "sink method, not called by vdprobe"},
};

constexpr MethodEntry kPinnedApps_Methods[] = {
    {"IsAppIdPinned", 3, "HRESULT IsAppIdPinned(HSTRING appId, BOOL*)",
     Confidence::High, "MScholtes + VDA agree", true, nullptr},
    {"IsViewPinned", 6, "HRESULT IsViewPinned(IApplicationView*, BOOL*)",
     Confidence::High, "MScholtes + VDA agree", true, nullptr},
};

// ---------------------------------------------------------------- the tables

constexpr LayoutTable kLayouts[] = {
    {"IVirtualDesktopManagerInternal", &IID_VDMI_53F5CA0B,
     "Win11 23H2 22631.3085+ / 24H2 26100 / 25H2 26200", MonitorAware::No, true,
     kVDMI_53F5CA0B_Methods},
    {"IVirtualDesktopManagerInternal", &IID_VDMI_A3175F2D,
     "Win11 22H2 22621.2215+ / 23H2 pre-3085", MonitorAware::No, false,
     kVDMI_A3175F2D_Methods},
    {"IVirtualDesktopManagerInternal", &IID_VDMI_B2F925B9,
     "Win11 21H2 22000 / 22H2 pre-2215", MonitorAware::Yes, false,
     kVDMI_B2F925B9_Methods},
    {"IVirtualDesktopManagerInternal", &IID_VDMI_094AFE11, "Windows Server 2022 20348",
     MonitorAware::Yes, false, kVDMI_094AFE11_Methods},
    {"IVirtualDesktopManagerInternal", &IID_VDMI_F31574D6,
     "Win10 1607-21H2 / Server 2016", MonitorAware::No, false, kVDMI_F31574D6_Methods},
    {"IVirtualDesktop", &IID_VD_3F07F4BE, "Win11 23H2 3085+ / 24H2 / 25H2",
     MonitorAware::Unknown, true, kVD_3F07F4BE_Methods},
    {"IVirtualDesktop", &IID_VD_536D3495, "Win11 21H2 / 22H2", MonitorAware::Unknown,
     false, kVD_536D3495_Methods},
    {"IApplicationViewCollection", &IID_IApplicationViewCollection,
     "Win10 1607 .. Win11 25H2", MonitorAware::Unknown, true,
     kAppViewCollection_Methods},
    {"IApplicationView", &IID_IApplicationView, "Win10 1607 .. Win11 25H2",
     MonitorAware::Unknown, true, kAppView_Methods},
    {"IVirtualDesktopNotificationService", &IID_IVirtualDesktopNotificationService,
     "Win10 1607 .. Win11 25H2", MonitorAware::Unknown, true, kNotifSvc_Methods},
    // Documentation-only: the sink layout vdprobe's own COM object must match.
    // applicable_to_current_family=false because this row is never a target of
    // InvokeSlot(); CheckInvocable's NotApplicable branch guarantees that even a
    // programming error cannot turn this into a live call through the gate.
    {"IVirtualDesktopNotification", &IID_IVirtualDesktopNotification,
     "Win11 24H2/25H2 26100+ (sink layout vdprobe implements)", MonitorAware::Unknown,
     false, kNotifSink_Methods},
    {"IVirtualDesktopPinnedApps", &IID_IVirtualDesktopPinnedApps,
     "Win10 1607 .. Win11 25H2", MonitorAware::Unknown, true, kPinnedApps_Methods},
};

}  // namespace

const char* ConfidenceText(Confidence c) {
    switch (c) {
        case Confidence::Verified: return "VERIFIED";
        case Confidence::High:     return "high";
        case Confidence::Medium:   return "medium";
        case Confidence::Low:      return "low";
        case Confidence::Unknown:  return "unknown";
    }
    return "?";
}

const char* GateText(Gate g) {
    switch (g) {
        case Gate::Ok:               return "ok";
        case Gate::NoSuchMethod:     return "REFUSED: method not in layout registry";
        case Gate::SlotNotAgreed:    return "REFUSED: sources disagree on vtable slot";
        case Gate::LowConfidence:    return "REFUSED: slot confidence below 'high'";
        case Gate::NotApplicable:    return "REFUSED: layout is for a different build family";
        case Gate::Mutating:         return "REFUSED: method mutates shell state (read-only milestone)";
        case Gate::NoObject:         return "REFUSED: null interface pointer";
        case Gate::UnreadableVtable: return "REFUSED: vtable pointer not readable";
        case Gate::NotCodePointer:   return "REFUSED: slot does not hold image code pointer";
    }
    return "REFUSED";
}

std::span<const LayoutTable> Layouts() {
    return {kLayouts, sizeof(kLayouts) / sizeof(kLayouts[0])};
}

std::span<const LayoutTable> LayoutsFor(const char* iface) {
    const LayoutTable* first = nullptr;
    size_t count = 0;
    for (const LayoutTable& t : Layouts()) {
        if (std::strcmp(t.iface, iface) == 0) {
            if (!first) first = &t;
            ++count;
        } else if (first) {
            break;
        }
    }
    if (!first) return {};
    return {first, count};
}

const LayoutTable* LayoutForIid(const GUID& iid) {
    for (const LayoutTable& t : Layouts()) {
        if (t.iid && ::IsEqualGUID(*t.iid, iid)) return &t;
    }
    return nullptr;
}

const MethodEntry* FindMethod(const LayoutTable& t, const char* method) {
    for (const MethodEntry& m : t.methods) {
        if (std::strcmp(m.method, method) == 0) return &m;
    }
    return nullptr;
}

Gate CheckInvocable(IUnknown* obj, const LayoutTable& t, const MethodEntry& m,
                    bool allow_mutating) {
    if (obj == nullptr) return Gate::NoObject;
    if (!t.applicable_to_current_family) return Gate::NotApplicable;
    if (m.slot == kUnknownSlot) return Gate::SlotNotAgreed;
    if (m.confidence < Confidence::High) return Gate::LowConfidence;
    if (!m.read_only && !allow_mutating) return Gate::Mutating;

    void** vt = VtableOf(obj);
    if (vt == nullptr) return Gate::UnreadableVtable;
    if (!IsReadablePointer(&vt[m.slot], sizeof(void*))) return Gate::UnreadableVtable;
    if (!IsImageCodePointer(vt[m.slot])) return Gate::NotCodePointer;
    return Gate::Ok;
}

}  // namespace vd
