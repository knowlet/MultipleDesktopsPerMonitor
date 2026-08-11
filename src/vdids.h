// vdids.h - CLSIDs, service IDs and the per-build IID candidate table.
//
// Nothing in here is invented.  Every candidate carries the build family it was
// observed on and the source it came from, and the probe reports which one the
// running system actually accepts.
#pragma once

#include <windows.h>
#include <objbase.h>

#include <cstddef>
#include <cstdint>
#include <span>

namespace vd {

// ------------------------------------------------------------------- classes

// CoCreateInstance-able, documented.
extern const GUID CLSID_VirtualDesktopManager;

// CoCreateInstance-able, undocumented; exposes IServiceProvider for the shell.
extern const GUID CLSID_ImmersiveShell;

// Service IDs passed as the first argument to IServiceProvider::QueryService.
extern const GUID SID_VirtualDesktopManagerInternal;
extern const GUID SID_VirtualDesktopPinnedApps;
extern const GUID SID_VirtualDesktopNotificationService;

// Documented / stable IIDs.
extern const GUID IID_IServiceProvider_Shell;  // 6D5140C1-... (SHIID)
extern const GUID IID_IVirtualDesktopManager;  // documented, shobjidl_core.h
extern const GUID IID_IObjectArray;

// ------------------------------------------------------ per-build private IIDs
//
// Named so that vdlayout.cpp can bind a vtable layout to an IID by reference
// rather than by matching description strings.

// IVirtualDesktopManagerInternal, newest first.
extern const GUID IID_VDMI_53F5CA0B;  // Win11 23H2 3085+ / 24H2 / 25H2
extern const GUID IID_VDMI_A3175F2D;  // Win11 22H2 2215+ / 23H2 pre-3085
extern const GUID IID_VDMI_B2F925B9;  // Win11 21H2 / 22H2 pre-2215  (per-monitor)
extern const GUID IID_VDMI_094AFE11;  // Windows Server 2022         (per-monitor)
extern const GUID IID_VDMI_F31574D6;  // Windows 10 / Server 2016

// IVirtualDesktop.
extern const GUID IID_VD_3F07F4BE;  // Win11 23H2 3085+ / 24H2 / 25H2
extern const GUID IID_VD_536D3495;  // Win11 21H2 / 22H2
extern const GUID IID_VD_FF72FFDD;  // Windows 10

// Support interfaces (stable across the Win10/Win11 range).
extern const GUID IID_IApplicationView;
extern const GUID IID_IApplicationViewCollection;
extern const GUID IID_IVirtualDesktopNotificationService;
extern const GUID IID_IVirtualDesktopPinnedApps;

// IVirtualDesktopNotification - the sink interface *we* implement so the shell
// can call back into vdprobe.  This is the callee side: vdprobe is the server,
// the shell is the client.  The layout must match this build's own binary
// exactly (verified by vtable dump against twinui.pcshell.dll), because a wrong
// shape here corrupts explorer.exe's call, not just vdprobe's.
extern const GUID IID_IVirtualDesktopNotification;

// ------------------------------------------------------------- IID candidates

// Whether the vtable layout historically associated with an IID takes an
// HMONITOR (or HWND-or-HMONITOR) discriminator on its desktop query methods.
enum class MonitorAware {
    No,       // layout has no monitor parameter
    Yes,      // layout takes HMONITOR/HWND-or-HMONITOR
    Unknown,  // not established
};

const char* MonitorAwareText(MonitorAware m);

struct IidCandidate {
    const char* iface;      // logical interface name
    const GUID* iid;        //
    const char* builds;     // build family the IID was observed on
    const char* source;     // where the value came from
    MonitorAware monitor;   // monitor-awareness of the *associated* layout
};

// All candidates, ordered newest-first per interface.
std::span<const IidCandidate> IidCandidates();

// Candidates for one logical interface name.
std::span<const IidCandidate> IidCandidatesFor(const char* iface);

// Logical interface names this probe knows about, in report order.
std::span<const char* const> KnownInterfaces();

}  // namespace vd
