#include "vdids.h"

#include <cstring>

namespace vd {
namespace {

// Helper so the definitions below read like the canonical registry form.
constexpr GUID G(uint32_t a, uint16_t b, uint16_t c, uint8_t d0, uint8_t d1, uint8_t d2,
                 uint8_t d3, uint8_t d4, uint8_t d5, uint8_t d6, uint8_t d7) {
    return GUID{a, b, c, {d0, d1, d2, d3, d4, d5, d6, d7}};
}

// Historical, low confidence.  Kept only so the probe can report a negative
// result for it instead of not looking.
constexpr GUID kNotifSvc_099B9B22 =
    G(0x099B9B22, 0xC0D6, 0x4638, 0xB4, 0x50, 0x83, 0x63, 0x1C, 0x9A, 0xC1, 0xD2);

}  // namespace

// -------------------------------------------------------------- classes / SIDs
//
// The four values below were read back out of twinui.pcshell.dll 6.2.26100.8875
// at the public data symbols SID_VirtualDesktopManager,
// SID_VirtualDesktopPinnedApps, SID_VirtualDesktopNotificationService and
// IID_IVirtualDesktopManager, so they are confirmed for the probe host rather
// than copied from a third party.

const GUID CLSID_VirtualDesktopManager =
    G(0xAA509086, 0x5CA9, 0x4C25, 0x8F, 0x95, 0x58, 0x9D, 0x3C, 0x07, 0xB4, 0x8A);
const GUID CLSID_ImmersiveShell =
    G(0xC2F03A33, 0x21F5, 0x47FA, 0xB4, 0xBB, 0x15, 0x63, 0x62, 0xA2, 0xF2, 0x39);

const GUID SID_VirtualDesktopManagerInternal =
    G(0xC5E0CDCA, 0x7B6E, 0x41B2, 0x9F, 0xC4, 0xD9, 0x39, 0x75, 0xCC, 0x46, 0x7B);
const GUID SID_VirtualDesktopPinnedApps =
    G(0xB5A399E7, 0x1C87, 0x46B8, 0x88, 0xE9, 0xFC, 0x57, 0x47, 0xB1, 0x71, 0xBD);
const GUID SID_VirtualDesktopNotificationService =
    G(0xA501FDEC, 0x4A09, 0x464C, 0xAE, 0x4E, 0x1B, 0x9C, 0x21, 0xB8, 0x49, 0x18);

const GUID IID_IServiceProvider_Shell =
    G(0x6D5140C1, 0x7436, 0x11CE, 0x80, 0x34, 0x00, 0xAA, 0x00, 0x60, 0x09, 0xFA);
const GUID IID_IVirtualDesktopManager =
    G(0xA5CD92FF, 0x29BE, 0x454C, 0x8D, 0x04, 0xD8, 0x28, 0x79, 0xFB, 0x3F, 0x1B);
const GUID IID_IObjectArray =
    G(0x92CA9DCD, 0x5622, 0x4BBA, 0xA8, 0x05, 0x5E, 0x9F, 0x54, 0x1B, 0xD8, 0xC9);

// ------------------------------------------------ per-build private interfaces

// Win11 23H2 22631.3085+ / 24H2 26100 / 25H2 26200.  Accepted by the live shell
// on the probe host and present in twinui.pcshell.dll and actxprxy.dll.
const GUID IID_VDMI_53F5CA0B =
    G(0x53F5CA0B, 0x158F, 0x4124, 0x90, 0x0C, 0x05, 0x71, 0x58, 0x06, 0x0B, 0x27);
// Win11 22H2 22621.2215 .. 23H2 pre-3085.  First revision with the per-monitor
// surface removed.
const GUID IID_VDMI_A3175F2D =
    G(0xA3175F2D, 0x239C, 0x4BD2, 0x8A, 0xA0, 0xEE, 0xBA, 0x8B, 0x0B, 0x13, 0x8E);
// Win11 21H2 22000 and 22H2 pre-2215.  Monitor-aware; exposes
// Get/SetDesktopIsPerMonitor.  21H2 and 22H2 share this IID but differ by one
// inserted slot, which is why an IID match is never treated as proof of layout.
const GUID IID_VDMI_B2F925B9 =
    G(0xB2F925B9, 0x5A0F, 0x4D2E, 0x9F, 0x4D, 0x2B, 0x15, 0x07, 0x59, 0x3C, 0x10);
// Windows Server 2022 (20348).  Monitor-aware; getter only.
const GUID IID_VDMI_094AFE11 =
    G(0x094AFE11, 0x44F2, 0x4BA0, 0x97, 0x6F, 0x29, 0xA9, 0x7E, 0x26, 0x3E, 0xE0);
// Windows 10 1607 .. 21H2 and Server 2016.
const GUID IID_VDMI_F31574D6 =
    G(0xF31574D6, 0xB682, 0x4CDC, 0xBD, 0x56, 0x18, 0x27, 0x86, 0x0A, 0xBE, 0xC6);

const GUID IID_VD_3F07F4BE =
    G(0x3F07F4BE, 0xB107, 0x441A, 0xAF, 0x0F, 0x39, 0xD8, 0x25, 0x29, 0x07, 0x2C);
const GUID IID_VD_536D3495 =
    G(0x536D3495, 0xB208, 0x4CC9, 0xAE, 0x26, 0xDE, 0x81, 0x11, 0x27, 0x5B, 0xF8);
const GUID IID_VD_FF72FFDD =
    G(0xFF72FFDD, 0xBE7E, 0x43FC, 0x9C, 0x03, 0xAD, 0x81, 0x68, 0x1E, 0x88, 0xE4);

const GUID IID_IApplicationView =
    G(0x372E1D3B, 0x38D3, 0x42E4, 0xA1, 0x5B, 0x8A, 0xB2, 0xB1, 0x78, 0xF5, 0x13);
const GUID IID_IApplicationViewCollection =
    G(0x1841C6D7, 0x4F9D, 0x42C0, 0xAF, 0x41, 0x87, 0x47, 0x53, 0x8F, 0x10, 0xE5);
const GUID IID_IVirtualDesktopNotificationService =
    G(0x0CD45E71, 0xD927, 0x4F15, 0x8B, 0x0A, 0x8F, 0xEF, 0x52, 0x53, 0x37, 0xBF);
const GUID IID_IVirtualDesktopPinnedApps =
    G(0x4CE81583, 0x1E4C, 0x4632, 0xA6, 0x21, 0x07, 0xA5, 0x35, 0x43, 0x14, 0x8F);

// Sink interface vdprobe implements to receive shell callbacks.  Present in
// this build's own symbols as the argument to
// VirtualDesktopNotificationForwarderHelper<...> and
// EventRegistrationHelpers::EventRegistration<IVirtualDesktopNotificationService,
// IVirtualDesktopNotification>; confirmed genuinely in active use, not legacy.
const GUID IID_IVirtualDesktopNotification =
    G(0xB9E5E94D, 0x233E, 0x49AB, 0xAF, 0x5C, 0x2B, 0x45, 0x41, 0xC3, 0xAA, 0xDE);

// ----------------------------------------------------------- candidate table

namespace {

constexpr const char* kMScholtes =
    "MScholtes/VirtualDesktop (C#), verified by download";
constexpr const char* kMScholtesHist =
    "MScholtes/VirtualDesktop @tag V1.15/V1.17 (C#), verified by download";
constexpr const char* kVDA =
    "Ciantic/VirtualDesktopAccessor branch 'rust' src/interfaces.rs";
constexpr const char* kHostVerified =
    "accepted by the live shell on the probe host; GUID bytes located in "
    "twinui.pcshell.dll and actxprxy.dll";

constexpr IidCandidate kTable[] = {
    // ---- IVirtualDesktopManagerInternal ---------------------------------
    {"IVirtualDesktopManagerInternal", &IID_VDMI_53F5CA0B,
     "Win11 23H2 22631.3085+ / 24H2 26100 / 25H2 26200", kHostVerified,
     MonitorAware::No},
    {"IVirtualDesktopManagerInternal", &IID_VDMI_A3175F2D,
     "Win11 22H2 22621.2215+ / 23H2 pre-3085", kMScholtesHist, MonitorAware::No},
    {"IVirtualDesktopManagerInternal", &IID_VDMI_B2F925B9,
     "Win11 21H2 22000 / 22H2 pre-2215", kMScholtesHist, MonitorAware::Yes},
    {"IVirtualDesktopManagerInternal", &IID_VDMI_094AFE11, "Windows Server 2022 20348",
     kMScholtes, MonitorAware::Yes},
    {"IVirtualDesktopManagerInternal", &IID_VDMI_F31574D6,
     "Win10 1607-21H2 / Server 2016", kMScholtes, MonitorAware::No},

    // ---- IVirtualDesktop -------------------------------------------------
    {"IVirtualDesktop", &IID_VD_3F07F4BE, "Win11 23H2 3085+ / 24H2 / 25H2",
     kHostVerified, MonitorAware::Unknown},
    {"IVirtualDesktop", &IID_VD_536D3495, "Win11 21H2 / 22H2", kMScholtesHist,
     MonitorAware::Unknown},
    {"IVirtualDesktop", &IID_VD_FF72FFDD, "Win10", kMScholtes, MonitorAware::Unknown},

    // ---- IApplicationView ------------------------------------------------
    {"IApplicationView", &IID_IApplicationView, "Win10 1607 .. Win11 25H2", kMScholtes,
     MonitorAware::Unknown},

    // ---- IApplicationViewCollection --------------------------------------
    {"IApplicationViewCollection", &IID_IApplicationViewCollection,
     "Win10 1607 .. Win11 25H2", kMScholtes, MonitorAware::Unknown},

    // ---- IVirtualDesktopNotificationService ------------------------------
    {"IVirtualDesktopNotificationService", &IID_IVirtualDesktopNotificationService,
     "Win10 1607 .. Win11 25H2", kVDA, MonitorAware::Unknown},
    {"IVirtualDesktopNotificationService", &kNotifSvc_099B9B22,
     "Win10 early builds (10130 era)", "historical, low confidence",
     MonitorAware::Unknown},

    // ---- IVirtualDesktopPinnedApps ---------------------------------------
    {"IVirtualDesktopPinnedApps", &IID_IVirtualDesktopPinnedApps,
     "Win10 1607 .. Win11 25H2", kMScholtes, MonitorAware::Unknown},

    // ---- documented ------------------------------------------------------
    {"IVirtualDesktopManager", &IID_IVirtualDesktopManager,
     "Win10 1607 .. Win11 25H2 (documented)", "Windows SDK shobjidl_core.h",
     MonitorAware::No},
};

constexpr const char* kIfaceOrder[] = {
    "IVirtualDesktopManager",
    "IVirtualDesktopManagerInternal",
    "IVirtualDesktop",
    "IApplicationView",
    "IApplicationViewCollection",
    "IVirtualDesktopNotificationService",
    "IVirtualDesktopNotification",
    "IVirtualDesktopPinnedApps",
};

}  // namespace

std::span<const IidCandidate> IidCandidates() {
    return {kTable, sizeof(kTable) / sizeof(kTable[0])};
}

const char* MonitorAwareText(MonitorAware m) {
    switch (m) {
        case MonitorAware::Yes:     return "YES";
        case MonitorAware::No:      return "no";
        case MonitorAware::Unknown: return "unknown";
    }
    return "?";
}

std::span<const IidCandidate> IidCandidatesFor(const char* iface) {
    // The table is grouped by interface, so return the contiguous run.
    const IidCandidate* first = nullptr;
    size_t count = 0;
    for (const IidCandidate& c : IidCandidates()) {
        if (std::strcmp(c.iface, iface) == 0) {
            if (first == nullptr) first = &c;
            ++count;
        } else if (first != nullptr) {
            break;
        }
    }
    if (first == nullptr) return {};
    return {first, count};
}

std::span<const char* const> KnownInterfaces() {
    return {kIfaceOrder, sizeof(kIfaceOrder) / sizeof(kIfaceOrder[0])};
}

}  // namespace vd
