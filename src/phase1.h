// phase1.h - documented-API-only enumeration.  Nothing here touches private
// COM; it is all shipped Win32 / shobjidl_core.h surface.
#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace vd {

// ------------------------------------------------------------------- system

struct BuildInfo {
    // From ntdll!RtlGetVersion, which is not subject to app-compat shimming.
    DWORD major = 0;
    DWORD minor = 0;
    DWORD build = 0;
    // From HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion.
    DWORD ubr = 0;
    std::string display_version;   // e.g. "25H2"
    std::string product_name;
    std::string edition_id;
    std::string build_lab_ex;
    // Module versions that matter for virtual desktops.
    std::string explorer_version;
    std::string twinui_pcshell_version;
    std::string twinui_version;
    std::string actxprxy_version;
};

BuildInfo GetBuildInfo();

// Which private-interface generation the recorded layouts consider "current".
// Derived from `build`/`ubr` only, and reported so the reader can see the
// assumption rather than having it buried in the gate.
struct BuildFamily {
    const char* name;
    // Whether public sources say the per-monitor surface exists on this family.
    bool per_monitor_expected;
    const char* rationale;
};

BuildFamily ClassifyBuild(const BuildInfo& b);

// ------------------------------------------------------------------ monitors

struct MonitorRec {
    int index = 0;
    HMONITOR handle = nullptr;
    std::wstring device;     // \\.\DISPLAY1
    std::wstring friendly;   // adapter/monitor description
    RECT bounds{};
    RECT work{};
    bool primary = false;
    UINT dpi_x = 0;
    UINT dpi_y = 0;
};

std::vector<MonitorRec> EnumerateMonitors();

// ------------------------------------------------------------------- windows

struct WindowRec {
    HWND hwnd = nullptr;
    DWORD pid = 0;
    std::wstring class_name;
    std::wstring title;
    std::wstring process;
    RECT rect{};
    HMONITOR monitor = nullptr;
    int monitor_index = -1;
    bool visible = false;
    DWORD cloaked = 0;  // DWMWA_CLOAKED value, 0 = not cloaked
    // Filled by the documented IVirtualDesktopManager, when available.
    bool desktop_id_ok = false;
    GUID desktop_id{};
    bool on_current_desktop = false;
    HRESULT vdm_hr = S_OK;
};

// `all` = include invisible/untitled windows too.
std::vector<WindowRec> EnumerateTopLevelWindows(bool all);

// Fills desktop_id / on_current_desktop using CLSID_VirtualDesktopManager.
// Returns the HRESULT of creating the manager.
HRESULT AnnotateWithDesktopIds(std::vector<WindowRec>& windows);

// ---------------------------------------------------------------- subcommands

int CmdSystem();
int CmdMonitors();
int CmdWindows(bool all);

}  // namespace vd
