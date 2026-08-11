#include "phase1.h"

#include <shobjidl.h>

#include <algorithm>
#include <cstring>

#include "comraw.h"
#include "util.h"
#include "vdids.h"

// DWM cloak query, declared here so we do not need to link dwmapi.
#ifndef DWMWA_CLOAKED
#define DWMWA_CLOAKED 14
#endif

namespace vd {
namespace {

using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
using GetDpiForMonitorFn = HRESULT(WINAPI*)(HMONITOR, int, UINT*, UINT*);
using DwmGetWindowAttributeFn = HRESULT(WINAPI*)(HWND, DWORD, PVOID, DWORD);

std::string RegString(HKEY root, const wchar_t* subkey, const wchar_t* name) {
    wchar_t buf[512]{};
    DWORD cb = sizeof(buf);
    DWORD type = 0;
    if (::RegGetValueW(root, subkey, name, RRF_RT_REG_SZ, &type, buf, &cb) !=
        ERROR_SUCCESS) {
        return {};
    }
    return ToUtf8(buf);
}

DWORD RegDword(HKEY root, const wchar_t* subkey, const wchar_t* name) {
    DWORD value = 0;
    DWORD cb = sizeof(value);
    if (::RegGetValueW(root, subkey, name, RRF_RT_REG_DWORD, nullptr, &value, &cb) !=
        ERROR_SUCCESS) {
        return 0;
    }
    return value;
}

std::wstring ProcessNameOf(DWORD pid) {
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h == nullptr) return L"?";
    wchar_t path[MAX_PATH]{};
    DWORD n = MAX_PATH;
    std::wstring out = L"?";
    if (::QueryFullProcessImageNameW(h, 0, path, &n) && n > 0) {
        std::wstring full(path, n);
        size_t slash = full.find_last_of(L'\\');
        out = (slash == std::wstring::npos) ? full : full.substr(slash + 1);
    }
    ::CloseHandle(h);
    return out;
}

struct MonitorEnumCtx {
    std::vector<MonitorRec>* out;
};

BOOL CALLBACK MonitorEnumProc(HMONITOR hmon, HDC, LPRECT, LPARAM lparam) {
    auto* ctx = reinterpret_cast<MonitorEnumCtx*>(lparam);
    MONITORINFOEXW mi{};
    mi.cbSize = sizeof(mi);
    if (!::GetMonitorInfoW(hmon, &mi)) return TRUE;

    MonitorRec rec;
    rec.index = static_cast<int>(ctx->out->size());
    rec.handle = hmon;
    rec.device = mi.szDevice;
    rec.bounds = mi.rcMonitor;
    rec.work = mi.rcWork;
    rec.primary = (mi.dwFlags & MONITORINFOF_PRIMARY) != 0;

    DISPLAY_DEVICEW dd{};
    dd.cb = sizeof(dd);
    if (::EnumDisplayDevicesW(mi.szDevice, 0, &dd, 0)) {
        rec.friendly = dd.DeviceString;
    }
    if (rec.friendly.empty()) {
        DISPLAY_DEVICEW adapter{};
        adapter.cb = sizeof(adapter);
        if (::EnumDisplayDevicesW(nullptr, 0, &adapter, 0)) rec.friendly = adapter.DeviceString;
    }

    static auto get_dpi =
        TryGetProcAs<GetDpiForMonitorFn>(L"shcore.dll", "GetDpiForMonitor");
    if (get_dpi != nullptr) {
        UINT dx = 0, dy = 0;
        if (SUCCEEDED(get_dpi(hmon, 0 /* MDT_EFFECTIVE_DPI */, &dx, &dy))) {
            rec.dpi_x = dx;
            rec.dpi_y = dy;
        }
    }
    ctx->out->push_back(std::move(rec));
    return TRUE;
}

struct WindowEnumCtx {
    std::vector<WindowRec>* out;
    bool all;
};

BOOL CALLBACK WindowEnumProc(HWND hwnd, LPARAM lparam) {
    auto* ctx = reinterpret_cast<WindowEnumCtx*>(lparam);
    const bool visible = ::IsWindowVisible(hwnd) != FALSE;

    wchar_t title[512]{};
    int tlen = ::GetWindowTextW(hwnd, title, 512);

    if (!ctx->all) {
        // Default view: the windows a user would consider "a window".
        if (!visible || tlen == 0) return TRUE;
        LONG_PTR ex = ::GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        if (ex & WS_EX_TOOLWINDOW) return TRUE;
        if (::GetWindow(hwnd, GW_OWNER) != nullptr) return TRUE;
    }

    WindowRec rec;
    rec.hwnd = hwnd;
    rec.visible = visible;
    rec.title.assign(title, static_cast<size_t>(tlen));
    wchar_t cls[256]{};
    int clen = ::GetClassNameW(hwnd, cls, 256);
    rec.class_name.assign(cls, static_cast<size_t>(std::max(clen, 0)));
    ::GetWindowThreadProcessId(hwnd, &rec.pid);
    rec.process = ProcessNameOf(rec.pid);
    ::GetWindowRect(hwnd, &rec.rect);
    rec.monitor = ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL);

    static auto dwm_get = TryGetProcAs<DwmGetWindowAttributeFn>(
        L"dwmapi.dll", "DwmGetWindowAttribute");
    if (dwm_get != nullptr) {
        DWORD cloaked = 0;
        if (SUCCEEDED(dwm_get(hwnd, DWMWA_CLOAKED, &cloaked, sizeof(cloaked)))) {
            rec.cloaked = cloaked;
        }
    }
    ctx->out->push_back(std::move(rec));
    return TRUE;
}

std::string RectText(const RECT& r) {
    return std::format("({},{})-({},{}) {}x{}", r.left, r.top, r.right, r.bottom,
                       r.right - r.left, r.bottom - r.top);
}

const char* CloakText(DWORD c) {
    switch (c) {
        case 0: return "no";
        case 1: return "app";
        case 2: return "shell(other-desktop)";
        case 4: return "inherited";
        default: return "yes";
    }
}

}  // namespace

// ------------------------------------------------------------------- system

BuildInfo GetBuildInfo() {
    BuildInfo b;
    static auto rtl_get_version =
        TryGetProcAs<RtlGetVersionFn>(L"ntdll.dll", "RtlGetVersion");
    if (rtl_get_version != nullptr) {
        RTL_OSVERSIONINFOW vi{};
        vi.dwOSVersionInfoSize = sizeof(vi);
        if (rtl_get_version(&vi) == 0) {
            b.major = vi.dwMajorVersion;
            b.minor = vi.dwMinorVersion;
            b.build = vi.dwBuildNumber;
        }
    }

    constexpr const wchar_t* kCv = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    b.ubr = RegDword(HKEY_LOCAL_MACHINE, kCv, L"UBR");
    b.display_version = RegString(HKEY_LOCAL_MACHINE, kCv, L"DisplayVersion");
    b.product_name = RegString(HKEY_LOCAL_MACHINE, kCv, L"ProductName");
    b.edition_id = RegString(HKEY_LOCAL_MACHINE, kCv, L"EditionID");
    b.build_lab_ex = RegString(HKEY_LOCAL_MACHINE, kCv, L"BuildLabEx");
    if (b.build == 0) {
        b.build = static_cast<DWORD>(
            std::strtoul(RegString(HKEY_LOCAL_MACHINE, kCv, L"CurrentBuild").c_str(),
                         nullptr, 10));
    }

    // explorer.exe lives in %WINDIR%, not System32.
    wchar_t windir[MAX_PATH]{};
    UINT n = ::GetWindowsDirectoryW(windir, MAX_PATH);
    if (n > 0) {
        b.explorer_version = FileVersionOf(std::wstring(windir, n) + L"\\explorer.exe");
    }
    b.twinui_pcshell_version = FileVersionOf(System32Path(L"twinui.pcshell.dll"));
    b.twinui_version = FileVersionOf(System32Path(L"twinui.dll"));
    b.actxprxy_version = FileVersionOf(System32Path(L"actxprxy.dll"));
    return b;
}

BuildFamily ClassifyBuild(const BuildInfo& b) {
    // Boundaries come from MScholtes' per-build source files, which are the
    // best-documented public record of when the interfaces changed.
    if (b.build >= 26100) {
        return {"Win11 24H2/25H2 (26100+)", false,
                "public sources for this family show IVirtualDesktopManagerInternal "
                "{53F5CA0B-...} with no HMONITOR parameters and no "
                "Get/SetDesktopIsPerMonitor"};
    }
    if (b.build >= 22631) {
        return {"Win11 23H2 (22631)", false,
                "22631.3085+ uses {53F5CA0B-...}; earlier 22631 uses {A3175F2D-...}; "
                "neither exposes a per-monitor surface"};
    }
    if (b.build >= 22621) {
        return {"Win11 22H2 (22621)", true,
                "builds below 22621.2215 use {B2F925B9-...} which IS monitor-aware and "
                "does expose Get/SetDesktopIsPerMonitor; .2215+ does not"};
    }
    if (b.build >= 22000) {
        return {"Win11 21H2 (22000)", true,
                "{B2F925B9-...} is monitor-aware and exposes "
                "Get/SetDesktopIsPerMonitor"};
    }
    if (b.build >= 20348) {
        return {"Windows Server 2022 (20348)", true,
                "{094AFE11-...} is monitor-aware and exposes GetDesktopIsPerMonitor "
                "(getter only)"};
    }
    if (b.build >= 10240) {
        return {"Windows 10", false, "{F31574D6-...} has no monitor parameters"};
    }
    return {"unknown", false, "build number not recognised"};
}

int CmdSystem() {
    BuildInfo b = GetBuildInfo();
    BuildFamily fam = ClassifyBuild(b);

    Heading("system");
    Field("RtlGetVersion", std::format("{}.{}.{}", b.major, b.minor, b.build));
    Field("UBR", std::format("{}", b.ubr));
    Field("full build", std::format("{}.{}.{}.{}", b.major, b.minor, b.build, b.ubr));
    Field("DisplayVersion", b.display_version.empty() ? "(none)" : b.display_version);
    Field("ProductName", b.product_name);
    Field("EditionID", b.edition_id);
    Field("BuildLabEx", b.build_lab_ex);

    Heading("shell modules");
    Field("explorer.exe", b.explorer_version.empty() ? "(none)" : b.explorer_version);
    Field("twinui.pcshell.dll",
          b.twinui_pcshell_version.empty() ? "(none)" : b.twinui_pcshell_version);
    Field("twinui.dll", b.twinui_version.empty() ? "(none)" : b.twinui_version);
    Field("actxprxy.dll", b.actxprxy_version.empty() ? "(none)" : b.actxprxy_version);
    Print(
        "  Two versions are shown where they differ: the StringFileInfo FileVersion\n"
        "  string first, then the binary VS_FIXEDFILEINFO fields, which Windows keeps\n"
        "  at 6.2.x on many shell modules for compatibility.  Neither is an error.\n");

    Heading("private interface generation");
    Field("build family", fam.name);
    Field("per-monitor expected", fam.per_monitor_expected ? "yes" : "no");
    Print("  rationale: {}\n", fam.rationale);
    Print(
        "\n  NOTE: 'expected' is derived from public sources only.  Run "
        "'vdprobe per-monitor-status'\n        for what this machine actually "
        "reports.\n");
    return 0;
}

// ------------------------------------------------------------------ monitors

std::vector<MonitorRec> EnumerateMonitors() {
    std::vector<MonitorRec> out;
    MonitorEnumCtx ctx{&out};
    ::EnumDisplayMonitors(nullptr, nullptr, MonitorEnumProc,
                          reinterpret_cast<LPARAM>(&ctx));
    return out;
}

int CmdMonitors() {
    std::vector<MonitorRec> mons = EnumerateMonitors();
    Heading("monitors");
    Field("count", std::format("{}", mons.size()));
    Field("virtual screen",
          std::format("({},{}) {}x{}", ::GetSystemMetrics(SM_XVIRTUALSCREEN),
                      ::GetSystemMetrics(SM_YVIRTUALSCREEN),
                      ::GetSystemMetrics(SM_CXVIRTUALSCREEN),
                      ::GetSystemMetrics(SM_CYVIRTUALSCREEN)));
    for (const MonitorRec& m : mons) {
        Print("\n  [{}] HMONITOR 0x{:016X}{}\n", m.index,
              reinterpret_cast<uintptr_t>(m.handle), m.primary ? "  (primary)" : "");
        Field("  device", ToUtf8(m.device));
        Field("  description", ToUtf8(m.friendly));
        Field("  bounds", RectText(m.bounds));
        Field("  work area", RectText(m.work));
        Field("  dpi", m.dpi_x ? std::format("{}x{} ({}%)", m.dpi_x, m.dpi_y,
                                             m.dpi_x * 100 / 96)
                               : "(unavailable)");
    }
    if (mons.size() < 2) {
        Print(
            "\n  NOTE: only one monitor is attached.  Per-monitor virtual desktop "
            "behaviour\n        cannot be observed on a single-monitor system.\n");
    }
    return 0;
}

// ------------------------------------------------------------------- windows

std::vector<WindowRec> EnumerateTopLevelWindows(bool all) {
    std::vector<WindowRec> out;
    WindowEnumCtx ctx{&out, all};
    ::EnumWindows(WindowEnumProc, reinterpret_cast<LPARAM>(&ctx));

    std::vector<MonitorRec> mons = EnumerateMonitors();
    for (WindowRec& w : out) {
        for (const MonitorRec& m : mons) {
            if (m.handle == w.monitor) {
                w.monitor_index = m.index;
                break;
            }
        }
    }
    return out;
}

HRESULT AnnotateWithDesktopIds(std::vector<WindowRec>& windows) {
    Com<IVirtualDesktopManager> vdm;
    HRESULT hr = ::CoCreateInstance(CLSID_VirtualDesktopManager, nullptr,
                                    CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER,
                                    IID_IVirtualDesktopManager, vdm.PutVoid());
    if (FAILED(hr)) return hr;

    for (WindowRec& w : windows) {
        GUID id{};
        HRESULT h1 = vdm->GetWindowDesktopId(w.hwnd, &id);
        w.vdm_hr = h1;
        if (SUCCEEDED(h1)) {
            w.desktop_id = id;
            w.desktop_id_ok = true;
        }
        BOOL on_current = FALSE;
        if (SUCCEEDED(vdm->IsWindowOnCurrentVirtualDesktop(w.hwnd, &on_current))) {
            w.on_current_desktop = on_current != FALSE;
        }
    }
    return S_OK;
}

int CmdWindows(bool all) {
    std::vector<WindowRec> wins = EnumerateTopLevelWindows(all);
    HRESULT hr = AnnotateWithDesktopIds(wins);

    Heading("windows");
    Field("count", std::format("{}", wins.size()));
    Field("filter", all ? "all top-level HWNDs" : "visible, titled, unowned, non-tool");
    Field("IVirtualDesktopManager", SUCCEEDED(hr) ? "obtained (documented API)"
                                                  : std::format("FAILED {}", HrToString(hr)));

    // Group by desktop GUID so the mapping is easy to read.
    Print("\n  {:<18} {:<4} {:<22} {:<28} {}\n", "HWND", "mon", "process", "class",
          "desktop GUID");
    Print("  {}\n", std::string(110, '-'));
    for (const WindowRec& w : wins) {
        std::string guid = w.desktop_id_ok ? GuidToString(w.desktop_id)
                                           : std::format("- {}", HrToString(w.vdm_hr));
        Print("  0x{:014X} {:<4} {:<22} {:<28} {}{}\n",
              reinterpret_cast<uintptr_t>(w.hwnd),
              w.monitor_index >= 0 ? std::format("{}", w.monitor_index) : "-",
              ToUtf8(w.process).substr(0, 22), ToUtf8(w.class_name).substr(0, 28), guid,
              w.on_current_desktop ? "  *current" : "");
    }

    // Cross-tabulate desktop GUID against monitor: this is the observation that
    // decides whether desktops are per-monitor in practice.
    Heading("desktop GUID x monitor cross-tab");
    std::vector<std::pair<std::string, std::vector<int>>> tab;
    for (const WindowRec& w : wins) {
        if (!w.desktop_id_ok) continue;
        std::string g = GuidToString(w.desktop_id);
        auto it = std::find_if(tab.begin(), tab.end(),
                               [&](const auto& e) { return e.first == g; });
        if (it == tab.end()) {
            tab.push_back({g, {}});
            it = tab.end() - 1;
        }
        if (std::find(it->second.begin(), it->second.end(), w.monitor_index) ==
            it->second.end()) {
            it->second.push_back(w.monitor_index);
        }
    }
    for (auto& [g, monitors] : tab) {
        std::sort(monitors.begin(), monitors.end());
        std::string list;
        for (int m : monitors) {
            if (!list.empty()) list += ",";
            list += (m < 0) ? "?" : std::format("{}", m);
        }
        Print("  {}  monitors: {}\n", g, list);
    }
    Print(
        "\n  Reading: if a single desktop GUID spans every monitor, the shell is "
        "treating\n  the desktop as global rather than per-monitor.\n");

    if (all) {
        Print("\n  cloak states (DWMWA_CLOAKED):\n");
        for (const WindowRec& w : wins) {
            if (w.cloaked == 0) continue;
            Print("    0x{:014X} {:<22} cloaked={}\n",
                  reinterpret_cast<uintptr_t>(w.hwnd), ToUtf8(w.process).substr(0, 22),
                  CloakText(w.cloaked));
        }
    }
    return 0;
}

}  // namespace vd
