// Read-only, application-neutral top-level window discovery.
//
// The discovery layer deliberately stops before workspace assignment and
// native mutation.  A caller supplies the platform observation callbacks
// (including the private IApplicationView lookup when available); this module
// validates the complete snapshot and classifies each HWND by runtime
// capability rather than executable name.
#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "workspace_engine.h"

namespace vd {

struct DiscoveredWindow {
    WindowIdentity identity;
    HMONITOR monitor = nullptr;
    HWND owner = nullptr;
    bool child = false;
    bool visible = false;
    DWORD cloaked = 0;
    bool cloaked_ok = false;
    bool tool_window = false;
    GUID desktop{};
    bool desktop_ok = false;
    bool on_current = false;
    bool on_current_ok = false;
    NativeDesktopRole native_role = NativeDesktopRole::Unknown;
    WindowCapabilities capabilities{};
    WindowPresentation presentation{};
    WindowDisposition disposition = WindowDisposition::Ambiguous;
};

struct WindowDiscoveryObservation {
    WindowIdentity identity;
    HMONITOR monitor = nullptr;
    HWND owner = nullptr;
    bool child = false;
    bool visible = false;
    DWORD cloaked = 0;
    bool cloaked_ok = false;
    bool tool_window = false;
    GUID desktop{};
    bool desktop_ok = false;
    bool on_current = false;
    bool on_current_ok = false;
    NativeDesktopRole native_role = NativeDesktopRole::Unknown;
    WindowCapabilities capabilities{};
    WindowPresentation presentation{};
};

class WindowDiscoveryBackend {
   public:
    using Enumerate = std::function<bool(std::vector<HWND>& handles,
                                         bool& complete,
                                         std::string* error)>;
    using Observe = std::function<bool(HWND hwnd,
                                       WindowDiscoveryObservation& observation,
                                       std::string* error)>;

    WindowDiscoveryBackend(Enumerate enumerate, Observe observe)
        : enumerate_(std::move(enumerate)), observe_(std::move(observe)) {}

    bool EnumerateWindows(std::vector<HWND>& handles, bool& complete,
                          std::string* error) const;
    bool ObserveWindow(HWND hwnd, WindowDiscoveryObservation& observation,
                       std::string* error) const;

   private:
    Enumerate enumerate_;
    Observe observe_;
};

// Injectable documented-Win32 seam used by the production backend.  The
// system factory below supplies EnumWindows, process-generation identity,
// presentation reads, and the documented IVirtualDesktopManager.  Tests can
// inject this seam without touching any live HWND or COM state.
struct Win32WindowObservation {
    HMONITOR monitor = nullptr;
    HWND owner = nullptr;
    bool child = false;
    bool visible = false;
    bool tool_window = false;
    DWORD cloaked = 0;
    bool cloaked_ok = false;
    WindowPresentation presentation{};
};

struct Win32DesktopObservation {
    GUID desktop{};
    bool desktop_ok = false;
    bool on_current = false;
    bool on_current_ok = false;
};

struct Win32WindowDiscoveryApi {
    using Enumerate =
        std::function<bool(std::vector<HWND>& handles, std::string* error)>;
    using ReadIdentity = std::function<bool(HWND hwnd, WindowIdentity& identity,
                                            std::string* error)>;
    using ReadWindow =
        std::function<bool(HWND hwnd, Win32WindowObservation& observation,
                           std::string* error)>;
    using ReadDesktop =
        std::function<bool(HWND hwnd, Win32DesktopObservation& observation,
                           std::string* error)>;

    Enumerate enumerate;
    ReadIdentity read_identity;
    ReadWindow read_window;
    ReadDesktop read_desktop;
};

struct Win32WindowDiscoveryOptions {
    using AugmentCapabilities = std::function<bool(
        HWND hwnd, const WindowDiscoveryObservation& observation,
        WindowCapabilities& capabilities, std::string* error)>;

    GUID carrier{};
    GUID parking{};
    // Optional private-IApplicationView augmentation.  Without it, discovery
    // remains useful and read-only, but every HWND fails closed as Unsupported
    // because has_application_view/can_move_desktops are not assumed.
    AugmentCapabilities augment_capabilities;
};

// Builds the application-neutral backend around an injected read-only API.
// This is public so a production IApplicationView resolver can be supplied as
// an augmentation without moving private Shell calls into discovery.
std::optional<WindowDiscoveryBackend> CreateWin32WindowDiscoveryBackend(
    Win32WindowDiscoveryOptions options, Win32WindowDiscoveryApi api,
    std::string* error = nullptr);

// Production factory: EnumWindows plus documented Win32 and
// IVirtualDesktopManager reads only.  COM must already be initialized on the
// calling thread.  No workspace assignment or native mutation is performed.
std::optional<WindowDiscoveryBackend> CreateSystemWindowDiscoveryBackend(
    Win32WindowDiscoveryOptions options, std::string* error = nullptr,
    HRESULT* bootstrap_hr = nullptr);

class WindowDiscovery {
   public:
    explicit WindowDiscovery(WindowDiscoveryBackend backend)
        : backend_(std::move(backend)) {}

    // Produces one validated, deterministic snapshot.  On any incomplete
    // enumeration, observation failure, duplicate identity, or unstable
    // top-level state, `out` is left unchanged and false is returned.
    bool Discover(std::vector<DiscoveredWindow>& out,
                  std::string* error = nullptr) const;

   private:
    WindowDiscoveryBackend backend_;
};

const char* DiscoveryDispositionText(WindowDisposition disposition) noexcept;

// Deterministic, non-mutating classification test.  No COM, HWND enumeration,
// native desktop, or user-window state is touched.
int CmdWorkspaceDiscoveryTest();

}  // namespace vd
