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
    bool tool_window = false;
    GUID desktop{};
    bool desktop_ok = false;
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
    bool tool_window = false;
    GUID desktop{};
    bool desktop_ok = false;
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
