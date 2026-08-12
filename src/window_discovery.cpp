#include "window_discovery.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

#include "util.h"

namespace vd {

namespace {

bool IsZeroGuid(const GUID& id) {
    static const GUID zero{};
    return ::IsEqualGUID(id, zero) != FALSE;
}

bool SameIdentity(const WindowIdentity& a, const WindowIdentity& b) {
    return a == b;
}

WindowDisposition Classify(const WindowDiscoveryObservation& observation) {
    // Child/owned windows are retained as observations, but never promoted to
    // independently manageable top-level records by this layer.
    if (observation.child || observation.owner != nullptr ||
        observation.tool_window ||
        !observation.capabilities.independent_top_level ||
        !observation.capabilities.owner_state_observable) {
        return WindowDisposition::Unsupported;
    }
    if (!observation.identity.IsValid() || observation.monitor == nullptr ||
        !observation.desktop_ok || IsZeroGuid(observation.desktop) ||
        (observation.native_role != NativeDesktopRole::Carrier &&
         observation.native_role != NativeDesktopRole::Parking)) {
        return WindowDisposition::Ambiguous;
    }
    if (!observation.capabilities.has_application_view ||
        !observation.capabilities.can_move_desktops ||
        !observation.capabilities.desktop_state_observable) {
        return WindowDisposition::Unsupported;
    }
    return WindowDisposition::Managed;
}

bool HasDuplicateHwnd(const std::vector<DiscoveredWindow>& windows, HWND hwnd) {
    return std::any_of(windows.begin(), windows.end(),
                       [&](const DiscoveredWindow& window) {
                           return window.identity.hwnd == hwnd;
                       });
}

bool HasDuplicateIdentity(const std::vector<DiscoveredWindow>& windows,
                          const WindowIdentity& identity) {
    return std::any_of(windows.begin(), windows.end(),
                       [&](const DiscoveredWindow& window) {
                           return SameIdentity(window.identity, identity);
                       });
}

}  // namespace

bool WindowDiscoveryBackend::EnumerateWindows(
    std::vector<HWND>& handles, bool& complete, std::string* error) const {
    handles.clear();
    complete = false;
    if (!enumerate_) {
        if (error != nullptr) *error = "window enumeration callback unavailable";
        return false;
    }
    return enumerate_(handles, complete, error);
}

bool WindowDiscoveryBackend::ObserveWindow(
    HWND hwnd, WindowDiscoveryObservation& observation,
    std::string* error) const {
    observation = {};
    if (!observe_) {
        if (error != nullptr) *error = "window observation callback unavailable";
        return false;
    }
    return observe_(hwnd, observation, error);
}

bool WindowDiscovery::Discover(std::vector<DiscoveredWindow>& out,
                               std::string* error) const {
    if (error != nullptr) *error = {};
    std::vector<HWND> handles;
    bool complete = false;
    std::string local_error;
    bool enumeration_ok = false;
    try {
        enumeration_ok =
            backend_.EnumerateWindows(handles, complete, &local_error);
    } catch (const std::exception& ex) {
        local_error = std::string("window enumeration callback threw: ") +
                      ex.what();
    } catch (...) {
        local_error = "window enumeration callback threw";
    }
    if (!enumeration_ok) {
        if (error != nullptr) *error = local_error.empty()
                                             ? "window enumeration failed"
                                             : local_error;
        return false;
    }
    if (!complete) {
        if (error != nullptr) *error = "window enumeration was incomplete";
        return false;
    }

    std::sort(handles.begin(), handles.end(),
              [](HWND a, HWND b) {
                  return reinterpret_cast<std::uintptr_t>(a) <
                         reinterpret_cast<std::uintptr_t>(b);
              });
    if (std::adjacent_find(handles.begin(), handles.end()) != handles.end()) {
        if (error != nullptr) *error = "duplicate HWND in complete enumeration";
        return false;
    }

    std::vector<DiscoveredWindow> candidate;
    candidate.reserve(handles.size());
    for (HWND hwnd : handles) {
        WindowDiscoveryObservation observation;
        local_error.clear();
        bool observation_ok = false;
        try {
            observation_ok =
                backend_.ObserveWindow(hwnd, observation, &local_error);
        } catch (const std::exception& ex) {
            local_error = std::string("window observation callback threw: ") +
                          ex.what();
        } catch (...) {
            local_error = "window observation callback threw";
        }
        if (!observation_ok) {
            if (error != nullptr) {
                *error = local_error.empty() ? "window observation failed"
                                             : local_error;
            }
            return false;
        }
        if (observation.identity.hwnd != hwnd ||
            !observation.identity.IsValid()) {
            if (error != nullptr) *error = "window identity changed during scan";
            return false;
        }
        if (HasDuplicateHwnd(candidate, hwnd) ||
            HasDuplicateIdentity(candidate, observation.identity)) {
            if (error != nullptr) *error = "duplicate HWND or window identity";
            return false;
        }

        DiscoveredWindow discovered;
        discovered.identity = observation.identity;
        discovered.monitor = observation.monitor;
        discovered.owner = observation.owner;
        discovered.child = observation.child;
        discovered.visible = observation.visible;
        discovered.tool_window = observation.tool_window;
        discovered.desktop = observation.desktop;
        discovered.desktop_ok = observation.desktop_ok;
        discovered.native_role = observation.native_role;
        discovered.capabilities = observation.capabilities;
        discovered.presentation = observation.presentation;
        discovered.disposition = Classify(observation);
        candidate.push_back(std::move(discovered));
    }

    out = std::move(candidate);
    return true;
}

const char* DiscoveryDispositionText(WindowDisposition disposition) noexcept {
    return WindowDispositionText(disposition);
}

int CmdWorkspaceDiscoveryTest() {
    Heading("workspace-discovery-test");
    GUID carrier{};
    carrier.Data1 = 0x10;

    auto identity = [](std::uintptr_t hwnd, DWORD pid,
                       DWORD creation_low) {
        WindowIdentity out;
        out.hwnd = reinterpret_cast<HWND>(hwnd);
        out.pid = pid;
        out.process_creation_time = {creation_low, 1};
        out.process_creation_time_ok = true;
        return out;
    };
    const WindowIdentity managed_id = identity(1, 100, 1);
    const WindowIdentity unsupported_id = identity(2, 101, 2);
    const WindowIdentity ambiguous_id = identity(3, 102, 3);
    const WindowIdentity owned_id = identity(4, 103, 4);

    const WindowCapabilities manageable{true, true, true, true, true};
    const WindowCapabilities no_view{false, false, true, true, true};

    std::vector<HWND> handles{
        managed_id.hwnd, unsupported_id.hwnd, ambiguous_id.hwnd,
        owned_id.hwnd};
    WindowDiscoveryBackend backend(
        [handles](std::vector<HWND>& out, bool& complete, std::string*) {
            out = handles;
            complete = true;
            return true;
        },
        [&](HWND hwnd, WindowDiscoveryObservation& out, std::string*) {
            out.monitor = reinterpret_cast<HMONITOR>(0x100);
            out.capabilities = manageable;
            out.desktop_ok = true;
            out.desktop = carrier;
            out.native_role = NativeDesktopRole::Carrier;
            if (hwnd == managed_id.hwnd) {
                out.identity = managed_id;
            } else if (hwnd == unsupported_id.hwnd) {
                out.identity = unsupported_id;
                out.capabilities = no_view;
            } else if (hwnd == ambiguous_id.hwnd) {
                out.identity = ambiguous_id;
                out.native_role = NativeDesktopRole::Unknown;
            } else {
                out.identity = owned_id;
                out.owner = managed_id.hwnd;
                out.capabilities.independent_top_level = false;
            }
            return true;
        });

    WindowDiscovery discovery(std::move(backend));
    std::vector<DiscoveredWindow> windows;
    std::string error;
    bool ok = discovery.Discover(windows, &error);
    ok = ok && windows.size() == 4 &&
         windows[0].disposition == WindowDisposition::Managed &&
         windows[1].disposition == WindowDisposition::Unsupported &&
         windows[2].disposition == WindowDisposition::Ambiguous &&
         windows[3].disposition == WindowDisposition::Unsupported;
    Field("classification", ok ? "PASS" : "FAIL");

    std::vector<DiscoveredWindow> preserved = windows;
    WindowDiscovery incomplete(
        WindowDiscoveryBackend(
            [](std::vector<HWND>&, bool& complete, std::string*) {
                complete = false;
                return true;
            },
            {}));
    error.clear();
    const bool incomplete_rejected =
        !incomplete.Discover(windows, &error) &&
        windows.size() == preserved.size() &&
        std::equal(windows.begin(), windows.end(), preserved.begin(),
                   [](const DiscoveredWindow& left,
                      const DiscoveredWindow& right) {
                       return left.identity == right.identity &&
                              left.disposition == right.disposition;
                   });
    Field("incomplete enumeration fail-closed",
          incomplete_rejected ? "PASS" : "FAIL");
    ok = ok && incomplete_rejected;

    WindowDiscovery duplicate(
        WindowDiscoveryBackend(
            [managed_id](std::vector<HWND>& out, bool& complete, std::string*) {
                out = {managed_id.hwnd, managed_id.hwnd};
                complete = true;
                return true;
            },
            [managed_id, manageable](HWND, WindowDiscoveryObservation& out,
                                     std::string*) {
                out.identity = managed_id;
                out.monitor = reinterpret_cast<HMONITOR>(0x100);
                out.desktop_ok = true;
                out.desktop.Data1 = 0x10;
                out.native_role = NativeDesktopRole::Carrier;
                out.capabilities = manageable;
                return true;
            }));
    error.clear();
    const bool duplicate_rejected = !duplicate.Discover(windows, &error);
    Field("duplicate HWND fail-closed",
          duplicate_rejected ? "PASS" : "FAIL");
    ok = ok && duplicate_rejected;

    WindowDiscovery tool_or_unobservable(
        WindowDiscoveryBackend(
            [managed_id](std::vector<HWND>& out, bool& complete, std::string*) {
                out = {managed_id.hwnd};
                complete = true;
                return true;
            },
            [managed_id, manageable, carrier](HWND,
                                     WindowDiscoveryObservation& out,
                                     std::string*) {
                out.identity = managed_id;
                out.monitor = reinterpret_cast<HMONITOR>(0x100);
                out.desktop_ok = true;
                out.desktop = carrier;
                out.native_role = NativeDesktopRole::Carrier;
                out.capabilities = manageable;
                out.tool_window = true;
                out.capabilities.owner_state_observable = false;
                return true;
            }));
    error.clear();
    const bool tool_rejected =
        tool_or_unobservable.Discover(windows, &error) &&
        windows.size() == 1 &&
        windows[0].disposition == WindowDisposition::Unsupported;
    Field("tool/owner-unobservable unsupported",
          tool_rejected ? "PASS" : "FAIL");
    ok = ok && tool_rejected;

    WindowDiscovery invalid_role(
        WindowDiscoveryBackend(
            [managed_id](std::vector<HWND>& out, bool& complete, std::string*) {
                out = {managed_id.hwnd};
                complete = true;
                return true;
            },
            [managed_id, manageable, carrier](HWND,
                                     WindowDiscoveryObservation& out,
                                     std::string*) {
                out.identity = managed_id;
                out.monitor = reinterpret_cast<HMONITOR>(0x100);
                out.desktop_ok = true;
                out.desktop = carrier;
                out.native_role = static_cast<NativeDesktopRole>(99);
                out.capabilities = manageable;
                return true;
            }));
    error.clear();
    const bool invalid_role_rejected =
        invalid_role.Discover(windows, &error) &&
        windows.size() == 1 &&
        windows[0].disposition == WindowDisposition::Ambiguous;
    Field("invalid native role ambiguous",
          invalid_role_rejected ? "PASS" : "FAIL");
    ok = ok && invalid_role_rejected;

    std::vector<DiscoveredWindow> before_throw = windows;
    WindowDiscovery throwing_enumerate(
        WindowDiscoveryBackend(
            [](std::vector<HWND>&, bool&, std::string*) -> bool {
                throw std::runtime_error("enumerate boom");
            },
            {}));
    error = "stale error";
    const bool enumerate_throw_rejected =
        !throwing_enumerate.Discover(windows, &error) &&
        windows.size() == before_throw.size() &&
        error.find("threw") != std::string::npos;
    Field("enumeration exception fail-closed",
          enumerate_throw_rejected ? "PASS" : "FAIL");
    ok = ok && enumerate_throw_rejected;

    WindowDiscovery throwing_observe(
        WindowDiscoveryBackend(
            [managed_id](std::vector<HWND>& out, bool& complete, std::string*) {
                out = {managed_id.hwnd};
                complete = true;
                return true;
            },
            [](HWND, WindowDiscoveryObservation&, std::string*) -> bool {
                throw std::runtime_error("observe boom");
            }));
    error = "stale error";
    const bool observe_throw_rejected =
        !throwing_observe.Discover(windows, &error) &&
        windows.size() == before_throw.size() &&
        error.find("threw") != std::string::npos;
    Field("observation exception fail-closed",
          observe_throw_rejected ? "PASS" : "FAIL");
    ok = ok && observe_throw_rejected;

    return ok ? 0 : 1;
}

}  // namespace vd
