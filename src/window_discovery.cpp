#include "window_discovery.h"

#include <shobjidl.h>

#include <algorithm>
#include <format>
#include <memory>
#include <stdexcept>
#include <utility>

#include "comraw.h"
#include "util.h"
#include "vdids.h"

namespace vd {

namespace {

bool IsZeroGuid(const GUID& id) {
    static const GUID zero{};
    return ::IsEqualGUID(id, zero) != FALSE;
}

bool SameIdentity(const WindowIdentity& a, const WindowIdentity& b) {
    return a == b;
}

bool SameGuid(const GUID& a, const GUID& b) {
    return ::IsEqualGUID(a, b) != FALSE;
}

std::string Win32Error(const char* operation, DWORD error) {
    return std::format("{} failed (Win32 {})", operation, error);
}

bool ReadWindowLong(HWND hwnd, int index, LONG_PTR& value) {
    ::SetLastError(ERROR_SUCCESS);
    value = ::GetWindowLongPtrW(hwnd, index);
    return value != 0 || ::GetLastError() == ERROR_SUCCESS;
}

using DwmGetWindowAttributeFn =
    HRESULT(WINAPI*)(HWND, DWORD, PVOID, DWORD);

bool TryReadCloaked(HWND hwnd, DWORD& cloaked) {
    static const auto get_attribute = [] {
        HMODULE module = ::GetModuleHandleW(L"dwmapi.dll");
        if (module == nullptr) module = ::LoadLibraryW(L"dwmapi.dll");
        return module == nullptr
                   ? nullptr
                   : reinterpret_cast<DwmGetWindowAttributeFn>(
                         ::GetProcAddress(module, "DwmGetWindowAttribute"));
    }();
    constexpr DWORD kDwmwaCloaked = 14;
    cloaked = 0;
    return get_attribute != nullptr &&
           SUCCEEDED(get_attribute(hwnd, kDwmwaCloaked, &cloaked,
                                   sizeof(cloaked)));
}

struct EnumContext {
    std::vector<HWND>* handles = nullptr;
    bool allocation_failed = false;
};

BOOL CALLBACK CollectTopLevelWindow(HWND hwnd, LPARAM parameter) {
    auto* context = reinterpret_cast<EnumContext*>(parameter);
    try {
        context->handles->push_back(hwnd);
        return TRUE;
    } catch (...) {
        context->allocation_failed = true;
        ::SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }
}

Win32WindowDiscoveryApi MakeSystemApi(std::string* error,
                                     HRESULT* bootstrap_hr) {
    Win32WindowDiscoveryApi api;
    if (bootstrap_hr != nullptr) *bootstrap_hr = S_OK;

    auto manager = std::make_shared<Com<IVirtualDesktopManager>>();
    const HRESULT hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER,
        IID_IVirtualDesktopManager, manager->PutVoid());
    if (FAILED(hr)) {
        if (bootstrap_hr != nullptr) *bootstrap_hr = hr;
        if (error != nullptr) {
            *error = std::format(
                "documented IVirtualDesktopManager unavailable ({})",
                HrToString(hr));
        }
        return api;
    }

    api.enumerate = [](std::vector<HWND>& handles, std::string* local_error) {
        handles.clear();
        EnumContext context{&handles, false};
        ::SetLastError(ERROR_SUCCESS);
        if (!::EnumWindows(CollectTopLevelWindow,
                           reinterpret_cast<LPARAM>(&context))) {
            const DWORD code = ::GetLastError();
            if (local_error != nullptr) {
                *local_error = context.allocation_failed
                                   ? "EnumWindows result allocation failed"
                                   : Win32Error("EnumWindows", code);
            }
            return false;
        }
        return true;
    };

    api.read_identity = [](HWND hwnd, WindowIdentity& identity,
                           std::string* local_error) {
        identity = {};
        if (hwnd == nullptr || !::IsWindow(hwnd)) {
            if (local_error != nullptr) *local_error = "HWND no longer exists";
            return false;
        }
        DWORD pid = 0;
        ::GetWindowThreadProcessId(hwnd, &pid);
        if (pid == 0) {
            if (local_error != nullptr) {
                *local_error = "GetWindowThreadProcessId returned no PID";
            }
            return false;
        }
        HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                       FALSE, pid);
        if (process == nullptr) {
            if (local_error != nullptr) {
                *local_error = Win32Error("OpenProcess", ::GetLastError());
            }
            return false;
        }
        FILETIME exit_time{};
        FILETIME kernel_time{};
        FILETIME user_time{};
        FILETIME creation_time{};
        const BOOL times_ok = ::GetProcessTimes(
            process, &creation_time, &exit_time, &kernel_time, &user_time);
        const DWORD times_error = times_ok ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(process);

        DWORD revalidated_pid = 0;
        ::GetWindowThreadProcessId(hwnd, &revalidated_pid);
        if (!times_ok || !::IsWindow(hwnd) || revalidated_pid != pid) {
            if (local_error != nullptr) {
                *local_error = times_ok
                                   ? "HWND identity changed during observation"
                                   : Win32Error("GetProcessTimes",
                                                times_error);
            }
            return false;
        }
        identity.hwnd = hwnd;
        identity.pid = pid;
        identity.process_creation_time = creation_time;
        identity.process_creation_time_ok = true;
        return true;
    };

    api.read_window = [](HWND hwnd, Win32WindowObservation& observation,
                         std::string* local_error) {
        observation = {};
        LONG_PTR style = 0;
        LONG_PTR extended_style = 0;
        if (!::IsWindow(hwnd) || !ReadWindowLong(hwnd, GWL_STYLE, style) ||
            !ReadWindowLong(hwnd, GWL_EXSTYLE, extended_style)) {
            if (local_error != nullptr) {
                *local_error = "window style unavailable or HWND vanished";
            }
            return false;
        }
        observation.owner = ::GetWindow(hwnd, GW_OWNER);
        observation.child = (style & WS_CHILD) != 0;
        observation.visible = ::IsWindowVisible(hwnd) != FALSE;
        observation.tool_window = (extended_style & WS_EX_TOOLWINDOW) != 0;
        observation.monitor =
            ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL);
        observation.cloaked_ok =
            TryReadCloaked(hwnd, observation.cloaked);

        observation.presentation.rect_valid =
            ::GetWindowRect(hwnd, &observation.presentation.rect) != FALSE;
        observation.presentation.placement.length = sizeof(WINDOWPLACEMENT);
        observation.presentation.placement_valid =
            ::GetWindowPlacement(hwnd,
                                 &observation.presentation.placement) != FALSE;
        observation.presentation.foreground =
            ::GetForegroundWindow() == hwnd;
        // EnumWindows is ordered top-to-bottom, but WindowDiscovery sorts the
        // complete HWND set for deterministic validation.  Reconstruct a
        // bounded relative rank using documented GW_HWNDPREV reads.
        constexpr std::int64_t kMaxZOrderWalk = 10000;
        HWND previous = hwnd;
        while (observation.presentation.z_order < kMaxZOrderWalk &&
               (previous = ::GetWindow(previous, GW_HWNDPREV)) != nullptr) {
            ++observation.presentation.z_order;
        }
        return true;
    };

    api.read_desktop =
        [manager](HWND hwnd, Win32DesktopObservation& observation,
                  std::string*) {
            observation = {};
            const HRESULT desktop_hr =
                (*manager)->GetWindowDesktopId(hwnd, &observation.desktop);
            observation.desktop_ok = SUCCEEDED(desktop_hr);
            BOOL on_current = FALSE;
            const HRESULT current_hr =
                (*manager)->IsWindowOnCurrentVirtualDesktop(hwnd, &on_current);
            observation.on_current_ok = SUCCEEDED(current_hr);
            observation.on_current = on_current != FALSE;
            // Per-HWND failures are observations, not an incomplete scan.  In
            // particular, Shell-owned helper HWNDs need not expose a desktop.
            return true;
        };
    return api;
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

std::optional<WindowDiscoveryBackend> CreateWin32WindowDiscoveryBackend(
    Win32WindowDiscoveryOptions options, Win32WindowDiscoveryApi api,
    std::string* error) {
    if (error != nullptr) *error = {};
    if (!api.enumerate || !api.read_identity || !api.read_window ||
        !api.read_desktop) {
        if (error != nullptr) {
            *error = "Win32 discovery API is missing a required read callback";
        }
        return std::nullopt;
    }
    if (IsZeroGuid(options.carrier) || IsZeroGuid(options.parking) ||
        SameGuid(options.carrier, options.parking)) {
        if (error != nullptr) {
            *error = "Carrier and Parking must be distinct non-null GUIDs";
        }
        return std::nullopt;
    }

    auto shared_api = std::make_shared<Win32WindowDiscoveryApi>(std::move(api));
    auto shared_options =
        std::make_shared<Win32WindowDiscoveryOptions>(std::move(options));
    WindowDiscoveryBackend backend(
        [shared_api](std::vector<HWND>& handles, bool& complete,
                     std::string* local_error) {
            complete = false;
            if (!shared_api->enumerate(handles, local_error)) return false;
            complete = true;
            return true;
        },
        [shared_api, shared_options](HWND hwnd,
                                     WindowDiscoveryObservation& observation,
                                     std::string* local_error) {
            observation = {};
            WindowIdentity identity;
            Win32WindowObservation window;
            Win32DesktopObservation desktop;
            const bool identity_ok =
                shared_api->read_identity(hwnd, identity, local_error);
            const bool window_ok =
                shared_api->read_window(hwnd, window, local_error);
            const bool desktop_ok =
                shared_api->read_desktop(hwnd, desktop, local_error);
            if (!identity_ok || !window_ok || !desktop_ok) {
                if (identity.hwnd == nullptr) identity.hwnd = hwnd;
                observation.identity = identity;
                observation.monitor = window.monitor;
                observation.owner = window.owner;
                observation.child = window.child;
                observation.visible = window.visible;
                observation.cloaked = window.cloaked;
                observation.cloaked_ok = window.cloaked_ok;
                observation.tool_window = window.tool_window;
                observation.desktop = desktop.desktop;
                observation.desktop_ok = desktop.desktop_ok;
                observation.on_current = desktop.on_current;
                observation.on_current_ok = desktop.on_current_ok;
                observation.presentation = window.presentation;
                // Base capability derivation stays the same as the normal
                // path so the missing identity classifies Ambiguous rather
                // than being misreported as Unsupported.  Private
                // IApplicationView augmentation is skipped for an
                // unreadable window.
                observation.capabilities.independent_top_level =
                    !window.child && window.owner == nullptr &&
                    !window.tool_window;
                observation.capabilities.desktop_state_observable =
                    desktop.desktop_ok && desktop.on_current_ok;
                observation.capabilities.owner_state_observable =
                    window.owner == nullptr;
                return true;
            }

            observation.identity = identity;
            observation.monitor = window.monitor;
            observation.owner = window.owner;
            observation.child = window.child;
            observation.visible = window.visible;
            observation.cloaked = window.cloaked;
            observation.cloaked_ok = window.cloaked_ok;
            observation.tool_window = window.tool_window;
            observation.desktop = desktop.desktop;
            observation.desktop_ok = desktop.desktop_ok;
            observation.on_current = desktop.on_current;
            observation.on_current_ok = desktop.on_current_ok;
            observation.presentation = window.presentation;

            observation.capabilities.independent_top_level =
                !window.child && window.owner == nullptr &&
                !window.tool_window;
            observation.capabilities.desktop_state_observable =
                desktop.desktop_ok && desktop.on_current_ok;
            observation.capabilities.owner_state_observable =
                window.owner == nullptr;

            if (desktop.desktop_ok &&
                SameGuid(desktop.desktop, shared_options->carrier)) {
                observation.native_role = NativeDesktopRole::Carrier;
            } else if (desktop.desktop_ok &&
                       SameGuid(desktop.desktop, shared_options->parking)) {
                observation.native_role = NativeDesktopRole::Parking;
            }

            if (shared_options->augment_capabilities) {
                WindowCapabilities augmented = observation.capabilities;
                if (!shared_options->augment_capabilities(
                        hwnd, observation, augmented, local_error)) {
                    return false;
                }
                // The private augmentation may establish only private Shell
                // capability.  It cannot relax the documented HWND safety
                // classification derived above.
                observation.capabilities.has_application_view =
                    augmented.has_application_view;
                observation.capabilities.can_move_desktops =
                    augmented.can_move_desktops;
            }

            WindowIdentity revalidated_identity;
            if (!shared_api->read_identity(hwnd, revalidated_identity,
                                           local_error) ||
                revalidated_identity != identity) {
                if (local_error != nullptr && local_error->empty()) {
                    *local_error =
                        "HWND identity changed during complete observation";
                }
                return false;
            }
            return true;
        });
    return backend;
}

std::optional<WindowDiscoveryBackend> CreateSystemWindowDiscoveryBackend(
    Win32WindowDiscoveryOptions options, std::string* error,
    HRESULT* bootstrap_hr) {
    if (error != nullptr) *error = {};
    Win32WindowDiscoveryApi api = MakeSystemApi(error, bootstrap_hr);
    if (!api.enumerate) return std::nullopt;
    return CreateWin32WindowDiscoveryBackend(std::move(options),
                                              std::move(api), error);
}

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
        if (observation.identity.hwnd != hwnd) {
            if (error != nullptr) *error = "window identity changed during scan";
            return false;
        }
        if (HasDuplicateHwnd(candidate, hwnd) ||
            (observation.identity.IsValid() &&
             HasDuplicateIdentity(candidate, observation.identity))) {
            if (error != nullptr) *error = "duplicate HWND or window identity";
            return false;
        }

        DiscoveredWindow discovered;
        discovered.identity = observation.identity;
        discovered.monitor = observation.monitor;
        discovered.owner = observation.owner;
        discovered.child = observation.child;
        discovered.visible = observation.visible;
        discovered.cloaked = observation.cloaked;
        discovered.cloaked_ok = observation.cloaked_ok;
        discovered.tool_window = observation.tool_window;
        discovered.desktop = observation.desktop;
        discovered.desktop_ok = observation.desktop_ok;
        discovered.on_current = observation.on_current;
        discovered.on_current_ok = observation.on_current_ok;
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

    GUID parking{};
    parking.Data1 = 0x20;
    std::size_t identity_reads = 0;
    std::size_t augment_calls = 0;
    Win32WindowDiscoveryApi win32_api;
    win32_api.enumerate =
        [managed_id](std::vector<HWND>& out, std::string*) {
            out = {managed_id.hwnd};
            return true;
        };
    win32_api.read_identity =
        [managed_id, &identity_reads](HWND, WindowIdentity& out,
                                      std::string*) {
            ++identity_reads;
            out = managed_id;
            return true;
        };
    win32_api.read_window =
        [](HWND, Win32WindowObservation& out, std::string*) {
            out.monitor = reinterpret_cast<HMONITOR>(0x100);
            out.visible = true;
            out.cloaked = 0;
            out.cloaked_ok = true;
            out.presentation.rect = {10, 20, 210, 220};
            out.presentation.rect_valid = true;
            out.presentation.placement.length = sizeof(WINDOWPLACEMENT);
            out.presentation.placement_valid = true;
            out.presentation.foreground = true;
            out.presentation.z_order = 3;
            return true;
        };
    win32_api.read_desktop =
        [carrier](HWND, Win32DesktopObservation& out, std::string*) {
            out.desktop = carrier;
            out.desktop_ok = true;
            out.on_current = true;
            out.on_current_ok = true;
            return true;
        };
    Win32WindowDiscoveryOptions win32_options;
    win32_options.carrier = carrier;
    win32_options.parking = parking;
    win32_options.augment_capabilities =
        [&augment_calls](HWND, const WindowDiscoveryObservation&,
                         WindowCapabilities& capabilities, std::string*) {
            ++augment_calls;
            capabilities.has_application_view = true;
            capabilities.can_move_desktops = true;
            // These unsafe overrides must be ignored by the factory.
            capabilities.independent_top_level = false;
            capabilities.desktop_state_observable = false;
            capabilities.owner_state_observable = false;
            return true;
        };
    error.clear();
    auto win32_backend = CreateWin32WindowDiscoveryBackend(
        std::move(win32_options), std::move(win32_api), &error);
    bool win32_seam_ok = win32_backend.has_value();
    if (win32_backend) {
        WindowDiscovery win32_discovery(std::move(*win32_backend));
        std::vector<DiscoveredWindow> live_like;
        win32_seam_ok = win32_discovery.Discover(live_like, &error) &&
                        live_like.size() == 1 &&
                        live_like[0].disposition == WindowDisposition::Managed &&
                        live_like[0].on_current_ok &&
                        live_like[0].on_current &&
                        live_like[0].cloaked_ok &&
                        live_like[0].presentation.rect_valid &&
                        live_like[0].presentation.placement_valid &&
                        live_like[0].presentation.foreground &&
                        live_like[0].presentation.z_order == 3 &&
                        identity_reads == 2 && augment_calls == 1;
    }
    Field("Win32 backend seam/classification",
          win32_seam_ok ? "PASS" : "FAIL");
    ok = ok && win32_seam_ok;

    std::size_t denied_identity_reads = 0;
    Win32WindowDiscoveryApi denied_api;
    denied_api.enumerate =
        [managed_id, unsupported_id](std::vector<HWND>& out, std::string*) {
            out = {managed_id.hwnd, unsupported_id.hwnd};
            return true;
        };
    denied_api.read_identity =
        [managed_id, unsupported_id, &denied_identity_reads](
            HWND hwnd, WindowIdentity& out, std::string* local_error) {
            if (hwnd == managed_id.hwnd) {
                out = managed_id;
                return true;
            }
            ++denied_identity_reads;
            if (local_error != nullptr) {
                *local_error = "OpenProcess failed (Win32 5)";
            }
            return false;
        };
    denied_api.read_window =
        [](HWND, Win32WindowObservation& out, std::string*) {
            out.monitor = reinterpret_cast<HMONITOR>(0x100);
            return true;
        };
    denied_api.read_desktop =
        [carrier](HWND, Win32DesktopObservation& out, std::string*) {
            out.desktop = carrier;
            out.desktop_ok = true;
            out.on_current = true;
            out.on_current_ok = true;
            return true;
        };
    Win32WindowDiscoveryOptions denied_options;
    denied_options.carrier = carrier;
    denied_options.parking = parking;
    std::size_t denied_augment_calls = 0;
    denied_options.augment_capabilities =
        [&denied_augment_calls](HWND, const WindowDiscoveryObservation&,
                                WindowCapabilities& capabilities,
                                std::string*) {
            ++denied_augment_calls;
            capabilities.has_application_view = true;
            capabilities.can_move_desktops = true;
            return true;
        };
    auto denied_backend = CreateWin32WindowDiscoveryBackend(
        std::move(denied_options), std::move(denied_api), &error);
    error.clear();
    bool denied_contained = denied_backend.has_value();
    if (denied_backend) {
        WindowDiscovery denied_discovery(std::move(*denied_backend));
        std::vector<DiscoveredWindow> denied_windows;
        denied_contained =
            denied_discovery.Discover(denied_windows, &error) &&
            denied_windows.size() == 2 &&
            denied_windows[0].disposition == WindowDisposition::Managed &&
            denied_windows[1].disposition == WindowDisposition::Ambiguous &&
            denied_identity_reads == 1 && denied_augment_calls == 1;
    }
    Field("unreadable identity contained as ambiguous",
          denied_contained ? "PASS" : "FAIL");
    ok = ok && denied_contained;

    WindowIdentity changed_id = managed_id;
    changed_id.process_creation_time.dwLowDateTime++;
    Win32WindowDiscoveryApi reuse_api;
    reuse_api.enumerate =
        [managed_id](std::vector<HWND>& out, std::string*) {
            out = {managed_id.hwnd};
            return true;
        };
    std::size_t reuse_reads = 0;
    reuse_api.read_identity =
        [managed_id, changed_id, &reuse_reads](HWND, WindowIdentity& out,
                                               std::string*) {
            out = reuse_reads++ == 0 ? managed_id : changed_id;
            return true;
        };
    reuse_api.read_window =
        [](HWND, Win32WindowObservation& out, std::string*) {
            out.monitor = reinterpret_cast<HMONITOR>(0x100);
            return true;
        };
    reuse_api.read_desktop =
        [carrier](HWND, Win32DesktopObservation& out, std::string*) {
            out.desktop = carrier;
            out.desktop_ok = true;
            out.on_current_ok = true;
            out.on_current = true;
            return true;
        };
    Win32WindowDiscoveryOptions reuse_options;
    reuse_options.carrier = carrier;
    reuse_options.parking = parking;
    auto reuse_backend = CreateWin32WindowDiscoveryBackend(
        std::move(reuse_options), std::move(reuse_api));
    const std::vector<DiscoveredWindow> before_reuse = windows;
    error.clear();
    bool reuse_rejected = reuse_backend.has_value();
    if (reuse_backend) {
        WindowDiscovery reuse_discovery(std::move(*reuse_backend));
        reuse_rejected = !reuse_discovery.Discover(windows, &error) &&
                         windows.size() == before_reuse.size() &&
                         std::equal(
                             windows.begin(), windows.end(),
                             before_reuse.begin(),
                             [](const DiscoveredWindow& left,
                                const DiscoveredWindow& right) {
                                 return left.identity == right.identity &&
                                        left.disposition == right.disposition;
                             });
    }
    Field("HWND generation change fail-closed",
          reuse_rejected ? "PASS" : "FAIL");
    ok = ok && reuse_rejected;

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
