#include "workspace_live_lifecycle.h"

#include <algorithm>
#include <cstdint>
#include <format>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "util.h"
#include "window_discovery.h"
#include "workspace_assignment.h"
#include "workspace_coordinator.h"

namespace vd {
namespace {

GUID TestGuid(DWORD value) {
    GUID result{};
    result.Data1 = value;
    return result;
}

WindowIdentity TestIdentity(std::uintptr_t hwnd, DWORD pid, DWORD generation) {
    return {reinterpret_cast<HWND>(hwnd),
            pid,
            {generation, generation + 1},
            true};
}

struct Assignment {
    MonitorId monitor = 0;
    WorkspaceId workspace = 0;
};

// Logical assignment is intentionally independent from discovery. An exact
// HWND/PID/process-generation tuple must be registered before it can enter the
// model; HWND reuse never inherits the previous generation's assignment.
class InMemoryAssignmentRegistry {
   public:
    void Assign(const WindowIdentity& identity, MonitorId monitor,
                WorkspaceId workspace) {
        assignments_[identity] = {monitor, workspace};
    }

    void Remove(const WindowIdentity& identity) { assignments_.erase(identity); }

    bool Convert(const std::vector<DiscoveredWindow>& discovered,
                 std::vector<WindowRecord>& records,
                 std::string* error) const {
        std::vector<WindowRecord> candidate;
        candidate.reserve(discovered.size());
        for (const DiscoveredWindow& window : discovered) {
            if (window.disposition != WindowDisposition::Managed ||
                !window.capabilities.Manageable() ||
                window.native_role == NativeDesktopRole::Unknown) {
                if (error) {
                    *error = "scoped window is not safely manageable";
                }
                return false;
            }
            const auto assignment = assignments_.find(window.identity);
            if (assignment == assignments_.end()) {
                if (error) {
                    *error = "window generation has no explicit assignment";
                }
                return false;
            }
            const MonitorId observed_monitor =
                reinterpret_cast<MonitorId>(window.monitor);
            if (observed_monitor == 0 ||
                assignment->second.monitor != observed_monitor) {
                if (error) {
                    *error = "window monitor does not match its assignment";
                }
                return false;
            }
            WindowRecord record;
            record.identity = window.identity;
            record.monitor = assignment->second.monitor;
            record.workspace = assignment->second.workspace;
            record.native_role = window.native_role;
            record.capabilities = window.capabilities;
            record.presentation = window.presentation;
            record.disposition = window.disposition;
            candidate.push_back(std::move(record));
        }
        records = std::move(candidate);
        return true;
    }

   private:
    std::unordered_map<WindowIdentity, Assignment, WindowIdentityHash>
        assignments_;
};

struct InjectedWindow {
    WindowIdentity identity;
    HMONITOR monitor = nullptr;
    GUID desktop{};
    bool can_move = true;
};

class InjectedDiscoveryState {
   public:
    std::vector<InjectedWindow> windows;
    HWND unstable_identity = nullptr;

    const InjectedWindow* Find(HWND hwnd) const {
        const auto found = std::find_if(
            windows.begin(), windows.end(),
            [hwnd](const InjectedWindow& window) {
                return window.identity.hwnd == hwnd;
            });
        return found == windows.end() ? nullptr : &*found;
    }

    void BeginEnumeration() { identity_reads_.clear(); }

    WindowIdentity ReadIdentity(HWND hwnd) {
        WindowIdentity identity = Find(hwnd)->identity;
        const std::size_t read = ++identity_reads_[hwnd];
        if (hwnd == unstable_identity && read > 1) {
            ++identity.process_creation_time.dwLowDateTime;
        }
        return identity;
    }

   private:
    std::unordered_map<HWND, std::size_t> identity_reads_;
};

void ReportCheck(const char* name, bool passed, bool& overall) {
    Field(name, passed ? "PASS" : "FAIL");
    overall = overall && passed;
}

}  // namespace

int CmdWorkspaceLiveLifecycleTest() {
    Heading("workspace-live-lifecycle-test");
    Field("window source", "deterministic injected probe-owned observations");
    Field("assignment", "explicit generation-keyed in-memory registry");
    Field("close authority", "complete snapshots only");
    Field("native mutation", "none");

    constexpr MonitorId kMonitor = 0x100;
    constexpr WorkspaceId kWorkspace = 10;
    constexpr WorkspaceId kOtherWorkspace = 11;
    const GUID carrier = TestGuid(0xA1);
    const GUID parking = TestGuid(0xA2);
    const WindowIdentity first = TestIdentity(0x101, 1001, 1);
    const WindowIdentity second = TestIdentity(0x102, 1002, 1);
    const WindowIdentity second_generation = TestIdentity(0x102, 1002, 2);

    InjectedDiscoveryState state;
    state.windows = {{first, reinterpret_cast<HMONITOR>(kMonitor), carrier}};
    InMemoryAssignmentRegistry assignments;
    assignments.Assign(first, kMonitor, kWorkspace);

    Win32WindowDiscoveryApi api;
    api.enumerate = [&](std::vector<HWND>& handles, std::string*) {
        state.BeginEnumeration();
        handles.clear();
        for (const InjectedWindow& window : state.windows) {
            handles.push_back(window.identity.hwnd);
        }
        return true;
    };
    api.read_identity = [&](HWND hwnd, WindowIdentity& identity,
                            std::string* error) {
        if (state.Find(hwnd) == nullptr) {
            if (error) *error = "injected HWND vanished";
            return false;
        }
        identity = state.ReadIdentity(hwnd);
        return true;
    };
    api.read_window = [&](HWND hwnd, Win32WindowObservation& observation,
                          std::string* error) {
        const InjectedWindow* window = state.Find(hwnd);
        if (!window) {
            if (error) *error = "injected HWND vanished";
            return false;
        }
        observation = {};
        observation.monitor = window->monitor;
        observation.visible = true;
        return true;
    };
    api.read_desktop = [&](HWND hwnd, Win32DesktopObservation& observation,
                           std::string* error) {
        const InjectedWindow* window = state.Find(hwnd);
        if (!window) {
            if (error) *error = "injected HWND vanished";
            return false;
        }
        observation = {};
        observation.desktop = window->desktop;
        observation.desktop_ok = true;
        observation.on_current = ::IsEqualGUID(window->desktop, carrier);
        observation.on_current_ok = true;
        return true;
    };
    Win32WindowDiscoveryOptions options;
    options.carrier = carrier;
    options.parking = parking;
    options.augment_capabilities =
        [&](HWND hwnd, const WindowDiscoveryObservation&,
            WindowCapabilities& capabilities, std::string* error) {
            const InjectedWindow* window = state.Find(hwnd);
            if (!window) {
                if (error) *error = "injected HWND vanished";
                return false;
            }
            capabilities.has_application_view = true;
            capabilities.can_move_desktops = window->can_move;
            return true;
        };

    std::string error;
    auto backend = CreateWin32WindowDiscoveryBackend(
        std::move(options), std::move(api), &error);
    if (!backend) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }
    WindowDiscovery discovery(std::move(*backend));
    WorkspaceEngine engine(carrier, parking);
    if (!engine.AddMonitor(kMonitor, kWorkspace,
                           {kWorkspace, kOtherWorkspace}, &error)) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }

    std::uintptr_t next_hook = 0x5000;
    WinEventLifecycleSource source(
        [&](DWORD, DWORD, WINEVENTPROC) {
            return reinterpret_cast<HWINEVENTHOOK>(next_hook++);
        },
        [](HWINEVENTHOOK) { return true; });
    if (!source.Start(&error)) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }

    bool inject_hint_during_discovery = false;
    WindowLifecycleAdapter lifecycle(engine, {});
    WorkspaceCoordinator coordinator(
        engine, lifecycle, source,
        [&](std::vector<WindowRecord>& observed, std::string* local_error) {
            std::vector<DiscoveredWindow> discovered;
            if (!discovery.Discover(discovered, local_error)) return false;
            if (inject_hint_during_discovery) {
                source.Collect({WindowLifecycleEventKind::Appeared,
                                first.hwnd, first});
            }
            return assignments.Convert(discovered, observed, local_error);
        },
        {}, {}, nullptr, 2);

    bool ok = true;
    CoordinatorResult result = coordinator.ReconcileDiscovery();
    ReportCheck("initial complete snapshot",
                result.succeeded() && result.lifecycle.discovery.added == 1 &&
                    engine.Windows().size() == 1,
                ok);

    state.windows.push_back(
        {second, reinterpret_cast<HMONITOR>(kMonitor), carrier});
    assignments.Assign(second, kMonitor, kWorkspace);
    source.Collect({WindowLifecycleEventKind::Appeared, second.hwnd, second});
    result = coordinator.ReconcileDiscovery();
    ReportCheck("appeared hint reconciled by snapshot",
                result.succeeded() && result.lifecycle.events == 1 &&
                    result.lifecycle.discovery.added == 1 &&
                    engine.Windows().size() == 2,
                ok);

    source.Collect({WindowLifecycleEventKind::Closed, second.hwnd,
                    std::nullopt});
    result = coordinator.ReconcileDiscovery();
    ReportCheck("close hint alone is non-authoritative",
                result.succeeded() && result.lifecycle.discovery.closed == 0 &&
                    engine.FindWindow(second) != nullptr,
                ok);

    state.windows.erase(
        std::remove_if(state.windows.begin(), state.windows.end(),
                       [&](const InjectedWindow& window) {
                           return window.identity == second;
                       }),
        state.windows.end());
    result = coordinator.ReconcileDiscovery();
    ReportCheck("complete snapshot closes omitted window",
                result.succeeded() && result.lifecycle.discovery.closed == 1 &&
                    engine.FindWindow(second) == nullptr,
                ok);

    state.windows.push_back(
        {second, reinterpret_cast<HMONITOR>(kMonitor), carrier});
    source.Collect({WindowLifecycleEventKind::Appeared, second.hwnd, second});
    result = coordinator.ReconcileDiscovery();
    const bool reappeared = result.succeeded() &&
                            result.lifecycle.discovery.added == 1;
    state.windows.back().identity = second_generation;
    assignments.Remove(second);
    assignments.Assign(second_generation, kMonitor, kWorkspace);
    source.Collect({WindowLifecycleEventKind::Appeared, second.hwnd, second});
    result = coordinator.ReconcileDiscovery();
    ReportCheck("recreated HWND generation",
                reappeared && result.succeeded() &&
                    result.lifecycle.discovery.recreated == 1 &&
                    result.lifecycle.stale_generations == 1 &&
                    engine.FindWindow(second) == nullptr &&
                    engine.FindWindow(second_generation) != nullptr,
                ok);

    const std::size_t stable_count = engine.Windows().size();
    assignments.Remove(second_generation);
    result = coordinator.ReconcileDiscovery();
    ReportCheck("missing assignment fails closed",
                result.code == CoordinatorResultCode::DiscoveryFailed &&
                    engine.Windows().size() == stable_count,
                ok);
    assignments.Assign(second_generation, kMonitor, kWorkspace);

    state.windows.back().monitor = reinterpret_cast<HMONITOR>(0x200);
    result = coordinator.ReconcileDiscovery();
    ReportCheck("monitor mismatch fails closed",
                result.code == CoordinatorResultCode::DiscoveryFailed &&
                    engine.Windows().size() == stable_count,
                ok);
    state.windows.back().monitor = reinterpret_cast<HMONITOR>(kMonitor);

    state.windows.back().can_move = false;
    result = coordinator.ReconcileDiscovery();
    ReportCheck("capability loss fails closed",
                result.code == CoordinatorResultCode::DiscoveryFailed &&
                    engine.Windows().size() == stable_count,
                ok);
    state.windows.back().can_move = true;

    state.unstable_identity = second_generation.hwnd;
    result = coordinator.ReconcileDiscovery();
    ReportCheck("unstable identity fails closed",
                result.code == CoordinatorResultCode::DiscoveryFailed &&
                    engine.Windows().size() == stable_count,
                ok);
    state.unstable_identity = nullptr;

    inject_hint_during_discovery = true;
    result = coordinator.ReconcileDiscovery();
    ReportCheck("unstable lifecycle is bounded",
                result.code == CoordinatorResultCode::DiscoveryUnstable &&
                    result.discovery_attempts == 2 &&
                    engine.Windows().size() == stable_count,
                ok);
    inject_hint_during_discovery = false;
    (void)source.DrainBatch();

    result = coordinator.ReconcileDiscovery();
    ReportCheck("stable recovery reconciliation",
                result.succeeded() && engine.CheckInvariant(&error), ok);

    // Same-process HWND reuse must be resolved before assignment conversion.
    // The identity tuple cannot distinguish the old parked window from the
    // newly created Carrier window, so the drained destroy hint is the only
    // evidence that the new observation must join the active workspace.
    WorkspaceEngine ordered_engine(carrier, parking);
    bool ordered_reuse =
        ordered_engine.AddMonitor(kMonitor, kWorkspace,
                                  {kWorkspace, kOtherWorkspace}, &error);
    const WindowIdentity reused = TestIdentity(0x103, 1003, 1);
    WindowCapabilities manageable{true, true, true, true, true};
    ordered_reuse =
        ordered_reuse &&
        ordered_engine.UpsertWindow(
            {reused, kMonitor, kOtherWorkspace,
             NativeDesktopRole::Parking, manageable},
            &error) == UpsertResult::Added;
    WorkspaceAssignmentAdapter ordered_assignment(ordered_engine);
    ordered_reuse =
        ordered_reuse &&
        ordered_assignment.ConfigureMonitor(
            kMonitor, kWorkspace, {kWorkspace, kOtherWorkspace}, &error);
    WinEventLifecycleSource ordered_source(
        [](DWORD, DWORD, WINEVENTPROC) {
            return reinterpret_cast<HWINEVENTHOOK>(0x6000);
        },
        [](HWINEVENTHOOK) { return true; });
    ordered_reuse = ordered_reuse && ordered_source.Start(&error);
    WindowLifecycleAdapter ordered_lifecycle(ordered_engine, {});
    DiscoveredWindow reused_observation;
    reused_observation.identity = reused;
    reused_observation.monitor = reinterpret_cast<HMONITOR>(kMonitor);
    reused_observation.native_role = NativeDesktopRole::Carrier;
    reused_observation.capabilities = manageable;
    reused_observation.disposition = WindowDisposition::Managed;
    WorkspaceCoordinator ordered_coordinator(
        ordered_engine, ordered_lifecycle, ordered_source, {}, {}, {}, nullptr,
        2, 3,
        [&](const std::vector<WindowLifecycleEvent>& hints,
            std::vector<WindowRecord>& observed, std::string* local_error) {
            return ordered_assignment.ConvertCompleteSnapshot(
                {reused_observation}, hints, observed, local_error);
        });
    ordered_source.Collect(
        {WindowLifecycleEventKind::Closed, reused.hwnd, std::nullopt});
    const CoordinatorResult ordered_result =
        ordered_coordinator.ReconcileDiscovery();
    const WindowRecord* ordered_record = ordered_engine.FindWindow(reused);
    ordered_reuse =
        ordered_reuse && ordered_result.succeeded() &&
        ordered_result.lifecycle.discovery.added == 1 &&
        ordered_record != nullptr && ordered_record->workspace == kWorkspace &&
        ordered_record->native_role == NativeDesktopRole::Carrier &&
        ordered_engine.Workspace(kOtherWorkspace)->z_order.empty() &&
        !ordered_engine.Workspace(kOtherWorkspace)->last_foreground.has_value();
    ordered_source.Stop();
    ordered_reuse = ordered_reuse && ordered_source.shutdown_ok();
    ReportCheck("same-process reuse ordered before assignment", ordered_reuse,
                ok);

    source.Stop();
    ReportCheck("owner-thread lifecycle shutdown", source.shutdown_ok(), ok);
    Field("move callback", "not installed");
    Field("result", ok ? "OK" : "ERROR");
    Print("MUTATION_STARTED=0\n");
    Print("ASSIGNMENT_REGISTRY=EXPLICIT\n");
    Print("CLOSE_AUTHORITY=COMPLETE_SNAPSHOT\n");
    Print("RESULT={}\n", ok ? "OK" : "ERROR");
    return ok ? 0 : 1;
}

}  // namespace vd
