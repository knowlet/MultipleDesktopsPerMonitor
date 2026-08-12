#include "workspace_readonly_host.h"

#include <algorithm>
#include <cstdint>
#include <system_error>
#include <unordered_map>
#include <utility>

#include "util.h"

namespace vd {
namespace {

WindowIdentity TestIdentity(std::uintptr_t hwnd, DWORD pid, DWORD generation) {
    return {reinterpret_cast<HWND>(hwnd), pid, {generation, generation}, true};
}

WindowCapabilities TestCapabilities() {
    return {true, true, true, true, true};
}

WindowDiscoveryObservation TestObservation(const WindowIdentity& identity,
                                           MonitorId monitor,
                                           NativeDesktopRole role,
                                           const GUID& carrier,
                                           const GUID& parking) {
    WindowDiscoveryObservation observation;
    observation.identity = identity;
    observation.monitor = reinterpret_cast<HMONITOR>(monitor);
    observation.visible = true;
    observation.cloaked_ok = true;
    observation.desktop_ok = true;
    observation.desktop = role == NativeDesktopRole::Carrier ? carrier : parking;
    observation.on_current_ok = true;
    observation.on_current = role == NativeDesktopRole::Carrier;
    observation.native_role = role;
    observation.capabilities = TestCapabilities();
    observation.presentation.rect_valid = true;
    observation.presentation.placement_valid = true;
    return observation;
}

std::filesystem::path TestJournalPath(const char* suffix) {
    return std::filesystem::temp_directory_path() /
           (std::string("vdprobe-workspace-readonly-host-") + suffix + "-" +
            std::to_string(GetCurrentProcessId()) + ".journal");
}

bool RemoveTestJournal(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::remove(path, error);
    return !error;
}

}  // namespace

WorkspaceReadOnlyHost::WorkspaceReadOnlyHost(
    GUID carrier, GUID parking,
    std::vector<ReadOnlyMonitorConfiguration> monitors,
    WindowDiscoveryBackend discovery_backend,
    std::filesystem::path journal_path,
    WinEventLifecycleSource::InstallHook install_hook,
    WinEventLifecycleSource::RemoveHook remove_hook,
    std::size_t max_snapshot_attempts)
    : owner_thread_id_(GetCurrentThreadId()),
      engine_(carrier, parking),
      discovery_(std::move(discovery_backend)),
      assignment_(engine_),
      source_(std::move(install_hook), std::move(remove_hook)),
      lifecycle_(engine_, [this](HWND hwnd) { return ObserveAssigned(hwnd); }),
      coordinator_journal_(journal_path),
      coordinator_(
          engine_, lifecycle_, source_,
          [this](std::vector<WindowRecord>& records, std::string* error) {
              return DiscoverAssigned(records, error);
          },
          {}, {}, &coordinator_journal_, max_snapshot_attempts),
      startup_(
          engine_, coordinator_, source_,
          [this](std::vector<WindowRecord>& records, std::string* error) {
              return DiscoverAssigned(records, error);
          },
          carrier, parking, std::move(journal_path), {}, max_snapshot_attempts) {
    std::sort(monitors.begin(), monitors.end(),
              [](const ReadOnlyMonitorConfiguration& left,
                 const ReadOnlyMonitorConfiguration& right) {
                  return left.monitor < right.monitor;
              });
    for (ReadOnlyMonitorConfiguration& monitor : monitors) {
        if (!configuration_error_.empty()) break;
        if (!engine_.AddMonitor(monitor.monitor, monitor.active,
                                monitor.workspaces, &configuration_error_)) {
            break;
        }
        if (!assignment_.ConfigureMonitor(
                monitor.monitor, monitor.active, std::move(monitor.workspaces),
                &configuration_error_)) {
            break;
        }
    }
    if (monitors.empty() && configuration_error_.empty()) {
        configuration_error_ = "read-only host requires monitor topology";
    }
}

WorkspaceReadOnlyHost::~WorkspaceReadOnlyHost() { (void)Stop(); }

ReadOnlyHostResult WorkspaceReadOnlyHost::WrongThreadResult() const {
    return {ReadOnlyHostResultCode::WrongThread, {},
            "read-only host must run on its owner thread"};
}

bool WorkspaceReadOnlyHost::DiscoverAssigned(
    std::vector<WindowRecord>& records, std::string* error) {
    std::vector<DiscoveredWindow> discovered;
    if (!discovery_.Discover(discovered, error)) return false;
    return assignment_.ConvertCompleteSnapshot(discovered, records, error);
}

std::optional<WindowRecord> WorkspaceReadOnlyHost::ObserveAssigned(HWND hwnd) {
    std::vector<WindowRecord> records;
    std::string error;
    if (!DiscoverAssigned(records, &error)) return std::nullopt;
    const auto found = std::find_if(
        records.begin(), records.end(),
        [hwnd](const WindowRecord& record) {
            return record.identity.hwnd == hwnd;
        });
    if (found == records.end()) return std::nullopt;
    return *found;
}

ReadOnlyHostResult WorkspaceReadOnlyHost::Start() {
    if (GetCurrentThreadId() != owner_thread_id_) return WrongThreadResult();
    if (running_) {
        return {ReadOnlyHostResultCode::AlreadyStarted, {},
                "read-only host is already started"};
    }
    if (!configuration_error_.empty()) {
        return {ReadOnlyHostResultCode::ConfigurationFailed, {},
                configuration_error_};
    }

    const WorkspaceStartupResult result = startup_.RecoverAtStartup();
    if (!result.ready()) {
        source_.Stop();
        if (!source_.shutdown_ok()) {
            return {ReadOnlyHostResultCode::ShutdownFailed, {},
                    "startup blocked and lifecycle shutdown failed: " +
                        result.error};
        }
        return {ReadOnlyHostResultCode::StartupBlocked, {}, result.error};
    }
    running_ = true;
    return {};
}

ReadOnlyHostResult WorkspaceReadOnlyHost::Reconcile() {
    if (GetCurrentThreadId() != owner_thread_id_) return WrongThreadResult();
    if (!running_) {
        return {ReadOnlyHostResultCode::NotStarted, {},
                "read-only host is not started"};
    }
    CoordinatorResult result = startup_.active_coordinator()->ReconcileDiscovery();
    if (!result.succeeded()) {
        std::string error = result.error;
        return {ReadOnlyHostResultCode::ReconcileFailed, std::move(result),
                std::move(error)};
    }
    return {ReadOnlyHostResultCode::Succeeded, std::move(result), {}};
}

ReadOnlyHostResult WorkspaceReadOnlyHost::Stop() noexcept {
    if (GetCurrentThreadId() != owner_thread_id_) return WrongThreadResult();
    source_.Stop();
    running_ = false;
    if (!source_.shutdown_ok()) {
        return {ReadOnlyHostResultCode::ShutdownFailed, {},
                "WinEvent lifecycle source shutdown failed"};
    }
    return {};
}

const WorkspaceEngine& WorkspaceReadOnlyHost::engine() const noexcept {
    return *startup_.active_engine();
}

const char* ReadOnlyHostResultCodeText(ReadOnlyHostResultCode code) noexcept {
    switch (code) {
        case ReadOnlyHostResultCode::Succeeded: return "succeeded";
        case ReadOnlyHostResultCode::AlreadyStarted: return "already-started";
        case ReadOnlyHostResultCode::NotStarted: return "not-started";
        case ReadOnlyHostResultCode::WrongThread: return "wrong-thread";
        case ReadOnlyHostResultCode::ConfigurationFailed:
            return "configuration-failed";
        case ReadOnlyHostResultCode::StartupBlocked: return "startup-blocked";
        case ReadOnlyHostResultCode::ReconcileFailed:
            return "reconcile-failed";
        case ReadOnlyHostResultCode::ShutdownFailed: return "shutdown-failed";
        default: return "unknown";
    }
}

int CmdWorkspaceReadOnlyHostTest() {
    Heading("workspace-readonly-host-test");
    Field("scope", "deterministic injected read-only host composition");
    Field("native mutation", "none");
    Field("move callback", "not installed");
    Field("observe callback", "not installed");

    GUID carrier{};
    carrier.Data1 = 81;
    GUID parking{};
    parking.Data1 = 82;
    const WindowIdentity first = TestIdentity(0x8101, 801, 1);
    const WindowIdentity second = TestIdentity(0x8102, 802, 1);
    std::vector<HWND> handles{first.hwnd};
    std::unordered_map<HWND, WindowDiscoveryObservation> observations{
        {first.hwnd,
         TestObservation(first, 1, NativeDesktopRole::Carrier, carrier,
                         parking)}};
    bool discovery_ok = true;
    WindowDiscoveryBackend backend(
        [&](std::vector<HWND>& out, bool& complete, std::string*) {
            if (!discovery_ok) return false;
            out = handles;
            complete = true;
            return true;
        },
        [&](HWND hwnd, WindowDiscoveryObservation& out, std::string*) {
            const auto found = observations.find(hwnd);
            if (found == observations.end()) return false;
            out = found->second;
            return true;
        });

    std::uintptr_t next_hook = 8100;
    std::size_t installs = 0;
    std::size_t removes = 0;
    const auto install = [&](DWORD, DWORD, WINEVENTPROC) {
        ++installs;
        return reinterpret_cast<HWINEVENTHOOK>(next_hook++);
    };
    const auto remove = [&](HWINEVENTHOOK) {
        ++removes;
        return true;
    };
    const std::filesystem::path clean_path = TestJournalPath("clean");
    RemoveTestJournal(clean_path);
    WorkspaceReadOnlyHost host(
        carrier, parking, {{1, 10, {10, 11}}}, std::move(backend), clean_path,
        install, remove);

    bool ok = true;
    const ReadOnlyHostResult started = host.Start();
    const bool start_ok =
        started.succeeded() && host.running() && installs == 1 &&
        host.engine().FindWindow(first) != nullptr &&
        host.engine().FindWindow(first)->workspace == 10;
    Field("authoritative startup", start_ok ? "PASS" : "FAIL");
    ok = ok && start_ok;

    handles.push_back(second.hwnd);
    observations.emplace(
        second.hwnd,
        TestObservation(second, 1, NativeDesktopRole::Carrier, carrier,
                        parking));
    const ReadOnlyHostResult reconciled = host.Reconcile();
    const bool reconcile_ok =
        reconciled.succeeded() && host.engine().FindWindow(second) != nullptr &&
        host.engine().FindWindow(second)->workspace == 10;
    Field("bounded complete reconciliation",
          reconcile_ok ? "PASS" : "FAIL");
    ok = ok && reconcile_ok;

    discovery_ok = false;
    const std::size_t before_failure = host.engine().Windows().size();
    const ReadOnlyHostResult failed = host.Reconcile();
    const bool failure_closed =
        failed.code == ReadOnlyHostResultCode::ReconcileFailed &&
        host.engine().Windows().size() == before_failure;
    Field("discovery failure preserves model",
          failure_closed ? "PASS" : "FAIL");
    ok = ok && failure_closed;

    const ReadOnlyHostResult stopped = host.Stop();
    const bool stop_ok = stopped.succeeded() && !host.running() && removes == 1;
    Field("owner-thread lifecycle shutdown", stop_ok ? "PASS" : "FAIL");
    ok = ok && stop_ok;
    RemoveTestJournal(clean_path);

    // A durable pending transaction must never cause this read-only host to
    // install mutation callbacks. Startup blocks and removes its hook.
    const std::filesystem::path pending_path = TestJournalPath("pending");
    RemoveTestJournal(pending_path);
    WorkspaceJournal pending_journal(pending_path);
    SwitchPlan pending_plan{1, 10, 11,
                            {{first, NativeDesktopRole::Carrier,
                              NativeDesktopRole::Parking}}};
    std::string error;
    const bool pending_written = pending_journal.Begin(pending_plan, &error);
    WindowDiscoveryBackend pending_backend(
        [&](std::vector<HWND>& out, bool& complete, std::string*) {
            out = {first.hwnd};
            complete = true;
            return true;
        },
        [&](HWND, WindowDiscoveryObservation& out, std::string*) {
            out = TestObservation(first, 1, NativeDesktopRole::Carrier,
                                  carrier, parking);
            return true;
        });
    WorkspaceReadOnlyHost pending_host(
        carrier, parking, {{1, 10, {10, 11}}},
        std::move(pending_backend), pending_path, install, remove);
    const ReadOnlyHostResult pending_start = pending_host.Start();
    const bool pending_blocked =
        pending_written &&
        pending_start.code == ReadOnlyHostResultCode::StartupBlocked &&
        !pending_host.running() && !pending_host.engine().FindWindow(first);
    Field("pending recovery blocks without mutation callbacks",
          pending_blocked ? "PASS" : "FAIL");
    ok = ok && pending_blocked;
    RemoveTestJournal(pending_path);

    Field("result", ok ? "PASS" : "FAIL");
    Print("MUTATION_STARTED=0\n");
    Print("MOVE_CALLBACK_INSTALLED=0\n");
    Print("OBSERVE_CALLBACK_INSTALLED=0\n");
    Print("RESULT={}\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

}  // namespace vd
