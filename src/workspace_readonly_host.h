// Reusable owner-thread host for the non-mutating workspace observation stack.
#pragma once

#include <filesystem>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "window_discovery.h"
#include "workspace_assignment.h"
#include "workspace_startup.h"

namespace vd {

struct ReadOnlyMonitorConfiguration {
    MonitorId monitor = 0;
    WorkspaceId active = 0;
    std::vector<WorkspaceId> workspaces;
};

enum class ReadOnlyHostResultCode {
    Succeeded,
    AlreadyStarted,
    NotStarted,
    WrongThread,
    ConfigurationFailed,
    StartupBlocked,
    PumpFailed,
    ReconcileFailed,
    ShutdownFailed,
};

struct ReadOnlyHostResult {
    ReadOnlyHostResultCode code = ReadOnlyHostResultCode::Succeeded;
    CoordinatorResult coordinator{};
    std::string error;

    bool succeeded() const noexcept {
        return code == ReadOnlyHostResultCode::Succeeded;
    }
};

class WorkspaceReadOnlyHost {
   public:
    WorkspaceReadOnlyHost(
        GUID carrier, GUID parking,
        std::vector<ReadOnlyMonitorConfiguration> monitors,
        WindowDiscoveryBackend discovery_backend,
        std::filesystem::path journal_path,
        WinEventLifecycleSource::InstallHook install_hook = {},
        WinEventLifecycleSource::RemoveHook remove_hook = {},
        std::size_t max_snapshot_attempts = 3,
        std::uint64_t rescan_interval_ms = 1000);
    ~WorkspaceReadOnlyHost();

    WorkspaceReadOnlyHost(const WorkspaceReadOnlyHost&) = delete;
    WorkspaceReadOnlyHost& operator=(const WorkspaceReadOnlyHost&) = delete;

    // All operations are owner-thread only. Start installs the read-only
    // WinEvent hook and requires an authoritative quiet snapshot. A pending
    // transaction remains blocked because this host intentionally supplies no
    // move, observe, or recovery callbacks.
    ReadOnlyHostResult Start();
    ReadOnlyHostResult Reconcile();
    // Pump owner-thread callbacks and run a complete authoritative rescan
    // when a hint arrives, the interval expires, or force_rescan is true.
    ReadOnlyHostResult Poll(bool force_rescan = false);
    // Enqueue an already-normalized lifecycle hint. Native WinEvent callbacks
    // normally reach the same source internally; this seam is also useful for
    // deterministic hosts and alternate read-only event producers.
    void CollectLifecycleHint(WindowLifecycleEvent event);
    ReadOnlyHostResult Stop() noexcept;

    bool running() const noexcept { return running_; }
    const WorkspaceEngine& engine() const noexcept;

   private:
    bool DiscoverAssigned(std::vector<WindowRecord>& records,
                          std::string* error);
    std::optional<WindowRecord> ObserveAssigned(HWND hwnd);
    ReadOnlyHostResult WrongThreadResult() const;
    ReadOnlyHostResult ReconcileAfterPump();

    DWORD owner_thread_id_ = 0;
    WorkspaceEngine engine_;
    WindowDiscovery discovery_;
    WorkspaceAssignmentAdapter assignment_;
    WinEventLifecycleSource source_;
    WindowLifecycleAdapter lifecycle_;
    WorkspaceJournal coordinator_journal_;
    WorkspaceCoordinator coordinator_;
    WorkspaceStartup startup_;
    std::string configuration_error_;
    bool running_ = false;
    std::uint64_t rescan_interval_ms_ = 1000;
    std::uint64_t last_reconcile_tick_ = 0;
    std::uint64_t last_reconcile_epoch_ = 0;
};

const char* ReadOnlyHostResultCodeText(ReadOnlyHostResultCode code) noexcept;
int CmdWorkspaceReadOnlyHostTest();

}  // namespace vd
