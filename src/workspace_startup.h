// Fail-closed startup ordering for the workspace model boundary.
#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "workspace_coordinator.h"

namespace vd {

enum class WorkspaceStartupState {
    Ready,
    Blocked,
};

struct WorkspaceStartupResult {
    WorkspaceStartupState state = WorkspaceStartupState::Blocked;
    bool recovered_pending = false;
    std::string error;

    bool ready() const noexcept { return state == WorkspaceStartupState::Ready; }
};

// Owns the fresh model objects used only after a pending durable transaction.
// The factory is caller-supplied so application assignment, discovery, and
// native callback policy stay outside this ordering boundary.
struct WorkspaceStartupRecoveryRuntime {
    std::unique_ptr<WorkspaceEngine> engine;
    std::unique_ptr<WindowLifecycleAdapter> lifecycle;
    std::unique_ptr<WorkspaceCoordinator> coordinator;
};

class WorkspaceStartup {
   public:
    using DiscoverCompleteSnapshot = WorkspaceCoordinator::DiscoverCompleteSnapshot;
    using RecoveryRuntimeFactory = std::function<
        std::unique_ptr<WorkspaceStartupRecoveryRuntime>(
            std::unique_ptr<WorkspaceEngine>, const WorkspaceJournal&,
            std::string* error)>;

    // `engine` and `coordinator` are the caller's normal-operation objects.
    // `journal_path` is deliberately injected rather than derived from a temp
    // directory, so a process restart reads the same durable handoff.
    WorkspaceStartup(WorkspaceEngine& engine, WorkspaceCoordinator& coordinator,
                     WinEventLifecycleSource& lifecycle_source,
                     DiscoverCompleteSnapshot discover, GUID carrier,
                     GUID parking, std::filesystem::path journal_path,
                     RecoveryRuntimeFactory make_recovery_runtime = {},
                     std::size_t max_snapshot_attempts = 3);

    // Starts/verifies the owner-thread lifecycle source, reads the journal,
    // and makes one authoritative complete snapshot mandatory before READY.
    // It never invokes a native move itself. A pending journal is recovered
    // only with a fresh bootstrapped engine and then fully reconciled.
    WorkspaceStartupResult RecoverAtStartup();

    const WorkspaceJournal& journal() const noexcept { return journal_; }
    WorkspaceEngine* active_engine() const noexcept;
    WorkspaceCoordinator* active_coordinator() const noexcept;

   private:
    bool CaptureQuietCompleteSnapshot(std::vector<WindowRecord>& observed,
                                      std::string* error);
    WorkspaceStartupResult Blocked(std::string error) const;

    WorkspaceEngine& normal_engine_;
    WorkspaceCoordinator& normal_coordinator_;
    WinEventLifecycleSource& lifecycle_source_;
    DiscoverCompleteSnapshot discover_;
    GUID carrier_{};
    GUID parking_{};
    WorkspaceJournal journal_;
    RecoveryRuntimeFactory make_recovery_runtime_;
    std::size_t max_snapshot_attempts_ = 3;
    std::unique_ptr<WorkspaceStartupRecoveryRuntime> recovery_runtime_;
};

const char* WorkspaceStartupStateText(WorkspaceStartupState state) noexcept;
int CmdWorkspaceStartupTest();

}  // namespace vd
