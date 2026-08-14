// Serialized production boundary for discovery, lifecycle hints and switches.
#pragma once

#include <windows.h>

#include <cstddef>
#include <functional>
#include <string>
#include <vector>

#include "window_lifecycle.h"
#include "workspace_engine.h"

namespace vd {

enum class CoordinatorResultCode {
    Succeeded,
    Busy,
    WrongThread,
    LifecycleUnavailable,
    PendingRecovery,
    DiscoveryFailed,
    DiscoveryUnstable,
    PlanRejected,
    TransactionFailed,
    RecoveryFailed,
};

struct CoordinatorResult {
    CoordinatorResultCode code = CoordinatorResultCode::Succeeded;
    std::size_t discovery_attempts = 0;
    std::size_t switch_attempts = 0;
    LifecycleReconcileResult lifecycle{};
    TransactionResult transaction{};
    RecoveryResult recovery{};
    std::string error;

    bool succeeded() const noexcept {
        return code == CoordinatorResultCode::Succeeded;
    }
};

class WorkspaceCoordinator {
   public:
    using DiscoverCompleteSnapshot =
        std::function<bool(std::vector<WindowRecord>& observed,
                           std::string* error)>;

    WorkspaceCoordinator(WorkspaceEngine& engine,
                         WindowLifecycleAdapter& lifecycle,
                         WinEventLifecycleSource& source,
                         DiscoverCompleteSnapshot discover,
                         WorkspaceEngine::MoveCallback move,
                         WorkspaceEngine::ObserveCallback observe,
                         const WorkspaceJournal* journal = nullptr,
                         std::size_t max_discovery_attempts = 3,
                         std::size_t max_switch_attempts = 3);

    CoordinatorResult ReconcileDiscovery();
    CoordinatorResult Switch(MonitorId monitor, WorkspaceId target_workspace);
    CoordinatorResult RecoverPending();

   private:
    class OperationScope;
    bool CheckEntry(CoordinatorResult& result);
    bool CheckNoPendingJournal(CoordinatorResult& result) const;
    CoordinatorResult ReconcileDiscoveryLocked();

    WorkspaceEngine& engine_;
    WindowLifecycleAdapter& lifecycle_;
    WinEventLifecycleSource& source_;
    DiscoverCompleteSnapshot discover_;
    WorkspaceEngine::MoveCallback move_;
    WorkspaceEngine::ObserveCallback observe_;
    const WorkspaceJournal* journal_ = nullptr;
    std::size_t max_discovery_attempts_ = 3;
    std::size_t max_switch_attempts_ = 3;
    DWORD owner_thread_id_ = 0;
    bool operation_active_ = false;
};

const char* CoordinatorResultCodeText(CoordinatorResultCode code) noexcept;
int CmdWorkspaceCoordinatorTest();

}  // namespace vd
