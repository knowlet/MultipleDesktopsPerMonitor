#include "workspace_coordinator.h"

#include <algorithm>
#include <filesystem>
#include <system_error>
#include <unordered_map>
#include <utility>

#include "util.h"

namespace vd {

class WorkspaceCoordinator::OperationScope {
   public:
    explicit OperationScope(WorkspaceCoordinator& owner) : owner_(owner) {
        owner_.operation_active_ = true;
    }
    ~OperationScope() { owner_.operation_active_ = false; }

   private:
    WorkspaceCoordinator& owner_;
};

WorkspaceCoordinator::WorkspaceCoordinator(
    WorkspaceEngine& engine, WindowLifecycleAdapter& lifecycle,
    WinEventLifecycleSource& source, DiscoverCompleteSnapshot discover,
    WorkspaceEngine::MoveCallback move,
    WorkspaceEngine::ObserveCallback observe,
    const WorkspaceJournal* journal, std::size_t max_discovery_attempts)
    : engine_(engine),
      lifecycle_(lifecycle),
      source_(source),
      discover_(std::move(discover)),
      move_(std::move(move)),
      observe_(std::move(observe)),
      journal_(journal),
      max_discovery_attempts_(std::max<std::size_t>(1,
                                                    max_discovery_attempts)),
      owner_thread_id_(GetCurrentThreadId()) {}

bool WorkspaceCoordinator::CheckEntry(CoordinatorResult& result) {
    if (GetCurrentThreadId() != owner_thread_id_) {
        result.code = CoordinatorResultCode::WrongThread;
        result.error = "coordinator must run on its owner thread";
        return false;
    }
    if (operation_active_) {
        result.code = CoordinatorResultCode::Busy;
        result.error = "coordinator operation is already active";
        return false;
    }
    return true;
}

bool WorkspaceCoordinator::CheckNoPendingJournal(
    CoordinatorResult& result) const {
    if (!journal_) return true;
    std::string error;
    const std::optional<SwitchPlan> pending = journal_->ReadPending(&error);
    if (!error.empty()) {
        result.code = CoordinatorResultCode::PendingRecovery;
        result.error = "journal read failed: " + error;
        return false;
    }
    if (pending) {
        result.code = CoordinatorResultCode::PendingRecovery;
        result.error = "pending journal transaction must be recovered first";
        return false;
    }
    return true;
}

CoordinatorResult WorkspaceCoordinator::ReconcileDiscoveryLocked() {
    CoordinatorResult result;
    if (!CheckNoPendingJournal(result)) return result;
    if (!discover_) {
        result.code = CoordinatorResultCode::DiscoveryFailed;
        result.error = "complete discovery callback is unavailable";
        return result;
    }

    std::vector<WindowLifecycleEvent> hints;
    for (std::size_t attempt = 1; attempt <= max_discovery_attempts_;
         ++attempt) {
        result.discovery_attempts = attempt;
        WindowLifecycleBatch before = source_.DrainBatch();
        hints.insert(hints.end(),
                     std::make_move_iterator(before.events.begin()),
                     std::make_move_iterator(before.events.end()));

        std::vector<WindowRecord> observed;
        std::string error;
        if (!discover_(observed, &error)) {
            result.code = CoordinatorResultCode::DiscoveryFailed;
            result.error = error.empty() ? "complete discovery failed" : error;
            return result;
        }

        WindowLifecycleBatch after = source_.DrainBatch();
        const bool quiet = !before.overflowed && !after.overflowed &&
                           after.events.empty();
        hints.insert(hints.end(),
                     std::make_move_iterator(after.events.begin()),
                     std::make_move_iterator(after.events.end()));
        if (!quiet) continue;

        if (!lifecycle_.ReconcileCompleteSnapshot(
                hints, std::move(observed), &result.lifecycle, &error)) {
            result.code = CoordinatorResultCode::DiscoveryFailed;
            result.error = error.empty() ? "snapshot reconciliation failed"
                                         : error;
            return result;
        }
        return result;
    }

    result.code = CoordinatorResultCode::DiscoveryUnstable;
    result.error = "lifecycle did not become quiet within discovery bound";
    return result;
}

CoordinatorResult WorkspaceCoordinator::ReconcileDiscovery() {
    CoordinatorResult result;
    if (!CheckEntry(result)) return result;
    OperationScope operation(*this);
    return ReconcileDiscoveryLocked();
}

CoordinatorResult WorkspaceCoordinator::Switch(MonitorId monitor,
                                                WorkspaceId target_workspace) {
    CoordinatorResult result;
    if (!CheckEntry(result)) return result;
    OperationScope operation(*this);

    result = ReconcileDiscoveryLocked();
    if (!result.succeeded()) return result;

    std::string error;
    const std::optional<SwitchPlan> plan =
        engine_.PrepareSwitch(monitor, target_workspace, &error);
    if (!plan) {
        result.code = CoordinatorResultCode::PlanRejected;
        result.error = error.empty() ? "switch plan was rejected" : error;
        return result;
    }

    // A hint after the authoritative snapshot makes this plan suspect. Leave
    // it queued for the next bounded reconciliation and fail without mutation.
    WindowLifecycleBatch late = source_.DrainBatch();
    for (WindowLifecycleEvent& event : late.events) {
        source_.Collect(std::move(event));
    }
    if (late.overflowed || !late.events.empty()) {
        result.code = CoordinatorResultCode::DiscoveryUnstable;
        result.error = "lifecycle changed after switch planning";
        return result;
    }

    result.transaction =
        engine_.ExecuteSwitch(*plan, move_, observe_, journal_);
    if (!result.transaction.committed) {
        result.code = CoordinatorResultCode::TransactionFailed;
        result.error = result.transaction.error;
    }
    return result;
}

CoordinatorResult WorkspaceCoordinator::RecoverPending() {
    CoordinatorResult result;
    if (!CheckEntry(result)) return result;
    OperationScope operation(*this);
    if (!journal_) {
        result.code = CoordinatorResultCode::RecoveryFailed;
        result.error = "recovery journal is unavailable";
        return result;
    }
    std::string error;
    const std::optional<SwitchPlan> pending = journal_->ReadPending(&error);
    if (!error.empty() || !pending) {
        result.code = CoordinatorResultCode::RecoveryFailed;
        result.error = !error.empty() ? "journal read failed: " + error
                                      : "journal has no pending transaction";
        return result;
    }
    result.recovery =
        engine_.RecoverPending(*pending, move_, observe_, journal_);
    if (!result.recovery.recovered) {
        result.code = CoordinatorResultCode::RecoveryFailed;
        result.error = result.recovery.error;
    }
    return result;
}

const char* CoordinatorResultCodeText(CoordinatorResultCode code) noexcept {
    switch (code) {
        case CoordinatorResultCode::Succeeded: return "succeeded";
        case CoordinatorResultCode::Busy: return "busy";
        case CoordinatorResultCode::WrongThread: return "wrong-thread";
        case CoordinatorResultCode::PendingRecovery: return "pending-recovery";
        case CoordinatorResultCode::DiscoveryFailed: return "discovery-failed";
        case CoordinatorResultCode::DiscoveryUnstable: return "discovery-unstable";
        case CoordinatorResultCode::PlanRejected: return "plan-rejected";
        case CoordinatorResultCode::TransactionFailed: return "transaction-failed";
        case CoordinatorResultCode::RecoveryFailed: return "recovery-failed";
        default: return "unknown";
    }
}

int CmdWorkspaceCoordinatorTest() {
    Heading("workspace-coordinator-test");
    GUID carrier{};
    carrier.Data1 = 1;
    GUID parking{};
    parking.Data1 = 2;
    WorkspaceEngine engine(carrier, parking);
    std::string error;
    bool ok = engine.AddMonitor(1, 10, {10, 11}, &error);

    WindowIdentity a{reinterpret_cast<HWND>(1), 100, {1, 1}, true};
    WindowIdentity b{reinterpret_cast<HWND>(2), 101, {2, 2}, true};
    WindowCapabilities capabilities{true, true, true, true, true};
    std::vector<WindowRecord> snapshot{
        {a, 1, 10, NativeDesktopRole::Carrier, capabilities},
        {b, 1, 11, NativeDesktopRole::Parking, capabilities}};
    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        roles{{a, NativeDesktopRole::Carrier},
              {b, NativeDesktopRole::Parking}};
    WinEventLifecycleSource source;
    WindowLifecycleAdapter lifecycle(engine, {});
    int discoveries = 0;
    WorkspaceCoordinator coordinator(
        engine, lifecycle, source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            observed = snapshot;
            if (++discoveries == 1) {
                source.Collect({WindowLifecycleEventKind::Appeared, a.hwnd, a});
            }
            return true;
        },
        [&](const WindowRecord& window, NativeDesktopRole target) {
            roles[window.identity] = target;
            return true;
        },
        [&](const WindowRecord& window) { return roles[window.identity]; },
        nullptr, 3);

    const CoordinatorResult reconciled = coordinator.ReconcileDiscovery();
    ok = ok && reconciled.succeeded() &&
         reconciled.discovery_attempts == 2 &&
         reconciled.lifecycle.events == 1;

    const std::filesystem::path pending_path =
        std::filesystem::temp_directory_path() /
        ("vdprobe-coordinator-pending-" +
         std::to_string(GetCurrentProcessId()) + ".journal");
    std::error_code remove_error;
    std::filesystem::remove(pending_path, remove_error);
    WorkspaceJournal pending_journal(pending_path);
    std::string pending_error;
    const std::optional<SwitchPlan> pending_plan =
        engine.PrepareSwitch(1, 11, &pending_error);
    const bool journal_started =
        pending_plan && pending_journal.Begin(*pending_plan, &pending_error);
    WorkspaceCoordinator gated(
        engine, lifecycle, source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            observed = snapshot;
            return true;
        },
        [&](const WindowRecord& window, NativeDesktopRole target) {
            roles[window.identity] = target;
            return true;
        },
        [&](const WindowRecord& window) { return roles[window.identity]; },
        &pending_journal, 2);
    const CoordinatorResult blocked =
        journal_started ? gated.Switch(1, 11) : CoordinatorResult{};
    const bool pending_gate_ok =
        journal_started &&
        blocked.code == CoordinatorResultCode::PendingRecovery &&
        roles[a] == NativeDesktopRole::Carrier &&
        roles[b] == NativeDesktopRole::Parking;
    if (journal_started) {
        std::string abort_error;
        if (!pending_journal.Abort(&abort_error)) {
            ok = false;
            if (error.empty()) error = abort_error;
        }
    }
    std::filesystem::remove(pending_path, remove_error);
    ok = ok && pending_gate_ok;

    const CoordinatorResult switched = coordinator.Switch(1, 11);
    ok = ok && switched.succeeded() && switched.transaction.committed &&
         engine.Monitor(1)->active == 11 &&
         roles[a] == NativeDesktopRole::Parking &&
         roles[b] == NativeDesktopRole::Carrier &&
         engine.CheckInvariant(&error);

    Field("bounded quiet snapshot", reconciled.succeeded() ? "PASS" : "FAIL");
    Field("pending journal gate",
          pending_gate_ok ? "PASS" : "FAIL");
    Field("serialized stale-safe switch", switched.succeeded() ? "PASS" : "FAIL");
    Field("result", ok ? "PASS" : "FAIL");
    if (!ok && !error.empty()) Field("error", error);
    return ok ? 0 : 1;
}

}  // namespace vd
