#include "workspace_coordinator.h"

#include <algorithm>
#include <exception>
#include <filesystem>
#include <stdexcept>
#include <system_error>
#include <unordered_map>
#include <utility>

#include "util.h"

namespace vd {

namespace {

std::string ExceptionError(const char* operation,
                           const std::exception& exception) {
    return std::string(operation) + " threw: " + exception.what();
}

std::string ExceptionError(const char* operation) {
    return std::string(operation) + " threw";
}

}  // namespace

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
    if (!source_.healthy()) {
        result.code = CoordinatorResultCode::LifecycleUnavailable;
        result.error = source_.running()
                           ? "lifecycle source is unhealthy"
                           : "lifecycle source is not running";
        return false;
    }
    return true;
}

bool WorkspaceCoordinator::CheckNoPendingJournal(
    CoordinatorResult& result) const {
    if (!journal_) return true;
    std::string error;
    std::optional<SwitchPlan> pending;
    try {
        pending = journal_->ReadPending(&error);
    } catch (const std::exception& exception) {
        result.code = CoordinatorResultCode::PendingRecovery;
        result.error = ExceptionError("journal read", exception);
        return false;
    } catch (...) {
        result.code = CoordinatorResultCode::PendingRecovery;
        result.error = ExceptionError("journal read");
        return false;
    }
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
    try {
        return ReconcileDiscoveryLocked();
    } catch (const std::exception& exception) {
        result.code = CoordinatorResultCode::DiscoveryFailed;
        result.error = ExceptionError("discovery", exception);
        return result;
    } catch (...) {
        result.code = CoordinatorResultCode::DiscoveryFailed;
        result.error = ExceptionError("discovery");
        return result;
    }
}

CoordinatorResult WorkspaceCoordinator::Switch(MonitorId monitor,
                                                WorkspaceId target_workspace) {
    CoordinatorResult result;
    if (!CheckEntry(result)) return result;
    OperationScope operation(*this);

    try {
        result = ReconcileDiscoveryLocked();
    } catch (const std::exception& exception) {
        result.code = CoordinatorResultCode::DiscoveryFailed;
        result.error = ExceptionError("discovery", exception);
        return result;
    } catch (...) {
        result.code = CoordinatorResultCode::DiscoveryFailed;
        result.error = ExceptionError("discovery");
        return result;
    }
    if (!result.succeeded()) return result;

    std::string error;
    std::optional<SwitchPlan> plan;
    try {
        plan = engine_.PrepareSwitch(monitor, target_workspace, &error);
    } catch (const std::exception& exception) {
        result.code = CoordinatorResultCode::PlanRejected;
        result.error = ExceptionError("switch planning", exception);
        return result;
    } catch (...) {
        result.code = CoordinatorResultCode::PlanRejected;
        result.error = ExceptionError("switch planning");
        return result;
    }
    if (!plan) {
        result.code = CoordinatorResultCode::PlanRejected;
        result.error = error.empty() ? "switch plan was rejected" : error;
        return result;
    }

    // A hint after the authoritative snapshot makes this plan suspect. Leave
    // it queued for the next bounded reconciliation and fail without mutation.
    WindowLifecycleBatch late;
    try {
        late = source_.DrainBatch();
        for (WindowLifecycleEvent& event : late.events) {
            source_.Collect(std::move(event));
        }
    } catch (const std::exception& exception) {
        result.code = CoordinatorResultCode::DiscoveryUnstable;
        result.error = ExceptionError("lifecycle validation", exception);
        return result;
    } catch (...) {
        result.code = CoordinatorResultCode::DiscoveryUnstable;
        result.error = ExceptionError("lifecycle validation");
        return result;
    }
    if (late.overflowed || !late.events.empty()) {
        result.code = CoordinatorResultCode::DiscoveryUnstable;
        result.error = "lifecycle changed after switch planning";
        return result;
    }

    // DrainBatch captures its epoch under the same queue lock. Any hint after
    // that quiet boundary therefore changes the epoch before pre-commit.
    const std::uint64_t lifecycle_epoch = late.event_epoch;
    try {
        result.transaction =
            engine_.ExecuteSwitch(*plan, move_, observe_, journal_, [&] {
                return source_.healthy() &&
                       source_.event_epoch() == lifecycle_epoch;
            });
    } catch (const std::exception& exception) {
        result.code = CoordinatorResultCode::TransactionFailed;
        result.error = ExceptionError("switch transaction", exception);
        return result;
    } catch (...) {
        result.code = CoordinatorResultCode::TransactionFailed;
        result.error = ExceptionError("switch transaction");
        return result;
    }
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
    std::optional<SwitchPlan> pending;
    try {
        pending = journal_->ReadPending(&error);
    } catch (const std::exception& exception) {
        result.code = CoordinatorResultCode::RecoveryFailed;
        result.error = ExceptionError("journal read", exception);
        return result;
    } catch (...) {
        result.code = CoordinatorResultCode::RecoveryFailed;
        result.error = ExceptionError("journal read");
        return result;
    }
    if (!error.empty() || !pending) {
        result.code = CoordinatorResultCode::RecoveryFailed;
        result.error = !error.empty() ? "journal read failed: " + error
                                      : "journal has no pending transaction";
        return result;
    }
    try {
        result.recovery =
            engine_.RecoverPending(*pending, move_, observe_, journal_);
    } catch (const std::exception& exception) {
        result.code = CoordinatorResultCode::RecoveryFailed;
        result.error = ExceptionError("pending recovery", exception);
        return result;
    } catch (...) {
        result.code = CoordinatorResultCode::RecoveryFailed;
        result.error = ExceptionError("pending recovery");
        return result;
    }
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
        case CoordinatorResultCode::LifecycleUnavailable:
            return "lifecycle-unavailable";
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
    std::uintptr_t fake_hook_value = 100;
    WinEventLifecycleSource source(
        [&](DWORD, DWORD, WINEVENTPROC) {
            return reinterpret_cast<HWINEVENTHOOK>(fake_hook_value++);
        },
        [](HWINEVENTHOOK) { return true; });
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

    const CoordinatorResult unavailable = coordinator.ReconcileDiscovery();
    const bool source_gate_ok =
        unavailable.code == CoordinatorResultCode::LifecycleUnavailable &&
        discoveries == 0 && source.Start(&error) && source.healthy();
    ok = ok && source_gate_ok;

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

    GUID exception_carrier{};
    exception_carrier.Data1 = 3;
    GUID exception_parking{};
    exception_parking.Data1 = 4;
    WorkspaceEngine exception_engine(exception_carrier, exception_parking);
    bool exception_tests_ok =
        exception_engine.AddMonitor(2, 20, {20, 21}, &error);
    WindowIdentity c{reinterpret_cast<HWND>(3), 102, {3, 3}, true};
    WindowIdentity d{reinterpret_cast<HWND>(4), 103, {4, 4}, true};
    std::vector<WindowRecord> exception_snapshot{
        {c, 2, 20, NativeDesktopRole::Carrier, capabilities},
        {d, 2, 21, NativeDesktopRole::Parking, capabilities}};
    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        exception_roles{{c, NativeDesktopRole::Carrier},
                        {d, NativeDesktopRole::Parking}};
    WinEventLifecycleSource exception_source(
        [&](DWORD, DWORD, WINEVENTPROC) {
            return reinterpret_cast<HWINEVENTHOOK>(fake_hook_value++);
        },
        [](HWINEVENTHOOK) { return true; });
    exception_tests_ok =
        exception_tests_ok && exception_source.Start(&error);
    WindowLifecycleAdapter exception_lifecycle(exception_engine, {});
    WorkspaceCoordinator throwing_discovery(
        exception_engine, exception_lifecycle, exception_source,
        [](std::vector<WindowRecord>&, std::string*) -> bool {
            throw std::runtime_error("test discovery exception");
        },
        [](const WindowRecord&, NativeDesktopRole) { return true; },
        [](const WindowRecord&) { return NativeDesktopRole::Unknown; });
    const CoordinatorResult discovery_exception =
        throwing_discovery.ReconcileDiscovery();
    const CoordinatorResult discovery_after_exception =
        throwing_discovery.ReconcileDiscovery();
    exception_tests_ok =
        exception_tests_ok &&
        discovery_exception.code == CoordinatorResultCode::DiscoveryFailed &&
        discovery_exception.error == "discovery threw: test discovery exception" &&
        discovery_after_exception.code == CoordinatorResultCode::DiscoveryFailed;

    WorkspaceCoordinator throwing_move(
        exception_engine, exception_lifecycle, exception_source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            observed = exception_snapshot;
            return true;
        },
        [](const WindowRecord&, NativeDesktopRole) -> bool {
            throw std::runtime_error("test move exception");
        },
        [&](const WindowRecord& window) {
            return exception_roles.at(window.identity);
        });
    const CoordinatorResult move_exception = throwing_move.Switch(2, 21);
    const CoordinatorResult move_after_exception =
        throwing_move.ReconcileDiscovery();
    exception_tests_ok =
        exception_tests_ok &&
        move_exception.code == CoordinatorResultCode::TransactionFailed &&
        move_exception.error == "move callback threw: test move exception" &&
        move_after_exception.succeeded();

    WorkspaceCoordinator throwing_observe(
        exception_engine, exception_lifecycle, exception_source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            observed = exception_snapshot;
            return true;
        },
        [&](const WindowRecord& window, NativeDesktopRole target) {
            exception_roles[window.identity] = target;
            return true;
        },
        [](const WindowRecord&) -> NativeDesktopRole {
            throw std::runtime_error("test observe exception");
        });
    const CoordinatorResult observe_exception = throwing_observe.Switch(2, 21);
    const CoordinatorResult observe_after_exception =
        throwing_observe.ReconcileDiscovery();
    exception_tests_ok =
        exception_tests_ok &&
        observe_exception.code == CoordinatorResultCode::TransactionFailed &&
        observe_exception.error.rfind(
            "observe callback threw: test observe exception", 0) == 0 &&
        observe_after_exception.succeeded();
    ok = ok && exception_tests_ok;

    GUID epoch_carrier{};
    epoch_carrier.Data1 = 5;
    GUID epoch_parking{};
    epoch_parking.Data1 = 6;
    WorkspaceEngine epoch_engine(epoch_carrier, epoch_parking);
    bool epoch_ok = epoch_engine.AddMonitor(3, 30, {30, 31}, &error);
    WindowIdentity e{reinterpret_cast<HWND>(5), 104, {5, 5}, true};
    WindowIdentity f{reinterpret_cast<HWND>(6), 105, {6, 6}, true};
    std::vector<WindowRecord> epoch_snapshot{
        {e, 3, 30, NativeDesktopRole::Carrier, capabilities},
        {f, 3, 31, NativeDesktopRole::Parking, capabilities}};
    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        epoch_roles{{e, NativeDesktopRole::Carrier},
                    {f, NativeDesktopRole::Parking}};
    WinEventLifecycleSource epoch_source(
        [&](DWORD, DWORD, WINEVENTPROC) {
            return reinterpret_cast<HWINEVENTHOOK>(fake_hook_value++);
        },
        [](HWINEVENTHOOK) { return true; });
    epoch_ok = epoch_ok && epoch_source.Start(&error);
    WindowLifecycleAdapter epoch_lifecycle(epoch_engine, {});
    bool injected_late_hint = false;
    WorkspaceCoordinator epoch_coordinator(
        epoch_engine, epoch_lifecycle, epoch_source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            observed = epoch_snapshot;
            return true;
        },
        [&](const WindowRecord& window, NativeDesktopRole target) {
            epoch_roles[window.identity] = target;
            if (!injected_late_hint) {
                injected_late_hint = true;
                epoch_source.Collect(
                    {WindowLifecycleEventKind::Appeared, e.hwnd, e});
            }
            return true;
        },
        [&](const WindowRecord& window) {
            return epoch_roles.at(window.identity);
        });
    const CoordinatorResult epoch_switch = epoch_coordinator.Switch(3, 31);
    epoch_ok = epoch_ok &&
               epoch_switch.code == CoordinatorResultCode::TransactionFailed &&
               !epoch_switch.transaction.committed &&
               epoch_switch.transaction.rollback_attempted &&
               epoch_switch.transaction.rollback_succeeded &&
               epoch_engine.Monitor(3)->active == 30 &&
               epoch_roles[e] == NativeDesktopRole::Carrier &&
               epoch_roles[f] == NativeDesktopRole::Parking;
    ok = ok && epoch_ok;

    Field("running lifecycle source gate", source_gate_ok ? "PASS" : "FAIL");
    Field("bounded quiet snapshot", reconciled.succeeded() ? "PASS" : "FAIL");
    Field("pending journal gate",
          pending_gate_ok ? "PASS" : "FAIL");
    Field("serialized stale-safe switch", switched.succeeded() ? "PASS" : "FAIL");
    Field("callback exception containment",
          exception_tests_ok ? "PASS" : "FAIL");
    Field("execution-time lifecycle epoch rollback",
          epoch_ok ? "PASS" : "FAIL");
    Field("result", ok ? "PASS" : "FAIL");
    if (!ok && !error.empty()) Field("error", error);
    return ok ? 0 : 1;
}

}  // namespace vd
