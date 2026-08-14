#include "workspace_coordinator.h"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <stdexcept>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
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
    const WorkspaceJournal* journal, std::size_t max_discovery_attempts,
    std::size_t max_switch_attempts)
    : engine_(engine),
      lifecycle_(lifecycle),
      source_(source),
      discover_(std::move(discover)),
      move_(std::move(move)),
      observe_(std::move(observe)),
      journal_(journal),
      max_discovery_attempts_(std::max<std::size_t>(1,
                                                    max_discovery_attempts)),
      max_switch_attempts_(std::max<std::size_t>(1, max_switch_attempts)),
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

    // A hint after the authoritative snapshot makes a plan suspect, but the
    // switch's own native moves can emit window-object events (for example
    // SHOW) for the very windows the plan moves.  Those self-inflicted events
    // are tolerated; an event for any other window means the snapshot may be
    // stale.  A clean rollback is retried with a fresh snapshot because live
    // sessions routinely emit transient window-object events for unrelated
    // windows; only a bounded number of attempts is allowed, and a failure
    // that could not be rolled back stops immediately.
    for (std::size_t attempt = 1; attempt <= max_switch_attempts_; ++attempt) {
        result.switch_attempts = attempt;
        CoordinatorResult attempt_result;
        try {
            attempt_result = ReconcileDiscoveryLocked();
        } catch (const std::exception& exception) {
            attempt_result.code = CoordinatorResultCode::DiscoveryFailed;
            attempt_result.error = ExceptionError("discovery", exception);
            return attempt_result;
        } catch (...) {
            attempt_result.code = CoordinatorResultCode::DiscoveryFailed;
            attempt_result.error = ExceptionError("discovery");
            return attempt_result;
        }
        attempt_result.switch_attempts = attempt;
        if (!attempt_result.succeeded()) return attempt_result;

        std::string error;
        std::optional<SwitchPlan> plan;
        try {
            plan = engine_.PrepareSwitch(monitor, target_workspace, &error);
        } catch (const std::exception& exception) {
            attempt_result.code = CoordinatorResultCode::PlanRejected;
            attempt_result.error = ExceptionError("switch planning", exception);
            return attempt_result;
        } catch (...) {
            attempt_result.code = CoordinatorResultCode::PlanRejected;
            attempt_result.error = ExceptionError("switch planning");
            return attempt_result;
        }
        if (!plan) {
            attempt_result.code = CoordinatorResultCode::PlanRejected;
            attempt_result.error =
                error.empty() ? "switch plan was rejected" : error;
            return attempt_result;
        }

        const std::unordered_set<std::uintptr_t> affected_hwnds = [&]() {
            std::unordered_set<std::uintptr_t> hwnds;
            for (const SwitchOperation& operation : plan->operations) {
                hwnds.insert(reinterpret_cast<std::uintptr_t>(
                    operation.identity.hwnd));
            }
            return hwnds;
        }();
        auto events_benign =
            [&affected_hwnds](const WindowLifecycleBatch& batch) {
                if (batch.overflowed) return false;
                for (const WindowLifecycleEvent& event : batch.events) {
                    if (event.hwnd == nullptr ||
                        !affected_hwnds.contains(
                            reinterpret_cast<std::uintptr_t>(event.hwnd))) {
                        return false;
                    }
                }
                return true;
            };

        WindowLifecycleBatch late;
        try {
            late = source_.DrainBatch();
            for (WindowLifecycleEvent& event : late.events) {
                source_.Collect(std::move(event));
            }
        } catch (const std::exception& exception) {
            attempt_result.code = CoordinatorResultCode::DiscoveryUnstable;
            attempt_result.error = ExceptionError("lifecycle validation",
                                                  exception);
            return attempt_result;
        } catch (...) {
            attempt_result.code = CoordinatorResultCode::DiscoveryUnstable;
            attempt_result.error = ExceptionError("lifecycle validation");
            return attempt_result;
        }
        if (!events_benign(late)) {
            if (attempt < max_switch_attempts_) continue;
            attempt_result.code = CoordinatorResultCode::DiscoveryUnstable;
            attempt_result.error = "lifecycle changed after switch planning";
            return attempt_result;
        }

        try {
            attempt_result.transaction =
                engine_.ExecuteSwitch(*plan, move_, observe_, journal_, [&] {
                    if (!source_.healthy()) return false;
                    WindowLifecycleBatch post = source_.DrainBatch();
                    for (WindowLifecycleEvent& event : post.events) {
                        source_.Collect(std::move(event));
                    }
                    return events_benign(post);
                });
        } catch (const std::exception& exception) {
            attempt_result.code = CoordinatorResultCode::TransactionFailed;
            attempt_result.error =
                ExceptionError("switch transaction", exception);
            return attempt_result;
        } catch (...) {
            attempt_result.code = CoordinatorResultCode::TransactionFailed;
            attempt_result.error = ExceptionError("switch transaction");
            return attempt_result;
        }
        if (attempt_result.transaction.committed) return attempt_result;

        attempt_result.code = CoordinatorResultCode::TransactionFailed;
        attempt_result.error = attempt_result.transaction.error;
        if (!attempt_result.transaction.rollback_succeeded ||
            attempt_result.transaction.recovery_required ||
            attempt >= max_switch_attempts_) {
            return attempt_result;
        }
    }

    result.code = CoordinatorResultCode::TransactionFailed;
    result.error = "switch did not stabilize within the attempt bound";
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
    exception_engine.SetAutoQuarantine(false);
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
    const WindowIdentity e{reinterpret_cast<HWND>(5), 104, {5, 5}, true};
    const WindowIdentity f{reinterpret_cast<HWND>(6), 105, {6, 6}, true};
    const std::vector<WindowRecord> epoch_snapshot{
        {e, 3, 30, NativeDesktopRole::Carrier, capabilities},
        {f, 3, 31, NativeDesktopRole::Parking, capabilities}};
    bool epoch_ok = true;

    // A lifecycle hint for a window the switch itself moves is self-inflicted
    // noise (the native move emits window-object events for the moved window)
    // and must be tolerated: the plan is still valid and commits.
    {
        WorkspaceEngine tolerant_engine(epoch_carrier, epoch_parking);
        tolerant_engine.SetAutoQuarantine(false);
        bool tolerant_ok =
            tolerant_engine.AddMonitor(3, 30, {30, 31}, &error);
        std::unordered_map<WindowIdentity, NativeDesktopRole,
                           WindowIdentityHash>
            tolerant_roles{{e, NativeDesktopRole::Carrier},
                           {f, NativeDesktopRole::Parking}};
        WinEventLifecycleSource tolerant_source(
            [&](DWORD, DWORD, WINEVENTPROC) {
                return reinterpret_cast<HWINEVENTHOOK>(fake_hook_value++);
            },
            [](HWINEVENTHOOK) { return true; });
        tolerant_ok = tolerant_ok && tolerant_source.Start(&error);
        WindowLifecycleAdapter tolerant_lifecycle(tolerant_engine, {});
        bool injected_self_hint = false;
        WorkspaceCoordinator tolerant_coordinator(
            tolerant_engine, tolerant_lifecycle, tolerant_source,
            [&](std::vector<WindowRecord>& observed, std::string*) {
                observed = epoch_snapshot;
                return true;
            },
            [&](const WindowRecord& window, NativeDesktopRole target) {
                tolerant_roles[window.identity] = target;
                if (!injected_self_hint) {
                    injected_self_hint = true;
                    tolerant_source.Collect(
                        {WindowLifecycleEventKind::Appeared, e.hwnd, e});
                }
                return true;
            },
            [&](const WindowRecord& window) {
                return tolerant_roles.at(window.identity);
            });
        const CoordinatorResult tolerant_switch =
            tolerant_coordinator.Switch(3, 31);
        tolerant_ok = tolerant_ok &&
                      tolerant_switch.succeeded() &&
                      tolerant_switch.transaction.committed &&
                      tolerant_engine.Monitor(3)->active == 31 &&
                      tolerant_roles[e] == NativeDesktopRole::Parking &&
                      tolerant_roles[f] == NativeDesktopRole::Carrier;
        tolerant_source.Stop();
        Field("self-inflicted plan-window hint tolerated",
              tolerant_ok ? "PASS" : "FAIL");
        epoch_ok = epoch_ok && tolerant_ok;
        ok = ok && tolerant_ok;
    }

    // A lifecycle hint for a window outside the switch plan means the
    // authoritative snapshot may be stale.  A transient hint is retried with
    // a fresh snapshot; only a persistent hint exhausts the bounded attempts.
    {
        WorkspaceEngine strict_engine(epoch_carrier, epoch_parking);
        strict_engine.SetAutoQuarantine(false);
        bool strict_ok = strict_engine.AddMonitor(3, 30, {30, 31}, &error);
        const WindowIdentity z{reinterpret_cast<HWND>(9), 109, {9, 9}, true};
        std::unordered_map<WindowIdentity, NativeDesktopRole,
                           WindowIdentityHash>
            strict_roles{{e, NativeDesktopRole::Carrier},
                         {f, NativeDesktopRole::Parking}};
        WinEventLifecycleSource strict_source(
            [&](DWORD, DWORD, WINEVENTPROC) {
                return reinterpret_cast<HWINEVENTHOOK>(fake_hook_value++);
            },
            [](HWINEVENTHOOK) { return true; });
        strict_ok = strict_ok && strict_source.Start(&error);
        WindowLifecycleAdapter strict_lifecycle(strict_engine, {});
        bool injected_unrelated_hint = false;
        WorkspaceCoordinator strict_coordinator(
            strict_engine, strict_lifecycle, strict_source,
            [&](std::vector<WindowRecord>& observed, std::string*) {
                observed = epoch_snapshot;
                return true;
            },
            [&](const WindowRecord& window, NativeDesktopRole target) {
                strict_roles[window.identity] = target;
                if (!injected_unrelated_hint) {
                    injected_unrelated_hint = true;
                    strict_source.Collect(
                        {WindowLifecycleEventKind::Appeared, z.hwnd, z});
                }
                return true;
            },
            [&](const WindowRecord& window) {
                return strict_roles.at(window.identity);
            });
        const CoordinatorResult strict_switch = strict_coordinator.Switch(3, 31);
        strict_ok = strict_ok &&
                    strict_switch.succeeded() &&
                    strict_switch.transaction.committed &&
                    strict_switch.switch_attempts == 2 &&
                    strict_engine.Monitor(3)->active == 31 &&
                    strict_roles[e] == NativeDesktopRole::Parking &&
                    strict_roles[f] == NativeDesktopRole::Carrier;
        strict_source.Stop();
        Field("transient unrelated-window hint retried and committed",
              strict_ok ? "PASS" : "FAIL");
        epoch_ok = epoch_ok && strict_ok;
        ok = ok && strict_ok;
    }

    {
        WorkspaceEngine noisy_engine(epoch_carrier, epoch_parking);
        noisy_engine.SetAutoQuarantine(false);
        bool noisy_ok = noisy_engine.AddMonitor(3, 30, {30, 31}, &error);
        const WindowIdentity z{reinterpret_cast<HWND>(9), 109, {9, 9}, true};
        std::unordered_map<WindowIdentity, NativeDesktopRole,
                           WindowIdentityHash>
            noisy_roles{{e, NativeDesktopRole::Carrier},
                        {f, NativeDesktopRole::Parking}};
        WinEventLifecycleSource noisy_source(
            [&](DWORD, DWORD, WINEVENTPROC) {
                return reinterpret_cast<HWINEVENTHOOK>(fake_hook_value++);
            },
            [](HWINEVENTHOOK) { return true; });
        noisy_ok = noisy_ok && noisy_source.Start(&error);
        WindowLifecycleAdapter noisy_lifecycle(noisy_engine, {});
        WorkspaceCoordinator noisy_coordinator(
            noisy_engine, noisy_lifecycle, noisy_source,
            [&](std::vector<WindowRecord>& observed, std::string*) {
                observed = epoch_snapshot;
                return true;
            },
            [&](const WindowRecord& window, NativeDesktopRole target) {
                noisy_roles[window.identity] = target;
                // Noise on every attempt: the switch can never stabilize.
                noisy_source.Collect(
                    {WindowLifecycleEventKind::Appeared, z.hwnd, z});
                return true;
            },
            [&](const WindowRecord& window) {
                return noisy_roles.at(window.identity);
            },
            nullptr, 3, 3);
        const CoordinatorResult noisy_switch = noisy_coordinator.Switch(3, 31);
        noisy_ok = noisy_ok &&
                   noisy_switch.code ==
                       CoordinatorResultCode::TransactionFailed &&
                   !noisy_switch.transaction.committed &&
                   noisy_switch.switch_attempts == 3 &&
                   noisy_engine.Monitor(3)->active == 30 &&
                   noisy_roles[e] == NativeDesktopRole::Carrier &&
                   noisy_roles[f] == NativeDesktopRole::Parking;
        noisy_source.Stop();
        Field("persistent unrelated-window hint bounded after retries",
              noisy_ok ? "PASS" : "FAIL");
        epoch_ok = epoch_ok && noisy_ok;
        ok = ok && noisy_ok;
    }

    // A journal must be sufficient to hand a pending operation to a newly
    // constructed coordinator.  This simulates a bounded restart without
    // retaining any old engine/coordinator objects.  After recovery, exercise
    // a complete authoritative snapshot that both closes an omitted record
    // and replaces an HWND generation; neither lifecycle hint is allowed to
    // mutate the replacement model on its own.
    GUID recovery_carrier{};
    recovery_carrier.Data1 = 7;
    GUID recovery_parking{};
    recovery_parking.Data1 = 8;
    WorkspaceEngine interrupted_engine(recovery_carrier, recovery_parking);
    bool fresh_recovery_ok =
        interrupted_engine.AddMonitor(4, 40, {40, 41}, &error);
    WindowIdentity g{reinterpret_cast<HWND>(7), 106, {7, 7}, true};
    WindowIdentity h{reinterpret_cast<HWND>(8), 107, {8, 8}, true};
    if (fresh_recovery_ok) {
        fresh_recovery_ok =
            interrupted_engine.UpsertWindow(
                {g, 4, 40, NativeDesktopRole::Carrier, capabilities},
                &error) == UpsertResult::Added &&
            interrupted_engine.UpsertWindow(
                {h, 4, 41, NativeDesktopRole::Parking, capabilities},
                &error) == UpsertResult::Added;
    }
    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        recovery_roles{{g, NativeDesktopRole::Carrier},
                       {h, NativeDesktopRole::Parking}};
    const std::filesystem::path recovery_path =
        std::filesystem::temp_directory_path() /
        ("vdprobe-coordinator-fresh-recovery-" +
         std::to_string(GetCurrentProcessId()) + ".journal");
    std::filesystem::remove(recovery_path, remove_error);
    WorkspaceJournal recovery_journal(recovery_path);
    const std::optional<SwitchPlan> recovery_plan =
        fresh_recovery_ok ? interrupted_engine.PrepareSwitch(4, 41, &error)
                          : std::nullopt;
    fresh_recovery_ok =
        fresh_recovery_ok && recovery_plan &&
        recovery_journal.Begin(*recovery_plan, &error);
    // Simulate a termination after only the first native operation has had an
    // effect. The original engine is intentionally never used for recovery.
    if (fresh_recovery_ok && !recovery_plan->operations.empty()) {
        const SwitchOperation& first_operation = recovery_plan->operations.front();
        recovery_roles[first_operation.identity] = first_operation.to;
    } else {
        fresh_recovery_ok = false;
    }

    // The replacement process gets no in-memory engine state. Its startup
    // snapshot is enough to reconstruct only the pending transaction model;
    // BootstrapPendingRecoveryModel itself makes no native calls.
    std::vector<WindowRecord> recovery_snapshot{
        {g, 4, 40, NativeDesktopRole::Parking, capabilities},
        {h, 4, 41, NativeDesktopRole::Carrier, capabilities}};
    std::string missing_bootstrap_error;
    const bool missing_bootstrap_rejected =
        fresh_recovery_ok &&
        WorkspaceEngine::BootstrapPendingRecoveryModel(
            recovery_carrier, recovery_parking, *recovery_plan,
            {recovery_snapshot.front()}, &missing_bootstrap_error) == nullptr &&
        missing_bootstrap_error ==
            "startup snapshot cannot prove every pending window identity";
    std::unique_ptr<WorkspaceEngine> replacement_engine =
        fresh_recovery_ok
            ? WorkspaceEngine::BootstrapPendingRecoveryModel(
                  recovery_carrier, recovery_parking, *recovery_plan,
                  recovery_snapshot, &error)
            : nullptr;
    fresh_recovery_ok = fresh_recovery_ok && missing_bootstrap_rejected &&
                        replacement_engine != nullptr;
    WorkspaceEngine replacement_fallback(recovery_carrier, recovery_parking);
    WorkspaceEngine& replacement = replacement_engine ? *replacement_engine
                                                       : replacement_fallback;
    WinEventLifecycleSource recovery_source(
        [&](DWORD, DWORD, WINEVENTPROC) {
            return reinterpret_cast<HWINEVENTHOOK>(fake_hook_value++);
        },
        [](HWINEVENTHOOK) { return true; });
    fresh_recovery_ok = fresh_recovery_ok && recovery_source.Start(&error);
    WindowLifecycleAdapter recovery_lifecycle(replacement, {});
    WorkspaceCoordinator replacement_coordinator(
        replacement, recovery_lifecycle, recovery_source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            observed = recovery_snapshot;
            return true;
        },
        [&](const WindowRecord& window, NativeDesktopRole target) {
            recovery_roles[window.identity] = target;
            return true;
        },
        [&](const WindowRecord& window) {
            return recovery_roles.at(window.identity);
        },
        &recovery_journal, 2);
    const CoordinatorResult fresh_recovered = fresh_recovery_ok
        ? replacement_coordinator.RecoverPending() : CoordinatorResult{};

    WindowIdentity replaced_old{reinterpret_cast<HWND>(9), 108, {9, 9}, true};
    WindowIdentity replaced_new{reinterpret_cast<HWND>(9), 109, {10, 10}, true};
    WindowIdentity closed{reinterpret_cast<HWND>(10), 110, {11, 11}, true};
    if (fresh_recovery_ok && fresh_recovered.succeeded()) {
        // The authoritative post-recovery snapshot must reflect the roles
        // that RecoverPending just observed and restored.
        recovery_snapshot[0].native_role = NativeDesktopRole::Carrier;
        recovery_snapshot[1].native_role = NativeDesktopRole::Parking;
        fresh_recovery_ok =
            replacement_engine->UpsertWindow(
                {replaced_old, 4, 40, NativeDesktopRole::Carrier,
                 capabilities}, &error) == UpsertResult::Added &&
            replacement_engine->UpsertWindow(
                {closed, 4, 40, NativeDesktopRole::Carrier, capabilities},
                &error) == UpsertResult::Added;
        recovery_snapshot.push_back(
            {replaced_new, 4, 40, NativeDesktopRole::Carrier, capabilities});
        recovery_source.Collect(
            {WindowLifecycleEventKind::Appeared, replaced_new.hwnd,
             replaced_old});
        recovery_source.Collect(
            {WindowLifecycleEventKind::Closed, closed.hwnd, std::nullopt});
    }
    const CoordinatorResult fresh_reconciled = fresh_recovery_ok
        ? replacement_coordinator.ReconcileDiscovery() : CoordinatorResult{};
    std::string fresh_pending_error;
    const std::optional<SwitchPlan> fresh_pending =
        recovery_journal.ReadPending(&fresh_pending_error);
    fresh_recovery_ok =
        fresh_recovery_ok && fresh_recovered.succeeded() &&
        fresh_recovered.recovery.recovered && fresh_reconciled.succeeded() &&
        fresh_reconciled.lifecycle.stale_generations == 1 &&
        fresh_reconciled.lifecycle.discovery.updated == 2 &&
        fresh_reconciled.lifecycle.discovery.recreated == 1 &&
        fresh_reconciled.lifecycle.discovery.closed == 1 &&
        replacement.FindWindow(replaced_old) == nullptr &&
        replacement.FindWindow(replaced_new) != nullptr &&
        replacement.FindWindow(closed) == nullptr &&
        replacement.Monitor(4) != nullptr &&
        replacement.Monitor(4)->active == 40 &&
        recovery_roles[g] == NativeDesktopRole::Carrier &&
        recovery_roles[h] == NativeDesktopRole::Parking && !fresh_pending &&
        fresh_pending_error.empty() && replacement.CheckInvariant(&error);
    recovery_source.Stop();
    fresh_recovery_ok = fresh_recovery_ok && recovery_source.shutdown_ok();
    std::filesystem::remove(recovery_path, remove_error);
    ok = ok && fresh_recovery_ok;

    Field("running lifecycle source gate", source_gate_ok ? "PASS" : "FAIL");
    Field("bounded quiet snapshot", reconciled.succeeded() ? "PASS" : "FAIL");
    Field("pending journal gate",
          pending_gate_ok ? "PASS" : "FAIL");
    Field("serialized stale-safe switch", switched.succeeded() ? "PASS" : "FAIL");
    Field("callback exception containment",
          exception_tests_ok ? "PASS" : "FAIL");
    Field("pre-commit lifecycle validation",
          epoch_ok ? "PASS" : "FAIL");
    Field("fresh coordinator recovery and complete lifecycle reconciliation",
          fresh_recovery_ok ? "PASS" : "FAIL");
    Field("result", ok ? "PASS" : "FAIL");
    if (!ok && !error.empty()) Field("error", error);
    return ok ? 0 : 1;
}

}  // namespace vd
