#include "workspace_startup.h"

#include <algorithm>
#include <exception>
#include <fstream>
#include <system_error>
#include <unordered_map>
#include <utility>

#include "util.h"

namespace vd {

WorkspaceStartup::WorkspaceStartup(
    WorkspaceEngine& engine, WorkspaceCoordinator& coordinator,
    WinEventLifecycleSource& lifecycle_source,
    DiscoverCompleteSnapshot discover, GUID carrier, GUID parking,
    std::filesystem::path journal_path,
    RecoveryRuntimeFactory make_recovery_runtime,
    std::size_t max_snapshot_attempts)
    : normal_engine_(engine),
      normal_coordinator_(coordinator),
      lifecycle_source_(lifecycle_source),
      discover_(std::move(discover)),
      carrier_(carrier),
      parking_(parking),
      journal_(std::move(journal_path)),
      make_recovery_runtime_(std::move(make_recovery_runtime)),
      max_snapshot_attempts_(std::max<std::size_t>(1, max_snapshot_attempts)) {}

WorkspaceStartupResult WorkspaceStartup::Blocked(std::string error) const {
    return {WorkspaceStartupState::Blocked, false, std::move(error)};
}

bool WorkspaceStartup::CaptureQuietCompleteSnapshot(
    std::vector<WindowRecord>& observed, std::string* error) {
    if (!discover_) {
        if (error) *error = "complete startup discovery callback is unavailable";
        return false;
    }
    for (std::size_t attempt = 0; attempt < max_snapshot_attempts_; ++attempt) {
        const WindowLifecycleBatch before = lifecycle_source_.DrainBatch();
        if (before.overflowed) continue;
        std::vector<WindowRecord> candidate;
        std::string discovery_error;
        bool discovered = false;
        try {
            discovered = discover_(candidate, &discovery_error);
        } catch (const std::exception& exception) {
            if (error) *error = std::string("complete startup discovery threw: ") +
                                exception.what();
            return false;
        } catch (...) {
            if (error) *error = "complete startup discovery threw";
            return false;
        }
        if (!discovered) {
            if (error) {
                *error = discovery_error.empty() ? "complete startup discovery failed"
                                                 : discovery_error;
            }
            return false;
        }
        const WindowLifecycleBatch after = lifecycle_source_.DrainBatch();
        if (!after.overflowed && after.events.empty()) {
            observed = std::move(candidate);
            return true;
        }
    }
    if (error) *error = "lifecycle did not become quiet during startup snapshot";
    return false;
}

WorkspaceStartupResult WorkspaceStartup::RecoverAtStartup() {
    recovery_runtime_.reset();
    std::string error;
    if (!lifecycle_source_.running() && !lifecycle_source_.Start(&error)) {
        return Blocked(error.empty() ? "lifecycle source failed to start" : error);
    }
    if (!lifecycle_source_.healthy()) {
        return Blocked("lifecycle source is unavailable at startup");
    }

    const std::optional<SwitchPlan> pending = journal_.ReadPending(&error);
    if (!error.empty()) return Blocked("journal read failed: " + error);

    if (!pending) {
        const CoordinatorResult reconciled = normal_coordinator_.ReconcileDiscovery();
        if (!reconciled.succeeded()) {
            return Blocked("initial complete reconciliation failed: " +
                           reconciled.error);
        }
        return {WorkspaceStartupState::Ready, false, {}};
    }

    // Do not let journal contents alone create a recovery model. A quiet,
    // complete snapshot must independently prove every pending identity.
    std::vector<WindowRecord> snapshot;
    if (!CaptureQuietCompleteSnapshot(snapshot, &error)) {
        return Blocked(error);
    }
    std::unique_ptr<WorkspaceEngine> recovered =
        WorkspaceEngine::BootstrapPendingRecoveryModel(
            carrier_, parking_, *pending, snapshot, &error);
    if (!recovered) {
        return Blocked(error.empty() ? "pending recovery model bootstrap failed" : error);
    }
    if (!make_recovery_runtime_) {
        return Blocked("pending recovery runtime factory is unavailable");
    }
    std::unique_ptr<WorkspaceStartupRecoveryRuntime> runtime;
    try {
        runtime = make_recovery_runtime_(std::move(recovered), journal_, &error);
    } catch (const std::exception& exception) {
        return Blocked(std::string("pending recovery runtime factory threw: ") +
                       exception.what());
    } catch (...) {
        return Blocked("pending recovery runtime factory threw");
    }
    if (!runtime || !runtime->engine || !runtime->lifecycle || !runtime->coordinator) {
        return Blocked(error.empty() ? "pending recovery runtime is incomplete" : error);
    }
    const CoordinatorResult recovery = runtime->coordinator->RecoverPending();
    if (!recovery.succeeded()) {
        return Blocked("pending recovery failed: " + recovery.error);
    }
    // Recovery changes native roles through caller callbacks. Require a new
    // full reconciliation before exposing either normal operations or READY.
    const CoordinatorResult reconciled = runtime->coordinator->ReconcileDiscovery();
    if (!reconciled.succeeded()) {
        return Blocked("post-recovery complete reconciliation failed: " +
                       reconciled.error);
    }
    recovery_runtime_ = std::move(runtime);
    return {WorkspaceStartupState::Ready, true, {}};
}

WorkspaceEngine* WorkspaceStartup::active_engine() const noexcept {
    return recovery_runtime_ ? recovery_runtime_->engine.get() : &normal_engine_;
}

WorkspaceCoordinator* WorkspaceStartup::active_coordinator() const noexcept {
    return recovery_runtime_ ? recovery_runtime_->coordinator.get()
                             : &normal_coordinator_;
}

const char* WorkspaceStartupStateText(WorkspaceStartupState state) noexcept {
    return state == WorkspaceStartupState::Ready ? "ready" : "blocked";
}

namespace {

GUID TestGuid(DWORD value) {
    GUID result{};
    result.Data1 = value;
    return result;
}

WindowCapabilities TestCapabilities() {
    return {true, true, true, true, true};
}

WindowIdentity TestIdentity(std::uintptr_t hwnd, DWORD pid, DWORD time) {
    return {reinterpret_cast<HWND>(hwnd), pid, {time, time}, true};
}

std::filesystem::path TestJournalPath(const char* name) {
    return std::filesystem::temp_directory_path() /
           (std::string("vdprobe-workspace-startup-") + name + "-" +
            std::to_string(GetCurrentProcessId()) + ".journal");
}

bool RemoveTestJournal(const std::filesystem::path& path) {
    std::error_code error;
    std::filesystem::remove(path, error);
    return !error;
}

}  // namespace

int CmdWorkspaceStartupTest() {
    Heading("workspace-startup-test");
    const GUID carrier = TestGuid(51);
    const GUID parking = TestGuid(52);
    const WindowIdentity first = TestIdentity(51, 501, 51);
    const WindowIdentity second = TestIdentity(52, 502, 52);
    const WindowCapabilities capabilities = TestCapabilities();
    std::uintptr_t hooks = 1000;
    auto install = [&](DWORD, DWORD, WINEVENTPROC) {
        return reinterpret_cast<HWINEVENTHOOK>(hooks++);
    };
    const auto remove = [](HWINEVENTHOOK) { return true; };
    bool ok = true;
    std::string error;

    // Clean startup: the supplied normal model/coordinator performs the first
    // authoritative reconciliation. The move callback must remain untouched.
    const std::filesystem::path clean_path = TestJournalPath("clean");
    RemoveTestJournal(clean_path);
    WorkspaceEngine clean_engine(carrier, parking);
    ok = clean_engine.AddMonitor(1, 10, {10, 11}, &error) && ok;
    WinEventLifecycleSource clean_source(install, remove);
    WindowLifecycleAdapter clean_lifecycle(clean_engine, {});
    int clean_discoveries = 0;
    int clean_moves = 0;
    const std::vector<WindowRecord> clean_snapshot{
        {first, 1, 10, NativeDesktopRole::Carrier, capabilities},
        {second, 1, 11, NativeDesktopRole::Parking, capabilities}};
    WorkspaceCoordinator clean_coordinator(
        clean_engine, clean_lifecycle, clean_source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            ++clean_discoveries;
            observed = clean_snapshot;
            return true;
        },
        [&](const WindowRecord&, NativeDesktopRole) { ++clean_moves; return true; },
        [](const WindowRecord& record) { return record.native_role; },
        nullptr, 2);
    WorkspaceStartup clean_startup(
        clean_engine, clean_coordinator, clean_source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            observed = clean_snapshot;
            return true;
        },
        carrier, parking, clean_path);
    const WorkspaceStartupResult clean = clean_startup.RecoverAtStartup();
    const bool clean_ok = clean.ready() && !clean.recovered_pending &&
                          clean_discoveries == 1 && clean_moves == 0 &&
                          clean_engine.FindWindow(first) != nullptr &&
                          clean_source.healthy();
    clean_source.Stop();
    ok = ok && clean_ok && clean_source.shutdown_ok() && RemoveTestJournal(clean_path);

    // Pending startup must use a fresh engine/coordinator and a second full
    // snapshot after recovery. The callbacks below only update an in-memory
    // role map; this command makes no native window or desktop calls.
    const std::filesystem::path pending_path = TestJournalPath("pending");
    RemoveTestJournal(pending_path);
    WorkspaceEngine interrupted(carrier, parking);
    ok = interrupted.AddMonitor(1, 10, {10, 11}, &error) && ok;
    ok = (interrupted.UpsertWindow({first, 1, 10, NativeDesktopRole::Carrier,
                                    capabilities}, &error) == UpsertResult::Added) && ok;
    ok = (interrupted.UpsertWindow({second, 1, 11, NativeDesktopRole::Parking,
                                    capabilities}, &error) == UpsertResult::Added) && ok;
    const std::optional<SwitchPlan> pending_plan = interrupted.PrepareSwitch(1, 11, &error);
    WorkspaceJournal pending_journal(pending_path);
    const bool began = pending_plan && pending_journal.Begin(*pending_plan, &error);
    WorkspaceEngine pending_normal(carrier, parking);
    ok = pending_normal.AddMonitor(1, 10, {10, 11}, &error) && ok;
    WinEventLifecycleSource pending_source(install, remove);
    WindowLifecycleAdapter pending_normal_lifecycle(pending_normal, {});
    WorkspaceCoordinator pending_normal_coordinator(
        pending_normal, pending_normal_lifecycle, pending_source,
        [](std::vector<WindowRecord>&, std::string*) { return false; }, {}, {},
        &pending_journal, 2);
    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash> roles{
        {first, NativeDesktopRole::Parking}, {second, NativeDesktopRole::Parking}};
    int recovery_moves = 0;
    int recovery_discoveries = 0;
    auto recovered_snapshot = [&] {
        return std::vector<WindowRecord>{
            {first, 1, 10, roles[first], capabilities},
            {second, 1, 11, roles[second], capabilities}};
    };
    WorkspaceStartup pending_startup(
        pending_normal, pending_normal_coordinator, pending_source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            observed = recovered_snapshot();
            return true;
        },
        carrier, parking, pending_path,
        [&](std::unique_ptr<WorkspaceEngine> engine, const WorkspaceJournal& journal,
            std::string*) {
            auto runtime = std::make_unique<WorkspaceStartupRecoveryRuntime>();
            runtime->engine = std::move(engine);
            runtime->lifecycle = std::make_unique<WindowLifecycleAdapter>(
                *runtime->engine, WindowLifecycleAdapter::ObserveWindow{});
            runtime->coordinator = std::make_unique<WorkspaceCoordinator>(
                *runtime->engine, *runtime->lifecycle, pending_source,
                [&](std::vector<WindowRecord>& observed, std::string*) {
                    ++recovery_discoveries;
                    observed = recovered_snapshot();
                    return true;
                },
                [&](const WindowRecord& record, NativeDesktopRole target) {
                    ++recovery_moves;
                    roles[record.identity] = target;
                    return true;
                },
                [&](const WindowRecord& record) { return roles[record.identity]; },
                &journal, 2);
            return runtime;
        });
    const WorkspaceStartupResult pending = began
        ? pending_startup.RecoverAtStartup() : WorkspaceStartupResult{};
    std::string pending_read_error;
    const bool pending_ok = began && pending.ready() && pending.recovered_pending &&
                            pending_startup.active_engine() != &pending_normal &&
                            recovery_moves == 1 && recovery_discoveries == 1 &&
                            roles[first] == NativeDesktopRole::Carrier &&
                            !pending_journal.ReadPending(&pending_read_error) &&
                            pending_read_error.empty();
    pending_source.Stop();
    ok = ok && pending_ok && pending_source.shutdown_ok() && RemoveTestJournal(pending_path);

    // A malformed durable record, a snapshot missing a journal identity, and
    // an unavailable lifecycle source all block before any move callback.
    const std::filesystem::path malformed_path = TestJournalPath("malformed");
    RemoveTestJournal(malformed_path);
    { std::ofstream malformed(malformed_path, std::ios::trunc); malformed << "BEGIN invalid\n"; }
    WorkspaceEngine malformed_engine(carrier, parking);
    malformed_engine.AddMonitor(1, 10, {10, 11}, &error);
    WinEventLifecycleSource malformed_source(install, remove);
    WindowLifecycleAdapter malformed_lifecycle(malformed_engine, {});
    int blocked_moves = 0;
    WorkspaceCoordinator malformed_coordinator(
        malformed_engine, malformed_lifecycle, malformed_source,
        [](std::vector<WindowRecord>&, std::string*) { return true; },
        [&](const WindowRecord&, NativeDesktopRole) { ++blocked_moves; return true; }, {},
        nullptr, 2);
    WorkspaceStartup malformed_startup(
        malformed_engine, malformed_coordinator, malformed_source,
        [](std::vector<WindowRecord>&, std::string*) { return true; },
        carrier, parking, malformed_path);
    const WorkspaceStartupResult malformed = malformed_startup.RecoverAtStartup();
    malformed_source.Stop();
    const bool malformed_ok = malformed.state == WorkspaceStartupState::Blocked &&
                              blocked_moves == 0 && std::filesystem::exists(malformed_path) &&
                              malformed_source.shutdown_ok();
    ok = ok && malformed_ok && RemoveTestJournal(malformed_path);

    const std::filesystem::path missing_path = TestJournalPath("missing");
    RemoveTestJournal(missing_path);
    WorkspaceJournal missing_journal(missing_path);
    const bool missing_began = pending_plan && missing_journal.Begin(*pending_plan, &error);
    WorkspaceEngine missing_engine(carrier, parking);
    missing_engine.AddMonitor(1, 10, {10, 11}, &error);
    WinEventLifecycleSource missing_source(install, remove);
    WindowLifecycleAdapter missing_lifecycle(missing_engine, {});
    WorkspaceCoordinator missing_coordinator(
        missing_engine, missing_lifecycle, missing_source,
        [](std::vector<WindowRecord>&, std::string*) { return false; }, {}, {},
        &missing_journal, 2);
    int missing_factory_calls = 0;
    WorkspaceStartup missing_startup(
        missing_engine, missing_coordinator, missing_source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            observed = {{first, 1, 10, NativeDesktopRole::Carrier, capabilities}};
            return true;
        },
        carrier, parking, missing_path,
        [&](std::unique_ptr<WorkspaceEngine>, const WorkspaceJournal&, std::string*) {
            ++missing_factory_calls;
            return std::unique_ptr<WorkspaceStartupRecoveryRuntime>{};
        });
    const WorkspaceStartupResult missing = missing_began
        ? missing_startup.RecoverAtStartup() : WorkspaceStartupResult{};
    missing_source.Stop();
    const bool missing_ok = missing_began && missing.state == WorkspaceStartupState::Blocked &&
                            missing_factory_calls == 0 && std::filesystem::exists(missing_path) &&
                            missing_source.shutdown_ok();
    ok = ok && missing_ok && RemoveTestJournal(missing_path);

    const std::filesystem::path unstable_path = TestJournalPath("unstable");
    RemoveTestJournal(unstable_path);
    WorkspaceJournal unstable_journal(unstable_path);
    const bool unstable_began = pending_plan && unstable_journal.Begin(*pending_plan, &error);
    WorkspaceEngine unstable_engine(carrier, parking);
    unstable_engine.AddMonitor(1, 10, {10, 11}, &error);
    WinEventLifecycleSource unstable_source(install, remove);
    WindowLifecycleAdapter unstable_lifecycle(unstable_engine, {});
    WorkspaceCoordinator unstable_coordinator(
        unstable_engine, unstable_lifecycle, unstable_source,
        [](std::vector<WindowRecord>&, std::string*) { return false; }, {}, {},
        &unstable_journal, 2);
    int unstable_factory_calls = 0;
    WorkspaceStartup unstable_startup(
        unstable_engine, unstable_coordinator, unstable_source,
        [&](std::vector<WindowRecord>& observed, std::string*) {
            observed = clean_snapshot;
            unstable_source.Collect(
                {WindowLifecycleEventKind::Appeared, first.hwnd, first});
            return true;
        },
        carrier, parking, unstable_path,
        [&](std::unique_ptr<WorkspaceEngine>, const WorkspaceJournal&, std::string*) {
            ++unstable_factory_calls;
            return std::unique_ptr<WorkspaceStartupRecoveryRuntime>{};
        },
        2);
    const WorkspaceStartupResult unstable = unstable_began
        ? unstable_startup.RecoverAtStartup() : WorkspaceStartupResult{};
    unstable_source.Stop();
    const bool unstable_ok = unstable_began &&
                             unstable.state == WorkspaceStartupState::Blocked &&
                             unstable_factory_calls == 0 &&
                             std::filesystem::exists(unstable_path) &&
                             unstable_source.shutdown_ok();
    ok = ok && unstable_ok && RemoveTestJournal(unstable_path);

    WorkspaceEngine unavailable_engine(carrier, parking);
    unavailable_engine.AddMonitor(1, 10, {10, 11}, &error);
    WinEventLifecycleSource unavailable_source(
        [](DWORD, DWORD, WINEVENTPROC) { return static_cast<HWINEVENTHOOK>(nullptr); }, remove);
    WindowLifecycleAdapter unavailable_lifecycle(unavailable_engine, {});
    int unavailable_discoveries = 0;
    WorkspaceCoordinator unavailable_coordinator(
        unavailable_engine, unavailable_lifecycle, unavailable_source,
        [](std::vector<WindowRecord>&, std::string*) { return true; }, {}, {});
    WorkspaceStartup unavailable_startup(
        unavailable_engine, unavailable_coordinator, unavailable_source,
        [&](std::vector<WindowRecord>&, std::string*) { ++unavailable_discoveries; return true; },
        carrier, parking, TestJournalPath("unavailable"));
    const WorkspaceStartupResult unavailable = unavailable_startup.RecoverAtStartup();
    const bool unavailable_ok = unavailable.state == WorkspaceStartupState::Blocked &&
                                unavailable_discoveries == 0 && !unavailable_source.running();
    ok = ok && unavailable_ok;

    Field("clean READY authoritative snapshot/no move", clean_ok ? "PASS" : "FAIL");
    Field("pending fresh recovery then reconcile", pending_ok ? "PASS" : "FAIL");
    Field("malformed journal blocks and remains", malformed_ok ? "PASS" : "FAIL");
    Field("missing pending identity blocks and remains", missing_ok ? "PASS" : "FAIL");
    Field("unstable lifecycle blocks and remains", unstable_ok ? "PASS" : "FAIL");
    Field("lifecycle unavailable blocks before discovery", unavailable_ok ? "PASS" : "FAIL");
    Field("result", ok ? "PASS" : "FAIL");
    if (!ok && !error.empty()) Field("error", error);
    return ok ? 0 : 1;
}

}  // namespace vd
