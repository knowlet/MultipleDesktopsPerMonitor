#include "workspace_assignment.h"

#include <algorithm>
#include <cstdint>
#include <unordered_set>
#include <utility>

#include "util.h"

namespace vd {
namespace {

void SetError(std::string* error, std::string message) {
    if (error != nullptr) *error = std::move(message);
}

bool SameWorkspaceSet(const std::vector<WorkspaceId>& left,
                      const std::vector<WorkspaceId>& right) {
    if (left.size() != right.size()) return false;
    for (WorkspaceId workspace : left) {
        if (std::count(left.begin(), left.end(), workspace) != 1 ||
            std::find(right.begin(), right.end(), workspace) == right.end()) {
            return false;
        }
    }
    return true;
}

WindowIdentity TestIdentity(std::uintptr_t hwnd, DWORD pid, DWORD generation) {
    WindowIdentity identity;
    identity.hwnd = reinterpret_cast<HWND>(hwnd);
    identity.pid = pid;
    identity.process_creation_time.dwLowDateTime = generation;
    identity.process_creation_time_ok = true;
    return identity;
}

WindowCapabilities TestCapabilities() {
    return {true, true, true, true, true};
}

DiscoveredWindow TestWindow(const WindowIdentity& identity, MonitorId monitor,
                            NativeDesktopRole role,
                            WindowDisposition disposition =
                                WindowDisposition::Managed) {
    DiscoveredWindow window;
    window.identity = identity;
    window.monitor = reinterpret_cast<HMONITOR>(monitor);
    window.native_role = role;
    window.capabilities = TestCapabilities();
    window.disposition = disposition;
    return window;
}

}  // namespace

const WorkspaceAssignmentAdapter::MonitorTopology*
WorkspaceAssignmentAdapter::Topology(MonitorId monitor) const noexcept {
    const auto found = std::find_if(
        topology_.begin(), topology_.end(),
        [monitor](const MonitorTopology& item) { return item.monitor == monitor; });
    return found == topology_.end() ? nullptr : &*found;
}

bool WorkspaceAssignmentAdapter::ConfigureMonitor(
    MonitorId monitor, WorkspaceId active,
    std::vector<WorkspaceId> workspaces, std::string* error) {
    if (error != nullptr) error->clear();
    if (Topology(monitor) != nullptr) {
        SetError(error, "assignment monitor is already configured");
        return false;
    }

    const MonitorWorkspaceState* state = engine_.Monitor(monitor);
    if (state == nullptr || state->active != active ||
        !SameWorkspaceSet(state->workspaces, workspaces)) {
        SetError(error, "assignment topology does not match the engine");
        return false;
    }
    topology_.push_back({monitor, std::move(workspaces)});
    std::sort(topology_.begin(), topology_.end(),
              [](const MonitorTopology& left, const MonitorTopology& right) {
                  return left.monitor < right.monitor;
              });
    return true;
}

bool WorkspaceAssignmentAdapter::ConvertCompleteSnapshot(
    const std::vector<DiscoveredWindow>& discovered,
    std::vector<WindowRecord>& out, std::string* error) const {
    if (error != nullptr) error->clear();

    std::unordered_set<WindowIdentity, WindowIdentityHash> identities;
    std::unordered_set<std::uintptr_t> hwnds;
    std::vector<WindowRecord> candidate;
    candidate.reserve(discovered.size());

    for (const DiscoveredWindow& window : discovered) {
        const std::uintptr_t hwnd =
            reinterpret_cast<std::uintptr_t>(window.identity.hwnd);
        if (window.disposition == WindowDisposition::Closed) {
            SetError(error, "assignment snapshot contains a closed window");
            return false;
        }
        if (window.disposition == WindowDisposition::Unsupported ||
            window.disposition == WindowDisposition::Ambiguous) {
            // Unobservable/unsupported windows (including protected processes
            // whose identity cannot be read) stay outside managed scope; they
            // are never assigned or moved.
            continue;
        }
        if (!window.identity.IsValid() ||
            !identities.insert(window.identity).second ||
            !hwnds.insert(hwnd).second) {
            SetError(error,
                     "assignment snapshot contains an invalid or duplicate window");
            return false;
        }
        if (window.disposition != WindowDisposition::Managed ||
            !window.capabilities.Manageable()) {
            SetError(error, "managed discovery window lacks required capabilities");
            return false;
        }

        const MonitorId observed_monitor =
            reinterpret_cast<MonitorId>(window.monitor);
        const MonitorTopology* topology = Topology(observed_monitor);
        const MonitorWorkspaceState* monitor = engine_.Monitor(observed_monitor);
        if (topology != nullptr &&
            (monitor == nullptr ||
             !SameWorkspaceSet(topology->workspaces, monitor->workspaces))) {
            SetError(error,
                     "configured assignment topology no longer matches the engine");
            return false;
        }
        const WindowRecord* tracked = engine_.FindWindow(window.identity);
        if (tracked != nullptr &&
            tracked->disposition == WindowDisposition::Managed) {
            WorkspaceId assigned_workspace = tracked->workspace;
            if (tracked->monitor != observed_monitor) {
                if (migration_policy_ == MonitorMigrationPolicy::FailClosed) {
                    SetError(error, "tracked window changed monitors");
                    return false;
                }
                if (topology == nullptr || monitor == nullptr) {
                    SetError(error,
                             "tracked window moved to an unconfigured monitor");
                    return false;
                }
                if (window.native_role != NativeDesktopRole::Carrier) {
                    SetError(error,
                             "tracked window moved onto an inactive desktop; "
                             "ownership cannot be proven");
                    return false;
                }
                assigned_workspace = monitor->active;
            }
            if (topology == nullptr ||
                std::find(topology->workspaces.begin(),
                          topology->workspaces.end(), assigned_workspace) ==
                    topology->workspaces.end()) {
                SetError(error,
                         "tracked window is outside configured assignment topology");
                return false;
            }
            const NativeDesktopRole expected =
                assigned_workspace == monitor->active
                    ? NativeDesktopRole::Carrier
                    : NativeDesktopRole::Parking;
            if (window.native_role != expected) {
                SetError(error,
                         "tracked window native role does not match its workspace");
                return false;
            }

            WindowRecord record;
            record.identity = window.identity;
            record.monitor = observed_monitor;
            record.workspace = assigned_workspace;
            record.native_role = window.native_role;
            record.capabilities = window.capabilities;
            record.presentation = window.presentation;
            record.disposition = WindowDisposition::Managed;
            candidate.push_back(std::move(record));
            continue;
        }

        // A different generation using a tracked HWND deliberately reaches
        // this new-candidate path: no assignment is inherited by HWND alone.
        if (topology == nullptr) continue;
        if (window.native_role == NativeDesktopRole::Parking) continue;
        if (window.native_role != NativeDesktopRole::Carrier) {
            SetError(error, "managed discovery window has no native role");
            return false;
        }

        WindowRecord record;
        record.identity = window.identity;
        record.monitor = observed_monitor;
        record.workspace = monitor->active;
        record.native_role = NativeDesktopRole::Carrier;
        record.capabilities = window.capabilities;
        record.presentation = window.presentation;
        record.disposition = WindowDisposition::Managed;
        candidate.push_back(std::move(record));
    }

    std::sort(candidate.begin(), candidate.end(),
              [](const WindowRecord& left, const WindowRecord& right) {
                  return reinterpret_cast<std::uintptr_t>(left.identity.hwnd) <
                         reinterpret_cast<std::uintptr_t>(right.identity.hwnd);
              });
    out = std::move(candidate);
    return true;
}

bool WorkspaceAssignmentAdapter::DeriveInheritedOwnership(
    const std::vector<DiscoveredWindow>& discovered,
    std::vector<InheritedOwnership>& out, std::string* error) const {
    if (error != nullptr) error->clear();

    auto find_window = [&discovered](HWND hwnd) -> const DiscoveredWindow* {
        const auto found = std::find_if(
            discovered.begin(), discovered.end(),
            [hwnd](const DiscoveredWindow& item) {
                return item.identity.hwnd == hwnd;
            });
        return found == discovered.end() ? nullptr : &*found;
    };

    std::vector<InheritedOwnership> result;
    for (const DiscoveredWindow& window : discovered) {
        if (window.owner == nullptr) continue;
        InheritedOwnership inherited;
        inherited.owned_hwnd = window.identity.hwnd;

        const DiscoveredWindow* root = find_window(window.owner);
        std::size_t hops = 0;
        constexpr std::size_t kMaxOwnerHops = 64;
        while (root != nullptr && root->owner != nullptr &&
               hops < kMaxOwnerHops) {
            root = find_window(root->owner);
            ++hops;
        }
        if (root != nullptr) inherited.owner = root->identity;

        if (root != nullptr &&
            root->disposition == WindowDisposition::Managed &&
            root->capabilities.Manageable()) {
            const MonitorId root_monitor =
                reinterpret_cast<MonitorId>(root->monitor);
            const MonitorTopology* root_topology = Topology(root_monitor);
            const MonitorWorkspaceState* root_state =
                engine_.Monitor(root_monitor);
            const WindowRecord* tracked = engine_.FindWindow(root->identity);
            if (root_topology != nullptr && root_state != nullptr &&
                tracked != nullptr &&
                tracked->disposition == WindowDisposition::Managed &&
                std::find(root_topology->workspaces.begin(),
                          root_topology->workspaces.end(),
                          tracked->workspace) !=
                    root_topology->workspaces.end()) {
                inherited.owner_managed = true;
                inherited.inherited_workspace = tracked->workspace;
            }
        }
        result.push_back(std::move(inherited));
    }

    out = std::move(result);
    return true;
}

int CmdWorkspaceAssignmentTest() {
    Heading("workspace-assignment-test");
    Field("native mutation", "none");

    const GUID carrier{0x10101010, 0x1010, 0x1010,
                       {0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10}};
    const GUID parking{0x20202020, 0x2020, 0x2020,
                       {0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20}};
    WorkspaceEngine engine(carrier, parking);
    std::string error;
    bool ok = engine.AddMonitor(1, 10, {10, 11, 12}, &error) &&
              engine.AddMonitor(2, 20, {20, 21}, &error);
    WorkspaceAssignmentAdapter adapter(engine);
    ok = ok && adapter.ConfigureMonitor(1, 10, {10, 11, 12}, &error) &&
         adapter.ConfigureMonitor(2, 20, {20, 21}, &error);

    const WindowIdentity parked = TestIdentity(1, 101, 1);
    const WindowIdentity migrated = TestIdentity(2, 102, 1);
    const WindowIdentity old_generation = TestIdentity(6, 106, 1);
    ok = ok &&
         engine.UpsertWindow({parked, 1, 11, NativeDesktopRole::Parking,
                              TestCapabilities()}, &error) == UpsertResult::Added &&
         engine.UpsertWindow({migrated, 1, 10, NativeDesktopRole::Carrier,
                              TestCapabilities()}, &error) == UpsertResult::Added &&
         engine.UpsertWindow({old_generation, 1, 12,
                              NativeDesktopRole::Parking, TestCapabilities()},
                             &error) == UpsertResult::Added;

    std::vector<WindowRecord> records;
    const WindowIdentity new_carrier = TestIdentity(3, 103, 1);
    const bool carrier_new =
        adapter.ConvertCompleteSnapshot(
            {TestWindow(new_carrier, 1, NativeDesktopRole::Carrier)}, records,
            &error) &&
        records.size() == 1 && records[0].workspace == 10 &&
        records[0].identity == new_carrier;
    Field("new Carrier joins active workspace", carrier_new ? "PASS" : "FAIL");
    ok = ok && carrier_new;

    const bool parking_new =
        adapter.ConvertCompleteSnapshot(
            {TestWindow(TestIdentity(4, 104, 1), 1,
                        NativeDesktopRole::Parking)},
            records, &error) &&
        records.empty();
    Field("new Parking window remains unassigned", parking_new ? "PASS" : "FAIL");
    ok = ok && parking_new;

    const bool parked_preserved =
        adapter.ConvertCompleteSnapshot(
            {TestWindow(parked, 1, NativeDesktopRole::Parking)}, records,
            &error) &&
        records.size() == 1 && records[0].workspace == 11;
    Field("tracked parked workspace preserved",
          parked_preserved ? "PASS" : "FAIL");
    ok = ok && parked_preserved;

    const std::vector<WindowRecord> before_mismatch = records;
    const bool mismatch_closed =
        !adapter.ConvertCompleteSnapshot(
            {TestWindow(parked, 1, NativeDesktopRole::Carrier)}, records,
            &error) &&
        records.size() == before_mismatch.size() &&
        records[0].identity == before_mismatch[0].identity &&
        engine.FindWindow(parked) != nullptr &&
        engine.FindWindow(parked)->workspace == 11;
    Field("tracked native-role mismatch fails closed",
          mismatch_closed ? "PASS" : "FAIL");
    ok = ok && mismatch_closed;

    const bool omitted =
        adapter.ConvertCompleteSnapshot(
            {TestWindow(TestIdentity(7, 107, 1), 1,
                        NativeDesktopRole::Carrier,
                        WindowDisposition::Unsupported),
             TestWindow(TestIdentity(8, 108, 1), 1,
                        NativeDesktopRole::Carrier,
                        WindowDisposition::Ambiguous)},
            records, &error) &&
        records.empty();
    Field("unsupported and ambiguous omitted", omitted ? "PASS" : "FAIL");
    ok = ok && omitted;

    DiscoveredWindow unreadable;
    unreadable.identity.hwnd = reinterpret_cast<HWND>(0x777);
    unreadable.disposition = WindowDisposition::Ambiguous;
    const bool unreadable_omitted =
        adapter.ConvertCompleteSnapshot({unreadable}, records, &error) &&
        records.empty();
    Field("unobservable identity omitted", unreadable_omitted ? "PASS" : "FAIL");
    ok = ok && unreadable_omitted;

    const WindowIdentity new_generation = TestIdentity(6, 206, 2);
    const bool generation_not_inherited =
        adapter.ConvertCompleteSnapshot(
            {TestWindow(new_generation, 1, NativeDesktopRole::Carrier)}, records,
            &error) &&
        records.size() == 1 && records[0].workspace == 10 &&
        records[0].workspace != engine.FindWindow(old_generation)->workspace;
    Field("recreated HWND generation does not inherit",
          generation_not_inherited ? "PASS" : "FAIL");
    ok = ok && generation_not_inherited;

    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        native_roles;
    for (const WindowRecord* window : engine.Windows()) {
        native_roles.emplace(window->identity, window->native_role);
    }
    const std::optional<SwitchPlan> switch_plan =
        engine.PrepareSwitch(1, 11, &error);
    const TransactionResult switched = switch_plan
        ? engine.ExecuteSwitch(
              *switch_plan,
              [&](const WindowRecord& window, NativeDesktopRole target) {
                  native_roles[window.identity] = target;
                  return true;
              },
              [&](const WindowRecord& window) {
                  const auto found = native_roles.find(window.identity);
                  return found == native_roles.end()
                      ? NativeDesktopRole::Unknown
                      : found->second;
              })
        : TransactionResult{};
    const WindowIdentity after_switch = TestIdentity(9, 109, 1);
    const bool active_tracks_engine =
        switched.committed && engine.Monitor(1)->active == 11 &&
        adapter.ConvertCompleteSnapshot(
            {TestWindow(parked, 1, NativeDesktopRole::Carrier),
             TestWindow(migrated, 1, NativeDesktopRole::Parking),
             TestWindow(after_switch, 1, NativeDesktopRole::Carrier)},
            records, &error) &&
        records.size() == 3 &&
        std::any_of(records.begin(), records.end(),
                    [&](const WindowRecord& record) {
                        return record.identity == parked &&
                               record.workspace == 11;
                    }) &&
        std::any_of(records.begin(), records.end(),
                    [&](const WindowRecord& record) {
                        return record.identity == migrated &&
                               record.workspace == 10;
                    }) &&
        std::any_of(records.begin(), records.end(),
                    [&](const WindowRecord& record) {
                        return record.identity == after_switch &&
                               record.workspace == 11;
                    });
    Field("assignment follows switched active workspace",
          active_tracks_engine ? "PASS" : "FAIL");
    ok = ok && active_tracks_engine;

    const bool migration_reassigned =
        adapter.ConvertCompleteSnapshot(
            {TestWindow(migrated, 2, NativeDesktopRole::Carrier)}, records,
            &error) &&
        std::any_of(records.begin(), records.end(),
                    [&](const WindowRecord& record) {
                        return record.identity == migrated &&
                               record.monitor == 2 && record.workspace == 20;
                    }) &&
        engine.FindWindow(migrated) != nullptr &&
        engine.FindWindow(migrated)->monitor == 1;
    Field("tracked monitor migration reassigns to destination active",
          migration_reassigned ? "PASS" : "FAIL");
    ok = ok && migration_reassigned;

    WorkspaceAssignmentAdapter strict_adapter(engine);
    strict_adapter.SetMonitorMigrationPolicy(
        MonitorMigrationPolicy::FailClosed);
    const bool strict_configured =
        strict_adapter.ConfigureMonitor(1, 11, {10, 11, 12}, &error) &&
        strict_adapter.ConfigureMonitor(2, 20, {20, 21}, &error);
    const std::vector<WindowRecord> before_migration = records;
    const bool migration_fail_closed =
        strict_configured &&
        !strict_adapter.ConvertCompleteSnapshot(
            {TestWindow(migrated, 2, NativeDesktopRole::Carrier)}, records,
            &error) &&
        error.find("changed monitors") != std::string::npos &&
        records.size() == before_migration.size() &&
        std::equal(records.begin(), records.end(), before_migration.begin(),
                   [](const WindowRecord& left, const WindowRecord& right) {
                       return left.identity == right.identity &&
                              left.monitor == right.monitor &&
                              left.workspace == right.workspace;
                   }) &&
        engine.FindWindow(migrated)->monitor == 1;
    Field("monitor migration fail-closed policy",
          migration_fail_closed ? "PASS" : "FAIL");
    ok = ok && migration_fail_closed;

    // Owner inheritance is observation-only: an owned window inherits the
    // root owner's logical workspace only when the root owner is managed.
    const WindowIdentity owner_managed_id = TestIdentity(10, 110, 1);
    const WindowIdentity owned_child_id = TestIdentity(11, 111, 1);
    const WindowIdentity owned_grandchild_id = TestIdentity(12, 112, 1);
    ok = ok &&
         engine.UpsertWindow(
             {owner_managed_id, 1, 11, NativeDesktopRole::Carrier,
              TestCapabilities()},
             &error) == UpsertResult::Added;
    DiscoveredWindow owner_managed_window =
        TestWindow(owner_managed_id, 1, NativeDesktopRole::Carrier);
    DiscoveredWindow owned_child;
    owned_child.identity = owned_child_id;
    owned_child.monitor = reinterpret_cast<HMONITOR>(1);
    owned_child.owner = owner_managed_id.hwnd;
    owned_child.native_role = NativeDesktopRole::Carrier;
    owned_child.capabilities = TestCapabilities();
    owned_child.disposition = WindowDisposition::Unsupported;
    DiscoveredWindow owned_grandchild;
    owned_grandchild.identity = owned_grandchild_id;
    owned_grandchild.monitor = reinterpret_cast<HMONITOR>(1);
    owned_grandchild.owner = owned_child_id.hwnd;
    owned_grandchild.native_role = NativeDesktopRole::Carrier;
    owned_grandchild.capabilities = TestCapabilities();
    owned_grandchild.disposition = WindowDisposition::Unsupported;
    DiscoveredWindow owned_unmanaged;
    owned_unmanaged.identity = TestIdentity(14, 114, 1);
    owned_unmanaged.monitor = reinterpret_cast<HMONITOR>(1);
    owned_unmanaged.owner = TestIdentity(13, 113, 1).hwnd;
    owned_unmanaged.native_role = NativeDesktopRole::Carrier;
    owned_unmanaged.capabilities = TestCapabilities();
    owned_unmanaged.disposition = WindowDisposition::Unsupported;
    std::vector<InheritedOwnership> inherited;
    const bool inheritance_ok =
        adapter.DeriveInheritedOwnership(
            {owner_managed_window, owned_child, owned_grandchild,
             owned_unmanaged},
            inherited, &error) &&
        inherited.size() == 3 &&
        std::any_of(inherited.begin(), inherited.end(),
                    [&](const InheritedOwnership& entry) {
                        return entry.owned_hwnd == owned_child_id.hwnd &&
                               entry.owner == owner_managed_id &&
                               entry.owner_managed &&
                               entry.inherited_workspace == 11;
                    }) &&
        std::any_of(inherited.begin(), inherited.end(),
                    [&](const InheritedOwnership& entry) {
                        return entry.owned_hwnd == owned_grandchild_id.hwnd &&
                               entry.owner == owner_managed_id &&
                               entry.owner_managed &&
                               entry.inherited_workspace == 11;
                    }) &&
        std::any_of(inherited.begin(), inherited.end(),
                    [&](const InheritedOwnership& entry) {
                        return entry.owned_hwnd ==
                                   owned_unmanaged.identity.hwnd &&
                               !entry.owner_managed;
                    });
    Field("owned window inherits root-owner workspace",
          inheritance_ok ? "PASS" : "FAIL");
    ok = ok && inheritance_ok;

    Field("result", ok ? "PASS" : "FAIL");
    Print("RESULT={}\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

}  // namespace vd
