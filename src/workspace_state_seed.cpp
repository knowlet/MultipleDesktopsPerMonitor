#include "workspace_state_seed.h"

#include <algorithm>
#include <exception>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace vd {
namespace {

void SetSeedError(std::string* error, std::string message) {
    if (error != nullptr) *error = std::move(message);
}

bool SameWorkspaceMembership(const std::vector<WorkspaceId>& left,
                             const std::vector<WorkspaceId>& right) {
    if (left.size() != right.size()) return false;
    return std::all_of(left.begin(), left.end(), [&](WorkspaceId workspace) {
        return std::find(right.begin(), right.end(), workspace) != right.end();
    });
}

}  // namespace

bool SeedWorkspaceEngineFromState(
    const WorkspaceState& checkpoint,
    const std::vector<MonitorWorkspaceState>& startup_topology,
    const std::vector<WindowRecord>& authoritative_snapshot,
    std::unique_ptr<WorkspaceEngine>& out, std::string* error) {
    if (error != nullptr) error->clear();

    try {
        std::string validation_error;
        if (!ValidateWorkspaceState(checkpoint, &validation_error)) {
            SetSeedError(
                error,
                "cannot seed invalid workspace state: " + validation_error);
            return false;
        }

        std::unordered_map<MonitorId, const MonitorWorkspaceState*>
            topology_by_monitor;
        std::unordered_map<WorkspaceId, MonitorId> workspace_monitor;
        std::unordered_set<WorkspaceId> topology_workspaces;
        for (const MonitorWorkspaceState& monitor : startup_topology) {
            if (monitor.monitor == 0 || monitor.workspaces.empty() ||
                std::find(monitor.workspaces.begin(), monitor.workspaces.end(),
                          monitor.active) == monitor.workspaces.end() ||
                !topology_by_monitor.emplace(monitor.monitor, &monitor).second) {
                SetSeedError(error, "invalid startup monitor topology");
                return false;
            }
            for (WorkspaceId workspace : monitor.workspaces) {
                if (workspace == 0 ||
                    !topology_workspaces.insert(workspace).second) {
                    SetSeedError(error,
                                 "startup workspace id is duplicated or invalid");
                    return false;
                }
                workspace_monitor.emplace(workspace, monitor.monitor);
            }
        }
        if (startup_topology.size() != checkpoint.monitors.size()) {
            SetSeedError(error,
                         "checkpoint topology does not match startup topology");
            return false;
        }

        std::unordered_set<MonitorId> checkpoint_monitors;
        for (const WorkspaceStateMonitor& monitor : checkpoint.monitors) {
            if (monitor.runtime_monitor == 0 ||
                !checkpoint_monitors.insert(monitor.runtime_monitor).second) {
                SetSeedError(error,
                             "workspace state has not been remapped for this startup");
                return false;
            }
            const auto topology =
                topology_by_monitor.find(monitor.runtime_monitor);
            if (topology == topology_by_monitor.end() ||
                !SameWorkspaceMembership(monitor.workspaces,
                                         topology->second->workspaces)) {
                SetSeedError(
                    error, "checkpoint topology does not match startup topology");
                return false;
            }
        }

        std::unordered_map<WindowIdentity, WorkspaceId, WindowIdentityHash>
            ownership;
        ownership.reserve(checkpoint.ownership.size());
        for (const WorkspaceOwnership& saved : checkpoint.ownership) {
            ownership.emplace(saved.identity, saved.workspace);
        }

        std::unordered_set<WindowIdentity, WindowIdentityHash>
            snapshot_identities;
        std::unordered_set<std::uintptr_t> snapshot_hwnds;
        std::vector<WindowRecord> records;
        records.reserve(authoritative_snapshot.size());
        for (const WindowRecord& observed : authoritative_snapshot) {
            if (observed.disposition == WindowDisposition::Closed) {
                SetSeedError(error,
                             "authoritative snapshot contains a closed window");
                return false;
            }
            if (!observed.identity.IsValid()) {
                if (observed.disposition == WindowDisposition::Managed) {
                    SetSeedError(error,
                                 "authoritative snapshot contains an invalid identity");
                    return false;
                }
                continue;
            }
            const std::uintptr_t hwnd =
                reinterpret_cast<std::uintptr_t>(observed.identity.hwnd);
            if (!snapshot_identities.insert(observed.identity).second ||
                !snapshot_hwnds.insert(hwnd).second) {
                SetSeedError(
                    error,
                    "authoritative snapshot contains a duplicate identity or HWND");
                return false;
            }

            const auto saved = ownership.find(observed.identity);
            const auto topology = topology_by_monitor.find(observed.monitor);
            if (saved != ownership.end()) {
                const auto saved_monitor = workspace_monitor.find(saved->second);
                if (saved_monitor == workspace_monitor.end() ||
                    saved_monitor->second != observed.monitor ||
                    topology == topology_by_monitor.end() || !observed.present ||
                    observed.disposition != WindowDisposition::Managed ||
                    !observed.capabilities.Manageable()) {
                    SetSeedError(error,
                                 "checkpoint window membership cannot be proven");
                    return false;
                }
                const NativeDesktopRole expected_role =
                    saved->second == topology->second->active
                        ? NativeDesktopRole::Carrier
                        : NativeDesktopRole::Parking;
                if (observed.native_role != expected_role) {
                    SetSeedError(error,
                                 "checkpoint window native role does not match");
                    return false;
                }
                WindowRecord restored = observed;
                restored.workspace = saved->second;
                records.push_back(std::move(restored));
                continue;
            }

            // Unknown observations outside configured scope, and unsafe
            // observations that have no checkpoint ownership to preserve,
            // remain outside the fresh managed model.
            if (topology == topology_by_monitor.end() || !observed.present ||
                observed.disposition != WindowDisposition::Managed ||
                !observed.capabilities.Manageable()) {
                continue;
            }
            if (observed.native_role == NativeDesktopRole::Parking) continue;
            if (observed.native_role != NativeDesktopRole::Carrier) {
                SetSeedError(error,
                             "managed startup window has no native desktop role");
                return false;
            }
            WindowRecord added = observed;
            added.workspace = topology->second->active;
            records.push_back(std::move(added));
        }

        std::vector<MonitorWorkspaceState> sorted_topology = startup_topology;
        std::sort(sorted_topology.begin(), sorted_topology.end(),
                  [](const MonitorWorkspaceState& left,
                     const MonitorWorkspaceState& right) {
                      return left.monitor < right.monitor;
                  });
        std::sort(records.begin(), records.end(),
                  [](const WindowRecord& left, const WindowRecord& right) {
                      return reinterpret_cast<std::uintptr_t>(
                                 left.identity.hwnd) <
                             reinterpret_cast<std::uintptr_t>(
                                 right.identity.hwnd);
                  });

        auto candidate = std::make_unique<WorkspaceEngine>(checkpoint.carrier,
                                                           checkpoint.parking);
        for (const MonitorWorkspaceState& monitor : sorted_topology) {
            if (!candidate->AddMonitor(monitor.monitor, monitor.active,
                                       monitor.workspaces, error)) {
                return false;
            }
        }
        for (WindowRecord& record : records) {
            if (candidate->UpsertWindow(std::move(record), error) ==
                UpsertResult::Rejected) {
                return false;
            }
        }
        std::string invariant_error;
        if (!candidate->CheckInvariant(&invariant_error)) {
            SetSeedError(error,
                         "seeded workspace engine is invalid: " + invariant_error);
            return false;
        }
        out = std::move(candidate);
        return true;
    } catch (const std::exception& exception) {
        SetSeedError(error,
                     std::string("workspace-state seed failed: ") +
                         exception.what());
        return false;
    }
}

}  // namespace vd
