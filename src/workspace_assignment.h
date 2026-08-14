// Read-only policy bridge between complete window discovery and the logical
// workspace engine.
#pragma once

#include <string>
#include <vector>

#include "window_discovery.h"
#include "workspace_engine.h"

namespace vd {

// Policy for a tracked window observed on a different configured monitor
// (for example a window dragged from monitor A to monitor B).
enum class MonitorMigrationPolicy {
    // Default: ownership.monitor becomes the destination monitor and
    // ownership.workspace becomes the destination monitor's active workspace.
    // Only applied when the observed native role is consistent with the
    // destination active workspace (Carrier).
    ReassignToDestinationActive,
    // Fail the complete conversion instead of guessing ownership.
    FailClosed,
};

// Observation-only owner-inheritance result for owned/transient windows.
struct InheritedOwnership {
    HWND owned_hwnd = nullptr;
    WindowIdentity owner{};
    bool owner_managed = false;
    WorkspaceId inherited_workspace = 0;
};

class WorkspaceAssignmentAdapter {
   public:
    explicit WorkspaceAssignmentAdapter(const WorkspaceEngine& engine)
        : engine_(engine) {}

    // Adds one monitor to this adapter's assignment scope. The supplied
    // workspace membership must already exist, unchanged, in the engine.
    // The engine remains authoritative for the active workspace, which may
    // legitimately change after a successful switch.
    bool ConfigureMonitor(MonitorId monitor, WorkspaceId active,
                          std::vector<WorkspaceId> workspaces,
                          std::string* error = nullptr);

    // Sets how a tracked window observed on a different configured monitor is
    // handled. Default is ReassignToDestinationActive.
    void SetMonitorMigrationPolicy(MonitorMigrationPolicy policy) noexcept {
        migration_policy_ = policy;
    }

    // Observation-only: derives the logical ownership an owned/transient
    // window inherits from its root owner when that owner is a managed
    // window. Owned windows are never mutated by this adapter; the result is
    // diagnostic/registry metadata only.
    bool DeriveInheritedOwnership(
        const std::vector<DiscoveredWindow>& discovered,
        std::vector<InheritedOwnership>& out,
        std::string* error = nullptr) const;

    // Converts a complete discovery snapshot without changing the engine.
    // `out` is replaced only when the complete candidate is valid.
    bool ConvertCompleteSnapshot(
        const std::vector<DiscoveredWindow>& discovered,
        std::vector<WindowRecord>& out, std::string* error = nullptr) const;

   private:
    struct MonitorTopology {
        MonitorId monitor = 0;
        std::vector<WorkspaceId> workspaces;
    };

    const MonitorTopology* Topology(MonitorId monitor) const noexcept;

    const WorkspaceEngine& engine_;
    std::vector<MonitorTopology> topology_;
    MonitorMigrationPolicy migration_policy_ =
        MonitorMigrationPolicy::ReassignToDestinationActive;
};

// Deterministic, non-mutating assignment-policy test.
int CmdWorkspaceAssignmentTest();

}  // namespace vd
