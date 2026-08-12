// Read-only policy bridge between complete window discovery and the logical
// workspace engine.
#pragma once

#include <string>
#include <vector>

#include "window_discovery.h"
#include "workspace_engine.h"

namespace vd {

class WorkspaceAssignmentAdapter {
   public:
    explicit WorkspaceAssignmentAdapter(const WorkspaceEngine& engine)
        : engine_(engine) {}

    // Adds one monitor to this adapter's assignment scope.  The supplied
    // topology must already exist, unchanged, in the engine.
    bool ConfigureMonitor(MonitorId monitor, WorkspaceId active,
                          std::vector<WorkspaceId> workspaces,
                          std::string* error = nullptr);

    // Converts a complete discovery snapshot without changing the engine.
    // `out` is replaced only when the complete candidate is valid.
    bool ConvertCompleteSnapshot(
        const std::vector<DiscoveredWindow>& discovered,
        std::vector<WindowRecord>& out, std::string* error = nullptr) const;

   private:
    struct MonitorTopology {
        MonitorId monitor = 0;
        WorkspaceId active = 0;
        std::vector<WorkspaceId> workspaces;
    };

    const MonitorTopology* Topology(MonitorId monitor) const noexcept;

    const WorkspaceEngine& engine_;
    std::vector<MonitorTopology> topology_;
};

// Deterministic, non-mutating assignment-policy test.
int CmdWorkspaceAssignmentTest();

}  // namespace vd
