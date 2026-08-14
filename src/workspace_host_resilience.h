#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "workspace_engine.h"

namespace vd {

// Runtime monitor topology tracking for the long-running host. Configured
// monitors are identified by device name (preferred) with order-based
// fallback, so a monitor that temporarily disappears suspends its workspaces
// instead of silently losing logical ownership.
class MonitorTopologyMapper {
   public:
    struct BoundMonitor {
        std::size_t config_index = 0;
        MonitorId real_monitor = 0;
        std::string device;
    };

    // Recomputes bindings against the current real monitors. Monitors that
    // disappear are dropped from the binding list (their workspaces are
    // suspended); monitors that return are re-bound. Binding fills up to
    // `expected_count` config indices (order fallback). Missing config
    // indices are appended to `missing`.
    void Update(const std::vector<std::pair<MonitorId, std::string>>& real,
                std::vector<BoundMonitor>& bound,
                std::vector<std::size_t>& missing,
                std::size_t expected_count) const;
};

// Host resilience state: which configured monitors are present and whether
// the shell has been lost and needs re-acquisition.
struct HostResilienceState {
    std::vector<bool> monitor_present;
    std::size_t display_changes_handled = 0;
    std::size_t resume_events_handled = 0;
    std::size_t shell_reacquire_attempts = 0;
    bool shell_lost = false;
    bool degraded = false;

    bool IsMonitorPresent(std::size_t config_index) const {
        return config_index < monitor_present.size() &&
               monitor_present[config_index];
    }
};

// Deterministic, non-mutating resilience test (topology changes, suspend/
// recover, device-vs-order identity).
int CmdWorkspaceHostResilienceTest();

}  // namespace vd
