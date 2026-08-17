// Durable logical-workspace checkpoint format and atomic file I/O.
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "workspace_engine.h"

namespace vd {

inline constexpr std::uint32_t kWorkspaceStateSchemaVersion = 2;

struct WorkspaceOwnership {
    WindowIdentity identity;
    WorkspaceId workspace = 0;
};

// An opaque, normalized identity supplied by monitor discovery (for example,
// a DisplayConfig target identity). runtime_monitor is process-local and is
// deliberately omitted from the durable encoding.
struct WorkspaceStateMonitor {
    std::string stable_key;
    MonitorId runtime_monitor = 0;
    WorkspaceId active = 0;
    std::vector<WorkspaceId> workspaces;
};

struct StableMonitorBinding {
    std::string stable_key;
    MonitorId runtime_monitor = 0;
};

// A logical checkpoint only. Native roles are intentionally reconstructed
// from each monitor's active workspace after authoritative discovery.
struct WorkspaceState {
    std::uint32_t schema_version = kWorkspaceStateSchemaVersion;
    GUID carrier{};
    GUID parking{};
    std::vector<WorkspaceStateMonitor> monitors;
    std::vector<WorkspaceOwnership> ownership;
};

bool CaptureWorkspaceState(const WorkspaceEngine& engine,
                           const std::vector<StableMonitorBinding>& bindings,
                           WorkspaceState& out,
                           std::string* error = nullptr);
// Resolves every persisted stable key against the current monitor topology.
// Extra current monitors are allowed; missing/duplicate keys or runtime ids
// reject the whole candidate without modifying out.
bool RemapWorkspaceStateTopology(
    const WorkspaceState& persisted,
    const std::vector<StableMonitorBinding>& current,
    WorkspaceState& out, std::string* error = nullptr);
bool ValidateWorkspaceState(const WorkspaceState& state,
                            std::string* error = nullptr);
bool SaveWorkspaceState(const WorkspaceState& state,
                        const std::filesystem::path& path,
                        std::string* error = nullptr);
bool LoadWorkspaceState(const std::filesystem::path& path, WorkspaceState& out,
                        std::string* error = nullptr);

// Deterministic, non-mutating persistence test. It uses only synthetic model
// identities and temporary files; no HWND, COM, or Shell operation is made.
int CmdWorkspaceStateTest();

}  // namespace vd
