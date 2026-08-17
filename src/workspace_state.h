// Durable logical-workspace checkpoint format and atomic file I/O.
#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "workspace_engine.h"

namespace vd {

inline constexpr std::uint32_t kWorkspaceStateSchemaVersion = 1;

struct WorkspaceOwnership {
    WindowIdentity identity;
    WorkspaceId workspace = 0;
};

// A logical checkpoint only. Native roles are intentionally reconstructed
// from each monitor's active workspace after authoritative discovery.
struct WorkspaceState {
    std::uint32_t schema_version = kWorkspaceStateSchemaVersion;
    GUID carrier{};
    GUID parking{};
    std::vector<MonitorWorkspaceState> monitors;
    std::vector<WorkspaceOwnership> ownership;
};

bool CaptureWorkspaceState(const WorkspaceEngine& engine, WorkspaceState& out,
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
