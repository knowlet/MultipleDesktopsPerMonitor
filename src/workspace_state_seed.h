// Pure checkpoint-to-engine startup seeding.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "workspace_state.h"

namespace vd {

// Builds a fresh logical engine from an already loaded and remapped checkpoint.
// `startup_topology` is authoritative for current active workspaces. Both its
// MonitorIds and WorkspaceStateMonitor::runtime_monitor are raw, process-local
// values valid only within the same startup scope; this API does not claim that
// a MonitorId is stable across restart or monitor re-enumeration.
//
// The complete authoritative snapshot is observation-only: no native desktop,
// window, COM, or shell operation is performed. Exact WindowIdentity matches
// retain checkpoint ownership only when current monitor membership and the
// Carrier/Parking role prove it. Missing identities are omitted; a reused HWND
// with a different identity follows new-window policy (Carrier joins the
// current active workspace, Parking remains unassigned).
//
// A failure leaves `out` unchanged. On success, `out` is atomically replaced
// with the fully validated fresh engine.
bool SeedWorkspaceEngineFromState(
    const WorkspaceState& checkpoint,
    const std::vector<MonitorWorkspaceState>& startup_topology,
    const std::vector<WindowRecord>& authoritative_snapshot,
    std::unique_ptr<WorkspaceEngine>& out,
    std::string* error = nullptr);

}  // namespace vd
