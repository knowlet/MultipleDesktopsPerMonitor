// Deterministic read-only integration probe for discovery, assignment,
// lifecycle hints, and authoritative coordinator reconciliation.
#pragma once

namespace vd {

// Uses injected HWND observations and an explicit in-memory assignment
// registry. No native HWND, desktop, GUI, hotkey, or persistent state is
// touched.
int CmdWorkspaceLiveLifecycleTest();

}  // namespace vd
