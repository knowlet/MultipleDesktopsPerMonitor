#pragma once

namespace vd {

// Deterministic, non-mutating stress test: many tracked windows, rapid
// switching with journal round-trips, rapid create/close, and HWND reuse,
// asserting the Carrier/Parking invariant after every step.
int CmdWorkspaceStressTest();

}  // namespace vd
