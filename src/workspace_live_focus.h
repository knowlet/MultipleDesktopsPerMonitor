// Phase 5A: deterministic composed focus/Z-order restore validation.
#pragma once

namespace vd {

// Deterministic, non-mutating focus/Z-order composition test.  It uses
// injected discovery and in-memory move/observe callbacks only; no COM,
// native window, desktop, or foreground operation is performed.
int CmdWorkspaceLiveFocusTest();

}  // namespace vd
