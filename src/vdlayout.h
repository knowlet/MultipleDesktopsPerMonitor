// vdlayout.h - the evidence gate.
//
// A private COM method may only be invoked if it appears in this registry with
// an agreed slot index and sufficient confidence.  The registry is data, not
// code: docs/interface-matrix.md is generated from it (`vdprobe matrix`), so the
// documentation cannot drift away from what the binary will actually do.
#pragma once

#include <windows.h>

#include <span>
#include <string>

#include "comraw.h"
#include "vdids.h"

namespace vd {

enum class Confidence {
    Unknown,   // no information
    Low,       // single source, or sources disagree
    Medium,    // single good source, plausible
    High,      // >=2 independent sources agree
    Verified,  // confirmed against this build's own symbols/binary
};

const char* ConfidenceText(Confidence c);

struct MethodEntry {
    const char* method;
    // Absolute vtable index (0..2 are IUnknown).  kUnknownSlot when sources
    // disagree; such an entry can be reported but never invoked.
    int slot;
    const char* signature;
    Confidence confidence;
    const char* evidence;
    // Read-only means: observed not to mutate desktop/window state.  The probe
    // refuses mutating methods unless explicitly unlocked.
    bool read_only;
    const char* note;  // may be nullptr
};

inline constexpr int kUnknownSlot = -1;

struct LayoutTable {
    const char* iface;
    const GUID* iid;
    const char* builds;
    MonitorAware monitor;
    // True when this layout describes the build family the probe is running on.
    // Historical layouts are kept for comparison but are never invocable.
    bool applicable_to_current_family;
    std::span<const MethodEntry> methods;
    // Runtime half of the mutation gate. The table above is compile-time;
    // these are the build boundaries the layout was actually validated
    // against. A mutating call is refused (UnsupportedBuild) when the live
    // build falls outside [min, max] even if the shell still answers the
    // recorded IID, so a future Windows build with a changed ABI can never
    // be mutated before the layout is re-validated. 0 means unbounded on
    // that side.
    DWORD validated_build_min = 0;
    DWORD validated_build_max = 0;
};

std::span<const LayoutTable> Layouts();

// Layouts recorded for a logical interface name.
std::span<const LayoutTable> LayoutsFor(const char* iface);

// Exact IID match.
const LayoutTable* LayoutForIid(const GUID& iid);

const MethodEntry* FindMethod(const LayoutTable& t, const char* method);

// ----------------------------------------------------------------- the gate

enum class Gate {
    Ok,
    NoSuchMethod,     // not in the registry for this IID
    SlotNotAgreed,    // sources disagree on the index
    LowConfidence,    // below the minimum bar for invocation
    NotApplicable,    // layout belongs to a different build family
    Mutating,         // would change shell state and was not unlocked
    NoObject,         // null interface pointer
    UnreadableVtable, // vtable pointer not readable
    NotCodePointer,   // slot does not hold a code pointer in a mapped image
    UnsupportedBuild, // live Windows build outside the validated range
};

const char* GateText(Gate g);

// Deterministic, non-mutating gate test.  No COM, HWND, or native desktop
// state is touched; the fake object's vtable lives in this image.
int CmdLayoutGateTest();

// Validates everything that can be validated without transferring control.
Gate CheckInvocable(IUnknown* obj, const LayoutTable& t, const MethodEntry& m,
                    bool allow_mutating);

// Invokes only after CheckInvocable returns Ok.  On refusal returns E_ABORT and
// sets `gate` so the caller can explain itself.
template <class... Args>
HRESULT InvokeSlot(IUnknown* obj, const LayoutTable& t, const MethodEntry& m, Gate& gate,
                   bool allow_mutating, Args... args) {
    gate = CheckInvocable(obj, t, m, allow_mutating);
    if (gate != Gate::Ok) return E_ABORT;
    return UnsafeCallSlot<HRESULT>(obj, static_cast<unsigned>(m.slot), args...);
}

}  // namespace vd
