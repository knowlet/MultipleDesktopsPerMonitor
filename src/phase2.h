// phase2.h - private ImmersiveShell COM probing.  Read-only.
#pragma once

#include <windows.h>
#include <servprov.h>

#include <string>
#include <vector>

#include "comraw.h"
#include "vdids.h"
#include "vdlayout.h"

namespace vd {

// CoCreateInstance(CLSID_ImmersiveShell) -> IServiceProvider.
HRESULT GetImmersiveShell(Com<IServiceProvider>& out);

// Result of asking the shell for one (service id, IID) pair.
struct ProbeResult {
    const IidCandidate* candidate = nullptr;
    HRESULT hr = E_FAIL;
    bool obtained = false;
    // Which module the returned vtable lives in ("actxprxy.dll" => marshalled).
    std::string vtable_module;
    // vtbl[-1] as an IID, when the object is a MIDL proxy.
    bool proxy_iid_ok = false;
    GUID proxy_iid{};
    // Length of the leading run of image code pointers in the vtable.  For a
    // MIDL proxy this equals 3 (IUnknown) + method count.
    unsigned vtable_run = 0;
};

// Probes every recorded candidate IID for one logical interface.
std::vector<ProbeResult> ProbeInterface(IServiceProvider* sp, const char* iface);

// The candidate the running build actually accepts, or nullptr.
const ProbeResult* FirstObtained(const std::vector<ProbeResult>& results);

// --------------------------------------------------------------- subcommands

int CmdPrivateStatus();
int CmdDesktops();
int CmdCurrentDesktop();
int CmdPerMonitorStatus();

// Phase 2A: registers a notification sink (IVirtualDesktopNotificationService
// ::Register, slot 3, read_only=false) and logs shell callbacks for
// `duration_seconds`.  With self_trigger=true, performs one existing-desktop
// original -> other -> original round-trip plus any required restoration
// attempts, gated by both confirm_register and confirm_mutate.
int CmdNotifyWatch(bool confirm_register, bool self_trigger, bool confirm_mutate,
                   int duration_seconds);

// Phase 2B: move one vdprobe-owned disposable probe window from the current
// desktop to an existing inactive desktop and back without calling
// SwitchDesktop.  Requires --confirm-mutate.
int CmdCarrierParkingTest(bool confirm_mutate);

// Phase 3: prove one deterministic logical per-monitor workspace round-trip
// using two existing native desktops as Carrier and shared Parking.  Creates
// three vdprobe-owned disposable windows, moves only the target monitor's views,
// and never calls SwitchDesktop/CreateDesktop/RemoveDesktop.  Requires
// --confirm-mutate.
int CmdLogicalWorkspaceTest(bool confirm_mutate);

// Phase 4: launch vdprobe-owned real Win32 child applications and characterize
// top-level/owned-window grouping when one application view is moved between
// the existing Carrier and Parking desktops.  Requires --confirm-mutate.
int CmdRealAppSemanticsTest(bool confirm_mutate);

// Phase 4B-1: launch two probe-owned Explorer windows and characterize whether
// one top-level Explorer view can move independently between Carrier/Parking.
// Requires --confirm-mutate.  The test closes only the HWNDs it created; it
// never terminates explorer.exe because that process may be shared with the
// user's shell.
int CmdExplorerSemanticsTest(bool confirm_mutate);

// Phase 4B-2A: launch one isolated Chromium-family browser profile and
// characterize two top-level Edge windows with one Carrier -> Parking move.
// The first milestone supports only `--browser edge`; it never touches an
// existing browser profile or terminates an existing browser process.
int CmdChromiumSemanticsTest(const std::string& browser, bool confirm_mutate);

// Phase 4C: characterize two probe-owned Windows Terminal top-level windows
// using the same Carrier/Parking contract.  The command never touches
// pre-existing Terminal windows or terminates an unrelated process.
int CmdTerminalSemanticsTest(bool confirm_mutate);

// Productization bootstrap probe: obtains the existing current Carrier and an
// existing inactive Parking desktop, augments the system discovery backend
// with read-only private application-view capability checks, and takes one
// complete snapshot. It never assigns a workspace or mutates native state.
int CmdWorkspaceLiveDiscoveryTest();

// Productization bootstrap validation: feeds the same read-only live snapshot
// into WorkspaceEngine using an explicitly synthetic in-memory assignment.
// It installs no move callback and performs no native or persistent mutation.
int CmdWorkspaceLiveBootstrapTest();

// Productization coordinator bootstrap validation: starts the read-only
// WinEvent source on the calling thread and reconciles bounded complete live
// discovery through WorkspaceCoordinator. Logical assignment remains
// explicitly synthetic and in-memory; no move callback is installed.
int CmdWorkspaceLiveCoordinatorBootstrapTest();

// Productization read-only host validation: composes the system discovery
// backend, capability augmentation, owner-thread WinEvent source, assignment
// policy, coordinator, and clean-journal startup boundary.  It never installs
// native move/observe/recovery callbacks and never mutates windows or desktops.
int CmdWorkspaceLiveReadOnlyHostTest();

// Confirmation-gated mutable composition milestone. Creates exactly three
// vdprobe-owned top-level windows, assigns A1/A2 on one monitor and B1 on a
// second monitor, and executes one A1 -> A2 -> A1 coordinator round-trip.
// Discovery is system-backed but capability promotion is restricted to the
// exact probe HWND generations. It never calls SwitchDesktop or creates or
// removes a native desktop.
int CmdWorkspaceLiveManagerTest(bool confirm_mutate);

// Confirmation-gated live focus restore milestone. Spawns four vdprobe-owned
// windows (A1 top/bottom, A2, B1), switches monitor A A1 -> A2 -> A1 through
// the coordinator, and executes identity-checked placement/Z-order restore
// (foreground best-effort) on the real probe HWNDs after each switch. Never
// calls SwitchDesktop or creates/removes a native desktop.
int CmdWorkspaceLiveFocusRestoreTest(bool confirm_mutate);

// Confirmation-gated minimal manager integration: registers real hotkeys and
// a tray icon, drives one monitor-local A1 -> A2 -> A1 round-trip through
// WM_HOTKEY dispatch, and cleans all UI resources before exit. Never calls
// SwitchDesktop or creates/removes a native desktop.
int CmdWorkspaceManager(bool confirm_mutate);

// Productization milestone: deterministic, non-mutating capability-driven
// workspace state/transaction engine test.
int CmdWorkspaceEngineTest();

// Internal child-process mode used only by CmdRealAppSemanticsTest.  It creates
// controlled ordinary Win32 windows and is not part of the public probe
// surface.
int CmdRealAppChild(int window_count, bool create_owned_window,
                    bool confirm_mutate);


class NotifySink;

// RAII wrapper around IVirtualDesktopNotificationService::Register/Unregister.
// Shared by notify-watch (Phase 2A) and the carrier/parking test (Phase 2B),
// which both need to know whether a global desktop switch occurred during a
// mutating operation.  Construction fails safely (ok()==false) rather than
// throwing; Unregister is attempted in the destructor on a best-effort basis.
class NotificationRegistration {
   public:
    // Does nothing (ok()==false) unless confirm_register is true: registering
    // a sink is a real, if small, mutation of shell state, so it goes through
    // the same explicit-confirmation discipline as everything else that isn't
    // read-only.
    NotificationRegistration(IServiceProvider* sp, NotifySink* sink,
                             bool confirm_register);
    ~NotificationRegistration();
    NotificationRegistration(const NotificationRegistration&) = delete;
    NotificationRegistration& operator=(const NotificationRegistration&) = delete;

    bool ok() const { return registered_; }
    HRESULT hr() const { return hr_; }
    Gate gate() const { return gate_; }
    DWORD cookie() const { return cookie_; }

    // Explicit, idempotent cleanup so callers can report the Unregister result
    // before the RAII destructor runs.  The destructor calls this as a
    // best-effort fallback when the caller does not.
    HRESULT UnregisterNow();
    HRESULT unregister_hr() const { return unregister_hr_; }
    Gate unregister_gate() const { return unregister_gate_; }
    bool unregister_attempted() const { return unregister_attempted_; }

   private:
    RawObject notif_svc_;
    NotifySink* sink_ = nullptr;
    const LayoutTable* layout_ = nullptr;
    DWORD cookie_ = 0;
    bool registered_ = false;
    HRESULT hr_ = E_FAIL;
    Gate gate_ = Gate::Ok;
    HRESULT unregister_hr_ = E_ABORT;
    Gate unregister_gate_ = Gate::NoObject;
    bool unregister_attempted_ = false;
};

// Emits the layout registry as markdown so docs/interface-matrix.md is generated
// from the same data the gate uses.
int CmdMatrix();

}  // namespace vd
