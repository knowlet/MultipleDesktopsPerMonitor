// vdprobe - feasibility probe for native per-monitor virtual desktops on
// Windows 11.
//
// Scope discipline: the default commands observe.  The explicitly gated
// notify-watch self-trigger validates the callback pipeline,
// carrier-parking-test validates the Carrier/Parking primitive, and
// logical-workspace-test validates one deterministic per-monitor workspace
// round-trip.  The phase 4 commands characterize application window
// granularity without touching pre-existing user windows.
#include <windows.h>

#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "phase1.h"
#include "phase2.h"
#include "util.h"
#include "window_discovery.h"
#include "workspace_assignment.h"
#include "workspace_coordinator.h"
#include "workspace_live_focus.h"
#include "workspace_manager.h"
#include "workspace_host_resilience.h"
#include "workspace_stress.h"
#include "workspace_live_lifecycle.h"
#include "workspace_readonly_host.h"
#include "workspace_startup.h"

namespace {

void Usage() {
    vd::Print(
        "vdprobe - read-only probe of Windows virtual desktop interfaces\n"
        "\n"
        "usage: vdprobe <subcommand> [options]\n"
        "\n"
        "phase 1 (documented APIs only)\n"
        "  system              exact Windows build, UBR and shell module versions\n"
        "  monitors            HMONITOR enumeration with bounds, work area and DPI\n"
        "  windows             top-level HWNDs, HWND->HMONITOR, desktop GUID via the\n"
        "                      documented IVirtualDesktopManager\n"
        "\n"
        "phase 2 (private ImmersiveShell COM)\n"
        "  private-status      which private interfaces and IIDs this build accepts\n"
        "  desktops            enumerate virtual desktops\n"
        "  current-desktop     identify the current virtual desktop\n"
        "  per-monitor-status  whether a monitor-aware desktop API still exists\n"
        "\n"
        "phase 2A (mutating: registers a callback; optional one-shot validation)\n"
        "  notify-watch        watch IVirtualDesktopNotification callbacks;\n"
        "                      requires --confirm-register\n"
        "\n"
        "phase 2B (mutating: carrier/parking feasibility)\n"
        "  carrier-parking-test\n"
        "                      move one vdprobe-owned probe window carrier -> parking\n"
        "                      -> carrier without SwitchDesktop; requires\n"
        "                      --confirm-mutate\n"
        "\n"
        "phase 3 (mutating: logical workspace feasibility)\n"
        "  logical-workspace-test\n"
        "                      move one monitor's logical workspace A1 -> A2\n"
        "                      -> A1 while a control window on monitor B is\n"
        "                      untouched; requires --confirm-mutate\n"
        "\n"
        "phase 4 (mutating: real application semantics)\n"
        "  real-app-semantics-test\n"
        "                      launch vdprobe-owned ordinary Win32 child apps,\n"
        "                      characterize top-level/owned-window grouping when\n"
        "                      moving one view; requires --confirm-mutate\n"
        "\n"
        "phase 4B-1 (mutating: Explorer semantics)\n"
        "  explorer-semantics-test\n"
        "                      launch two probe-owned Explorer windows and move\n"
        "                      one view Carrier -> Parking while observing the\n"
        "                      sibling, owned popups, callbacks, and restore;\n"
        "                      requires --confirm-mutate\n"
        "\n"
        "phase 4B-2A (mutating: isolated Chromium semantics)\n"
        "  chromium-semantics-test\n"
        "                      launch one isolated Edge profile with two\n"
        "                      attributable top-level windows, move one view\n"
        "                      Carrier -> Parking -> Carrier; requires\n"
        "                      --browser edge --confirm-mutate\n"
        "\n"
        "phase 4C (mutating: representative compatibility)\n"
        "  terminal-semantics-test\n"
        "                      launch two probe-owned Windows Terminal windows,\n"
        "                      move one top-level view Carrier -> Parking and\n"
        "                      restore it; requires --confirm-mutate\n"
        "\n"
        "productization (non-mutating state engine)\n"
        "  workspace-discovery-test\n"
        "                      deterministic injected-backend discovery and\n"
        "                      capability-classification checks\n"
        "  workspace-live-discovery-test\n"
        "                      one complete read-only live Carrier/Parking\n"
        "                      window snapshot with private capability checks\n"
        "  workspace-live-bootstrap-test\n"
        "                      validate that live read-only snapshot in the\n"
        "                      engine with synthetic in-memory assignment\n"
        "  workspace-live-coordinator-bootstrap-test\n"
        "                      reconcile bounded live read-only discovery via\n"
        "                      lifecycle/coordinator with synthetic assignment\n"
        "  workspace-live-readonly-host-test\n"
        "                      compose system discovery, assignment, lifecycle,\n"
        "                      coordinator, and clean startup read-only\n"
        "  workspace-live-manager-test\n"
        "                      bounded probe-owned system discovery, explicit\n"
        "                      assignment, lifecycle, journaled coordinator, and\n"
        "                      one monitor-local A1 -> A2 -> A1 round-trip;\n"
        "                      requires --confirm-mutate\n"
        "  workspace-live-focus-restore-test\n"
        "                      live identity-checked placement/Z-order restore of\n"
        "                      probe-owned windows across an A1 -> A2 -> A1 switch;\n"
        "                      requires --confirm-mutate\n"
        "  workspace-manager\n"
        "                      minimal manager self-test: real hotkeys and tray\n"
        "                      icon drive one probe-owned A1 -> A2 -> A1 switch;\n"
        "                      requires --confirm-mutate\n"
        "  workspace-manager-test\n"
        "                      deterministic config parsing, hotkey binding\n"
        "                      validation, and dispatch resolution; read-only\n"
        "  workspace-host-resilience-test\n"
        "                      deterministic monitor topology suspend/recover and\n"
        "                      device-identity mapping; read-only\n"
        "  workspace-stress-test\n"
        "                      deterministic many-window/rapid-switch/create-close\n"
        "                      stress with invariant checks; read-only\n"
        "  workspace-live-focus-test\n"
        "                      deterministic injected per-workspace focus/Z-order\n"
        "                      capture, switch, and identity-checked presentation\n"
        "                      restore planning/execution; read-only\n"
        "  workspace-live-lifecycle-test\n"
        "                      deterministic read-only lifecycle and explicit\n"
        "                      in-memory assignment integration\n"
        "  workspace-engine-test\n"
        "                      exercise capability-driven monitor/workspace\n"
        "                      ownership, lifecycle, rollback, and journal\n"
        "                      recovery without touching COM or native desktops\n"
        "  workspace-assignment-test\n"
        "                      exercise read-only discovery-to-workspace policy,\n"
        "                      identity preservation, and fail-closed mismatch\n"
        "  workspace-coordinator-test\n"
        "                      exercise serialized discovery, lifecycle quiet\n"
        "                      boundaries, stale-safe switching, and recovery\n"
        "                      without touching COM or native desktops\n"
        "  workspace-startup-test\n"
        "                      exercise fail-closed startup ordering, stable\n"
        "                      journal recovery, and fresh-model reconciliation\n"
        "  workspace-readonly-host-test\n"
        "                      exercise the reusable non-mutating discovery,\n"
        "                      assignment, lifecycle, coordinator, and startup\n"
        "                      host boundary with injected platform seams\n"
        "\n"
        "documentation\n"
        "  matrix              emit the vtable layout registry as markdown\n"
        "\n"
        "options\n"
        "  --all               'windows': include invisible and untitled HWNDs\n"
        "  --confirm-register  unlock notify-watch's Register/Unregister calls\n"
        "  --self-trigger      notify-watch: perform one existing-desktop round-trip\n"
        "                      original -> other -> original, with required restore\n"
        "  --confirm-mutate    unlock explicitly gated desktop/window mutations\n"
        "  --seconds N         'notify-watch': how long to watch (default 20)\n"
        "  --config PATH       'workspace-manager': load a schema-v1 config file\n"
        "  --run               'workspace-manager': long-running host mode\n"
        "  --stop              'workspace-manager': request clean shutdown\n"
        "  --reload            'workspace-manager': request transactional\n"
        "                      configuration reload\n"
        "  --install-startup   'workspace-manager': add the HKCU Run entry\n"
        "  --remove-startup    'workspace-manager': remove the HKCU Run entry\n"
        "  --self-resilience   'workspace-manager --run': post display/resume\n"
        "                      events to the host window for live validation\n"
        "  --probe-gate        'workspace-manager --run': bounded probe-owned\n"
        "                      host gate (default is the production host)\n"
        "  --rounds N          'workspace-live-manager-test': switch round-trips\n"
        "                      (default 1; use >1 for live stress)\n"
        "  --version           print the manager version and exit\n"
        "  --diagnostics       'workspace-manager': print a diagnostics bundle\n"
        "  --help, -h          this text\n"
        "\n"
        "This build never invokes a vtable slot that is not recorded with an agreed\n"
        "index in src/vdlayout.cpp.  notify-watch --self-trigger is the only\n"
        "command path that invokes SwitchDesktop; it requires both explicit\n"
        "confirmation flags.  The Carrier/Parking and logical-workspace tests\n"
        "never invoke SwitchDesktop or create/remove native desktops.\n");
}

// COM is initialised as an STA because that is what every public virtual desktop
// implementation does, and the ImmersiveShell objects are apartment-sensitive.
class ComScope {
   public:
    ComScope() { hr_ = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED); }
    ~ComScope() {
        if (SUCCEEDED(hr_)) ::CoUninitialize();
    }
    HRESULT hr() const { return hr_; }

   private:
    HRESULT hr_ = E_FAIL;
};

}  // namespace

int main(int argc, char** argv) {
    vd::InitConsole();

    std::string cmd;
    bool all = false;
    bool confirm_register = false;
    bool self_trigger = false;
    bool confirm_mutate = false;
    bool run_mode = false;
    bool stop_mode = false;
    bool install_startup = false;
    bool remove_startup = false;
    bool self_resilience = false;
    bool reload_mode = false;
    int rounds = 1;
    bool probe_gate = false;
    bool version_mode = false;
    bool diagnostics_mode = false;
    std::string config_path;
    std::string browser;
    int seconds = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--all") {
            all = true;
        } else if (a == "--confirm-register") {
            confirm_register = true;
        } else if (a == "--self-trigger") {
            self_trigger = true;
        } else if (a == "--confirm-mutate") {
            confirm_mutate = true;
        } else if (a == "--browser" && i + 1 < argc) {
            browser = vd::ToLowerAscii(argv[++i]);
        } else if (a == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        } else if (a == "--run") {
            run_mode = true;
        } else if (a == "--stop") {
            stop_mode = true;
        } else if (a == "--install-startup") {
            install_startup = true;
        } else if (a == "--remove-startup") {
            remove_startup = true;
        } else if (a == "--self-resilience") {
            self_resilience = true;
        } else if (a == "--reload") {
            reload_mode = true;
        } else if (a == "--rounds" && i + 1 < argc) {
            rounds = std::atoi(argv[++i]);
            if (rounds < 1) rounds = 1;
        } else if (a == "--probe-gate") {
            probe_gate = true;
        } else if (a == "--version") {
            version_mode = true;
        } else if (a == "--diagnostics") {
            diagnostics_mode = true;
        } else if (a == "--seconds" && i + 1 < argc) {
            seconds = std::atoi(argv[++i]);
        } else if (a == "--help" || a == "-h" || a == "/?") {
            Usage();
            return 0;
        } else if (cmd.empty()) {
            cmd = vd::ToLowerAscii(a);
        }
    }

    if (version_mode) {
        vd::Print("vdprobe 0.1.0 (per-monitor workspace manager)\n");
        return 0;
    }

    if (cmd.empty()) {
        Usage();
        return 2;
    }

    ComScope com;
    if (FAILED(com.hr())) {
        vd::Print("CoInitializeEx failed: {}\n", vd::HrToString(com.hr()));
        return 1;
    }

    int rc;
    if (cmd == "system") {
        rc = vd::CmdSystem();
    } else if (cmd == "monitors") {
        rc = vd::CmdMonitors();
    } else if (cmd == "windows") {
        rc = vd::CmdWindows(all);
    } else if (cmd == "private-status") {
        rc = vd::CmdPrivateStatus();
    } else if (cmd == "desktops") {
        rc = vd::CmdDesktops();
    } else if (cmd == "current-desktop") {
        rc = vd::CmdCurrentDesktop();
    } else if (cmd == "per-monitor-status") {
        rc = vd::CmdPerMonitorStatus();
    } else if (cmd == "notify-watch") {
        rc = vd::CmdNotifyWatch(confirm_register, self_trigger, confirm_mutate,
                                seconds > 0 ? seconds : 20);
    } else if (cmd == "carrier-parking-test") {
        rc = vd::CmdCarrierParkingTest(confirm_mutate);
    } else if (cmd == "logical-workspace-test") {
        rc = vd::CmdLogicalWorkspaceTest(confirm_mutate);
    } else if (cmd == "real-app-semantics-test") {
        rc = vd::CmdRealAppSemanticsTest(confirm_mutate);
    } else if (cmd == "explorer-semantics-test") {
        rc = vd::CmdExplorerSemanticsTest(confirm_mutate);
    } else if (cmd == "chromium-semantics-test") {
        rc = vd::CmdChromiumSemanticsTest(browser, confirm_mutate);
    } else if (cmd == "terminal-semantics-test") {
        rc = vd::CmdTerminalSemanticsTest(confirm_mutate);
    } else if (cmd == "workspace-discovery-test") {
        rc = vd::CmdWorkspaceDiscoveryTest();
    } else if (cmd == "workspace-live-discovery-test") {
        rc = vd::CmdWorkspaceLiveDiscoveryTest();
    } else if (cmd == "workspace-live-bootstrap-test") {
        rc = vd::CmdWorkspaceLiveBootstrapTest();
    } else if (cmd == "workspace-live-coordinator-bootstrap-test") {
        rc = vd::CmdWorkspaceLiveCoordinatorBootstrapTest();
    } else if (cmd == "workspace-live-readonly-host-test") {
        rc = vd::CmdWorkspaceLiveReadOnlyHostTest();
    } else if (cmd == "workspace-live-manager-test") {
        rc = vd::CmdWorkspaceLiveManagerTest(confirm_mutate, rounds);
    } else if (cmd == "workspace-live-focus-restore-test") {
        rc = vd::CmdWorkspaceLiveFocusRestoreTest(confirm_mutate);
    } else if (cmd == "workspace-manager") {
        if (stop_mode) {
            rc = vd::CmdWorkspaceManagerStop();
        } else if (diagnostics_mode) {
            rc = vd::CmdWorkspaceManagerDiagnostics(
                config_path.empty() ? nullptr : config_path.c_str());
        } else if (reload_mode) {
            rc = vd::CmdWorkspaceManagerReload();
        } else if (install_startup || remove_startup) {
            rc = vd::CmdWorkspaceManagerInstallStartup(
                remove_startup, config_path.empty() ? nullptr
                                                    : config_path.c_str());
        } else if (run_mode) {
            rc = vd::CmdWorkspaceManagerRun(
                config_path.empty() ? nullptr : config_path.c_str(), seconds,
                self_resilience, confirm_mutate, probe_gate);
        } else {
            rc = vd::CmdWorkspaceManager(confirm_mutate,
                                         config_path.empty()
                                             ? nullptr
                                             : config_path.c_str());
        }
    } else if (cmd == "workspace-manager-test") {
        rc = vd::CmdWorkspaceManagerTest();
    } else if (cmd == "workspace-host-resilience-test") {
        rc = vd::CmdWorkspaceHostResilienceTest();
    } else if (cmd == "workspace-stress-test") {
        rc = vd::CmdWorkspaceStressTest();
    } else if (cmd == "workspace-live-lifecycle-test") {
        rc = vd::CmdWorkspaceLiveLifecycleTest();
    } else if (cmd == "workspace-live-focus-test") {
        rc = vd::CmdWorkspaceLiveFocusTest();
    } else if (cmd == "workspace-engine-test") {
        rc = vd::CmdWorkspaceEngineTest();
    } else if (cmd == "workspace-assignment-test") {
        rc = vd::CmdWorkspaceAssignmentTest();
    } else if (cmd == "workspace-coordinator-test") {
        rc = vd::CmdWorkspaceCoordinatorTest();
    } else if (cmd == "workspace-startup-test") {
        rc = vd::CmdWorkspaceStartupTest();
    } else if (cmd == "workspace-readonly-host-test") {
        rc = vd::CmdWorkspaceReadOnlyHostTest();
    } else if (cmd == "real-app-child") {
        // Internal helper launched by real-app-semantics-test.  It is not
        // documented as a standalone probe command.
        int window_count = 2;
        bool owned = true;
        bool child_confirm_mutate = false;
        for (int i = 1; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--windows" && i + 1 < argc) {
                window_count = std::atoi(argv[++i]);
            } else if (a == "--no-owned") {
                owned = false;
            } else if (a == "--confirm-mutate") {
                child_confirm_mutate = true;
            }
        }
        rc = vd::CmdRealAppChild(window_count, owned, child_confirm_mutate);
    } else if (cmd == "matrix") {
        rc = vd::CmdMatrix();
    } else {
        vd::Print("unknown subcommand: {}\n\n", cmd);
        Usage();
        rc = 2;
    }

    std::fflush(stdout);
    return rc;
}
