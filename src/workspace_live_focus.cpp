#include "workspace_live_focus.h"

#include <algorithm>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "util.h"
#include "window_discovery.h"
#include "workspace_assignment.h"
#include "workspace_engine.h"

namespace vd {
namespace {

GUID TestGuid(DWORD value) {
    GUID result{};
    result.Data1 = value;
    return result;
}

WindowIdentity TestIdentity(std::uintptr_t hwnd, DWORD pid, DWORD generation) {
    return {reinterpret_cast<HWND>(hwnd), pid, {generation, generation + 1},
            true};
}

struct InjectedWindow {
    WindowIdentity identity;
    HMONITOR monitor = nullptr;
    GUID desktop{};
    bool on_current = true;
    bool foreground = false;
    std::int64_t z_order = 0;
    RECT rect{};
};

class InjectedFocusState {
   public:
    std::vector<InjectedWindow> windows;

    const InjectedWindow* Find(HWND hwnd) const {
        const auto found = std::find_if(
            windows.begin(), windows.end(),
            [hwnd](const InjectedWindow& window) {
                return window.identity.hwnd == hwnd;
            });
        return found == windows.end() ? nullptr : &*found;
    }
};

void ReportCheck(const char* name, bool passed, bool& overall) {
    Field(name, passed ? "PASS" : "FAIL");
    overall = overall && passed;
}

const char* OperationText(PresentationOperationKind kind) {
    switch (kind) {
        case PresentationOperationKind::RestorePlacement:
            return "placement";
        case PresentationOperationKind::RestoreZOrder:
            return "zorder";
        case PresentationOperationKind::RestoreForeground:
            return "foreground";
    }
    return "unknown";
}

std::string OperationLabel(PresentationOperationKind kind,
                           const WindowRecord& record) {
    return std::format("{}:0x{:X}", OperationText(kind),
                       reinterpret_cast<std::uintptr_t>(
                           record.identity.hwnd));
}

}  // namespace

int CmdWorkspaceLiveFocusTest() {
    Heading("workspace-live-focus-test");
    Field("scope",
          "deterministic injected per-workspace focus/Z-order capture and restore");
    Field("native mutation", "none");
    Field("move callback", "identity-checked in-memory");
    Field("observe callback", "identity-checked in-memory");

    constexpr MonitorId kMonitorA = 0x100;
    constexpr MonitorId kMonitorB = 0x200;
    constexpr WorkspaceId kA1 = 1;
    constexpr WorkspaceId kA2 = 2;
    constexpr WorkspaceId kB1 = 3;
    const GUID carrier = TestGuid(0xA1);
    const GUID parking = TestGuid(0xA2);

    const WindowIdentity a1_top = TestIdentity(0x101, 1001, 1);
    const WindowIdentity a1_bot = TestIdentity(0x102, 1002, 1);
    const WindowIdentity a2_top = TestIdentity(0x103, 1003, 1);
    const WindowIdentity a2_bot = TestIdentity(0x104, 1004, 1);
    const WindowIdentity b1 = TestIdentity(0x105, 1005, 1);

    InjectedFocusState state;
    state.windows = {
        {a1_top, reinterpret_cast<HMONITOR>(kMonitorA), carrier, true, true, 0,
         {10, 10, 210, 160}},
        {a1_bot, reinterpret_cast<HMONITOR>(kMonitorA), carrier, true, false, 1,
         {20, 20, 220, 170}},
        {a2_top, reinterpret_cast<HMONITOR>(kMonitorA), parking, false, true, 0,
         {30, 30, 230, 180}},
        {a2_bot, reinterpret_cast<HMONITOR>(kMonitorA), parking, false, false, 1,
         {40, 40, 240, 190}},
        {b1, reinterpret_cast<HMONITOR>(kMonitorB), carrier, true, false, 0,
         {50, 50, 250, 200}},
    };

    Win32WindowDiscoveryApi api;
    api.enumerate = [&state](std::vector<HWND>& handles, std::string*) {
        handles.clear();
        for (const InjectedWindow& window : state.windows) {
            handles.push_back(window.identity.hwnd);
        }
        return true;
    };
    api.read_identity = [&state](HWND hwnd, WindowIdentity& identity,
                                 std::string* error) {
        const InjectedWindow* window = state.Find(hwnd);
        if (!window) {
            if (error) *error = "injected HWND vanished";
            return false;
        }
        identity = window->identity;
        return true;
    };
    api.read_window = [&state](HWND hwnd, Win32WindowObservation& observation,
                               std::string* error) {
        const InjectedWindow* window = state.Find(hwnd);
        if (!window) {
            if (error) *error = "injected HWND vanished";
            return false;
        }
        observation = {};
        observation.monitor = window->monitor;
        observation.visible = true;
        observation.cloaked = 0;
        observation.cloaked_ok = true;
        observation.presentation.rect = window->rect;
        observation.presentation.rect_valid = true;
        observation.presentation.placement.length = sizeof(WINDOWPLACEMENT);
        observation.presentation.placement.rcNormalPosition = window->rect;
        observation.presentation.placement_valid = true;
        observation.presentation.foreground = window->foreground;
        observation.presentation.z_order = window->z_order;
        return true;
    };
    api.read_desktop = [&state](HWND hwnd,
                                Win32DesktopObservation& observation,
                                std::string* error) {
        const InjectedWindow* window = state.Find(hwnd);
        if (!window) {
            if (error) *error = "injected HWND vanished";
            return false;
        }
        observation = {};
        observation.desktop = window->desktop;
        observation.desktop_ok = true;
        observation.on_current = window->on_current;
        observation.on_current_ok = true;
        return true;
    };
    Win32WindowDiscoveryOptions options;
    options.carrier = carrier;
    options.parking = parking;
    options.augment_capabilities =
        [](HWND, const WindowDiscoveryObservation&,
           WindowCapabilities& capabilities, std::string*) {
            capabilities.has_application_view = true;
            capabilities.can_move_desktops = true;
            return true;
        };

    std::string error;
    auto backend = CreateWin32WindowDiscoveryBackend(std::move(options),
                                                     std::move(api), &error);
    if (!backend) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }
    WindowDiscovery discovery(std::move(*backend));
    WorkspaceEngine engine(carrier, parking);
    bool ok = true;
    if (!engine.AddMonitor(kMonitorA, kA1, {kA1, kA2}, &error) ||
        !engine.AddMonitor(kMonitorB, kB1, {kB1}, &error)) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }
    WorkspaceAssignmentAdapter assignment(engine);
    if (!assignment.ConfigureMonitor(kMonitorA, kA1, {kA1, kA2}, &error) ||
        !assignment.ConfigureMonitor(kMonitorB, kB1, {kB1}, &error)) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }

    std::vector<DiscoveredWindow> discovered;
    if (!discovery.Discover(discovered, &error)) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }

    auto make_record = [](const WindowIdentity& identity, WorkspaceId workspace,
                          NativeDesktopRole role,
                          const DiscoveredWindow& window) {
        WindowRecord record;
        record.identity = identity;
        record.monitor = reinterpret_cast<MonitorId>(window.monitor);
        record.workspace = workspace;
        record.native_role = role;
        record.capabilities = window.capabilities;
        record.presentation = window.presentation;
        record.disposition = window.disposition;
        return record;
    };

    // The inactive A2 windows are pre-assigned (mirroring the live manager's
    // setup move) so the assignment adapter preserves their workspace.
    for (const DiscoveredWindow& window : discovered) {
        if (window.identity == a2_top || window.identity == a2_bot) {
            if (engine.UpsertWindow(
                    make_record(window.identity, kA2,
                                NativeDesktopRole::Parking, window),
                    &error) != UpsertResult::Added) {
                Field("result", "ERROR");
                Field("reason", "A2 setup upsert failed: " + error);
                return 1;
            }
        }
    }

    std::vector<WindowRecord> records;
    if (!assignment.ConvertCompleteSnapshot(discovered, records, &error)) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }
    ReportCheck("complete snapshot converts all five windows",
                records.size() == 5, ok);
    if (!engine.ReconcileDiscoverySnapshot(std::move(records), nullptr,
                                           &error)) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }

    // Phase 5 capture: derive per-workspace last_foreground/Z-order from the
    // complete snapshot presentation state.
    auto populate_focus =
        [&](MonitorId monitor, WorkspaceId workspace,
            const std::vector<WindowIdentity>& members) -> bool {
        std::vector<WindowIdentity> top_to_bottom = members;
        std::stable_sort(top_to_bottom.begin(), top_to_bottom.end(),
                         [&](const WindowIdentity& left,
                             const WindowIdentity& right) {
                             const WindowRecord* l = engine.FindWindow(left);
                             const WindowRecord* r = engine.FindWindow(right);
                             return l->presentation.z_order <
                                    r->presentation.z_order;
                         });
        if (!engine.SetZOrder(monitor, workspace, top_to_bottom, &error)) {
            return false;
        }
        for (const WindowIdentity& member : members) {
            const WindowRecord* record = engine.FindWindow(member);
            if (record->presentation.foreground) {
                if (!engine.SetLastForeground(monitor, workspace, member,
                                              &error)) {
                    return false;
                }
            }
        }
        return true;
    };
    if (!populate_focus(kMonitorA, kA1, {a1_top, a1_bot}) ||
        !populate_focus(kMonitorA, kA2, {a2_top, a2_bot}) ||
        !populate_focus(kMonitorB, kB1, {b1})) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }

    const WorkspaceDefinition* workspace_a1 = engine.Workspace(kA1);
    const WorkspaceDefinition* workspace_a2 = engine.Workspace(kA2);
    const WorkspaceDefinition* workspace_b1 = engine.Workspace(kB1);
    ReportCheck(
        "A1 focus snapshot captured",
        workspace_a1 != nullptr && workspace_a1->last_foreground.has_value() &&
            *workspace_a1->last_foreground == a1_top &&
            workspace_a1->z_order.size() == 2 &&
            workspace_a1->z_order[0] == a1_top &&
            workspace_a1->z_order[1] == a1_bot,
        ok);
    ReportCheck(
        "A2 focus snapshot captured",
        workspace_a2 != nullptr && workspace_a2->last_foreground.has_value() &&
            *workspace_a2->last_foreground == a2_top &&
            workspace_a2->z_order.size() == 2 &&
            workspace_a2->z_order[0] == a2_top &&
            workspace_a2->z_order[1] == a2_bot,
        ok);
    ReportCheck(
        "B1 focus snapshot captured",
        workspace_b1 != nullptr && !workspace_b1->last_foreground.has_value() &&
            workspace_b1->z_order.size() == 1 &&
            workspace_b1->z_order[0] == b1,
        ok);

    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        native_roles;
    for (const DiscoveredWindow& window : discovered) {
        native_roles[window.identity] = window.native_role;
    }
    auto move_to_role = [&native_roles](const WindowRecord& record,
                                        NativeDesktopRole target) {
        native_roles[record.identity] = target;
        return true;
    };
    auto observe_role = [&native_roles](const WindowRecord& record) {
        const auto found = native_roles.find(record.identity);
        return found == native_roles.end() ? NativeDesktopRole::Unknown
                                           : found->second;
    };

    std::optional<SwitchPlan> forward_plan =
        engine.PrepareSwitch(kMonitorA, kA2, &error);
    const TransactionResult forward = forward_plan
        ? engine.ExecuteSwitch(*forward_plan, move_to_role, observe_role)
        : TransactionResult{};
    ReportCheck("A1 -> A2 switch commits",
                forward.committed &&
                    engine.Monitor(kMonitorA)->active == kA2 &&
                    engine.CheckInvariant(&error),
                ok);
    ReportCheck("Monitor B control window stays Carrier",
                observe_role(*engine.FindWindow(b1)) ==
                    NativeDesktopRole::Carrier,
                ok);

    const std::optional<PresentationPlan> plan_a2 =
        engine.PreparePresentationRestore(kMonitorA, kA2, &error);
    const bool plan_shape_ok =
        plan_a2.has_value() && plan_a2->workspace == kA2 &&
        plan_a2->operations.size() == 5 &&
        plan_a2->operations[0].kind ==
            PresentationOperationKind::RestorePlacement &&
        plan_a2->operations[0].identity == a2_top &&
        plan_a2->operations[1].kind ==
            PresentationOperationKind::RestorePlacement &&
        plan_a2->operations[1].identity == a2_bot &&
        plan_a2->operations[2].kind ==
            PresentationOperationKind::RestoreZOrder &&
        plan_a2->operations[2].identity == a2_bot &&
        plan_a2->operations[3].kind ==
            PresentationOperationKind::RestoreZOrder &&
        plan_a2->operations[3].identity == a2_top &&
        plan_a2->operations[4].kind ==
            PresentationOperationKind::RestoreForeground &&
        plan_a2->operations[4].identity == a2_top;
    ReportCheck("A2 restore plan ordered placement/Z-order/foreground",
                plan_shape_ok, ok);

    std::vector<std::string> applied_order;
    const PresentationResult restore_a2 = plan_a2
        ? engine.ExecutePresentationRestore(
              *plan_a2,
              [](const WindowRecord&) { return true; },
              [&applied_order](const WindowRecord& record,
                               const PresentationOperation& operation) {
                  applied_order.push_back(
                      OperationLabel(operation.kind, record));
                  return true;
              })
        : PresentationResult{};
    const bool restore_order_ok =
        restore_a2.completed && restore_a2.applied == 5 &&
        applied_order.size() == 5 &&
        applied_order[0] == "placement:0x103" &&
        applied_order[1] == "placement:0x104" &&
        applied_order[2] == "zorder:0x104" &&
        applied_order[3] == "zorder:0x103" &&
        applied_order[4] == "foreground:0x103";
    ReportCheck("A2 restore executes in plan order", restore_order_ok, ok);

    std::optional<SwitchPlan> reverse_plan =
        engine.PrepareSwitch(kMonitorA, kA1, &error);
    const TransactionResult reverse = reverse_plan
        ? engine.ExecuteSwitch(*reverse_plan, move_to_role, observe_role)
        : TransactionResult{};
    ReportCheck("A2 -> A1 switch commits",
                reverse.committed &&
                    engine.Monitor(kMonitorA)->active == kA1 &&
                    engine.CheckInvariant(&error),
                ok);

    applied_order.clear();
    const std::optional<PresentationPlan> plan_a1 =
        engine.PreparePresentationRestore(kMonitorA, kA1, &error);
    const PresentationResult restore_a1 = plan_a1
        ? engine.ExecutePresentationRestore(
              *plan_a1,
              [](const WindowRecord&) { return true; },
              [&applied_order](const WindowRecord& record,
                               const PresentationOperation& operation) {
                  applied_order.push_back(
                      OperationLabel(operation.kind, record));
                  return true;
              })
        : PresentationResult{};
    const bool restore_a1_ok =
        plan_a1.has_value() && restore_a1.completed && restore_a1.applied == 5 &&
        applied_order.size() == 5 &&
        applied_order[0] == "placement:0x101" &&
        applied_order[1] == "placement:0x102" &&
        applied_order[2] == "zorder:0x102" &&
        applied_order[3] == "zorder:0x101" &&
        applied_order[4] == "foreground:0x101";
    ReportCheck("A1 restore executes in plan order", restore_a1_ok, ok);

    applied_order.clear();
    std::size_t identity_calls = 0;
    const PresentationResult denied = plan_a1
        ? engine.ExecutePresentationRestore(
              *plan_a1,
              [&identity_calls](const WindowRecord&) {
                  return ++identity_calls != 5;
              },
              [&applied_order](const WindowRecord& record,
                               const PresentationOperation& operation) {
                  applied_order.push_back(
                      OperationLabel(operation.kind, record));
                  return true;
              })
        : PresentationResult{};
    ReportCheck("identity mismatch stops before the failing operation",
                !denied.completed && denied.applied == 4 &&
                    identity_calls == 5 && applied_order.size() == 4,
                ok);

    bool altered_rejected = false;
    if (plan_a1) {
        PresentationPlan altered = *plan_a1;
        std::swap(altered.operations[0], altered.operations[1]);
        const PresentationResult altered_result =
            engine.ExecutePresentationRestore(
                altered,
                [](const WindowRecord&) { return true; },
                [](const WindowRecord&, const PresentationOperation&) {
                    return true;
                });
        altered_rejected =
            !altered_result.completed && altered_result.applied == 0 &&
            altered_result.error.find("stale") != std::string::npos;
    }
    ReportCheck("altered plan rejected before mutation", altered_rejected, ok);

    WorkspaceEngine stale_engine(carrier, parking);
    const WindowIdentity s1 = TestIdentity(0x201, 2001, 1);
    const WindowIdentity s2 = TestIdentity(0x202, 2002, 1);
    bool stale_rejected = false;
    if (stale_engine.AddMonitor(kMonitorA, kA1, {kA1, kA2}, &error) &&
        stale_engine.UpsertWindow(
            {s1, kMonitorA, kA1, NativeDesktopRole::Carrier,
             {true, true, true, true, true}},
            &error) == UpsertResult::Added &&
        stale_engine.UpsertWindow(
            {s2, kMonitorA, kA1, NativeDesktopRole::Carrier,
             {true, true, true, true, true}},
            &error) == UpsertResult::Added) {
        std::string z_error;
        const bool set_z_ok =
            stale_engine.SetZOrder(kMonitorA, kA1, {s1}, &z_error);
        const std::optional<PresentationPlan> stale_plan =
            stale_engine.PreparePresentationRestore(kMonitorA, kA1, &error);
        stale_rejected = !set_z_ok && !stale_plan.has_value();
    }
    ReportCheck("incomplete Z-order snapshot fails closed", stale_rejected, ok);

    Field("result", ok ? "OK" : "ERROR");
    Print("MUTATION_STARTED=0\n");
    Print("PRESENTATION_APPLIED={}\n",
          ok ? "placement+zorder+foreground" : "n/a");
    Print("RESULT={}\n", ok ? "OK" : "ERROR");
    return ok ? 0 : 1;
}

}  // namespace vd
