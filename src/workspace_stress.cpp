#include "workspace_stress.h"

#include <filesystem>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "util.h"
#include "workspace_engine.h"

namespace vd {
namespace {

GUID StressGuid(DWORD value) {
    GUID result{};
    result.Data1 = value;
    return result;
}

WindowIdentity StressIdentity(std::uintptr_t hwnd, DWORD pid,
                              DWORD generation) {
    return {reinterpret_cast<HWND>(hwnd), pid, {generation, generation + 1},
            true};
}

}  // namespace

int CmdWorkspaceStressTest() {
    Heading("workspace-stress-test");
    Field("scope",
          "many tracked windows, rapid switching, rapid create/close, "
          "HWND reuse; invariant after every step");
    Field("native mutation", "none");

    const GUID carrier = StressGuid(0x10);
    const GUID parking = StressGuid(0x20);
    const WindowCapabilities manageable{true, true, true, true, true};
    constexpr std::size_t kWindowsPerWorkspace = 20;
    constexpr std::size_t kRoundTrips = 100;

    WorkspaceEngine engine(carrier, parking);
    std::string error;
    bool ok = engine.AddMonitor(1, 1, {1, 2}, &error) &&
              engine.AddMonitor(2, 3, {3}, &error);
    if (!ok) {
        Field("result", "ERROR");
        Field("reason", error);
        return 1;
    }

    std::vector<WindowIdentity> a1;
    std::vector<WindowIdentity> a2;
    std::vector<WindowIdentity> b1;
    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        roles;
    for (std::size_t i = 0; i < kWindowsPerWorkspace; ++i) {
        const WindowIdentity id = StressIdentity(0x100 + i, 1001, 1);
        a1.push_back(id);
        roles[id] = NativeDesktopRole::Carrier;
        if (engine.UpsertWindow(
                {id, 1, 1, NativeDesktopRole::Carrier, manageable, {}, {},
                 true},
                &error) != UpsertResult::Added) {
            ok = false;
        }
    }
    for (std::size_t i = 0; i < kWindowsPerWorkspace; ++i) {
        const WindowIdentity id = StressIdentity(0x200 + i, 1002, 1);
        a2.push_back(id);
        roles[id] = NativeDesktopRole::Parking;
        if (engine.UpsertWindow(
                {id, 1, 2, NativeDesktopRole::Parking, manageable, {}, {},
                 true},
                &error) != UpsertResult::Added) {
            ok = false;
        }
    }
    for (std::size_t i = 0; i < kWindowsPerWorkspace; ++i) {
        const WindowIdentity id = StressIdentity(0x300 + i, 1003, 1);
        b1.push_back(id);
        roles[id] = NativeDesktopRole::Carrier;
        if (engine.UpsertWindow(
                {id, 2, 3, NativeDesktopRole::Carrier, manageable, {}, {},
                 true},
                &error) != UpsertResult::Added) {
            ok = false;
        }
    }
    const std::filesystem::path journal_path =
        std::filesystem::temp_directory_path() /
        "vdprobe-workspace-stress-test.journal";
    std::error_code remove_error;
    std::filesystem::remove(journal_path, remove_error);
    WorkspaceJournal journal(journal_path);

    auto move = [&roles](const WindowRecord& window, NativeDesktopRole target) {
        roles[window.identity] = target;
        return true;
    };
    auto observe = [&roles](const WindowRecord& window) {
        return roles.at(window.identity);
    };

    bool switches_ok = ok;
    for (std::size_t round = 0; round < kRoundTrips && switches_ok; ++round) {
        const WorkspaceId target = round % 2 == 0 ? 2 : 1;
        const std::optional<SwitchPlan> plan =
            engine.PrepareSwitch(1, target, &error);
        if (!plan) {
            switches_ok = false;
            break;
        }
        const TransactionResult result =
            engine.ExecuteSwitch(*plan, move, observe, &journal);
        switches_ok = result.committed &&
                      engine.Monitor(1)->active == target &&
                      engine.Monitor(2)->active == 3 &&
                      engine.CheckInvariant(&error) &&
                      !journal.ReadPending(&error);
    }
    ok = switches_ok;
    Field("rapid switching maintains invariant",
          switches_ok ? "PASS" : "FAIL");

    const std::size_t tracked_after_switch = engine.Windows().size();
    const bool many_windows_ok =
        tracked_after_switch == 3 * kWindowsPerWorkspace &&
        engine.CheckInvariant(&error);
    Field("many tracked windows reconciled",
          many_windows_ok ? "PASS" : "FAIL");
    ok = ok && many_windows_ok;

    // Rapid create/close: 20 new A1 windows added then closed by an
    // authoritative snapshot, then re-observed.
    bool lifecycle_ok = true;
    std::vector<WindowIdentity> transient;
    for (std::size_t i = 0; i < 20; ++i) {
        const WindowIdentity id = StressIdentity(0x400 + i, 1004, 1);
        transient.push_back(id);
        roles[id] = NativeDesktopRole::Carrier;
        lifecycle_ok =
            lifecycle_ok &&
            engine.UpsertWindow(
                {id, 1, 1, NativeDesktopRole::Carrier, manageable, {}, {},
                 true},
                &error) == UpsertResult::Added;
    }
    std::vector<WindowRecord> without_transient;
    without_transient.reserve(tracked_after_switch);
    for (const WindowIdentity& id : a1) {
        without_transient.push_back(
            {id, 1, 1, NativeDesktopRole::Carrier, manageable, {}, {}, true});
    }
    for (const WindowIdentity& id : a2) {
        without_transient.push_back(
            {id, 1, 2, NativeDesktopRole::Parking, manageable, {}, {}, true});
    }
    for (const WindowIdentity& id : b1) {
        without_transient.push_back(
            {id, 2, 3, NativeDesktopRole::Carrier, manageable, {}, {}, true});
    }
    lifecycle_ok = lifecycle_ok &&
                   engine.ReconcileDiscoverySnapshot(
                       std::move(without_transient), nullptr, &error) &&
                   engine.Windows().size() == tracked_after_switch &&
                   engine.CheckInvariant(&error);
    Field("rapid create/close reconciles", lifecycle_ok ? "PASS" : "FAIL");
    ok = ok && lifecycle_ok;

    // HWND reuse during the same run creates a new generation.
    const WindowIdentity reused_old = StressIdentity(0x500, 1005, 1);
    const WindowIdentity reused_new = StressIdentity(0x500, 1005, 2);
    bool reuse_ok =
        engine.UpsertWindow(
            {reused_old, 1, 1, NativeDesktopRole::Carrier, manageable, {}, {},
             true},
            &error) == UpsertResult::Added &&
        engine.UpsertWindow(
            {reused_new, 1, 1, NativeDesktopRole::Carrier, manageable, {}, {},
             true},
            &error) == UpsertResult::Recreated &&
        engine.FindWindow(reused_old) == nullptr &&
        engine.FindWindow(reused_new) != nullptr &&
        engine.CheckInvariant(&error);
    Field("HWND reuse under load creates new generation",
          reuse_ok ? "PASS" : "FAIL");
    ok = ok && reuse_ok;

    std::filesystem::remove(journal_path, remove_error);
    Field("result", ok ? "PASS" : "FAIL");
    Print("RESULT={}\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

}  // namespace vd
