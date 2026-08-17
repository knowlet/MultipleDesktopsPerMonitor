#include "workspace_state_seed.h"

#include <memory>
#include <string>
#include <vector>

#include "util.h"

namespace vd {

namespace {

WindowIdentity SeedTestIdentity(std::uintptr_t hwnd, DWORD pid, DWORD high,
                                DWORD low) {
    WindowIdentity identity;
    identity.hwnd = reinterpret_cast<HWND>(hwnd);
    identity.pid = pid;
    identity.process_creation_time = {low, high};
    identity.process_creation_time_ok = true;
    return identity;
}

WindowCapabilities SeedTestCapabilities() {
    return {true, true, true, true, true};
}

}  // namespace

bool RunWorkspaceStateSeedTests() {
    const GUID carrier{0x10203040, 0x5060, 0x7080,
                       {0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01}};
    const GUID parking{0xfedcba98, 0x7654, 0x3210,
                       {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}};
    const WindowIdentity carrier_identity =
        SeedTestIdentity(0x1001, 100, 11, 1);
    const WindowIdentity parked_identity =
        SeedTestIdentity(0x2002, 200, 22, 2);
    const WindowCapabilities capabilities = SeedTestCapabilities();

    WorkspaceState checkpoint;
    checkpoint.carrier = carrier;
    checkpoint.parking = parking;
    checkpoint.monitors = {{"display-B", 20, 201, {201}},
                           {"display-A", 10, 101, {101, 102}}};
    checkpoint.ownership = {{carrier_identity, 201},
                            {parked_identity, 102}};

    const std::vector<MonitorWorkspaceState> startup_topology{
        {20, 201, {201}}, {10, 101, {101, 102}}};
    const std::vector<WindowRecord> authoritative_snapshot{
        {carrier_identity, 20, 0, NativeDesktopRole::Carrier, capabilities},
        {parked_identity, 10, 0, NativeDesktopRole::Parking, capabilities}};

    bool ok = true;
    std::unique_ptr<WorkspaceEngine> seeded;
    std::string seed_error;
    const bool seeded_ok = SeedWorkspaceEngineFromState(
        checkpoint, startup_topology, authoritative_snapshot, seeded,
        &seed_error);
    const WindowRecord* parked =
        seeded == nullptr ? nullptr : seeded->FindWindow(parked_identity);
    const bool topology_ok =
        seeded_ok && seeded != nullptr && seeded->Monitors().size() == 2 &&
        seeded->Workspace(101) != nullptr && seeded->Workspace(102) != nullptr &&
        seeded->Workspace(201) != nullptr && seeded->Workspace(202) == nullptr;
    const bool parked_ok =
        parked != nullptr && parked->monitor == 10 && parked->workspace == 102 &&
        parked->native_role == NativeDesktopRole::Parking;
    ok = topology_ok && parked_ok && ok;
    Field("seed 2 monitors / 3 workspaces", topology_ok ? "PASS" : "FAIL");
    Field("seed preserves parked ownership", parked_ok ? "PASS" : "FAIL");

    // The caller's startup configuration, not the checkpoint's prior active
    // value, defines which saved workspace is currently on Carrier.
    const std::vector<MonitorWorkspaceState> changed_active_topology{
        {20, 201, {201}}, {10, 102, {101, 102}}};
    std::vector<WindowRecord> changed_active_snapshot =
        authoritative_snapshot;
    changed_active_snapshot[1].native_role = NativeDesktopRole::Carrier;
    std::unique_ptr<WorkspaceEngine> changed_active_seed;
    std::string changed_active_error;
    const bool changed_active_seeded = SeedWorkspaceEngineFromState(
        checkpoint, changed_active_topology, changed_active_snapshot,
        changed_active_seed, &changed_active_error);
    const MonitorWorkspaceState* changed_active_monitor =
        changed_active_seed == nullptr ? nullptr
                                       : changed_active_seed->Monitor(10);
    const WindowRecord* changed_active_window =
        changed_active_seed == nullptr
            ? nullptr
            : changed_active_seed->FindWindow(parked_identity);
    const bool caller_active_ok =
        changed_active_seeded && changed_active_monitor != nullptr &&
        changed_active_monitor->active == 102 &&
        changed_active_window != nullptr &&
        changed_active_window->workspace == 102 &&
        changed_active_window->native_role == NativeDesktopRole::Carrier;
    ok = caller_active_ok && ok;
    Field("seed caller active workspace is authoritative",
          caller_active_ok ? "PASS" : "FAIL");

    const GUID sentinel_carrier{
        0x01010101, 0x0202, 0x0303,
        {0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}};
    const GUID sentinel_parking{
        0x11111111, 0x1212, 0x1313,
        {0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b}};
    auto unchanged =
        std::make_unique<WorkspaceEngine>(sentinel_carrier, sentinel_parking);
    std::string setup_error;
    ok = unchanged->AddMonitor(99, 9901, {9901}, &setup_error) && ok;
    WorkspaceEngine* const unchanged_address = unchanged.get();
    const std::vector<MonitorWorkspaceState> mismatched_topology{
        {20, 201, {201}}, {10, 101, {101, 103}}};
    std::string mismatch_error;
    const bool mismatch_ok =
        !SeedWorkspaceEngineFromState(checkpoint, mismatched_topology,
                                      authoritative_snapshot, unchanged,
                                      &mismatch_error) &&
        unchanged.get() == unchanged_address &&
        unchanged->Monitor(99) != nullptr;
    ok = mismatch_ok && ok;
    Field("seed topology mismatch fails atomically",
          mismatch_ok ? "PASS" : "FAIL");

    const WindowIdentity reused_identity =
        SeedTestIdentity(0x2002, 999, 99, 9);
    const std::vector<WindowRecord> reused_snapshot{
        {carrier_identity, 20, 0, NativeDesktopRole::Carrier, capabilities},
        {reused_identity, 10, 0, NativeDesktopRole::Carrier, capabilities}};
    std::unique_ptr<WorkspaceEngine> reused_seed;
    std::string reused_error;
    const bool reused_seeded = SeedWorkspaceEngineFromState(
        checkpoint, startup_topology, reused_snapshot, reused_seed,
        &reused_error);
    const WindowRecord* reused =
        reused_seed == nullptr ? nullptr
                               : reused_seed->FindWindow(reused_identity);
    const bool missing_reused_ok =
        reused_seeded && reused_seed != nullptr &&
        reused_seed->FindWindow(parked_identity) == nullptr && reused != nullptr &&
        reused->workspace == 101 &&
        reused->native_role == NativeDesktopRole::Carrier;
    ok = missing_reused_ok && ok;
    Field("seed missing/reused identity never inherits ownership",
          missing_reused_ok ? "PASS" : "FAIL");

    std::vector<WindowRecord> wrong_role_snapshot = authoritative_snapshot;
    wrong_role_snapshot[1].native_role = NativeDesktopRole::Carrier;
    auto role_output =
        std::make_unique<WorkspaceEngine>(sentinel_carrier, sentinel_parking);
    ok = role_output->AddMonitor(98, 9801, {9801}, &setup_error) && ok;
    WorkspaceEngine* const role_output_address = role_output.get();
    std::string role_error;
    const bool role_mismatch_ok =
        !SeedWorkspaceEngineFromState(checkpoint, startup_topology,
                                      wrong_role_snapshot, role_output,
                                      &role_error) &&
        role_output.get() == role_output_address &&
        role_output->Monitor(98) != nullptr;
    ok = role_mismatch_ok && ok;
    Field("seed native-role mismatch fails atomically",
          role_mismatch_ok ? "PASS" : "FAIL");

    if (!ok && !seed_error.empty()) Field("seed error", seed_error);
    return ok;
}

}  // namespace vd
