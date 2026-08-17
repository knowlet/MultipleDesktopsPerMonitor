#include "workspace_state.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "util.h"

namespace vd {

bool RunWorkspaceStateSeedTests();

namespace {

WindowIdentity TestIdentity(std::uintptr_t hwnd, DWORD pid, DWORD high,
                            DWORD low) {
    WindowIdentity identity;
    identity.hwnd = reinterpret_cast<HWND>(hwnd);
    identity.pid = pid;
    identity.process_creation_time = {low, high};
    identity.process_creation_time_ok = true;
    return identity;
}

std::vector<char> ReadBytes(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

std::uint32_t TestCrc32(const char* data, std::size_t size) {
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0; i < size; ++i) {
        crc ^= static_cast<std::uint8_t>(data[i]);
        for (int bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask =
                0u - static_cast<std::uint32_t>(crc & 1u);
            crc = (crc >> 1) ^ (0xedb88320u & mask);
        }
    }
    return ~crc;
}

void SetU32(std::vector<char>& bytes, std::size_t offset,
            std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        bytes[offset++] = static_cast<char>(value >> shift);
    }
}

bool SameGuid(const GUID& a, const GUID& b) {
    return IsEqualGUID(a, b) != FALSE;
}

bool SameDurableState(const WorkspaceState& a, const WorkspaceState& b) {
    if (a.schema_version != b.schema_version ||
        !SameGuid(a.carrier, b.carrier) || !SameGuid(a.parking, b.parking) ||
        a.monitors.size() != b.monitors.size() ||
        a.ownership.size() != b.ownership.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.monitors.size(); ++i) {
        const auto& left = a.monitors[i];
        const auto& right = b.monitors[i];
        if (left.stable_key != right.stable_key ||
            left.active != right.active ||
            left.workspaces != right.workspaces) {
            return false;
        }
    }
    for (std::size_t i = 0; i < a.ownership.size(); ++i) {
        if (a.ownership[i].identity != b.ownership[i].identity ||
            a.ownership[i].workspace != b.ownership[i].workspace) {
            return false;
        }
    }
    return true;
}

}  // namespace

int CmdWorkspaceStateTest() {
    Heading("workspace-state-test");
    Field("scope", "deterministic durable logical checkpoint");
    Field("native desktop mutation", "none");

    bool ok = RunWorkspaceStateSeedTests();

    const GUID carrier{0x10203040, 0x5060, 0x7080,
                       {0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01}};
    const GUID parking{0xfedcba98, 0x7654, 0x3210,
                       {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}};

    WorkspaceEngine engine(carrier, parking);
    std::string error;
    ok = engine.AddMonitor(20, 201, {201, 202}, &error) &&
         engine.AddMonitor(10, 101, {101, 102}, &error) && ok;

    WindowRecord second;
    second.identity = TestIdentity(0x2002, 200, 22, 2);
    second.monitor = 20;
    second.workspace = 202;
    second.native_role = NativeDesktopRole::Parking;
    second.capabilities = {true, true, true, true, true};
    ok = ok && engine.UpsertWindow(second, &error) != UpsertResult::Rejected;

    WindowRecord first;
    first.identity = TestIdentity(0x1001, 100, 11, 1);
    first.monitor = 10;
    first.workspace = 101;
    first.native_role = NativeDesktopRole::Carrier;
    first.capabilities = {true, true, true, true, true};
    ok = ok && engine.UpsertWindow(first, &error) != UpsertResult::Rejected;

    const std::vector<StableMonitorBinding> initial_bindings = {
        {"display-target-B", 20}, {"display-target-A", 10}};
    WorkspaceState captured;
    ok = ok &&
         CaptureWorkspaceState(engine, initial_bindings, captured, &error);
    Field("engine snapshot", ok ? "PASS" : "FAIL");

    const auto directory = std::filesystem::temp_directory_path() /
                           "vdprobe-workspace-state-test";
    std::error_code cleanup_error;
    std::filesystem::remove_all(directory, cleanup_error);
    std::filesystem::create_directories(directory, cleanup_error);
    const auto first_path = directory / "first.state";
    const auto second_path = directory / "second.state";

    ok = ok && SaveWorkspaceState(captured, first_path, &error);
    WorkspaceState loaded;
    ok = ok && LoadWorkspaceState(first_path, loaded, &error) &&
         SameDurableState(captured, loaded) &&
         std::all_of(loaded.monitors.begin(), loaded.monitors.end(),
                     [](const WorkspaceStateMonitor& monitor) {
                         return monitor.runtime_monitor == 0;
                     });
    Field("atomic save/load round trip", ok ? "PASS" : "FAIL");

    const std::vector<StableMonitorBinding> restarted_bindings = {
        {"display-target-B", 0xb002},
        {"unmanaged-extra-display", 0xc003},
        {"display-target-A", 0xa001}};
    WorkspaceState remapped;
    ok = ok && RemapWorkspaceStateTopology(
                   loaded, restarted_bindings, remapped, &error);
    const auto monitor_a = std::find_if(
        remapped.monitors.begin(), remapped.monitors.end(),
        [](const WorkspaceStateMonitor& monitor) {
            return monitor.stable_key == "display-target-A";
        });
    const auto monitor_b = std::find_if(
        remapped.monitors.begin(), remapped.monitors.end(),
        [](const WorkspaceStateMonitor& monitor) {
            return monitor.stable_key == "display-target-B";
        });
    const bool restart_remap_ok =
        monitor_a != remapped.monitors.end() &&
        monitor_a->runtime_monitor == 0xa001 &&
        monitor_b != remapped.monitors.end() &&
        monitor_b->runtime_monitor == 0xb002;
    ok = ok && restart_remap_ok;
    Field("stable keys remap changed runtime handles",
          restart_remap_ok ? "PASS" : "FAIL");

    WorkspaceState reordered = captured;
    std::reverse(reordered.monitors.begin(), reordered.monitors.end());
    for (WorkspaceStateMonitor& monitor : reordered.monitors) {
        std::reverse(monitor.workspaces.begin(), monitor.workspaces.end());
        monitor.runtime_monitor += 0x10000;
    }
    std::reverse(reordered.ownership.begin(), reordered.ownership.end());
    ok = ok && SaveWorkspaceState(reordered, second_path, &error) &&
         ReadBytes(first_path) == ReadBytes(second_path);
    Field("canonical byte order", ok ? "PASS" : "FAIL");

    WorkspaceState remap_sentinel;
    remap_sentinel.schema_version = 999;
    std::string missing_key_error;
    const std::vector<StableMonitorBinding> missing_bindings = {
        {"display-target-A", 0xa001}};
    const bool missing_key_rejected =
        !RemapWorkspaceStateTopology(
            loaded, missing_bindings, remap_sentinel, &missing_key_error) &&
        remap_sentinel.schema_version == 999;
    ok = ok && missing_key_rejected;
    Field("missing stable key fails atomically",
          missing_key_rejected ? "PASS" : "FAIL");

    std::string duplicate_binding_error;
    const std::vector<StableMonitorBinding> duplicate_key_bindings = {
        {"display-target-A", 0xa001},
        {"display-target-A", 0xa002},
        {"display-target-B", 0xb002}};
    const std::vector<StableMonitorBinding> duplicate_runtime_bindings = {
        {"display-target-A", 0xa001},
        {"display-target-B", 0xa001}};
    const bool duplicate_bindings_rejected =
        !RemapWorkspaceStateTopology(
            loaded, duplicate_key_bindings,
            remap_sentinel, &duplicate_binding_error) &&
        !RemapWorkspaceStateTopology(
            loaded, duplicate_runtime_bindings,
            remap_sentinel, &duplicate_binding_error);
    ok = ok && duplicate_bindings_rejected;
    Field("duplicate key/runtime bindings rejected",
          duplicate_bindings_rejected ? "PASS" : "FAIL");

    WorkspaceState duplicate_stable_key = captured;
    duplicate_stable_key.monitors[1].stable_key =
        duplicate_stable_key.monitors[0].stable_key;
    std::string duplicate_stable_key_error;
    const bool duplicate_stable_key_rejected =
        !SaveWorkspaceState(duplicate_stable_key, second_path,
                            &duplicate_stable_key_error);
    ok = ok && duplicate_stable_key_rejected;
    Field("duplicate persisted stable key rejected",
          duplicate_stable_key_rejected ? "PASS" : "FAIL");

    WorkspaceState invalid = captured;
    invalid.monitors[0].active = 999999;
    const std::vector<char> valid_bytes = ReadBytes(first_path);
    std::string invalid_error;
    const bool invalid_rejected =
        !SaveWorkspaceState(invalid, first_path, &invalid_error) &&
        ReadBytes(first_path) == valid_bytes;
    ok = ok && invalid_rejected;
    Field("invalid save preserves prior checkpoint",
          invalid_rejected ? "PASS" : "FAIL");

    WorkspaceState zero_guid = captured;
    zero_guid.carrier = {};
    WorkspaceState zero_parking = captured;
    zero_parking.parking = {};
    std::string zero_guid_error;
    const bool zero_guid_rejected =
        !SaveWorkspaceState(zero_guid, second_path, &zero_guid_error) &&
        !SaveWorkspaceState(zero_parking, second_path, &zero_guid_error);
    ok = ok && zero_guid_rejected;
    Field("zero Carrier/Parking GUID rejected",
          zero_guid_rejected ? "PASS" : "FAIL");

    WorkspaceState duplicate_hwnd = captured;
    duplicate_hwnd.ownership[1].identity.hwnd =
        duplicate_hwnd.ownership[0].identity.hwnd;
    std::string duplicate_hwnd_error;
    const bool duplicate_hwnd_rejected =
        !SaveWorkspaceState(duplicate_hwnd, second_path,
                            &duplicate_hwnd_error);
    ok = ok && duplicate_hwnd_rejected;
    Field("duplicate HWND across generations rejected",
          duplicate_hwnd_rejected ? "PASS" : "FAIL");

    WorkspaceState excessive_workspace_count = captured;
    excessive_workspace_count.monitors[0].workspaces.resize(65537, 101);
    std::string excessive_count_error;
    const bool excessive_count_rejected =
        !SaveWorkspaceState(excessive_workspace_count, second_path,
                            &excessive_count_error) &&
        ReadBytes(first_path) == valid_bytes;
    ok = ok && excessive_count_rejected;
    Field("input count preflight preserves checkpoint",
          excessive_count_rejected ? "PASS" : "FAIL");

    // Schema 2 intentionally replaces schema 1 because v1 persisted raw
    // HMONITOR values. A v1 header with a valid checksum must fail closed.
    std::vector<char> old_schema = valid_bytes;
    SetU32(old_schema, 8, 1);
    const std::uint32_t old_schema_crc =
        TestCrc32(old_schema.data(), old_schema.size() - 4);
    SetU32(old_schema, old_schema.size() - 4, old_schema_crc);
    {
        std::ofstream output(second_path,
                             std::ios::binary | std::ios::trunc);
        output.write(old_schema.data(),
                     static_cast<std::streamsize>(old_schema.size()));
    }
    WorkspaceState old_schema_sentinel;
    old_schema_sentinel.schema_version = 666;
    std::string old_schema_error;
    const bool old_schema_rejected =
        !LoadWorkspaceState(second_path, old_schema_sentinel,
                            &old_schema_error) &&
        old_schema_sentinel.schema_version == 666;
    ok = ok && old_schema_rejected;
    Field("raw-monitor schema 1 rejected",
          old_schema_rejected ? "PASS" : "FAIL");

    // The monitor count lives at byte 44. Keep the checksum valid so load
    // must reject the impossible count from the remaining-byte preflight,
    // before reserving a monitor/workspace graph.
    std::vector<char> impossible_count = valid_bytes;
    SetU32(impossible_count, 44, 4096);
    const std::uint32_t impossible_crc =
        TestCrc32(impossible_count.data(), impossible_count.size() - 4);
    SetU32(impossible_count, impossible_count.size() - 4, impossible_crc);
    {
        std::ofstream output(second_path,
                             std::ios::binary | std::ios::trunc);
        output.write(impossible_count.data(),
                     static_cast<std::streamsize>(impossible_count.size()));
    }
    WorkspaceState preflight_sentinel;
    preflight_sentinel.schema_version = 888;
    std::string preflight_error;
    const bool impossible_count_rejected =
        !LoadWorkspaceState(second_path, preflight_sentinel,
                            &preflight_error) &&
        preflight_sentinel.schema_version == 888;
    ok = ok && impossible_count_rejected;
    Field("encoded count preflight rejects impossible allocation",
          impossible_count_rejected ? "PASS" : "FAIL");

    std::vector<char> corrupt = valid_bytes;
    if (corrupt.size() > 12) corrupt[12] ^= 0x5a;
    {
        std::ofstream output(second_path,
                             std::ios::binary | std::ios::trunc);
        output.write(corrupt.data(), static_cast<std::streamsize>(corrupt.size()));
    }
    WorkspaceState sentinel;
    sentinel.schema_version = 777;
    std::string corrupt_error;
    const bool corrupt_rejected =
        !LoadWorkspaceState(second_path, sentinel, &corrupt_error) &&
        sentinel.schema_version == 777;
    ok = ok && corrupt_rejected;
    Field("corrupt load rejected without partial output",
          corrupt_rejected ? "PASS" : "FAIL");

    std::filesystem::remove_all(directory, cleanup_error);
    if (!ok && !error.empty()) Field("error", error);
    Field("result", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

}  // namespace vd
