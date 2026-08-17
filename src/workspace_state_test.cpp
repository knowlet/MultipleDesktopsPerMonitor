#include "workspace_state.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "util.h"

namespace vd {
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

bool SameState(const WorkspaceState& a, const WorkspaceState& b) {
    if (a.schema_version != b.schema_version ||
        !SameGuid(a.carrier, b.carrier) || !SameGuid(a.parking, b.parking) ||
        a.monitors.size() != b.monitors.size() ||
        a.ownership.size() != b.ownership.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.monitors.size(); ++i) {
        const auto& left = a.monitors[i];
        const auto& right = b.monitors[i];
        if (left.monitor != right.monitor || left.active != right.active ||
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

    const GUID carrier{0x10203040, 0x5060, 0x7080,
                       {0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01}};
    const GUID parking{0xfedcba98, 0x7654, 0x3210,
                       {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}};

    WorkspaceEngine engine(carrier, parking);
    std::string error;
    bool ok = engine.AddMonitor(20, 201, {201, 202}, &error) &&
              engine.AddMonitor(10, 101, {101, 102}, &error);

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

    WorkspaceState captured;
    ok = ok && CaptureWorkspaceState(engine, captured, &error);
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
         SameState(captured, loaded);
    Field("atomic save/load round trip", ok ? "PASS" : "FAIL");

    WorkspaceState reordered = captured;
    std::reverse(reordered.monitors.begin(), reordered.monitors.end());
    for (MonitorWorkspaceState& monitor : reordered.monitors) {
        std::reverse(monitor.workspaces.begin(), monitor.workspaces.end());
    }
    std::reverse(reordered.ownership.begin(), reordered.ownership.end());
    ok = ok && SaveWorkspaceState(reordered, second_path, &error) &&
         ReadBytes(first_path) == ReadBytes(second_path);
    Field("canonical byte order", ok ? "PASS" : "FAIL");

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
