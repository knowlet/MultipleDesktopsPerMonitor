#include "workspace_state.h"

#include <algorithm>
#include <array>
#include <limits>
#include <system_error>
#include <unordered_set>
#include <utility>

namespace vd {
namespace {

constexpr std::array<std::uint8_t, 8> kMagic = {
    'V', 'D', 'W', 'S', 'T', 'A', 'T', 'E'};
constexpr std::uint64_t kMaximumFileBytes = 64ull * 1024ull * 1024ull;
constexpr std::uint32_t kMaximumMonitors = 4096;
constexpr std::uint32_t kMaximumWorkspacesPerMonitor = 65536;
constexpr std::uint32_t kMaximumOwnershipRecords = 1000000;
constexpr std::uint32_t kMaximumStableMonitorKeyBytes = 4096;

void SetError(std::string* error, std::string message) {
    if (error) *error = std::move(message);
}

std::string Win32Error(const char* action, DWORD code = GetLastError()) {
    return std::string(action) + ": " +
           std::system_category().message(static_cast<int>(code));
}

bool IdentityLess(const WorkspaceOwnership& left,
                  const WorkspaceOwnership& right) noexcept {
    const auto left_hwnd =
        reinterpret_cast<std::uintptr_t>(left.identity.hwnd);
    const auto right_hwnd =
        reinterpret_cast<std::uintptr_t>(right.identity.hwnd);
    if (left_hwnd != right_hwnd) return left_hwnd < right_hwnd;
    if (left.identity.pid != right.identity.pid) {
        return left.identity.pid < right.identity.pid;
    }
    const FILETIME& left_time = left.identity.process_creation_time;
    const FILETIME& right_time = right.identity.process_creation_time;
    if (left_time.dwHighDateTime != right_time.dwHighDateTime) {
        return left_time.dwHighDateTime < right_time.dwHighDateTime;
    }
    if (left_time.dwLowDateTime != right_time.dwLowDateTime) {
        return left_time.dwLowDateTime < right_time.dwLowDateTime;
    }
    return left.workspace < right.workspace;
}

bool EncodedSize(const WorkspaceState& state, std::size_t& size,
                 std::string* error);

bool ValidStableKey(const std::string& key) noexcept {
    return !key.empty() && key.size() <= kMaximumStableMonitorKeyBytes &&
           key.find('\0') == std::string::npos;
}

bool ValidateBindings(const std::vector<StableMonitorBinding>& bindings,
                      std::string* error) {
    std::unordered_set<std::string> keys;
    std::unordered_set<MonitorId> runtime_monitors;
    for (const StableMonitorBinding& binding : bindings) {
        if (!ValidStableKey(binding.stable_key) ||
            binding.runtime_monitor == 0 ||
            !keys.insert(binding.stable_key).second ||
            !runtime_monitors.insert(binding.runtime_monitor).second) {
            SetError(error, "invalid or duplicate stable monitor binding");
            return false;
        }
    }
    return true;
}

bool ValidateAndCanonicalize(const WorkspaceState& state,
                             WorkspaceState& canonical,
                             std::string* error) {
    if (state.schema_version != kWorkspaceStateSchemaVersion) {
        SetError(error, "unsupported workspace-state schema version");
        return false;
    }
    const GUID zero_guid{};
    if (IsEqualGUID(state.carrier, zero_guid) ||
        IsEqualGUID(state.parking, zero_guid) ||
        IsEqualGUID(state.carrier, state.parking)) {
        SetError(error, "carrier and parking GUIDs must be nonzero and differ");
        return false;
    }
    if (state.monitors.size() > kMaximumMonitors ||
        state.ownership.size() > kMaximumOwnershipRecords) {
        SetError(error, "workspace-state count exceeds format limit");
        return false;
    }
    for (const WorkspaceStateMonitor& monitor : state.monitors) {
        if (!ValidStableKey(monitor.stable_key) ||
            monitor.workspaces.empty() ||
            monitor.workspaces.size() > kMaximumWorkspacesPerMonitor) {
            SetError(error, "workspace-state count exceeds format limit");
            return false;
        }
    }
    std::size_t encoded_size = 0;
    if (!EncodedSize(state, encoded_size, error)) return false;

    canonical = state;
    std::sort(canonical.monitors.begin(), canonical.monitors.end(),
              [](const WorkspaceStateMonitor& left,
                 const WorkspaceStateMonitor& right) {
                  return left.stable_key < right.stable_key;
              });
    std::sort(canonical.ownership.begin(), canonical.ownership.end(),
              IdentityLess);

    std::unordered_set<std::string> stable_keys;
    std::unordered_set<MonitorId> runtime_monitors;
    std::unordered_set<WorkspaceId> workspaces;
    for (WorkspaceStateMonitor& monitor : canonical.monitors) {
        if (!ValidStableKey(monitor.stable_key) ||
            !stable_keys.insert(monitor.stable_key).second ||
            (monitor.runtime_monitor != 0 &&
             !runtime_monitors.insert(monitor.runtime_monitor).second) ||
            monitor.workspaces.empty() ||
            monitor.workspaces.size() > kMaximumWorkspacesPerMonitor ||
            std::find(monitor.workspaces.begin(), monitor.workspaces.end(),
                      monitor.active) == monitor.workspaces.end()) {
            SetError(error, "invalid monitor workspace topology");
            return false;
        }
        std::sort(monitor.workspaces.begin(), monitor.workspaces.end());
        for (WorkspaceId workspace : monitor.workspaces) {
            if (workspace == 0 || !workspaces.insert(workspace).second) {
                SetError(error, "workspace id is duplicated or invalid");
                return false;
            }
        }
    }

    std::unordered_set<WindowIdentity, WindowIdentityHash> identities;
    std::unordered_set<std::uintptr_t> hwnds;
    for (const WorkspaceOwnership& ownership : canonical.ownership) {
        const auto hwnd =
            reinterpret_cast<std::uintptr_t>(ownership.identity.hwnd);
        if (!ownership.identity.IsValid() || !hwnds.insert(hwnd).second ||
            !identities.insert(ownership.identity).second ||
            !workspaces.contains(ownership.workspace)) {
            SetError(error, "invalid window workspace ownership");
            return false;
        }
    }
    return true;
}

bool AddEncodedSize(std::size_t amount, std::size_t& total) noexcept {
    if (amount > std::numeric_limits<std::size_t>::max() - total) return false;
    total += amount;
    return total <= kMaximumFileBytes;
}

bool EncodedSize(const WorkspaceState& state, std::size_t& size,
                 std::string* error) {
    // magic + version + two GUIDs + monitor count + ownership count + CRC
    size = 8 + 4 + 16 + 16 + 4 + 4 + 4;
    for (const WorkspaceStateMonitor& monitor : state.monitors) {
        if (monitor.workspaces.size() >
                (std::numeric_limits<std::size_t>::max() - 16 -
                 monitor.stable_key.size()) /
                    8 ||
            !AddEncodedSize(16 + monitor.stable_key.size() +
                                monitor.workspaces.size() * 8,
                            size)) {
            SetError(error, "workspace-state encoded size exceeds limit");
            return false;
        }
    }
    if (state.ownership.size() >
            std::numeric_limits<std::size_t>::max() / 28 ||
        !AddEncodedSize(state.ownership.size() * 28, size)) {
        SetError(error, "workspace-state encoded size exceeds limit");
        return false;
    }
    return true;
}

void AppendU16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8));
}

void AppendU32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    for (unsigned shift = 0; shift < 32; shift += 8) {
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void AppendU64(std::vector<std::uint8_t>& bytes, std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        bytes.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void AppendGuid(std::vector<std::uint8_t>& bytes, const GUID& guid) {
    AppendU32(bytes, guid.Data1);
    AppendU16(bytes, guid.Data2);
    AppendU16(bytes, guid.Data3);
    bytes.insert(bytes.end(), std::begin(guid.Data4), std::end(guid.Data4));
}

std::uint32_t Crc32(const std::uint8_t* data, std::size_t size) noexcept {
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            const std::uint32_t mask =
                0u - static_cast<std::uint32_t>(crc & 1u);
            crc = (crc >> 1) ^ (0xedb88320u & mask);
        }
    }
    return ~crc;
}

std::vector<std::uint8_t> Serialize(const WorkspaceState& state,
                                    std::size_t encoded_size) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(encoded_size);
    bytes.insert(bytes.end(), kMagic.begin(), kMagic.end());
    AppendU32(bytes, state.schema_version);
    AppendGuid(bytes, state.carrier);
    AppendGuid(bytes, state.parking);
    AppendU32(bytes, static_cast<std::uint32_t>(state.monitors.size()));
    for (const WorkspaceStateMonitor& monitor : state.monitors) {
        AppendU32(bytes,
                  static_cast<std::uint32_t>(monitor.stable_key.size()));
        bytes.insert(bytes.end(), monitor.stable_key.begin(),
                     monitor.stable_key.end());
        AppendU64(bytes, monitor.active);
        AppendU32(bytes,
                  static_cast<std::uint32_t>(monitor.workspaces.size()));
        for (WorkspaceId workspace : monitor.workspaces) {
            AppendU64(bytes, workspace);
        }
    }
    AppendU32(bytes, static_cast<std::uint32_t>(state.ownership.size()));
    for (const WorkspaceOwnership& ownership : state.ownership) {
        AppendU64(bytes, static_cast<std::uint64_t>(
                             reinterpret_cast<std::uintptr_t>(
                                 ownership.identity.hwnd)));
        AppendU32(bytes, ownership.identity.pid);
        AppendU32(bytes,
                  ownership.identity.process_creation_time.dwHighDateTime);
        AppendU32(bytes,
                  ownership.identity.process_creation_time.dwLowDateTime);
        AppendU64(bytes, ownership.workspace);
    }
    AppendU32(bytes, Crc32(bytes.data(), bytes.size()));
    return bytes;
}

class Reader {
   public:
    Reader(const std::vector<std::uint8_t>& bytes, std::size_t end)
        : bytes_(bytes), end_(end) {}

    bool U16(std::uint16_t& value) {
        if (end_ - offset_ < 2) return false;
        value = static_cast<std::uint16_t>(bytes_[offset_]) |
                static_cast<std::uint16_t>(bytes_[offset_ + 1]) << 8;
        offset_ += 2;
        return true;
    }

    bool U32(std::uint32_t& value) {
        if (end_ - offset_ < 4) return false;
        value = 0;
        for (unsigned shift = 0; shift < 32; shift += 8) {
            value |= static_cast<std::uint32_t>(bytes_[offset_++]) << shift;
        }
        return true;
    }

    bool U64(std::uint64_t& value) {
        if (end_ - offset_ < 8) return false;
        value = 0;
        for (unsigned shift = 0; shift < 64; shift += 8) {
            value |= static_cast<std::uint64_t>(bytes_[offset_++]) << shift;
        }
        return true;
    }

    bool Guid(GUID& guid) {
        std::uint32_t data1 = 0;
        if (!U32(data1) || !U16(guid.Data2) || !U16(guid.Data3) ||
            end_ - offset_ < sizeof(guid.Data4)) {
            return false;
        }
        guid.Data1 = static_cast<decltype(guid.Data1)>(data1);
        std::copy_n(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
                    sizeof(guid.Data4), guid.Data4);
        offset_ += sizeof(guid.Data4);
        return true;
    }

    bool Magic() {
        if (end_ - offset_ < kMagic.size() ||
            !std::equal(kMagic.begin(), kMagic.end(),
                        bytes_.begin() + static_cast<std::ptrdiff_t>(offset_))) {
            return false;
        }
        offset_ += kMagic.size();
        return true;
    }

    bool String(std::uint32_t length, std::string& value) {
        if (length > end_ - offset_) return false;
        value.assign(
            reinterpret_cast<const char*>(bytes_.data() + offset_), length);
        offset_ += length;
        return true;
    }

    bool AtEnd() const noexcept { return offset_ == end_; }
    std::size_t Remaining() const noexcept { return end_ - offset_; }

   private:
    const std::vector<std::uint8_t>& bytes_;
    std::size_t end_ = 0;
    std::size_t offset_ = 0;
};

bool Deserialize(const std::vector<std::uint8_t>& bytes, WorkspaceState& out,
                 std::string* error) {
    if (bytes.size() < kMagic.size() + sizeof(std::uint32_t) * 2) {
        SetError(error, "workspace-state file is truncated");
        return false;
    }
    const std::size_t payload_size = bytes.size() - sizeof(std::uint32_t);
    const std::uint32_t stored_crc =
        static_cast<std::uint32_t>(bytes[payload_size]) |
        static_cast<std::uint32_t>(bytes[payload_size + 1]) << 8 |
        static_cast<std::uint32_t>(bytes[payload_size + 2]) << 16 |
        static_cast<std::uint32_t>(bytes[payload_size + 3]) << 24;
    if (stored_crc != Crc32(bytes.data(), payload_size)) {
        SetError(error, "workspace-state checksum mismatch");
        return false;
    }

    Reader reader(bytes, payload_size);
    WorkspaceState candidate;
    std::uint32_t monitor_count = 0;
    if (!reader.Magic() || !reader.U32(candidate.schema_version) ||
        !reader.Guid(candidate.carrier) || !reader.Guid(candidate.parking) ||
        !reader.U32(monitor_count) || monitor_count > kMaximumMonitors) {
        SetError(error, "invalid workspace-state header");
        return false;
    }
    if (reader.Remaining() < 4 ||
        monitor_count > (reader.Remaining() - 4) / 25) {
        SetError(error, "monitor count exceeds remaining encoded bytes");
        return false;
    }
    candidate.monitors.reserve(monitor_count);
    for (std::uint32_t i = 0; i < monitor_count; ++i) {
        WorkspaceStateMonitor monitor;
        std::uint32_t stable_key_size = 0;
        std::uint32_t workspace_count = 0;
        if (!reader.U32(stable_key_size) || stable_key_size == 0 ||
            stable_key_size > kMaximumStableMonitorKeyBytes ||
            stable_key_size > reader.Remaining() ||
            !reader.String(stable_key_size, monitor.stable_key) ||
            !reader.U64(monitor.active) ||
            !reader.U32(workspace_count) || workspace_count == 0 ||
            workspace_count > kMaximumWorkspacesPerMonitor ||
            workspace_count > reader.Remaining() / sizeof(WorkspaceId)) {
            SetError(error, "invalid monitor record");
            return false;
        }
        monitor.workspaces.reserve(workspace_count);
        for (std::uint32_t j = 0; j < workspace_count; ++j) {
            WorkspaceId workspace = 0;
            if (!reader.U64(workspace)) {
                SetError(error, "truncated workspace list");
                return false;
            }
            monitor.workspaces.push_back(workspace);
        }
        candidate.monitors.push_back(std::move(monitor));
    }

    std::uint32_t ownership_count = 0;
    if (!reader.U32(ownership_count) ||
        ownership_count > kMaximumOwnershipRecords ||
        static_cast<std::size_t>(ownership_count) * 28 !=
            reader.Remaining()) {
        SetError(error, "invalid ownership count");
        return false;
    }
    candidate.ownership.reserve(ownership_count);
    for (std::uint32_t i = 0; i < ownership_count; ++i) {
        std::uint64_t hwnd_value = 0;
        std::uint32_t pid = 0;
        std::uint32_t creation_high = 0;
        std::uint32_t creation_low = 0;
        WorkspaceOwnership ownership;
        if (!reader.U64(hwnd_value) || !reader.U32(pid) ||
            !reader.U32(creation_high) || !reader.U32(creation_low) ||
            !reader.U64(ownership.workspace) ||
            hwnd_value > std::numeric_limits<std::uintptr_t>::max()) {
            SetError(error, "invalid ownership record");
            return false;
        }
        ownership.identity.hwnd = reinterpret_cast<HWND>(
            static_cast<std::uintptr_t>(hwnd_value));
        ownership.identity.pid = static_cast<DWORD>(pid);
        ownership.identity.process_creation_time.dwHighDateTime =
            static_cast<DWORD>(creation_high);
        ownership.identity.process_creation_time.dwLowDateTime =
            static_cast<DWORD>(creation_low);
        ownership.identity.process_creation_time_ok = true;
        candidate.ownership.push_back(ownership);
    }
    if (!reader.AtEnd()) {
        SetError(error, "workspace-state file has trailing data");
        return false;
    }

    WorkspaceState canonical;
    if (!ValidateAndCanonicalize(candidate, canonical, error)) return false;
    out = std::move(canonical);
    return true;
}

bool WriteAll(HANDLE file, const std::vector<std::uint8_t>& bytes,
              std::string* error) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
            bytes.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(file, bytes.data() + offset, requested, &written,
                       nullptr) || written == 0) {
            SetError(error, Win32Error("write workspace-state temporary failed"));
            return false;
        }
        offset += written;
    }
    if (!FlushFileBuffers(file)) {
        SetError(error, Win32Error("flush workspace-state temporary failed"));
        return false;
    }
    return true;
}

}  // namespace

bool CaptureWorkspaceState(const WorkspaceEngine& engine,
                           const std::vector<StableMonitorBinding>& bindings,
                           WorkspaceState& out, std::string* error) {
    std::string invariant_error;
    if (!engine.CheckInvariant(&invariant_error)) {
        SetError(error, "cannot checkpoint invalid workspace engine: " +
                            invariant_error);
        return false;
    }
    if (!ValidateBindings(bindings, error)) return false;
    WorkspaceState candidate;
    candidate.carrier = engine.carrier();
    candidate.parking = engine.parking();
    for (const MonitorWorkspaceState& monitor : engine.Monitors()) {
        const auto binding = std::find_if(
            bindings.begin(), bindings.end(),
            [&](const StableMonitorBinding& candidate_binding) {
                return candidate_binding.runtime_monitor == monitor.monitor;
            });
        if (binding == bindings.end()) {
            SetError(error,
                     "engine monitor has no stable monitor binding");
            return false;
        }
        candidate.monitors.push_back({binding->stable_key, monitor.monitor,
                                      monitor.active, monitor.workspaces});
    }
    for (const WindowRecord* window : engine.Windows()) {
        candidate.ownership.push_back({window->identity, window->workspace});
    }
    WorkspaceState canonical;
    if (!ValidateAndCanonicalize(candidate, canonical, error)) return false;
    out = std::move(canonical);
    return true;
}

bool RemapWorkspaceStateTopology(
    const WorkspaceState& persisted,
    const std::vector<StableMonitorBinding>& current, WorkspaceState& out,
    std::string* error) {
    WorkspaceState candidate;
    if (!ValidateAndCanonicalize(persisted, candidate, error) ||
        !ValidateBindings(current, error)) {
        return false;
    }
    for (WorkspaceStateMonitor& monitor : candidate.monitors) {
        const auto binding = std::find_if(
            current.begin(), current.end(),
            [&](const StableMonitorBinding& candidate_binding) {
                return candidate_binding.stable_key == monitor.stable_key;
            });
        if (binding == current.end()) {
            SetError(error, "persisted stable monitor key is not present");
            return false;
        }
        monitor.runtime_monitor = binding->runtime_monitor;
    }
    out = std::move(candidate);
    return true;
}

bool ValidateWorkspaceState(const WorkspaceState& state, std::string* error) {
    WorkspaceState canonical;
    return ValidateAndCanonicalize(state, canonical, error);
}

bool SaveWorkspaceState(const WorkspaceState& state,
                        const std::filesystem::path& path,
                        std::string* error) {
    WorkspaceState canonical;
    if (!ValidateAndCanonicalize(state, canonical, error)) return false;
    if (path.empty()) {
        SetError(error, "workspace-state path is empty");
        return false;
    }
    std::size_t encoded_size = 0;
    if (!EncodedSize(canonical, encoded_size, error)) return false;
    const std::vector<std::uint8_t> bytes =
        Serialize(canonical, encoded_size);

    std::filesystem::path temporary;
    HANDLE file = INVALID_HANDLE_VALUE;
    try {
        if (!path.parent_path().empty()) {
            std::filesystem::create_directories(path.parent_path());
        }
        for (unsigned attempt = 0; attempt < 16; ++attempt) {
            temporary = path;
            temporary += L".tmp." + std::to_wstring(GetCurrentProcessId()) +
                         L"." + std::to_wstring(GetCurrentThreadId()) + L"." +
                         std::to_wstring(GetTickCount64()) + L"." +
                         std::to_wstring(attempt);
            file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_NEW,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
                               nullptr);
            if (file != INVALID_HANDLE_VALUE) break;
            if (GetLastError() != ERROR_FILE_EXISTS &&
                GetLastError() != ERROR_ALREADY_EXISTS) {
                SetError(error,
                         Win32Error("create workspace-state temporary failed"));
                return false;
            }
        }
        if (file == INVALID_HANDLE_VALUE) {
            SetError(error, "could not allocate workspace-state temporary");
            return false;
        }
        const bool written = WriteAll(file, bytes, error);
        CloseHandle(file);
        file = INVALID_HANDLE_VALUE;
        if (!written) {
            DeleteFileW(temporary.c_str());
            return false;
        }
        if (!MoveFileExW(temporary.c_str(), path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            SetError(error, Win32Error("replace workspace-state failed"));
            DeleteFileW(temporary.c_str());
            return false;
        }
        return true;
    } catch (const std::exception& exception) {
        if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
        if (!temporary.empty()) DeleteFileW(temporary.c_str());
        SetError(error, exception.what());
        return false;
    }
}

bool LoadWorkspaceState(const std::filesystem::path& path, WorkspaceState& out,
                        std::string* error) {
    HANDLE file = CreateFileW(
        path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        SetError(error, Win32Error("open workspace-state failed"));
        return false;
    }
    LARGE_INTEGER size{};
    const bool size_read = GetFileSizeEx(file, &size) != FALSE;
    if (!size_read || size.QuadPart < 0 ||
        static_cast<std::uint64_t>(size.QuadPart) > kMaximumFileBytes) {
        const DWORD code = size_read ? ERROR_SUCCESS : GetLastError();
        CloseHandle(file);
        SetError(error, code == ERROR_SUCCESS
                            ? "workspace-state file exceeds size limit"
                            : Win32Error("size workspace-state failed", code));
        return false;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
            bytes.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD read = 0;
        if (!ReadFile(file, bytes.data() + offset, requested, &read, nullptr) ||
            read == 0) {
            const DWORD code = GetLastError();
            CloseHandle(file);
            SetError(error,
                     Win32Error("read workspace-state failed", code));
            return false;
        }
        offset += read;
    }
    CloseHandle(file);
    return Deserialize(bytes, out, error);
}

}  // namespace vd
