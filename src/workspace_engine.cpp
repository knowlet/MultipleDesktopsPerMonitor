#include "workspace_engine.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <system_error>
#include <unordered_set>

#include "util.h"
#include "window_lifecycle.h"

namespace vd {
namespace {

std::string IdentityText(const WindowIdentity& identity) {
    std::ostringstream out;
    out << "0x" << std::hex
        << reinterpret_cast<std::uintptr_t>(identity.hwnd) << ' ' << std::dec
        << identity.pid << ' ' << identity.process_creation_time.dwHighDateTime
        << ' ' << identity.process_creation_time.dwLowDateTime;
    return out.str();
}

bool ParseIdentity(std::istringstream& in, WindowIdentity& identity) {
    std::uintptr_t hwnd = 0;
    DWORD high = 0;
    DWORD low = 0;
    if (!(in >> std::hex >> hwnd >> std::dec >> identity.pid >> high >> low)) {
        return false;
    }
    identity.hwnd = reinterpret_cast<HWND>(hwnd);
    identity.process_creation_time.dwHighDateTime = high;
    identity.process_creation_time.dwLowDateTime = low;
    identity.process_creation_time_ok = true;
    return identity.IsValid();
}

const char* RoleLetter(NativeDesktopRole role) noexcept {
    switch (role) {
        case NativeDesktopRole::Carrier:
            return "C";
        case NativeDesktopRole::Parking:
            return "P";
        default:
            return "U";
    }
}

NativeDesktopRole ParseRole(const std::string& value) noexcept {
    if (value == "C") return NativeDesktopRole::Carrier;
    if (value == "P") return NativeDesktopRole::Parking;
    return NativeDesktopRole::Unknown;
}

bool PlansMatch(const SwitchPlan& a, const SwitchPlan& b) noexcept {
    if (a.monitor != b.monitor || a.from_workspace != b.from_workspace ||
        a.to_workspace != b.to_workspace ||
        a.operations.size() != b.operations.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.operations.size(); ++i) {
        const SwitchOperation& left = a.operations[i];
        const SwitchOperation& right = b.operations[i];
        if (left.identity != right.identity || left.from != right.from ||
            left.to != right.to) {
            return false;
        }
    }
    return true;
}

std::string Win32Error(const char* action, DWORD code = GetLastError()) {
    return std::string(action) + ": " +
           std::system_category().message(static_cast<int>(code));
}

bool WriteHandle(HANDLE file, const std::string& contents,
                 std::string* error) {
    std::size_t offset = 0;
    while (offset < contents.size()) {
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
            contents.size() - offset, std::numeric_limits<DWORD>::max()));
        DWORD written = 0;
        if (!WriteFile(file, contents.data() + offset, requested, &written,
                       nullptr) || written == 0) {
            if (error) *error = Win32Error("write journal failed");
            return false;
        }
        offset += written;
    }
    if (!FlushFileBuffers(file)) {
        if (error) *error = Win32Error("flush journal failed");
        return false;
    }
    return true;
}

}  // namespace

bool WindowIdentity::IsValid() const noexcept {
    return hwnd != nullptr && pid != 0 && process_creation_time_ok;
}

bool operator==(const WindowIdentity& a, const WindowIdentity& b) noexcept {
    return a.hwnd == b.hwnd && a.pid == b.pid &&
           a.process_creation_time_ok == b.process_creation_time_ok &&
           (!a.process_creation_time_ok ||
            (a.process_creation_time.dwHighDateTime ==
                 b.process_creation_time.dwHighDateTime &&
             a.process_creation_time.dwLowDateTime ==
                 b.process_creation_time.dwLowDateTime));
}

bool operator!=(const WindowIdentity& a, const WindowIdentity& b) noexcept {
    return !(a == b);
}

std::size_t WindowIdentityHash::operator()(
    const WindowIdentity& identity) const noexcept {
    std::size_t value =
        std::hash<std::uintptr_t>{}(
            reinterpret_cast<std::uintptr_t>(identity.hwnd));
    value ^= std::hash<DWORD>{}(identity.pid) + 0x9e3779b9u + (value << 6) +
             (value >> 2);
    value ^= std::hash<DWORD>{}(identity.process_creation_time.dwHighDateTime) +
             0x9e3779b9u + (value << 6) + (value >> 2);
    value ^= std::hash<DWORD>{}(identity.process_creation_time.dwLowDateTime) +
             0x9e3779b9u + (value << 6) + (value >> 2);
    return value;
}

WorkspaceJournal::WorkspaceJournal(std::filesystem::path path)
    : path_(std::move(path)) {}

bool WorkspaceJournal::Append(const std::string& line,
                               std::string* error) const {
    try {
        if (!path_.parent_path().empty()) {
            std::filesystem::create_directories(path_.parent_path());
        }
        HANDLE file = CreateFileW(
            path_.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
            OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
            nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            if (error) *error = Win32Error("open journal failed");
            return false;
        }
        const bool written = WriteHandle(file, line + '\n', error);
        CloseHandle(file);
        return written;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool WorkspaceJournal::Begin(const SwitchPlan& plan, std::string* error) const {
    try {
        std::string pending_error;
        const std::optional<SwitchPlan> pending = ReadPending(&pending_error);
        if (!pending_error.empty()) {
            if (error) *error = "read existing journal failed: " + pending_error;
            return false;
        }
        if (pending) {
            if (error) *error = "journal already contains a pending transaction";
            return false;
        }
        if (!path_.parent_path().empty()) {
            std::filesystem::create_directories(path_.parent_path());
        }
        std::ostringstream contents;
        contents << "BEGIN " << plan.monitor << ' ' << plan.from_workspace
                 << ' ' << plan.to_workspace << '\n';
        for (const SwitchOperation& operation : plan.operations) {
            contents << "MOVE " << IdentityText(operation.identity) << ' '
                     << RoleLetter(operation.from) << ' '
                     << RoleLetter(operation.to) << '\n';
        }

        std::filesystem::path temporary = path_;
        temporary += L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." +
                     std::to_wstring(GetCurrentThreadId()) + L"." +
                     std::to_wstring(GetTickCount64());
        HANDLE file = CreateFileW(
            temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
        if (file == INVALID_HANDLE_VALUE) {
            if (error) *error = Win32Error("create journal temporary failed");
            return false;
        }
        const bool written = WriteHandle(file, contents.str(), error);
        CloseHandle(file);
        if (!written) {
            DeleteFileW(temporary.c_str());
            return false;
        }
        if (!MoveFileExW(temporary.c_str(), path_.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
            if (error) *error = Win32Error("replace journal failed");
            DeleteFileW(temporary.c_str());
            return false;
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool WorkspaceJournal::Commit(std::string* error) const {
    return Append("COMMIT", error);
}

bool WorkspaceJournal::Abort(std::string* error) const {
    return Append("ABORT", error);
}

bool WorkspaceJournal::Recovered(std::string* error) const {
    return Append("RECOVERED", error);
}

std::optional<SwitchPlan> WorkspaceJournal::ReadPending(
    std::string* error) const {
    try {
        std::ifstream in(path_, std::ios::binary);
        if (!in) return std::nullopt;

        std::string line;
        SwitchPlan plan;
        bool in_transaction = false;
        while (std::getline(in, line)) {
            std::istringstream row(line);
            std::string tag;
            row >> tag;
            if (tag == "BEGIN") {
                plan = {};
                if (!(row >> plan.monitor >> plan.from_workspace >>
                      plan.to_workspace)) {
                    if (error) *error = "invalid BEGIN record";
                    return std::nullopt;
                }
                in_transaction = true;
                continue;
            }
            if (!in_transaction) continue;
            if (tag == "MOVE") {
                SwitchOperation operation;
                std::string from;
                std::string to;
                if (!ParseIdentity(row, operation.identity) ||
                    !(row >> from >> to)) {
                    if (error) *error = "invalid MOVE record";
                    return std::nullopt;
                }
                operation.from = ParseRole(from);
                operation.to = ParseRole(to);
                if (operation.from == NativeDesktopRole::Unknown ||
                    operation.to == NativeDesktopRole::Unknown) {
                    if (error) *error = "invalid MOVE role";
                    return std::nullopt;
                }
                plan.operations.push_back(operation);
                continue;
            }
            if (tag == "COMMIT" || tag == "ABORT" || tag == "RECOVERED") {
                in_transaction = false;
                plan = {};
            }
        }
        if (in_transaction) return plan;
        return std::nullopt;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return std::nullopt;
    }
}

WorkspaceEngine::WorkspaceEngine(GUID carrier, GUID parking)
    : carrier_(carrier), parking_(parking) {}

bool WorkspaceEngine::HasWorkspace(MonitorId monitor,
                                   WorkspaceId workspace) const {
    return std::any_of(workspaces_.begin(), workspaces_.end(),
                       [&](const WorkspaceDefinition& definition) {
                           return definition.id == workspace &&
                                  definition.monitor == monitor;
                       });
}

WorkspaceDefinition* WorkspaceEngine::MutableWorkspace(WorkspaceId workspace) {
    auto it = std::find_if(
        workspaces_.begin(), workspaces_.end(),
        [&](const WorkspaceDefinition& definition) {
            return definition.id == workspace;
        });
    return it == workspaces_.end() ? nullptr : &*it;
}

MonitorWorkspaceState* WorkspaceEngine::MutableMonitor(MonitorId monitor) {
    auto it = std::find_if(
        monitors_.begin(), monitors_.end(),
        [&](const MonitorWorkspaceState& state) { return state.monitor == monitor; });
    return it == monitors_.end() ? nullptr : &*it;
}

bool WorkspaceEngine::AddMonitor(MonitorId monitor, WorkspaceId active,
                                 std::vector<WorkspaceId> workspaces,
                                 std::string* error) {
    if (monitor == 0 || workspaces.empty() ||
        std::find(workspaces.begin(), workspaces.end(), active) ==
            workspaces.end()) {
        if (error) *error = "monitor requires a non-empty workspace set";
        return false;
    }
    if (MutableMonitor(monitor) != nullptr) {
        if (error) *error = "monitor already exists";
        return false;
    }
    for (WorkspaceId workspace : workspaces) {
        if (workspace == 0 || MutableWorkspace(workspace) != nullptr) {
            if (error) *error = "workspace id is duplicated or invalid";
            return false;
        }
    }
    monitors_.push_back({monitor, active, std::move(workspaces)});
    const auto& state = monitors_.back();
    for (WorkspaceId workspace : state.workspaces) {
        workspaces_.push_back({workspace, monitor, {}, std::nullopt, {}});
    }
    return true;
}

bool WorkspaceEngine::SetLastForeground(MonitorId monitor,
                                         WorkspaceId workspace,
                                         const WindowIdentity& identity,
                                         std::string* error) {
    const MonitorWorkspaceState* state = Monitor(monitor);
    if (state == nullptr ||
        std::find(state->workspaces.begin(), state->workspaces.end(),
                  workspace) == state->workspaces.end()) {
        if (error) *error = "workspace does not belong to monitor";
        return false;
    }
    const WindowRecord* window = FindWindow(identity);
    if (window == nullptr || window->monitor != monitor ||
        window->workspace != workspace || !window->present ||
        window->disposition != WindowDisposition::Managed ||
        !window->capabilities.Manageable()) {
        if (error) *error = "foreground window is not assigned to workspace";
        return false;
    }
    WorkspaceDefinition* definition = MutableWorkspace(workspace);
    if (definition->last_foreground &&
        *definition->last_foreground != identity) {
        auto previous = windows_.find(*definition->last_foreground);
        if (previous != windows_.end()) {
            previous->second.presentation.foreground = false;
        }
    }
    definition->last_foreground = identity;
    for (const WindowIdentity& member : definition->windows) {
        auto it = windows_.find(member);
        if (it != windows_.end()) {
            it->second.presentation.foreground = (member == identity);
        }
    }
    return true;
}

bool WorkspaceEngine::SetZOrder(MonitorId monitor, WorkspaceId workspace,
                                std::vector<WindowIdentity> top_to_bottom,
                                std::string* error) {
    const MonitorWorkspaceState* state = Monitor(monitor);
    WorkspaceDefinition* definition = MutableWorkspace(workspace);
    if (state == nullptr || definition == nullptr ||
        definition->monitor != monitor) {
        if (error) *error = "workspace does not belong to monitor";
        return false;
    }
    if (top_to_bottom.size() != definition->windows.size()) {
        if (error) *error = "Z-order snapshot must contain every workspace window";
        return false;
    }
    std::unordered_set<WindowIdentity, WindowIdentityHash> seen;
    for (const WindowIdentity& identity : top_to_bottom) {
        const WindowRecord* window = FindWindow(identity);
        if (window == nullptr || window->monitor != monitor ||
            window->workspace != workspace || !window->present ||
            window->disposition != WindowDisposition::Managed ||
            !window->capabilities.Manageable() ||
            !window->capabilities.owner_state_observable ||
            !seen.insert(identity).second) {
            if (error) *error = "Z-order snapshot contains an invalid window";
            return false;
        }
    }
    definition->z_order = std::move(top_to_bottom);
    for (std::size_t i = 0; i < definition->z_order.size(); ++i) {
        auto it = windows_.find(definition->z_order[i]);
        if (it != windows_.end()) {
            it->second.presentation.z_order = static_cast<std::int64_t>(i);
        }
    }
    return true;
}

bool WorkspaceEngine::ValidateRecord(const WindowRecord& record,
                                     std::string* error) const {
    if (!record.identity.IsValid()) {
        if (error) *error = "invalid window identity";
        return false;
    }
    if (!HasWorkspace(record.monitor, record.workspace)) {
        if (error) *error = "window workspace does not belong to monitor";
        return false;
    }
    return true;
}

void WorkspaceEngine::RemoveIdentityFromWorkspace(
    const WindowIdentity& identity, WorkspaceId workspace) {
    WorkspaceDefinition* definition = MutableWorkspace(workspace);
    if (definition == nullptr) return;
    definition->windows.erase(
        std::remove(definition->windows.begin(), definition->windows.end(),
                    identity),
        definition->windows.end());
    if (definition->last_foreground &&
        *definition->last_foreground == identity) {
        definition->last_foreground.reset();
    }
    definition->z_order.erase(
        std::remove(definition->z_order.begin(), definition->z_order.end(),
                    identity),
        definition->z_order.end());
}

void WorkspaceEngine::AddIdentityToWorkspace(const WindowIdentity& identity,
                                             WorkspaceId workspace) {
    WorkspaceDefinition* definition = MutableWorkspace(workspace);
    if (definition == nullptr) return;
    if (std::find(definition->windows.begin(), definition->windows.end(),
                  identity) == definition->windows.end()) {
        definition->windows.push_back(identity);
    }
}

UpsertResult WorkspaceEngine::UpsertWindow(WindowRecord record,
                                           std::string* error) {
    if (!ValidateRecord(record, error)) return UpsertResult::Rejected;
    record.present = true;
    if (record.disposition == WindowDisposition::Managed &&
        (!record.capabilities.Manageable() ||
         record.native_role == NativeDesktopRole::Unknown)) {
        record.disposition = WindowDisposition::Unsupported;
    }

    const auto hwnd_it = hwnd_index_.find(
        reinterpret_cast<std::uintptr_t>(record.identity.hwnd));
    if (hwnd_it != hwnd_index_.end() && hwnd_it->second != record.identity) {
        const auto old_it = windows_.find(hwnd_it->second);
        if (old_it != windows_.end()) {
            RemoveIdentityFromWorkspace(old_it->second.identity,
                                        old_it->second.workspace);
            windows_.erase(old_it);
        }
        hwnd_it->second = record.identity;
        AddIdentityToWorkspace(record.identity, record.workspace);
        windows_.emplace(record.identity, std::move(record));
        return UpsertResult::Recreated;
    }

    const auto existing = windows_.find(record.identity);
    if (existing == windows_.end()) {
        hwnd_index_[reinterpret_cast<std::uintptr_t>(record.identity.hwnd)] =
            record.identity;
        AddIdentityToWorkspace(record.identity, record.workspace);
        windows_.emplace(record.identity, std::move(record));
        return UpsertResult::Added;
    }

    if (existing->second.monitor != record.monitor ||
        existing->second.workspace != record.workspace) {
        RemoveIdentityFromWorkspace(existing->second.identity,
                                    existing->second.workspace);
        AddIdentityToWorkspace(record.identity, record.workspace);
    }
    existing->second = std::move(record);
    return UpsertResult::Updated;
}

bool WorkspaceEngine::CloseWindow(const WindowIdentity& identity,
                                  std::string* error) {
    auto it = windows_.find(identity);
    if (it == windows_.end()) {
        if (error) *error = "window not tracked";
        return false;
    }
    WindowRecord closed = it->second;
    closed.present = false;
    closed.disposition = WindowDisposition::Closed;
    closed_windows_.push_back(closed);
    RemoveIdentityFromWorkspace(it->second.identity, it->second.workspace);
    hwnd_index_.erase(reinterpret_cast<std::uintptr_t>(identity.hwnd));
    windows_.erase(it);
    return true;
}

bool WorkspaceEngine::ReconcileDiscoverySnapshot(
    std::vector<WindowRecord> observed, DiscoveryReconcileResult* result,
    std::string* error) {
    if (result) *result = {};
    DiscoveryReconcileResult next_result;
    std::unordered_set<WindowIdentity, WindowIdentityHash> identities;
    std::unordered_set<std::uintptr_t> hwnds;
    for (const WindowRecord& record : observed) {
        const std::uintptr_t hwnd =
            reinterpret_cast<std::uintptr_t>(record.identity.hwnd);
        if (!ValidateRecord(record, error) ||
            record.disposition == WindowDisposition::Closed ||
            !identities.insert(record.identity).second ||
            !hwnds.insert(hwnd).second) {
            if (error && error->empty()) {
                *error = "discovery snapshot contains an invalid or duplicate window";
            }
            return false;
        }
    }

    // Prevalidation above makes all following model mutations deterministic
    // and non-failing under the engine's current record rules. Sorting also
    // makes lifecycle results independent of enumeration order.
    std::sort(observed.begin(), observed.end(),
              [](const WindowRecord& a, const WindowRecord& b) {
                  return reinterpret_cast<std::uintptr_t>(a.identity.hwnd) <
                         reinterpret_cast<std::uintptr_t>(b.identity.hwnd);
              });
    for (WindowRecord& record : observed) {
        const UpsertResult upsert = UpsertWindow(std::move(record), error);
        switch (upsert) {
            case UpsertResult::Added:
                ++next_result.added;
                break;
            case UpsertResult::Updated:
                ++next_result.updated;
                break;
            case UpsertResult::Recreated:
                ++next_result.recreated;
                break;
            case UpsertResult::Rejected:
                if (error && error->empty()) {
                    *error = "validated discovery window was rejected";
                }
                return false;
        }
    }

    const std::vector<const WindowRecord*> current = Windows();
    for (const WindowRecord* window : current) {
        if (!identities.contains(window->identity) &&
            !hwnds.contains(reinterpret_cast<std::uintptr_t>(
                window->identity.hwnd))) {
            const WindowIdentity identity = window->identity;
            if (!CloseWindow(identity, error)) return false;
            ++next_result.closed;
        }
    }
    if (result) *result = next_result;
    return true;
}

const WindowRecord* WorkspaceEngine::FindWindow(
    const WindowIdentity& identity) const {
    const auto it = windows_.find(identity);
    return it == windows_.end() ? nullptr : &it->second;
}

const WindowRecord* WorkspaceEngine::FindWindowByHwnd(HWND hwnd) const {
    const auto it = hwnd_index_.find(reinterpret_cast<std::uintptr_t>(hwnd));
    return it == hwnd_index_.end() ? nullptr : FindWindow(it->second);
}

std::vector<const WindowRecord*> WorkspaceEngine::Windows() const {
    std::vector<const WindowRecord*> result;
    result.reserve(windows_.size());
    for (const auto& [identity, record] : windows_) result.push_back(&record);
    std::sort(result.begin(), result.end(), [](const WindowRecord* a,
                                               const WindowRecord* b) {
        return reinterpret_cast<std::uintptr_t>(a->identity.hwnd) <
               reinterpret_cast<std::uintptr_t>(b->identity.hwnd);
    });
    return result;
}

std::vector<const WindowRecord*> WorkspaceEngine::WindowsForMonitor(
    MonitorId monitor) const {
    std::vector<const WindowRecord*> result;
    for (const auto& [identity, record] : windows_) {
        if (record.monitor == monitor) result.push_back(&record);
    }
    std::sort(result.begin(), result.end(), [](const WindowRecord* a,
                                               const WindowRecord* b) {
        return reinterpret_cast<std::uintptr_t>(a->identity.hwnd) <
               reinterpret_cast<std::uintptr_t>(b->identity.hwnd);
    });
    return result;
}

const MonitorWorkspaceState* WorkspaceEngine::Monitor(MonitorId monitor) const {
    const auto it = std::find_if(
        monitors_.begin(), monitors_.end(),
        [&](const MonitorWorkspaceState& state) { return state.monitor == monitor; });
    return it == monitors_.end() ? nullptr : &*it;
}

const WorkspaceDefinition* WorkspaceEngine::Workspace(
    WorkspaceId workspace) const {
    const auto it = std::find_if(
        workspaces_.begin(), workspaces_.end(),
        [&](const WorkspaceDefinition& definition) {
            return definition.id == workspace;
        });
    return it == workspaces_.end() ? nullptr : &*it;
}

bool WorkspaceEngine::CheckInvariant(std::string* error) const {
    std::unordered_set<WorkspaceId> seen_workspaces;
    for (const MonitorWorkspaceState& monitor : monitors_) {
        if (monitor.monitor == 0 || monitor.workspaces.empty() ||
            std::find(monitor.workspaces.begin(), monitor.workspaces.end(),
                      monitor.active) == monitor.workspaces.end()) {
            if (error) *error = "invalid monitor workspace state";
            return false;
        }
        for (WorkspaceId workspace : monitor.workspaces) {
            if (!seen_workspaces.insert(workspace).second ||
                !HasWorkspace(monitor.monitor, workspace)) {
                if (error) *error = "workspace ownership is inconsistent";
                return false;
            }
        }
    }
    for (const auto& [identity, record] : windows_) {
        if (!(identity == record.identity) || !record.present ||
            !ValidateRecord(record, error)) {
            return false;
        }
        if (record.disposition == WindowDisposition::Managed &&
            (!record.capabilities.Manageable() ||
             record.native_role == NativeDesktopRole::Unknown)) {
            if (error) *error =
                "managed window lacks required capabilities or native role";
            return false;
        }
        const WorkspaceDefinition* workspace = Workspace(record.workspace);
        if (workspace == nullptr ||
            std::find(workspace->windows.begin(), workspace->windows.end(),
                      identity) == workspace->windows.end()) {
            if (error) *error = "window missing from workspace index";
            return false;
        }
        if (record.disposition == WindowDisposition::Managed) {
            const MonitorWorkspaceState* monitor = Monitor(record.monitor);
            const NativeDesktopRole expected =
                monitor->active == record.workspace
                    ? NativeDesktopRole::Carrier
                    : NativeDesktopRole::Parking;
            if (record.native_role != expected) {
                if (error) *error = "managed window violates Carrier/Parking invariant";
                return false;
            }
        }
    }
    return true;
}

std::optional<SwitchPlan> WorkspaceEngine::PrepareSwitch(
    MonitorId monitor, WorkspaceId target_workspace, std::string* error) const {
    const MonitorWorkspaceState* state = Monitor(monitor);
    if (state == nullptr ||
        !HasWorkspace(monitor, target_workspace)) {
        if (error) *error = "target workspace does not belong to monitor";
        return std::nullopt;
    }
    if (state->active == target_workspace) {
        if (error) *error = "target workspace is already active";
        return std::nullopt;
    }
    std::string invariant_error;
    if (!CheckInvariant(&invariant_error)) {
        if (error) *error = invariant_error;
        return std::nullopt;
    }

    SwitchPlan plan{monitor, state->active, target_workspace, {}};
    for (const WindowRecord* window : WindowsForMonitor(monitor)) {
        const bool affected = window->workspace == state->active ||
                              window->workspace == target_workspace;
        if (affected && window->disposition != WindowDisposition::Managed) {
            if (error) *error = "affected workspace contains unsupported/ambiguous window";
            return std::nullopt;
        }
        const NativeDesktopRole target =
            window->workspace == state->active
                ? NativeDesktopRole::Parking
                : window->workspace == target_workspace
                    ? NativeDesktopRole::Carrier
                    : window->native_role;
        if (affected) {
            plan.operations.push_back(
                {window->identity, window->native_role, target});
        }
    }
    std::stable_sort(
        plan.operations.begin(), plan.operations.end(),
        [](const SwitchOperation& a, const SwitchOperation& b) {
            if (a.from != b.from) {
                return a.from == NativeDesktopRole::Carrier;
            }
            return reinterpret_cast<std::uintptr_t>(a.identity.hwnd) <
                   reinterpret_cast<std::uintptr_t>(b.identity.hwnd);
        });
    return plan;
}

std::optional<PresentationPlan> WorkspaceEngine::PreparePresentationRestore(
    MonitorId monitor, WorkspaceId workspace, std::string* error) const {
    const MonitorWorkspaceState* state = Monitor(monitor);
    const WorkspaceDefinition* definition = Workspace(workspace);
    if (state == nullptr || definition == nullptr ||
        definition->monitor != monitor || state->active != workspace) {
        if (error) *error = "presentation restore requires the active workspace";
        return std::nullopt;
    }
    if (definition->z_order.size() != definition->windows.size()) {
        if (error) *error = "workspace has no complete Z-order snapshot";
        return std::nullopt;
    }

    std::unordered_set<WindowIdentity, WindowIdentityHash> seen;
    for (const WindowIdentity& identity : definition->z_order) {
        const WindowRecord* window = FindWindow(identity);
        if (window == nullptr || window->monitor != monitor ||
            window->workspace != workspace || !window->present ||
            window->disposition != WindowDisposition::Managed ||
            !window->capabilities.Manageable() ||
            !window->capabilities.owner_state_observable ||
            !seen.insert(identity).second) {
            if (error) *error = "presentation snapshot is stale or unsafe";
            return std::nullopt;
        }
        if (!window->presentation.placement_valid) {
            if (error) *error = "presentation snapshot lacks placement data";
            return std::nullopt;
        }
    }
    if (definition->last_foreground &&
        !seen.contains(*definition->last_foreground)) {
        if (error) *error = "foreground snapshot is stale or unsafe";
        return std::nullopt;
    }

    PresentationPlan plan{monitor, workspace, {}};
    for (const WindowIdentity& identity : definition->z_order) {
        const WindowRecord* window = FindWindow(identity);
        if (window->presentation.placement_valid) {
            plan.operations.push_back({
                PresentationOperationKind::RestorePlacement, identity,
                window->presentation});
        }
    }
    for (auto it = definition->z_order.rbegin();
         it != definition->z_order.rend(); ++it) {
        const WindowRecord* window = FindWindow(*it);
        plan.operations.push_back({PresentationOperationKind::RestoreZOrder,
                                   *it, window->presentation});
    }
    if (definition->last_foreground) {
        const WindowRecord* foreground =
            FindWindow(*definition->last_foreground);
        plan.operations.push_back({
            PresentationOperationKind::RestoreForeground,
            *definition->last_foreground, foreground->presentation});
    }
    return plan;
}

bool WorkspaceEngine::RolesMatch(const SwitchOperation& operation,
                                 const ObserveCallback& observe) const {
    const WindowRecord* window = FindWindow(operation.identity);
    return window != nullptr &&
           (!observe || observe(*window) == operation.to);
}

bool WorkspaceEngine::ApplyOperations(
    const std::vector<SwitchOperation>& operations, const MoveCallback& move,
    const ObserveCallback& observe, std::vector<SwitchOperation>& applied,
    std::string* error) {
    if (!move || !observe) {
        if (error) *error = "move and observation callbacks are required";
        return false;
    }
    for (const SwitchOperation& operation : operations) {
        const WindowRecord* window = FindWindow(operation.identity);
        if (window == nullptr || window->disposition != WindowDisposition::Managed) {
            if (error) *error = "operation references an unmanaged window";
            return false;
        }
        if (observe(*window) != operation.from) {
            if (error) *error = "native state changed before operation";
            return false;
        }
        // Record the attempted operation before invoking the native callback.
        // A false HRESULT/boolean does not prove that the shell left the view
        // untouched; rollback therefore always gets a chance to observe and
        // restore this operation.
        applied.push_back(operation);
        const bool move_ok = move(*window, operation.to);
        if (!move_ok || !RolesMatch(operation, observe)) {
            if (error) {
                *error = move_ok ? "native move verification failed"
                                 : "native move reported failure";
            }
            return false;
        }
    }
    return true;
}

bool WorkspaceEngine::RestoreOperations(
    const std::vector<SwitchOperation>& applied, const MoveCallback& move,
    const ObserveCallback& observe, std::string* error) {
    if (!move || !observe) {
        if (error) *error = "move and observation callbacks are required";
        return false;
    }
    for (auto it = applied.rbegin(); it != applied.rend(); ++it) {
        const SwitchOperation restore{it->identity, it->to, it->from};
        const WindowRecord* window = FindWindow(restore.identity);
        if (window == nullptr) {
            if (error) *error = "rollback failed";
            return false;
        }
        const NativeDesktopRole current = observe(*window);
        if (current == restore.to) continue;
        if (current != restore.from || !move(*window, restore.to) ||
            observe(*window) != restore.to) {
            if (error) *error = "rollback failed";
            return false;
        }
    }
    return true;
}

void WorkspaceEngine::CommitPlan(const SwitchPlan& plan) {
    MonitorWorkspaceState* monitor = MutableMonitor(plan.monitor);
    if (monitor != nullptr) monitor->active = plan.to_workspace;
    for (const SwitchOperation& operation : plan.operations) {
        auto it = windows_.find(operation.identity);
        if (it != windows_.end()) it->second.native_role = operation.to;
    }
}

TransactionResult WorkspaceEngine::ExecuteSwitch(
    const SwitchPlan& plan, const MoveCallback& move,
    const ObserveCallback& observe, const WorkspaceJournal* journal) {
    TransactionResult result;
    std::string expected_error;
    const std::optional<SwitchPlan> expected =
        PrepareSwitch(plan.monitor, plan.to_workspace, &expected_error);
    if (!expected || !PlansMatch(*expected, plan)) {
        result.error = "stale switch plan";
        return result;
    }

    std::string journal_error;
    if (journal && !journal->Begin(plan, &journal_error)) {
        result.error = "journal begin failed: " + journal_error;
        return result;
    }
    std::vector<SwitchOperation> applied;
    std::string error;
    if (!ApplyOperations(plan.operations, move, observe, applied, &error)) {
        result.rollback_attempted = !applied.empty();
        // Verify the entire recorded baseline before declaring the transaction
        // aborted. Native side effects are not necessarily limited to the
        // operation whose callback was invoked.
        result.rollback_succeeded =
            RestoreOperations(plan.operations, move, observe, &error);
        if (result.rollback_succeeded && journal) {
            std::string abort_error;
            if (!journal->Abort(&abort_error)) {
                result.recovery_required = true;
                error += "; journal abort failed: " + abort_error;
            }
        }
        result.recovery_required =
            result.recovery_required || !result.rollback_succeeded;
        result.error = error;
        return result;
    }

    // A move callback may pump lifecycle work, and a later move can disturb a
    // window that was already verified. Revalidate both the complete modeled
    // membership and every native post-state before making the transaction
    // durable or updating the active workspace.
    const std::optional<SwitchPlan> current =
        PrepareSwitch(plan.monitor, plan.to_workspace, &expected_error);
    bool post_state_matches = current && PlansMatch(*current, plan);
    if (post_state_matches) {
        for (const SwitchOperation& operation : plan.operations) {
            const WindowRecord* window = FindWindow(operation.identity);
            if (window == nullptr || observe(*window) != operation.to) {
                post_state_matches = false;
                break;
            }
        }
    }
    if (!post_state_matches) {
        result.rollback_attempted = !applied.empty();
        error = "switch state changed during execution";
        result.rollback_succeeded =
            RestoreOperations(plan.operations, move, observe, &error);
        if (result.rollback_succeeded && journal) {
            std::string abort_error;
            if (!journal->Abort(&abort_error)) {
                result.recovery_required = true;
                error += "; journal abort failed: " + abort_error;
            }
        }
        result.recovery_required =
            result.recovery_required || !result.rollback_succeeded;
        result.error = error;
        return result;
    }

    if (journal && !journal->Commit(&journal_error)) {
        result.rollback_attempted = true;
        result.rollback_succeeded =
            RestoreOperations(plan.operations, move, observe, &error);
        if (result.rollback_succeeded) {
            std::string abort_error;
            if (!journal->Abort(&abort_error)) {
                result.recovery_required = true;
                error += "; journal abort failed: " + abort_error;
            }
        }
        result.recovery_required =
            result.recovery_required || !result.rollback_succeeded;
        result.error = "journal commit failed: " + journal_error;
        if (!error.empty()) result.error += "; " + error;
        return result;
    }

    CommitPlan(plan);
    result.committed = true;
    return result;
}

RecoveryResult WorkspaceEngine::RecoverPending(
    const SwitchPlan& plan, const MoveCallback& move,
    const ObserveCallback& observe, const WorkspaceJournal* journal) {
    RecoveryResult result;
    if (!move || !observe) {
        result.recovery_required = true;
        result.error = "move and observation callbacks are required";
        return result;
    }
    if (journal) {
        std::string journal_error;
        const std::optional<SwitchPlan> recorded =
            journal->ReadPending(&journal_error);
        if (!journal_error.empty()) {
            result.recovery_required = true;
            result.error = "journal recovery read failed: " + journal_error;
            return result;
        }
        if (!recorded || !PlansMatch(*recorded, plan)) {
            result.recovery_required = true;
            result.error = "recovery plan does not match pending journal";
            return result;
        }
    }
    if (plan.monitor == 0) {
        if (plan.from_workspace != 0 || plan.to_workspace != 0) {
            result.recovery_required = true;
            result.error = "invalid reconcile recovery plan";
            return result;
        }
    } else {
        const MonitorWorkspaceState* monitor = Monitor(plan.monitor);
        if (monitor == nullptr || plan.from_workspace == plan.to_workspace ||
            !HasWorkspace(plan.monitor, plan.from_workspace) ||
            !HasWorkspace(plan.monitor, plan.to_workspace) ||
            monitor->active != plan.from_workspace) {
            result.recovery_required = true;
            result.error = "invalid or stale switch recovery plan";
            return result;
        }
        std::string expected_error;
        const std::optional<SwitchPlan> expected =
            PrepareSwitch(plan.monitor, plan.to_workspace, &expected_error);
        if (!expected || !PlansMatch(*expected, plan)) {
            result.recovery_required = true;
            result.error = "recovery plan does not match current workspace state";
            return result;
        }
    }
    std::unordered_set<WindowIdentity, WindowIdentityHash> identities;
    for (const SwitchOperation& operation : plan.operations) {
        const WindowRecord* window = FindWindow(operation.identity);
        if (window == nullptr ||
            window->disposition != WindowDisposition::Managed ||
            !window->capabilities.Manageable() ||
            operation.from == NativeDesktopRole::Unknown ||
            operation.to == NativeDesktopRole::Unknown ||
            operation.from == operation.to ||
            !identities.insert(operation.identity).second ||
            (plan.monitor != 0 && window->monitor != plan.monitor)) {
            result.recovery_required = true;
            result.error = "invalid or stale recovery operation";
            return result;
        }
        if (plan.monitor == 0) {
            const MonitorWorkspaceState* monitor = Monitor(window->monitor);
            const NativeDesktopRole desired =
                monitor != nullptr && monitor->active == window->workspace
                    ? NativeDesktopRole::Carrier
                    : NativeDesktopRole::Parking;
            if (monitor == nullptr || operation.to != desired) {
                result.recovery_required = true;
                result.error = "reconcile recovery operation is stale";
                return result;
            }
        }
    }
    std::vector<SwitchOperation> pending = plan.operations;
    std::string error;
    if (!RestoreOperations(pending, move, observe, &error)) {
        result.recovery_required = true;
        result.error = error;
        return result;
    }
    if (plan.monitor != 0) {
        MonitorWorkspaceState* monitor = MutableMonitor(plan.monitor);
        if (monitor != nullptr) monitor->active = plan.from_workspace;
    }
    for (const SwitchOperation& operation : plan.operations) {
        auto it = windows_.find(operation.identity);
        if (it != windows_.end()) it->second.native_role = operation.from;
    }
    if (journal && !journal->Recovered(&error)) {
        result.recovery_required = true;
        result.error = "journal recovery marker failed: " + error;
        return result;
    }
    result.recovered = true;
    return result;
}

bool WorkspaceEngine::Reconcile(const MoveCallback& move,
                                const ObserveCallback& observe,
                                const WorkspaceJournal* journal,
                                std::string* error) {
    std::vector<SwitchOperation> operations;
    for (const WindowRecord* window : Windows()) {
        if (window->disposition != WindowDisposition::Managed) continue;
        const MonitorWorkspaceState* monitor = Monitor(window->monitor);
        if (monitor == nullptr) continue;
        const NativeDesktopRole desired =
            monitor->active == window->workspace
                ? NativeDesktopRole::Carrier
                : NativeDesktopRole::Parking;
        NativeDesktopRole current = window->native_role;
        if (observe) current = observe(*window);
        if (current == NativeDesktopRole::Unknown) {
            if (error) *error = "native role is unobservable";
            return false;
        }
        if (current != desired) {
            operations.push_back({window->identity, current, desired});
        }
    }
    if (operations.empty()) return true;

    SwitchPlan plan{};
    plan.monitor = 0;
    plan.operations = operations;
    std::string journal_error;
    if (journal && !journal->Begin(plan, &journal_error)) {
        if (error) *error = "journal reconcile begin failed: " + journal_error;
        return false;
    }

    std::vector<SwitchOperation> applied;
    if (!ApplyOperations(operations, move, observe, applied, error)) {
        std::string rollback_error;
        const bool rolled_back =
            RestoreOperations(applied, move, observe, &rollback_error);
        if (!rolled_back && error) {
            *error += "; " + rollback_error + "; recovery required";
        }
        if (rolled_back && journal) {
            std::string abort_error;
            if (!journal->Abort(&abort_error) && error) {
                *error += "; journal abort failed: " + abort_error +
                          "; recovery required";
            }
        }
        return false;
    }
    if (journal && !journal->Commit(&journal_error)) {
        std::string rollback_error;
        const bool rolled_back =
            RestoreOperations(applied, move, observe, &rollback_error);
        if (!rolled_back && error) {
            *error = "journal reconcile commit failed: " + journal_error +
                     "; " + rollback_error;
        } else if (error) {
            *error = "journal reconcile commit failed: " + journal_error;
        }
        if (rolled_back) {
            std::string abort_error;
            if (!journal->Abort(&abort_error) && error) {
                *error += "; journal abort failed: " + abort_error +
                          "; recovery required";
            }
        }
        return false;
    }
    for (const SwitchOperation& operation : operations) {
        auto it = windows_.find(operation.identity);
        if (it != windows_.end()) it->second.native_role = operation.to;
    }
    return true;
}

const char* NativeDesktopRoleText(NativeDesktopRole role) noexcept {
    switch (role) {
        case NativeDesktopRole::Carrier:
            return "Carrier";
        case NativeDesktopRole::Parking:
            return "Parking";
        default:
            return "Unknown";
    }
}

const char* WindowDispositionText(WindowDisposition disposition) noexcept {
    switch (disposition) {
        case WindowDisposition::Managed:
            return "managed";
        case WindowDisposition::Unsupported:
            return "unsupported";
        case WindowDisposition::Ambiguous:
            return "ambiguous";
        case WindowDisposition::Closed:
            return "closed";
        default:
            return "unknown";
    }
}

const char* UpsertResultText(UpsertResult result) noexcept {
    switch (result) {
        case UpsertResult::Added:
            return "added";
        case UpsertResult::Updated:
            return "updated";
        case UpsertResult::Recreated:
            return "recreated";
        case UpsertResult::Rejected:
            return "rejected";
        default:
            return "unknown";
    }
}

int CmdWorkspaceEngineTest() {
    Heading("workspace-engine-test");
    Field("scope", "deterministic capability-driven state/transaction test");
    Field("native desktop mutation", "none");
    Field("application whitelist", "none");

    GUID carrier{0x11111111, 0x2222, 0x3333,
                 {0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}};
    GUID parking{0xaaaaaaaa, 0xbbbb, 0xcccc,
                 {0xdd, 0xee, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}};
    WorkspaceEngine engine(carrier, parking);
    std::string error;
    bool ok = engine.AddMonitor(1, 1, {1, 2}, &error) &&
              engine.AddMonitor(2, 3, {3, 4}, &error);
    Field("two-monitor model", ok ? "PASS" : "FAIL");

    auto identity = [](std::uintptr_t hwnd, DWORD pid,
                       DWORD high) -> WindowIdentity {
        WindowIdentity result;
        result.hwnd = reinterpret_cast<HWND>(hwnd);
        result.pid = pid;
        result.process_creation_time = {1, high};
        result.process_creation_time_ok = true;
        return result;
    };
    const WindowIdentity a1_id = identity(0x1001, 101, 1);
    const WindowIdentity a2_id = identity(0x1002, 101, 1);
    const WindowIdentity b1_id = identity(0x2001, 202, 2);
    const WindowCapabilities manageable{true, true, true, true, true};
    ok = ok &&
         engine.UpsertWindow(
             {a1_id, 1, 1, NativeDesktopRole::Carrier, manageable, {}, {}, true},
             &error) == UpsertResult::Added &&
         engine.UpsertWindow(
             {a2_id, 1, 2, NativeDesktopRole::Parking, manageable, {}, {}, true},
             &error) == UpsertResult::Added &&
         engine.UpsertWindow(
             {b1_id, 2, 3, NativeDesktopRole::Carrier, manageable, {}, {}, true},
             &error) == UpsertResult::Added &&
         engine.CheckInvariant(&error);
    Field("initial Carrier/Parking invariant", ok ? "PASS" : "FAIL");

    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        fake_roles{{a1_id, NativeDesktopRole::Carrier},
                   {a2_id, NativeDesktopRole::Parking},
                   {b1_id, NativeDesktopRole::Carrier}};
    auto move = [&](const WindowRecord& window,
                    NativeDesktopRole target) -> bool {
        fake_roles[window.identity] = target;
        return true;
    };
    auto observe = [&](const WindowRecord& window) {
        return fake_roles[window.identity];
    };

    auto plan = engine.PrepareSwitch(1, 2, &error);
    TransactionResult transaction =
        plan ? engine.ExecuteSwitch(*plan, move, observe) : TransactionResult{};
    ok = ok && plan.has_value() && transaction.committed &&
         engine.Monitor(1)->active == 2 &&
         fake_roles[a1_id] == NativeDesktopRole::Parking &&
         fake_roles[a2_id] == NativeDesktopRole::Carrier &&
         fake_roles[b1_id] == NativeDesktopRole::Carrier &&
         engine.CheckInvariant(&error);
    Field("monitor A switch leaves monitor B unchanged", ok ? "PASS" : "FAIL");

    auto back_plan = engine.PrepareSwitch(1, 1, &error);
    TransactionResult back =
        back_plan ? engine.ExecuteSwitch(*back_plan, move, observe)
                  : TransactionResult{};
    ok = ok && back.committed && engine.Monitor(1)->active == 1 &&
         engine.CheckInvariant(&error);
    Field("round-trip restore", ok ? "PASS" : "FAIL");

    auto failure_plan = engine.PrepareSwitch(1, 2, &error);
    auto fail_after_side_effect = [&](const WindowRecord& window,
                                      NativeDesktopRole target) -> bool {
        fake_roles[window.identity] = target;
        return !(window.identity == a2_id &&
                 target == NativeDesktopRole::Carrier);
    };
    const TransactionResult failed =
        failure_plan
            ? engine.ExecuteSwitch(*failure_plan, fail_after_side_effect, observe)
            : TransactionResult{};
    ok = ok && failure_plan.has_value() && !failed.committed &&
         failed.rollback_attempted && failed.rollback_succeeded &&
         !failed.recovery_required && engine.Monitor(1)->active == 1 &&
         fake_roles[a1_id] == NativeDesktopRole::Carrier &&
         fake_roles[a2_id] == NativeDesktopRole::Parking &&
         engine.CheckInvariant(&error);
    Field("failed move rolls back observed side effects",
          ok ? "PASS" : "FAIL");

    WorkspaceEngine stale_plan_engine(carrier, parking);
    bool stale_plan_ok =
        stale_plan_engine.AddMonitor(5, 51, {51, 52}, &error);
    const WindowIdentity stale_a_id = identity(0x1101, 111, 1);
    const WindowIdentity stale_b_id = identity(0x1102, 112, 1);
    const WindowIdentity stale_added_id = identity(0x1103, 113, 1);
    if (stale_plan_ok) {
        stale_plan_ok =
            stale_plan_engine.UpsertWindow(
                {stale_a_id, 5, 51, NativeDesktopRole::Carrier, manageable,
                 {}, {}, true},
                &error) == UpsertResult::Added &&
            stale_plan_engine.UpsertWindow(
                {stale_b_id, 5, 52, NativeDesktopRole::Parking, manageable,
                 {}, {}, true},
                &error) == UpsertResult::Added;
    }
    const std::optional<SwitchPlan> prepared_stale_plan =
        stale_plan_ok
            ? stale_plan_engine.PrepareSwitch(5, 52, &error)
            : std::nullopt;
    if (stale_plan_ok) {
        stale_plan_ok = prepared_stale_plan.has_value() &&
            stale_plan_engine.UpsertWindow(
                {stale_added_id, 5, 52, NativeDesktopRole::Parking,
                 manageable, {}, {}, true},
                &error) == UpsertResult::Added;
    }
    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        stale_roles{{stale_a_id, NativeDesktopRole::Carrier},
                    {stale_b_id, NativeDesktopRole::Parking},
                    {stale_added_id, NativeDesktopRole::Parking}};
    int stale_move_calls = 0;
    auto stale_move = [&](const WindowRecord& window,
                          NativeDesktopRole target) {
        ++stale_move_calls;
        stale_roles[window.identity] = target;
        return true;
    };
    auto stale_observe = [&](const WindowRecord& window) {
        return stale_roles[window.identity];
    };
    std::filesystem::path stale_plan_journal_path =
        std::filesystem::temp_directory_path() /
        "vdprobe-workspace-engine-stale-plan-test.journal";
    std::error_code stale_plan_ignored;
    std::filesystem::remove(stale_plan_journal_path, stale_plan_ignored);
    WorkspaceJournal stale_plan_journal(stale_plan_journal_path);
    const TransactionResult stale_transaction =
        prepared_stale_plan
            ? stale_plan_engine.ExecuteSwitch(
                  *prepared_stale_plan, stale_move, stale_observe,
                  &stale_plan_journal)
            : TransactionResult{};
    stale_plan_ok = stale_plan_ok && !stale_transaction.committed &&
                    stale_transaction.error == "stale switch plan" &&
                    stale_move_calls == 0 &&
                    !std::filesystem::exists(stale_plan_journal_path) &&
                    stale_plan_engine.Monitor(5)->active == 51 &&
                    stale_plan_engine.CheckInvariant(&error);
    std::filesystem::remove(stale_plan_journal_path, stale_plan_ignored);
    ok = ok && stale_plan_ok;
    Field("membership change invalidates prepared plan before journal BEGIN",
          stale_plan_ok ? "PASS" : "FAIL");

    WorkspaceEngine post_state_engine(carrier, parking);
    bool post_state_ok =
        post_state_engine.AddMonitor(6, 61, {61, 62}, &error);
    const WindowIdentity post_a_id = identity(0x1201, 121, 1);
    const WindowIdentity post_b_id = identity(0x1202, 122, 1);
    if (post_state_ok) {
        post_state_ok =
            post_state_engine.UpsertWindow(
                {post_a_id, 6, 61, NativeDesktopRole::Carrier, manageable,
                 {}, {}, true},
                &error) == UpsertResult::Added &&
            post_state_engine.UpsertWindow(
                {post_b_id, 6, 62, NativeDesktopRole::Parking, manageable,
                 {}, {}, true},
                &error) == UpsertResult::Added;
    }
    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        post_roles{{post_a_id, NativeDesktopRole::Carrier},
                   {post_b_id, NativeDesktopRole::Parking}};
    auto post_observe = [&](const WindowRecord& window) {
        return post_roles[window.identity];
    };
    auto disturb_earlier_move = [&](const WindowRecord& window,
                                    NativeDesktopRole target) {
        post_roles[window.identity] = target;
        if (window.identity == post_b_id &&
            target == NativeDesktopRole::Carrier) {
            post_roles[post_a_id] = NativeDesktopRole::Carrier;
        }
        return true;
    };
    const std::optional<SwitchPlan> post_plan =
        post_state_ok
            ? post_state_engine.PrepareSwitch(6, 62, &error)
            : std::nullopt;
    const TransactionResult post_transaction =
        post_plan ? post_state_engine.ExecuteSwitch(
                        *post_plan, disturb_earlier_move, post_observe)
                  : TransactionResult{};
    post_state_ok = post_state_ok && post_plan.has_value() &&
                    !post_transaction.committed &&
                    post_transaction.rollback_attempted &&
                    post_transaction.rollback_succeeded &&
                    !post_transaction.recovery_required &&
                    post_state_engine.Monitor(6)->active == 61 &&
                    post_roles[post_a_id] == NativeDesktopRole::Carrier &&
                    post_roles[post_b_id] == NativeDesktopRole::Parking &&
                    post_state_engine.CheckInvariant(&error);
    ok = ok && post_state_ok;
    Field("full native post-state is verified before commit",
          post_state_ok ? "PASS" : "FAIL");

    const WindowIdentity reused_id = identity(0x1002, 303, 9);
    const UpsertResult recreated = engine.UpsertWindow(
        {reused_id, 1, 2, NativeDesktopRole::Parking, manageable, {}, {}, true},
        &error);
    ok = ok && recreated == UpsertResult::Recreated &&
         engine.FindWindow(a2_id) == nullptr &&
         engine.FindWindow(reused_id) != nullptr;
    Field("HWND reuse creates a new generation", ok ? "PASS" : "FAIL");

    ok = ok && engine.CloseWindow(reused_id, &error) &&
         engine.FindWindow(reused_id) == nullptr;
    const UpsertResult reopened = engine.UpsertWindow(
        {reused_id, 1, 2, NativeDesktopRole::Parking, manageable, {}, {}, true},
        &error);
    ok = ok && reopened == UpsertResult::Added;
    Field("close and recreate lifecycle", ok ? "PASS" : "FAIL");

    WorkspaceEngine lifecycle_engine(carrier, parking);
    bool lifecycle_ok =
        lifecycle_engine.AddMonitor(70, 71, {71, 72}, &error);
    const WindowIdentity l1_id = identity(0x8001, 901, 9);
    const WindowIdentity l1_reused_id = identity(0x8001, 902, 10);
    std::optional<WindowRecord> lifecycle_observation = WindowRecord{
        l1_id, 70, 71, NativeDesktopRole::Carrier, manageable, {}, {}, true};
    WindowLifecycleAdapter lifecycle_adapter(
        lifecycle_engine, [&](HWND hwnd) -> std::optional<WindowRecord> {
            if (!lifecycle_observation ||
                lifecycle_observation->identity.hwnd != hwnd) {
                return std::nullopt;
            }
            return lifecycle_observation;
        });
    if (lifecycle_ok) {
        lifecycle_ok =
            lifecycle_adapter.Apply({WindowLifecycleEventKind::Appeared,
                                     l1_id.hwnd, l1_id},
                                    &error) == LifecycleApplyResult::Added;
    }
    lifecycle_observation = WindowRecord{
        l1_reused_id, 70, 71, NativeDesktopRole::Carrier, manageable, {}, {},
        true};
    if (lifecycle_ok) {
        lifecycle_ok =
            lifecycle_adapter.Apply({WindowLifecycleEventKind::Appeared,
                                     l1_reused_id.hwnd, l1_reused_id},
                                    &error) == LifecycleApplyResult::Recreated &&
            lifecycle_engine.FindWindow(l1_id) == nullptr &&
            lifecycle_engine.FindWindow(l1_reused_id) != nullptr;
    }
    if (lifecycle_ok) {
        lifecycle_ok =
            lifecycle_adapter.Apply({WindowLifecycleEventKind::Closed,
                                     l1_reused_id.hwnd, std::nullopt},
                                    &error) ==
                LifecycleApplyResult::NeedsReconcile &&
            lifecycle_adapter.reconciliation_required() &&
            lifecycle_engine.FindWindow(l1_reused_id) != nullptr;
    }
    if (lifecycle_ok) {
        lifecycle_ok =
            lifecycle_adapter.Apply({WindowLifecycleEventKind::Appeared,
                                     l1_reused_id.hwnd, l1_reused_id},
                                    &error) ==
                LifecycleApplyResult::NeedsReconcile &&
            lifecycle_engine.FindWindow(l1_reused_id) != nullptr;
    }
    if (lifecycle_ok) {
        lifecycle_ok = lifecycle_adapter.ReconcileCompleteSnapshot(
                           {{WindowLifecycleEventKind::Closed,
                             l1_reused_id.hwnd, std::nullopt}},
                           {}, nullptr, &error) &&
                       !lifecycle_adapter.reconciliation_required() &&
                       lifecycle_engine.FindWindow(l1_reused_id) == nullptr &&
                       lifecycle_engine.CheckInvariant(&error);
    }
    ok = ok && lifecycle_ok;
    Field("generation-safe lifecycle observation adapter",
          lifecycle_ok ? "PASS" : "FAIL");

    WorkspaceEngine lifecycle_batch_engine(carrier, parking);
    bool lifecycle_batch_ok =
        lifecycle_batch_engine.AddMonitor(80, 81, {81, 82}, &error);
    const WindowIdentity lb_old_id = identity(0x8101, 911, 11);
    const WindowIdentity lb_new_id = identity(0x8101, 912, 12);
    const WindowIdentity lb_other_id = identity(0x8102, 913, 12);
    WindowLifecycleAdapter lifecycle_batch_adapter(lifecycle_batch_engine, {});
    LifecycleReconcileResult lifecycle_batch_result;
    if (lifecycle_batch_ok) {
        lifecycle_batch_ok = lifecycle_batch_adapter.ReconcileCompleteSnapshot(
            {{WindowLifecycleEventKind::Appeared, lb_new_id.hwnd, lb_new_id},
             {WindowLifecycleEventKind::Appeared, lb_new_id.hwnd, lb_new_id},
             {WindowLifecycleEventKind::Closed, lb_old_id.hwnd, lb_old_id}},
            {{lb_other_id, 80, 82, NativeDesktopRole::Parking, manageable, {},
              {}, true},
             {lb_new_id, 80, 81, NativeDesktopRole::Carrier, manageable, {},
              {}, true}},
            &lifecycle_batch_result, &error);
    }
    lifecycle_batch_ok =
        lifecycle_batch_ok && lifecycle_batch_result.events == 3 &&
        lifecycle_batch_result.duplicates == 1 &&
        lifecycle_batch_result.stale_generations == 1 &&
        lifecycle_batch_result.discovery.added == 2 &&
        lifecycle_batch_engine.FindWindow(lb_old_id) == nullptr &&
        lifecycle_batch_engine.FindWindow(lb_new_id) != nullptr &&
        !lifecycle_batch_adapter.reconciliation_required() &&
        lifecycle_batch_engine.CheckInvariant(&error);
    ok = ok && lifecycle_batch_ok;
    Field("complete lifecycle batch ignores duplicate/stale hints",
          lifecycle_batch_ok ? "PASS" : "FAIL");

    std::vector<HWINEVENTHOOK> removed_hooks;
    std::uintptr_t next_fake_hook = 1;
    {
        WinEventLifecycleSource source(
            [&](DWORD, DWORD, WINEVENTPROC) {
                return reinterpret_cast<HWINEVENTHOOK>(next_fake_hook++);
            },
            [&](HWINEVENTHOOK hook) {
                removed_hooks.push_back(hook);
                return true;
            });
        lifecycle_batch_ok = lifecycle_batch_ok && source.Start(&error) &&
                             source.running();
        source.Collect({WindowLifecycleEventKind::Appeared, lb_new_id.hwnd,
                        lb_new_id});
        source.Collect({WindowLifecycleEventKind::Appeared, lb_new_id.hwnd,
                        lb_new_id});
        const std::vector<WindowLifecycleEvent> drained = source.Drain();
        lifecycle_batch_ok = lifecycle_batch_ok && drained.size() == 2 &&
                             source.Drain().empty();
        source.Stop();
        lifecycle_batch_ok = lifecycle_batch_ok && !source.running() &&
                             source.shutdown_ok();
    }
    lifecycle_batch_ok = lifecycle_batch_ok && removed_hooks.size() == 1;

    std::vector<HWINEVENTHOOK> partial_removed;
    int install_attempt = 0;
    {
        WinEventLifecycleSource partial_source(
            [&](DWORD, DWORD, WINEVENTPROC) -> HWINEVENTHOOK {
                ++install_attempt;
                return nullptr;
            },
            [&](HWINEVENTHOOK hook) {
                partial_removed.push_back(hook);
                return true;
            });
        std::string start_error;
        lifecycle_batch_ok = lifecycle_batch_ok &&
                             !partial_source.Start(&start_error) &&
                             !partial_source.running();
    }
    lifecycle_batch_ok = lifecycle_batch_ok && partial_removed.empty();
    ok = ok && lifecycle_batch_ok;
    Field("WinEvent queue drain and owner-thread unhook cleanup",
          lifecycle_batch_ok ? "PASS" : "FAIL");

    WorkspaceEngine discovery_engine(carrier, parking);
    bool discovery_ok =
        discovery_engine.AddMonitor(10, 11, {11, 12}, &error);
    const WindowIdentity d1_id = identity(0x3001, 301, 3);
    const WindowIdentity d2_id = identity(0x3002, 302, 3);
    const WindowIdentity d3_id = identity(0x3003, 303, 3);
    const WindowIdentity d2_reused_id = identity(0x3002, 402, 4);
    DiscoveryReconcileResult discovery_initial;
    if (discovery_ok) {
        discovery_ok = discovery_engine.ReconcileDiscoverySnapshot(
            {{d3_id, 10, 12, NativeDesktopRole::Parking, manageable, {}, {},
              true},
             {d1_id, 10, 11, NativeDesktopRole::Carrier, manageable, {}, {},
              true},
             {d2_id, 10, 12, NativeDesktopRole::Parking, manageable, {}, {},
              true}},
            &discovery_initial, &error);
    }
    DiscoveryReconcileResult discovery_next;
    if (discovery_ok) {
        discovery_ok = discovery_engine.ReconcileDiscoverySnapshot(
            {{d2_reused_id, 10, 12, NativeDesktopRole::Parking, manageable,
              {}, {}, true},
             {d1_id, 10, 11, NativeDesktopRole::Carrier, manageable, {}, {},
              true}},
            &discovery_next, &error);
    }
    discovery_ok = discovery_ok && discovery_initial.added == 3 &&
                   discovery_next.updated == 1 &&
                   discovery_next.recreated == 1 &&
                   discovery_next.closed == 1 &&
                   discovery_engine.FindWindow(d2_id) == nullptr &&
                   discovery_engine.FindWindow(d2_reused_id) != nullptr &&
                   discovery_engine.FindWindow(d3_id) == nullptr &&
                   discovery_engine.CheckInvariant(&error);
    ok = ok && discovery_ok;
    Field("complete discovery snapshot reconciles generations and closes",
          discovery_ok ? "PASS" : "FAIL");

    WorkspaceEngine rejected_discovery_engine(carrier, parking);
    bool rejected_discovery_ok =
        rejected_discovery_engine.AddMonitor(60, 61, {61}, &error);
    const WindowIdentity rejected_id = identity(0x7001, 801, 8);
    DiscoveryReconcileResult rejected_result{99, 99, 99, 99};
    if (rejected_discovery_ok) {
        rejected_discovery_ok =
            rejected_discovery_engine.ReconcileDiscoverySnapshot(
                {{rejected_id, 60, 61, NativeDesktopRole::Carrier, manageable,
                  {}, {}, true}},
                &rejected_result, &error);
    }
    const DiscoveryReconcileResult before_rejected = rejected_result;
    if (rejected_discovery_ok) {
        rejected_discovery_ok =
            !rejected_discovery_engine.ReconcileDiscoverySnapshot(
                {{rejected_id, 60, 61, NativeDesktopRole::Carrier, manageable,
                  {}, {}, true},
                 {rejected_id, 60, 61, NativeDesktopRole::Carrier, manageable,
                  {}, {}, true}},
                &rejected_result, &error);
    }
    rejected_discovery_ok =
        rejected_discovery_ok && before_rejected.added == 1 &&
        rejected_result.added == 0 && rejected_result.updated == 0 &&
        rejected_result.recreated == 0 && rejected_result.closed == 0 &&
        rejected_discovery_engine.FindWindow(rejected_id) != nullptr &&
        rejected_discovery_engine.CheckInvariant(&error);
    ok = ok && rejected_discovery_ok;
    Field("invalid discovery snapshot fails closed",
          rejected_discovery_ok ? "PASS" : "FAIL");

    WorkspaceEngine presentation_engine(carrier, parking);
    bool presentation_ok =
        presentation_engine.AddMonitor(20, 21, {21, 22}, &error);
    const WindowIdentity p1_id = identity(0x4001, 501, 5);
    const WindowIdentity p2_id = identity(0x4002, 502, 5);
    WindowPresentation p1_presentation{};
    p1_presentation.placement.length = sizeof(WINDOWPLACEMENT);
    p1_presentation.placement_valid = true;
    WindowPresentation p2_presentation{};
    p2_presentation.placement.length = sizeof(WINDOWPLACEMENT);
    p2_presentation.placement_valid = true;
    if (presentation_ok) {
        presentation_ok =
            presentation_engine.UpsertWindow(
                {p1_id, 20, 21, NativeDesktopRole::Carrier, manageable,
                 p1_presentation, {}, true},
                &error) == UpsertResult::Added &&
            presentation_engine.UpsertWindow(
                {p2_id, 20, 21, NativeDesktopRole::Carrier, manageable,
                 p2_presentation, {}, true},
                &error) == UpsertResult::Added;
    }
    std::string rejected_order_error;
    const bool incomplete_order_rejected =
        presentation_ok &&
        !presentation_engine.SetZOrder(20, 21, {p1_id},
                                       &rejected_order_error);
    if (presentation_ok) {
        presentation_ok = incomplete_order_rejected &&
                          presentation_engine.SetZOrder(
                              20, 21, {p1_id, p2_id}, &error) &&
                          presentation_engine.SetLastForeground(
                              20, 21, p1_id, &error);
    }
    bool foreground_state_ok = false;
    if (presentation_ok) {
        const WindowRecord* p1 = presentation_engine.FindWindow(p1_id);
        const WindowRecord* p2 = presentation_engine.FindWindow(p2_id);
        foreground_state_ok = p1 != nullptr && p2 != nullptr &&
                              p1->presentation.foreground &&
                              !p2->presentation.foreground &&
                              presentation_engine.SetLastForeground(
                                  20, 21, p2_id, &error);
        p1 = presentation_engine.FindWindow(p1_id);
        p2 = presentation_engine.FindWindow(p2_id);
        foreground_state_ok = foreground_state_ok && p1 != nullptr &&
                              p2 != nullptr && !p1->presentation.foreground &&
                              p2->presentation.foreground &&
                              presentation_engine.SetLastForeground(
                                  20, 21, p1_id, &error);
    }
    const std::optional<PresentationPlan> presentation_plan =
        presentation_ok && foreground_state_ok
            ? presentation_engine.PreparePresentationRestore(20, 21, &error)
            : std::nullopt;
    presentation_ok =
        presentation_ok && foreground_state_ok && presentation_plan.has_value() &&
        presentation_plan->operations.size() == 5 &&
        presentation_plan->operations[0].kind ==
            PresentationOperationKind::RestorePlacement &&
        presentation_plan->operations[0].identity == p1_id &&
        presentation_plan->operations[1].kind ==
            PresentationOperationKind::RestorePlacement &&
        presentation_plan->operations[1].identity == p2_id &&
        presentation_plan->operations[2].kind ==
            PresentationOperationKind::RestoreZOrder &&
        presentation_plan->operations[2].identity == p2_id &&
        presentation_plan->operations[3].kind ==
            PresentationOperationKind::RestoreZOrder &&
        presentation_plan->operations[3].identity == p1_id &&
        presentation_plan->operations[4].kind ==
            PresentationOperationKind::RestoreForeground &&
        presentation_plan->operations[4].identity == p1_id;
    ok = ok && presentation_ok;
    Field("presentation plan is complete, ordered, and fail-closed",
          presentation_ok ? "PASS" : "FAIL");

    WorkspaceEngine incomplete_presentation_engine(carrier, parking);
    bool incomplete_presentation_ok =
        incomplete_presentation_engine.AddMonitor(40, 41, {41}, &error);
    WindowPresentation incomplete_presentation{};
    if (incomplete_presentation_ok) {
        incomplete_presentation_ok =
            incomplete_presentation_engine.UpsertWindow(
                {p1_id, 40, 41, NativeDesktopRole::Carrier, manageable,
                 incomplete_presentation, {}, true},
                &error) == UpsertResult::Added &&
            incomplete_presentation_engine.SetZOrder(
                40, 41, {p1_id}, &error) &&
            incomplete_presentation_engine.SetLastForeground(
                40, 41, p1_id, &error);
    }
    std::string incomplete_presentation_error;
    const bool incomplete_presentation_rejected =
        incomplete_presentation_ok &&
        !incomplete_presentation_engine.PreparePresentationRestore(
            40, 41, &incomplete_presentation_error);
    incomplete_presentation_ok =
        incomplete_presentation_rejected &&
        incomplete_presentation_error == "presentation snapshot lacks placement data";
    ok = ok && incomplete_presentation_ok;
    Field("incomplete presentation snapshot fails closed",
          incomplete_presentation_ok ? "PASS" : "FAIL");

    WorkspaceEngine unknown_role_engine(carrier, parking);
    bool unknown_role_ok =
        unknown_role_engine.AddMonitor(50, 51, {51}, &error);
    if (unknown_role_ok) {
        const WindowIdentity unknown_id = identity(0x6001, 701, 7);
        unknown_role_ok =
            unknown_role_engine.UpsertWindow(
                {unknown_id, 50, 51, NativeDesktopRole::Unknown, manageable,
                 {}, {}, true},
                &error) == UpsertResult::Added;
        const WindowRecord* unknown =
            unknown_role_engine.FindWindow(unknown_id);
        unknown_role_ok = unknown_role_ok && unknown != nullptr &&
                          unknown->disposition == WindowDisposition::Unsupported;
    }
    ok = ok && unknown_role_ok;
    Field("unknown native role is unsupported", unknown_role_ok ? "PASS" : "FAIL");

    WorkspaceEngine reconcile_engine(carrier, parking);
    bool bounded_rollback_ok =
        reconcile_engine.AddMonitor(30, 31, {31, 32}, &error);
    const WindowIdentity r1_id = identity(0x5001, 601, 6);
    const WindowIdentity r2_id = identity(0x5002, 602, 6);
    const WindowIdentity r3_id = identity(0x5003, 603, 6);
    if (bounded_rollback_ok) {
        bounded_rollback_ok =
            reconcile_engine.UpsertWindow(
                {r1_id, 30, 31, NativeDesktopRole::Carrier, manageable, {},
                 {}, true},
                &error) == UpsertResult::Added &&
            reconcile_engine.UpsertWindow(
                {r2_id, 30, 31, NativeDesktopRole::Carrier, manageable, {},
                 {}, true},
                &error) == UpsertResult::Added &&
            reconcile_engine.UpsertWindow(
                {r3_id, 30, 31, NativeDesktopRole::Carrier, manageable, {},
                 {}, true},
                &error) == UpsertResult::Added;
    }
    std::unordered_map<WindowIdentity, NativeDesktopRole, WindowIdentityHash>
        reconcile_roles{{r1_id, NativeDesktopRole::Parking},
                        {r2_id, NativeDesktopRole::Parking},
                        {r3_id, NativeDesktopRole::Parking}};
    std::vector<WindowIdentity> reconcile_move_calls;
    auto reconcile_move = [&](const WindowRecord& window,
                              NativeDesktopRole target) {
        reconcile_move_calls.push_back(window.identity);
        if (window.identity == r2_id &&
            target == NativeDesktopRole::Carrier) {
            return false;
        }
        reconcile_roles[window.identity] = target;
        return true;
    };
    auto reconcile_observe = [&](const WindowRecord& window) {
        return reconcile_roles[window.identity];
    };
    std::string reconcile_error;
    if (bounded_rollback_ok) {
        bounded_rollback_ok = !reconcile_engine.Reconcile(
            reconcile_move, reconcile_observe, nullptr, &reconcile_error);
    }
    bounded_rollback_ok =
        bounded_rollback_ok && reconcile_move_calls.size() == 3 &&
        reconcile_move_calls[0] == r1_id &&
        reconcile_move_calls[1] == r2_id &&
        reconcile_move_calls[2] == r1_id &&
        reconcile_roles[r1_id] == NativeDesktopRole::Parking &&
        reconcile_roles[r2_id] == NativeDesktopRole::Parking &&
        reconcile_roles[r3_id] == NativeDesktopRole::Parking;
    ok = ok && bounded_rollback_ok;
    Field("reconcile rollback touches only attempted operations",
          bounded_rollback_ok ? "PASS" : "FAIL");

    const WindowIdentity unsupported_id = identity(0x2002, 202, 2);
    const WindowCapabilities unsupported{true, false, false, true, false};
    const UpsertResult unsupported_result = engine.UpsertWindow(
        {unsupported_id, 2, 4, NativeDesktopRole::Parking, unsupported, {}, {},
         true},
        &error);
    auto refused_plan = engine.PrepareSwitch(2, 4, &error);
    ok = ok && unsupported_result == UpsertResult::Added && !refused_plan &&
         engine.Monitor(2)->active == 3;
    Field("unsupported window fails closed", ok ? "PASS" : "FAIL");

    std::filesystem::path journal_path =
        std::filesystem::temp_directory_path() /
        "vdprobe-workspace-engine-test.journal";
    std::error_code ignored;
    std::filesystem::remove(journal_path, ignored);
    WorkspaceJournal journal(journal_path);
    auto recovery_plan = engine.PrepareSwitch(1, 2, &error);
    bool recovery_ok = recovery_plan.has_value() &&
                       journal.Begin(*recovery_plan, &error);
    if (recovery_ok) {
        std::string second_begin_error;
        recovery_ok = !journal.Begin(*recovery_plan, &second_begin_error) &&
                      second_begin_error ==
                          "journal already contains a pending transaction";
    }
    if (recovery_ok) {
        const std::optional<SwitchPlan> pending =
            journal.ReadPending(&error);
        recovery_ok = pending.has_value() &&
                      pending->operations.size() ==
                          recovery_plan->operations.size();
    }
    if (recovery_ok) {
        fake_roles[a1_id] = NativeDesktopRole::Parking;
        fake_roles[reused_id] = NativeDesktopRole::Carrier;
        const RecoveryResult recovered =
            engine.RecoverPending(*recovery_plan, move, observe, &journal);
        recovery_ok = recovered.recovered &&
                      fake_roles[a1_id] == NativeDesktopRole::Carrier &&
                      fake_roles[reused_id] == NativeDesktopRole::Parking;
    }
    std::filesystem::remove(journal_path, ignored);
    ok = ok && recovery_ok;
    Field("interrupted transaction recovery", recovery_ok ? "PASS" : "FAIL");

    std::filesystem::remove(journal_path, ignored);
    std::filesystem::path stale_temporary = journal_path;
    stale_temporary += L".tmp.stale";
    {
        std::ofstream stale(stale_temporary, std::ios::binary | std::ios::trunc);
        stale << "incomplete replacement";
    }
    bool durable_journal = recovery_plan.has_value() &&
                           journal.Begin(*recovery_plan, &error);
    if (durable_journal) {
        std::ifstream persisted(journal_path, std::ios::binary);
        const std::string journal_contents(
            (std::istreambuf_iterator<char>(persisted)),
            std::istreambuf_iterator<char>());
        durable_journal = journal_contents.starts_with("BEGIN ") &&
                          journal_contents.find("MOVE ") != std::string::npos &&
                          journal.Abort(&error) && !journal.ReadPending(&error);
    }
    std::filesystem::remove(journal_path, ignored);
    std::filesystem::remove(stale_temporary, ignored);
    ok = ok && durable_journal;
    Field("durable journal replacement and marker",
          durable_journal ? "PASS" : "FAIL");

    std::filesystem::remove(journal_path, ignored);
    WorkspaceJournal rollback_journal(journal_path);
    auto rollback_plan = engine.PrepareSwitch(1, 2, &error);
    bool retained_pending = rollback_plan.has_value();
    int rollback_move_count = 0;
    auto fail_move_and_rollback = [&](const WindowRecord& window,
                                      NativeDesktopRole target) -> bool {
        ++rollback_move_count;
        fake_roles[window.identity] = target;
        // The first operation succeeds, the second reports failure after its
        // side effect, and restoring either operation then fails.
        return rollback_move_count < 2;
    };
    if (retained_pending) {
        const TransactionResult rollback_failed = engine.ExecuteSwitch(
            *rollback_plan, fail_move_and_rollback, observe, &rollback_journal);
        const std::optional<SwitchPlan> still_pending =
            rollback_journal.ReadPending(&error);
        retained_pending = !rollback_failed.committed &&
                           rollback_failed.recovery_required &&
                           still_pending.has_value() &&
                           PlansMatch(*still_pending, *rollback_plan);
    }
    fake_roles[a1_id] = NativeDesktopRole::Carrier;
    fake_roles[reused_id] = NativeDesktopRole::Parking;
    std::filesystem::remove(journal_path, ignored);
    ok = ok && retained_pending;
    Field("failed rollback retains pending journal",
          retained_pending ? "PASS" : "FAIL");

    SwitchPlan stale_plan{};
    stale_plan.monitor = 99;
    stale_plan.from_workspace = 1;
    stale_plan.to_workspace = 2;
    stale_plan.operations = {{a1_id, NativeDesktopRole::Carrier,
                              NativeDesktopRole::Parking}};
    const RecoveryResult stale_recovery =
        engine.RecoverPending(stale_plan, move, observe);
    const bool stale_rejected = !stale_recovery.recovered &&
                                stale_recovery.recovery_required &&
                                fake_roles[a1_id] == NativeDesktopRole::Carrier;
    ok = ok && stale_rejected;
    Field("stale recovery plan is rejected",
          stale_rejected ? "PASS" : "FAIL");

    Field("result", ok ? "PASS" : "FAIL");
    if (!ok && !error.empty()) Field("error", error);
    return ok ? 0 : 1;
}

}  // namespace vd
