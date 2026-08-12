#include "workspace_engine.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <system_error>
#include <unordered_set>

#include "util.h"

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
        std::ofstream out(path_, std::ios::binary | std::ios::app);
        if (!out) {
            if (error) *error = "open journal failed";
            return false;
        }
        out << line << '\n';
        out.flush();
        if (!out) {
            if (error) *error = "write journal failed";
            return false;
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool WorkspaceJournal::Begin(const SwitchPlan& plan, std::string* error) const {
    try {
        if (!path_.parent_path().empty()) {
            std::filesystem::create_directories(path_.parent_path());
        }
        std::ofstream out(path_, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (error) *error = "create journal failed";
            return false;
        }
        out << "BEGIN " << plan.monitor << ' ' << plan.from_workspace << ' '
            << plan.to_workspace << '\n';
        for (const SwitchOperation& operation : plan.operations) {
            out << "MOVE " << IdentityText(operation.identity) << ' '
                << RoleLetter(operation.from) << ' ' << RoleLetter(operation.to)
                << '\n';
        }
        out.flush();
        if (!out) {
            if (error) *error = "write journal failed";
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
        window->workspace != workspace || !window->present) {
        if (error) *error = "foreground window is not assigned to workspace";
        return false;
    }
    WorkspaceDefinition* definition = MutableWorkspace(workspace);
    definition->last_foreground = identity;
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
        !record.capabilities.Manageable()) {
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
    const MonitorWorkspaceState* monitor = Monitor(plan.monitor);
    if (monitor == nullptr || monitor->active != plan.from_workspace ||
        !HasWorkspace(plan.monitor, plan.to_workspace)) {
        result.error = "stale switch plan";
        return result;
    }
    std::string invariant_error;
    if (!CheckInvariant(&invariant_error)) {
        result.error = invariant_error;
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
        if (!applied.empty()) {
            result.rollback_succeeded =
                RestoreOperations(applied, move, observe, &error);
        }
        if (result.rollback_succeeded && journal) {
            (void)journal->Abort(nullptr);
        }
        result.recovery_required = !result.rollback_succeeded;
        result.error = error;
        return result;
    }

    if (journal && !journal->Commit(&journal_error)) {
        result.rollback_attempted = true;
        result.rollback_succeeded =
            RestoreOperations(applied, move, observe, &error);
        if (result.rollback_succeeded) {
            (void)journal->Abort(nullptr);
        } else {
            result.recovery_required = true;
        }
        result.error = "journal commit failed: " + journal_error;
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
        if (!applied.empty()) {
            std::string rollback_error;
            if (!RestoreOperations(applied, move, observe, &rollback_error) &&
                error) {
                *error += "; " + rollback_error;
            }
        }
        if (journal) (void)journal->Abort(nullptr);
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
        if (rolled_back) (void)journal->Abort(nullptr);
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

    Field("result", ok ? "PASS" : "FAIL");
    if (!ok && !error.empty()) Field("error", error);
    return ok ? 0 : 1;
}

}  // namespace vd
