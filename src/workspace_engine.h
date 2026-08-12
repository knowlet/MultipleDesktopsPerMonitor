// Capability-driven logical workspace state and transaction engine.
//
// This module deliberately knows nothing about executable names.  A caller
// discovers a top-level HWND, resolves its IApplicationView, and supplies the
// resulting capability/identity snapshot here.  Native virtual desktop calls
// remain behind callbacks so the state machine can be tested without mutating
// the user's shell.
#pragma once

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <unordered_map>
#include <optional>
#include <string>
#include <vector>

namespace vd {

using WorkspaceId = std::uint64_t;
using MonitorId = std::uintptr_t;

enum class NativeDesktopRole {
    Unknown,
    Carrier,
    Parking,
};

enum class WindowDisposition {
    Managed,
    Unsupported,
    Ambiguous,
    Closed,
};

struct WindowIdentity {
    HWND hwnd = nullptr;
    DWORD pid = 0;
    FILETIME process_creation_time{};
    bool process_creation_time_ok = false;

    bool IsValid() const noexcept;
};

bool operator==(const WindowIdentity& a, const WindowIdentity& b) noexcept;
bool operator!=(const WindowIdentity& a, const WindowIdentity& b) noexcept;

struct WindowIdentityHash {
    std::size_t operator()(const WindowIdentity& identity) const noexcept;
};

struct WindowCapabilities {
    bool has_application_view = false;
    bool can_move_desktops = false;
    bool independent_top_level = false;
    bool desktop_state_observable = false;
    bool owner_state_observable = false;

    bool Manageable() const noexcept {
        return has_application_view && can_move_desktops &&
               independent_top_level && desktop_state_observable;
    }
};

struct WindowPresentation {
    RECT rect{};
    WINDOWPLACEMENT placement{};
    bool rect_valid = false;
    bool placement_valid = false;
    bool foreground = false;
    std::int64_t z_order = 0;
};

struct WindowRecord {
    WindowIdentity identity;
    MonitorId monitor = 0;
    WorkspaceId workspace = 0;
    NativeDesktopRole native_role = NativeDesktopRole::Unknown;
    WindowCapabilities capabilities{};
    WindowPresentation presentation{};
    WindowDisposition disposition = WindowDisposition::Managed;
    bool present = true;
};

struct DiscoveryReconcileResult {
    std::size_t added = 0;
    std::size_t updated = 0;
    std::size_t recreated = 0;
    std::size_t closed = 0;
};

struct WorkspaceDefinition {
    WorkspaceId id = 0;
    MonitorId monitor = 0;
    std::vector<WindowIdentity> windows;
    std::optional<WindowIdentity> last_foreground;
    std::vector<WindowIdentity> z_order;
};

struct MonitorWorkspaceState {
    MonitorId monitor = 0;
    WorkspaceId active = 0;
    std::vector<WorkspaceId> workspaces;
};

struct SwitchOperation {
    WindowIdentity identity;
    NativeDesktopRole from = NativeDesktopRole::Unknown;
    NativeDesktopRole to = NativeDesktopRole::Unknown;
};

struct SwitchPlan {
    MonitorId monitor = 0;
    WorkspaceId from_workspace = 0;
    WorkspaceId to_workspace = 0;
    std::vector<SwitchOperation> operations;
};

enum class PresentationOperationKind {
    RestorePlacement,
    RestoreZOrder,
    RestoreForeground,
};

struct PresentationOperation {
    PresentationOperationKind kind =
        PresentationOperationKind::RestorePlacement;
    WindowIdentity identity;
    WindowPresentation presentation{};
};

struct PresentationPlan {
    MonitorId monitor = 0;
    WorkspaceId workspace = 0;
    // Placements are emitted first, followed by relative Z-order from bottom
    // to top, with foreground activation last.  A native adapter must preserve
    // this order and revalidate WindowIdentity immediately before each call.
    std::vector<PresentationOperation> operations;
};

struct TransactionResult {
    bool committed = false;
    bool rollback_attempted = false;
    bool rollback_succeeded = true;
    bool recovery_required = false;
    std::string error;
};

struct RecoveryResult {
    bool recovered = false;
    bool recovery_required = false;
    std::string error;
};

enum class UpsertResult {
    Added,
    Updated,
    Recreated,
    Rejected,
};

class WorkspaceJournal {
   public:
    explicit WorkspaceJournal(std::filesystem::path path);

    const std::filesystem::path& path() const noexcept { return path_; }

    bool Begin(const SwitchPlan& plan, std::string* error = nullptr) const;
    bool Commit(std::string* error = nullptr) const;
    bool Abort(std::string* error = nullptr) const;
    bool Recovered(std::string* error = nullptr) const;

    std::optional<SwitchPlan> ReadPending(std::string* error = nullptr) const;

   private:
    bool Append(const std::string& line, std::string* error) const;
    std::filesystem::path path_;
};

class WorkspaceEngine {
   public:
    using MoveCallback =
        std::function<bool(const WindowRecord&, NativeDesktopRole target)>;
    using ObserveCallback =
        std::function<NativeDesktopRole(const WindowRecord&)>;
    using PreCommitCallback = std::function<bool()>;

    WorkspaceEngine(GUID carrier, GUID parking);

    const GUID& carrier() const noexcept { return carrier_; }
    const GUID& parking() const noexcept { return parking_; }

    bool AddMonitor(MonitorId monitor, WorkspaceId active,
                    std::vector<WorkspaceId> workspaces,
                    std::string* error = nullptr);
    bool SetLastForeground(MonitorId monitor, WorkspaceId workspace,
                           const WindowIdentity& identity,
                           std::string* error = nullptr);
    bool SetZOrder(MonitorId monitor, WorkspaceId workspace,
                   std::vector<WindowIdentity> top_to_bottom,
                   std::string* error = nullptr);

    UpsertResult UpsertWindow(WindowRecord record,
                              std::string* error = nullptr);
    bool CloseWindow(const WindowIdentity& identity,
                     std::string* error = nullptr);
    // Applies one complete, point-in-time discovery snapshot after validating
    // the full input and then using deterministic model updates. Callers must
    // not pass a filtered or partial enumeration: tracked windows omitted from
    // the snapshot are recorded as closed.
    bool ReconcileDiscoverySnapshot(
        std::vector<WindowRecord> observed,
        DiscoveryReconcileResult* result = nullptr,
        std::string* error = nullptr);

    const WindowRecord* FindWindow(const WindowIdentity& identity) const;
    const WindowRecord* FindWindowByHwnd(HWND hwnd) const;
    std::vector<const WindowRecord*> Windows() const;
    std::vector<const WindowRecord*> WindowsForMonitor(MonitorId monitor) const;

    const MonitorWorkspaceState* Monitor(MonitorId monitor) const;
    const WorkspaceDefinition* Workspace(WorkspaceId workspace) const;

    bool CheckInvariant(std::string* error = nullptr) const;
    std::optional<SwitchPlan> PrepareSwitch(MonitorId monitor,
                                             WorkspaceId target_workspace,
                                             std::string* error = nullptr) const;
    std::optional<PresentationPlan> PreparePresentationRestore(
        MonitorId monitor, WorkspaceId workspace,
        std::string* error = nullptr) const;

    TransactionResult ExecuteSwitch(const SwitchPlan& plan,
                                    const MoveCallback& move,
                                    const ObserveCallback& observe = {},
                                    const WorkspaceJournal* journal = nullptr,
                                    const PreCommitCallback& pre_commit = {});

    RecoveryResult RecoverPending(const SwitchPlan& plan,
                                  const MoveCallback& move,
                                  const ObserveCallback& observe = {},
                                  const WorkspaceJournal* journal = nullptr);

    bool Reconcile(const MoveCallback& move, const ObserveCallback& observe = {},
                   const WorkspaceJournal* journal = nullptr,
                   std::string* error = nullptr);

   private:
    bool HasWorkspace(MonitorId monitor, WorkspaceId workspace) const;
    WorkspaceDefinition* MutableWorkspace(WorkspaceId workspace);
    MonitorWorkspaceState* MutableMonitor(MonitorId monitor);
    bool ValidateRecord(const WindowRecord& record,
                        std::string* error) const;
    void RemoveIdentityFromWorkspace(const WindowIdentity& identity,
                                     WorkspaceId workspace);
    void AddIdentityToWorkspace(const WindowIdentity& identity,
                                WorkspaceId workspace);
    bool ApplyOperations(const std::vector<SwitchOperation>& operations,
                         const MoveCallback& move,
                         const ObserveCallback& observe,
                         std::vector<SwitchOperation>& applied,
                         std::string* error);
    bool RestoreOperations(const std::vector<SwitchOperation>& applied,
                           const MoveCallback& move,
                           const ObserveCallback& observe,
                           std::string* error);
    void CommitPlan(const SwitchPlan& plan);
    bool RolesMatch(const SwitchOperation& operation,
                    const ObserveCallback& observe) const;

    GUID carrier_{};
    GUID parking_{};
    std::vector<MonitorWorkspaceState> monitors_;
    std::vector<WorkspaceDefinition> workspaces_;
    std::unordered_map<WindowIdentity, WindowRecord, WindowIdentityHash>
        windows_;
    std::unordered_map<std::uintptr_t, WindowIdentity> hwnd_index_;
    std::vector<WindowRecord> closed_windows_;
};

const char* NativeDesktopRoleText(NativeDesktopRole role) noexcept;
const char* WindowDispositionText(WindowDisposition disposition) noexcept;
const char* UpsertResultText(UpsertResult result) noexcept;

// Deterministic, non-mutating state-machine test.  This intentionally does not
// touch COM, native desktops, user windows, focus, or the shell.
int CmdWorkspaceEngineTest();

}  // namespace vd
