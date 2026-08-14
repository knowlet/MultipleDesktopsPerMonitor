#pragma once

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "workspace_engine.h"
#include "workspace_assignment.h"

namespace vd {

// A single user-facing hotkey binding: pressing modifiers+vk switches the
// configured monitor to the configured logical workspace.
struct WorkspaceHotkey {
    UINT modifiers = 0;
    UINT vk = 0;

    bool operator==(const WorkspaceHotkey& other) const noexcept {
        return modifiers == other.modifiers && vk == other.vk;
    }
};

struct WorkspaceHotkeyBinding {
    WorkspaceHotkey hotkey;
    MonitorId monitor = 0;
    WorkspaceId workspace = 0;
};

enum class ManagerLogLevel {
    Debug,
    Info,
    Warn,
    Error,
};

// One configured monitor: its ordered workspace names (the i-th name maps to
// WorkspaceId i+1 within this monitor) and the persisted last-active name.
struct WorkspaceConfigEntry {
    MonitorId monitor = 0;
    std::vector<std::string> workspace_names;
    std::string active_name;
};

struct WorkspaceManagerConfig {
    std::uint32_t schema_version = 0;
    std::vector<WorkspaceConfigEntry> monitors;
    std::vector<WorkspaceHotkeyBinding> bindings;
    MonitorMigrationPolicy migration_policy =
        MonitorMigrationPolicy::ReassignToDestinationActive;
    ManagerLogLevel log_level = ManagerLogLevel::Info;
    std::filesystem::path journal_path;
    bool tray_icon = true;
};

// Runtime topology derived from a parsed config and the live monitor list.
// The i-th configured monitor maps to the i-th enumerated real monitor, and
// the i-th workspace name maps to WorkspaceId i+1 within its monitor.
struct ManagerRuntimeTopology {
    struct MonitorBinding {
        MonitorId real_monitor = 0;
        std::size_t workspace_count = 0;
        WorkspaceId active = 0;
        std::string active_name;
        // Engine-usable workspace ids for this monitor. Each configured
        // monitor gets a disjoint id range (monitor i starts at i*1000+1) so
        // ids are globally unique while remaining stable across restarts.
        std::vector<WorkspaceId> workspace_ids;
    };
    std::vector<MonitorBinding> monitors;
    std::vector<WorkspaceHotkeyBinding> bindings;
};

// Parses the versioned, line-based manager config (schema version 1):
//
//   version 1
//   monitor <id> workspaces <name1,name2,...> active <name>
//   hotkey <mods>+<key> <monitor> <workspace>
//   assignment monitor-migration <reassign|fail-closed>
//   log-level <debug|info|warn|error>
//   journal <path>
//   tray <on|off>
//
// where <mods> is a '+'-separated list of Ctrl, Alt, Shift, Win and <key> is
// a single VK name (Q..Z, 0..9, F1..F24, Left, Right, Up, Down, Home, End).
// Workspace names are validated against the monitor definition; the i-th name
// maps to WorkspaceId i+1 within its monitor. Missing or unsupported schema
// versions, duplicate hotkeys/monitors/workspace names, unknown
// modifiers/keys/workspaces, and malformed lines are rejected.
bool ParseWorkspaceManagerConfig(const std::string& text,
                                 WorkspaceManagerConfig& out,
                                 std::string* error = nullptr);

// Persists the config in canonical schema-version-1 text form. Returns false
// and leaves the error set when the config is not representable.
bool SaveManagerConfig(const WorkspaceManagerConfig& config,
                       const std::filesystem::path& path,
                       std::string* error = nullptr);

// Loads and parses a persisted config file.
bool LoadManagerConfig(const std::filesystem::path& path,
                       WorkspaceManagerConfig& out,
                       std::string* error = nullptr);

// Maps a parsed config onto the enumerated real monitors (by order) and
// remaps hotkey bindings from symbolic monitor ids to real MonitorIds.
bool DeriveManagerRuntimeTopology(
    const WorkspaceManagerConfig& config,
    const std::vector<HMONITOR>& real_monitors,
    ManagerRuntimeTopology& out, std::string* error = nullptr);

// Default per-user config path: %APPDATA%\vdprobe\workspace-manager.conf.
// Falls back to the current directory when APPDATA is unavailable.
std::filesystem::path DefaultManagerConfigPath();

// Resolves a raw WM_HOTKEY modifiers/vk pair against the config bindings.
bool ResolveWorkspaceHotkey(const WorkspaceManagerConfig& config,
                            UINT modifiers, UINT vk, MonitorId& monitor,
                            WorkspaceId& workspace);

// Deterministic, non-mutating config/binding/dispatch tests.  No real hotkey,
// window, COM, or native shell call is made.
int CmdWorkspaceManagerTest();

}  // namespace vd
