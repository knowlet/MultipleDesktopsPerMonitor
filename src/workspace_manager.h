#pragma once

#include <windows.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "workspace_engine.h"

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

struct WorkspaceManagerConfig {
    std::vector<WorkspaceHotkeyBinding> bindings;
    std::filesystem::path journal_path;
    bool tray_icon = true;
};

// Parses the minimal line-based manager config:
//
//   hotkey <mods>+<key> <monitor> <workspace>
//   journal <path>
//   tray <on|off>
//
// where <mods> is a '+'-separated list of Ctrl, Alt, Shift, Win and <key> is
// a single VK name (Q..Z, 0..9, F1..F24, Left, Right, Up, Down, Home, End).
// Duplicate hotkeys, unknown modifiers/keys, and malformed lines are rejected.
bool ParseWorkspaceManagerConfig(const std::string& text,
                                 WorkspaceManagerConfig& out,
                                 std::string* error = nullptr);

// Resolves a raw WM_HOTKEY modifiers/vk pair against the config bindings.
bool ResolveWorkspaceHotkey(const WorkspaceManagerConfig& config,
                            UINT modifiers, UINT vk, MonitorId& monitor,
                            WorkspaceId& workspace);

// Deterministic, non-mutating config/binding/dispatch tests.  No real hotkey,
// window, COM, or native shell call is made.
int CmdWorkspaceManagerTest();

}  // namespace vd
