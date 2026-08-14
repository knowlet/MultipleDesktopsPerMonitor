#include "workspace_manager.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <optional>
#include <sstream>
#include <string>

#include "util.h"

namespace vd {
namespace {

void SetError(std::string* error, std::string message) {
    if (error != nullptr) *error = std::move(message);
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

std::vector<std::string> Split(std::string_view text, char delimiter) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= text.size()) {
        const std::size_t end = text.find(delimiter, start);
        parts.emplace_back(text.substr(start, end - start));
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return parts;
}

bool ParseModifier(const std::string& token, UINT& modifier) {
    const std::string lower = Lower(token);
    if (lower == "ctrl" || lower == "control") {
        modifier = MOD_CONTROL;
    } else if (lower == "alt") {
        modifier = MOD_ALT;
    } else if (lower == "shift") {
        modifier = MOD_SHIFT;
    } else if (lower == "win" || lower == "windows") {
        modifier = MOD_WIN;
    } else {
        return false;
    }
    return true;
}

bool ParseKeyName(const std::string& token, UINT& vk) {
    if (token.size() == 1) {
        const char c = token[0];
        if (c >= '0' && c <= '9') {
            vk = '0' + (c - '0');
            return true;
        }
        if (c >= 'A' && c <= 'Z') {
            vk = 'A' + (c - 'A');
            return true;
        }
    }
    const std::string lower = Lower(token);
    if (lower.rfind("f", 0) == 0 && lower.size() > 1) {
        int number = 0;
        const auto result =
            std::from_chars(lower.data() + 1, lower.data() + lower.size(), number);
        if (result.ec == std::errc() && number >= 1 && number <= 24) {
            vk = VK_F1 + (number - 1);
            return true;
        }
    }
    struct NamedKey {
        const char* name;
        UINT vk;
    };
    static constexpr NamedKey kNamedKeys[] = {
        {"left", VK_LEFT},     {"right", VK_RIGHT}, {"up", VK_UP},
        {"down", VK_DOWN},     {"home", VK_HOME},   {"end", VK_END},
        {"space", VK_SPACE},   {"tab", VK_TAB},     {"enter", VK_RETURN},
        {"escape", VK_ESCAPE},
    };
    for (const NamedKey& key : kNamedKeys) {
        if (lower == key.name) {
            vk = key.vk;
            return true;
        }
    }
    return false;
}

bool ParseUint(std::string_view text, std::uint64_t& out) {
    out = 0;
    if (text.empty()) return false;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), out);
    return result.ec == std::errc() && result.ptr == text.data() + text.size();
}

}  // namespace

bool ParseWorkspaceManagerConfig(const std::string& text,
                                 WorkspaceManagerConfig& out,
                                 std::string* error) {
    WorkspaceManagerConfig config;
    std::istringstream stream(text);
    std::string line;
    std::size_t line_number = 0;
    while (std::getline(stream, line)) {
        ++line_number;
        const std::size_t comment = line.find('#');
        if (comment != std::string::npos) line.erase(comment);
        const auto not_space = [](unsigned char c) {
            return std::isspace(c) == 0;
        };
        line.erase(line.begin(),
                   std::find_if(line.begin(), line.end(), not_space));
        line.erase(std::find_if(line.rbegin(), line.rend(), not_space).base(),
                   line.end());
        if (line.empty()) continue;

        const std::vector<std::string> tokens = Split(line, ' ');
        if (tokens.empty()) continue;
        if (tokens[0] == "hotkey") {
            if (tokens.size() != 4) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": hotkey requires '<mods>+<key> <monitor> "
                                    "<workspace>'");
                return false;
            }
            WorkspaceHotkey hotkey;
            const std::vector<std::string> modifier_parts =
                Split(tokens[1], '+');
            if (modifier_parts.size() < 2) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": hotkey requires '<mods>+<key>'");
                return false;
            }
            UINT modifiers = 0;
            for (std::size_t i = 0; i + 1 < modifier_parts.size(); ++i) {
                UINT modifier = 0;
                if (!ParseModifier(modifier_parts[i], modifier) ||
                    (modifiers & modifier) != 0) {
                    SetError(error,
                             "line " + std::to_string(line_number) +
                                 ": unknown or duplicate modifier '" +
                                 modifier_parts[i] + "'");
                    return false;
                }
                modifiers |= modifier;
            }
            hotkey.modifiers = modifiers;
            const std::string key_token = modifier_parts.back();
            if (!ParseKeyName(key_token, hotkey.vk)) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": unknown key '" + key_token + "'");
                return false;
            }
            std::uint64_t monitor = 0;
            std::uint64_t workspace = 0;
            if (!ParseUint(tokens[2], monitor) || monitor == 0 ||
                !ParseUint(tokens[3], workspace) || workspace == 0) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": monitor and workspace must be positive "
                                    "integers");
                return false;
            }
            if (std::any_of(
                    config.bindings.begin(), config.bindings.end(),
                    [&](const WorkspaceHotkeyBinding& binding) {
                        return binding.hotkey == hotkey;
                    })) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": duplicate hotkey binding");
                return false;
            }
            config.bindings.push_back(
                {hotkey, reinterpret_cast<MonitorId>(monitor), workspace});
        } else if (tokens[0] == "journal") {
            if (tokens.size() != 2) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": journal requires one path");
                return false;
            }
            config.journal_path = tokens[1];
        } else if (tokens[0] == "tray") {
            if (tokens.size() != 2 || (tokens[1] != "on" && tokens[1] != "off")) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": tray requires 'on' or 'off'");
                return false;
            }
            config.tray_icon = tokens[1] == "on";
        } else {
            SetError(error, "line " + std::to_string(line_number) +
                                ": unknown directive '" + tokens[0] + "'");
            return false;
        }
    }
    out = std::move(config);
    return true;
}

bool ResolveWorkspaceHotkey(const WorkspaceManagerConfig& config,
                            UINT modifiers, UINT vk, MonitorId& monitor,
                            WorkspaceId& workspace) {
    const WorkspaceHotkey hotkey{modifiers, vk};
    for (const WorkspaceHotkeyBinding& binding : config.bindings) {
        if (binding.hotkey == hotkey) {
            monitor = binding.monitor;
            workspace = binding.workspace;
            return true;
        }
    }
    return false;
}

int CmdWorkspaceManagerTest() {
    Heading("workspace-manager-test");
    Field("scope", "deterministic config parsing, binding validation, dispatch");
    Field("native mutation", "none");

    const std::string valid =
        "# per-monitor workspace manager test config\n"
        "hotkey Ctrl+Alt+F9 1 2\n"
        "hotkey Ctrl+Alt+Shift+F10 1 1\n"
        "journal C:\\tmp\\vdprobe-manager.journal\n"
        "tray on\n";
    WorkspaceManagerConfig config;
    std::string error;
    bool ok = ParseWorkspaceManagerConfig(valid, config, &error);
    ok = ok && config.bindings.size() == 2 &&
         config.bindings[0].hotkey.modifiers == (MOD_CONTROL | MOD_ALT) &&
         config.bindings[0].hotkey.vk == VK_F9 &&
         config.bindings[0].workspace == 2 &&
         config.bindings[1].hotkey.modifiers ==
             (MOD_CONTROL | MOD_ALT | MOD_SHIFT) &&
         config.bindings[1].hotkey.vk == VK_F10 &&
         config.journal_path == L"C:\\tmp\\vdprobe-manager.journal" &&
         config.tray_icon;
    Field("valid config parsed", ok ? "PASS" : "FAIL");

    MonitorId monitor = 0;
    WorkspaceId workspace = 0;
    ok = ok &&
         ResolveWorkspaceHotkey(config, MOD_CONTROL | MOD_ALT, VK_F9,
                                monitor, workspace) &&
         monitor == static_cast<MonitorId>(1) && workspace == 2 &&
         ResolveWorkspaceHotkey(config, MOD_CONTROL | MOD_ALT | MOD_SHIFT,
                                VK_F10, monitor, workspace) &&
         monitor == static_cast<MonitorId>(1) && workspace == 1;
    Field("hotkey dispatch resolves bindings", ok ? "PASS" : "FAIL");

    bool unmatched = !ResolveWorkspaceHotkey(config, MOD_CONTROL | MOD_ALT,
                                             VK_F8, monitor, workspace);
    Field("unbound hotkey rejected", unmatched ? "PASS" : "FAIL");
    ok = ok && unmatched;

    const std::string duplicate =
        "hotkey Ctrl+Alt+F9 1 2\n"
        "hotkey Ctrl+Alt+F9 1 1\n";
    WorkspaceManagerConfig ignored;
    const bool duplicate_rejected =
        !ParseWorkspaceManagerConfig(duplicate, ignored, &error) &&
        error.find("duplicate") != std::string::npos;
    Field("duplicate hotkey rejected", duplicate_rejected ? "PASS" : "FAIL");
    ok = ok && duplicate_rejected;

    const std::string bad_modifier = "hotkey Ctrl+Super+F9 1 2\n";
    const bool bad_modifier_rejected =
        !ParseWorkspaceManagerConfig(bad_modifier, ignored, &error) &&
        error.find("modifier") != std::string::npos;
    Field("unknown modifier rejected", bad_modifier_rejected ? "PASS" : "FAIL");
    ok = ok && bad_modifier_rejected;

    const std::string bad_key = "hotkey Ctrl+Alt+Nonsense 1 2\n";
    const bool bad_key_rejected =
        !ParseWorkspaceManagerConfig(bad_key, ignored, &error) &&
        error.find("key") != std::string::npos;
    Field("unknown key rejected", bad_key_rejected ? "PASS" : "FAIL");
    ok = ok && bad_key_rejected;

    const std::string bad_workspace = "hotkey Ctrl+Alt+F9 1 0\n";
    const bool bad_workspace_rejected =
        !ParseWorkspaceManagerConfig(bad_workspace, ignored, &error) &&
        error.find("positive") != std::string::npos;
    Field("zero workspace rejected", bad_workspace_rejected ? "PASS" : "FAIL");
    ok = ok && bad_workspace_rejected;

    const std::string unknown_directive = "frobnicate 1\n";
    const bool unknown_directive_rejected =
        !ParseWorkspaceManagerConfig(unknown_directive, ignored, &error) &&
        error.find("directive") != std::string::npos;
    Field("unknown directive rejected",
          unknown_directive_rejected ? "PASS" : "FAIL");
    ok = ok && unknown_directive_rejected;

    Field("result", ok ? "PASS" : "FAIL");
    Print("RESULT={}\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

}  // namespace vd
