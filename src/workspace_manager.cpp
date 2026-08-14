#include "workspace_manager.h"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <fstream>
#include <limits>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>

#include "util.h"

namespace vd {
namespace {

constexpr std::uint32_t kConfigSchemaVersion = 1;

void SetError(std::string* error, std::string message) {
    if (error != nullptr) *error = std::move(message);
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                   });
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

std::string Trim(std::string value) {
    const auto not_space = [](unsigned char c) {
        return std::isspace(c) == 0;
    };
    value.erase(value.begin(),
                std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(),
                value.end());
    return value;
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
            std::from_chars(lower.data() + 1, lower.data() + lower.size(),
                            number);
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
    const auto result =
        std::from_chars(text.data(), text.data() + text.size(), out);
    return result.ec == std::errc() &&
           result.ptr == text.data() + text.size();
}

std::string ModifiersText(UINT modifiers) {
    std::string text;
    const struct {
        UINT flag;
        const char* name;
    } kOrder[] = {
        {MOD_CONTROL, "Ctrl"},
        {MOD_ALT, "Alt"},
        {MOD_SHIFT, "Shift"},
        {MOD_WIN, "Win"},
    };
    for (const auto& entry : kOrder) {
        if ((modifiers & entry.flag) != 0) {
            if (!text.empty()) text += '+';
            text += entry.name;
        }
    }
    return text;
}

std::string KeyText(UINT vk) {
    if (vk >= '0' && vk <= '9') {
        return std::string(1, static_cast<char>(vk));
    }
    if (vk >= 'A' && vk <= 'Z') {
        return std::string(1, static_cast<char>(vk));
    }
    if (vk >= VK_F1 && vk <= VK_F24) {
        return "F" + std::to_string(vk - VK_F1 + 1);
    }
    switch (vk) {
        case VK_LEFT:
            return "Left";
        case VK_RIGHT:
            return "Right";
        case VK_UP:
            return "Up";
        case VK_DOWN:
            return "Down";
        case VK_HOME:
            return "Home";
        case VK_END:
            return "End";
        case VK_SPACE:
            return "Space";
        case VK_TAB:
            return "Tab";
        case VK_RETURN:
            return "Enter";
        case VK_ESCAPE:
            return "Escape";
    }
    return "?";
}

const WorkspaceConfigEntry* FindMonitor(
    const WorkspaceManagerConfig& config, MonitorId monitor) {
    const auto found =
        std::find_if(config.monitors.begin(), config.monitors.end(),
                     [monitor](const WorkspaceConfigEntry& entry) {
                         return entry.monitor == monitor;
                     });
    return found == config.monitors.end() ? nullptr : &*found;
}

bool WorkspaceNameToId(const WorkspaceConfigEntry& entry,
                       const std::string& name, WorkspaceId& out) {
    for (std::size_t i = 0; i < entry.workspace_names.size(); ++i) {
        if (entry.workspace_names[i] == name) {
            out = static_cast<WorkspaceId>(i + 1);
            return true;
        }
    }
    return false;
}

bool WorkspaceIdToName(const WorkspaceConfigEntry& entry, WorkspaceId id,
                       std::string& out) {
    if (id == 0 || id > entry.workspace_names.size()) return false;
    out = entry.workspace_names[id - 1];
    return true;
}

std::string JoinNames(const std::vector<std::string>& names) {
    std::string text;
    for (const std::string& name : names) {
        if (!text.empty()) text += ',';
        text += name;
    }
    return text;
}

}  // namespace

bool ParseWorkspaceManagerConfig(const std::string& text,
                                 WorkspaceManagerConfig& out,
                                 std::string* error) {
    WorkspaceManagerConfig config;
    std::istringstream stream(text);
    std::string line;
    std::size_t line_number = 0;
    bool version_seen = false;
    std::unordered_set<std::uintptr_t> seen_monitors;
    while (std::getline(stream, line)) {
        ++line_number;
        const std::size_t comment = line.find('#');
        if (comment != std::string::npos) line.erase(comment);
        line = Trim(std::move(line));
        if (line.empty()) continue;
        const std::vector<std::string> tokens = Split(line, ' ');
        if (tokens.empty()) continue;
        const std::string directive = Lower(tokens[0]);

        if (directive == "version") {
            std::uint64_t version_value = 0;
            if (tokens.size() != 2 || !ParseUint(tokens[1], version_value)) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": version requires one integer");
                return false;
            }
            if (version_value > std::numeric_limits<std::uint32_t>::max()) {
                SetError(error,
                         "line " + std::to_string(line_number) +
                             ": version out of range");
                return false;
            }
            config.schema_version = static_cast<std::uint32_t>(version_value);
            if (version_seen) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": duplicate version directive");
                return false;
            }
            if (config.schema_version != kConfigSchemaVersion) {
                SetError(error,
                         "line " + std::to_string(line_number) +
                             ": unsupported schema version " +
                             std::to_string(config.schema_version) +
                             " (expected 1)");
                return false;
            }
            version_seen = true;
        } else if (directive == "monitor") {
            if (tokens.size() != 6 || tokens[2] != "workspaces" ||
                tokens[4] != "active") {
                SetError(error,
                         "line " + std::to_string(line_number) +
                             ": monitor requires 'monitor <id> workspaces "
                             "<names> active <name>'");
                return false;
            }
            std::uint64_t monitor_value = 0;
            if (!ParseUint(tokens[1], monitor_value) || monitor_value == 0) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": monitor id must be a positive integer");
                return false;
            }
            const MonitorId monitor = static_cast<MonitorId>(monitor_value);
            if (!seen_monitors.insert(monitor).second) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": duplicate monitor definition");
                return false;
            }
            WorkspaceConfigEntry entry;
            entry.monitor = monitor;
            const std::vector<std::string> names = Split(tokens[3], ',');
            std::set<std::string> unique_names;
            for (const std::string& name : names) {
                const std::string trimmed = Trim(name);
                if (trimmed.empty() || !unique_names.insert(trimmed).second) {
                    SetError(error,
                             "line " + std::to_string(line_number) +
                                 ": workspace names must be non-empty and "
                                 "unique");
                    return false;
                }
                entry.workspace_names.push_back(trimmed);
            }
            if (entry.workspace_names.empty()) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": monitor requires at least one workspace");
                return false;
            }
            entry.active_name = tokens[5];
            if (std::find(entry.workspace_names.begin(),
                          entry.workspace_names.end(), entry.active_name) ==
                entry.workspace_names.end()) {
                SetError(error,
                         "line " + std::to_string(line_number) +
                             ": active workspace '" + entry.active_name +
                             "' is not defined for monitor " +
                             std::to_string(monitor_value));
                return false;
            }
            config.monitors.push_back(std::move(entry));
        } else if (directive == "hotkey") {
            if (tokens.size() != 4) {
                SetError(error,
                         "line " + std::to_string(line_number) +
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
            std::uint64_t monitor_value = 0;
            if (!ParseUint(tokens[2], monitor_value) || monitor_value == 0) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": hotkey monitor must be a positive "
                                    "integer");
                return false;
            }
            const MonitorId monitor = static_cast<MonitorId>(monitor_value);
            const WorkspaceConfigEntry* monitor_entry =
                FindMonitor(config, monitor);
            if (monitor_entry == nullptr) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": hotkey references undefined monitor " +
                                    std::to_string(monitor_value));
                return false;
            }
            WorkspaceId workspace = 0;
            if (!WorkspaceNameToId(*monitor_entry, tokens[3], workspace)) {
                SetError(error,
                         "line " + std::to_string(line_number) +
                             ": hotkey references undefined workspace '" +
                             tokens[3] + "' on monitor " +
                             std::to_string(monitor_value));
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
            config.bindings.push_back({hotkey, monitor, workspace});
        } else if (directive == "assignment") {
            if (tokens.size() != 3 ||
                Lower(tokens[1]) != "monitor-migration") {
                SetError(error,
                         "line " + std::to_string(line_number) +
                             ": assignment requires 'assignment "
                             "monitor-migration <reassign|fail-closed>'");
                return false;
            }
            const std::string value = Lower(tokens[2]);
            if (value == "reassign") {
                config.migration_policy =
                    MonitorMigrationPolicy::ReassignToDestinationActive;
            } else if (value == "fail-closed") {
                config.migration_policy = MonitorMigrationPolicy::FailClosed;
            } else {
                SetError(error,
                         "line " + std::to_string(line_number) +
                             ": monitor-migration must be 'reassign' or "
                             "'fail-closed'");
                return false;
            }
        } else if (directive == "log-level") {
            if (tokens.size() != 2) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": log-level requires one value");
                return false;
            }
            const std::string value = Lower(tokens[1]);
            if (value == "debug") {
                config.log_level = ManagerLogLevel::Debug;
            } else if (value == "info") {
                config.log_level = ManagerLogLevel::Info;
            } else if (value == "warn") {
                config.log_level = ManagerLogLevel::Warn;
            } else if (value == "error") {
                config.log_level = ManagerLogLevel::Error;
            } else {
                SetError(error,
                         "line " + std::to_string(line_number) +
                             ": log-level must be debug, info, warn, or error");
                return false;
            }
        } else if (directive == "quarantine") {
            if (tokens.size() != 2 ||
                (tokens[1] != "on" && tokens[1] != "off")) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": quarantine requires 'on' or 'off'");
                return false;
            }
            config.quarantine_enabled = tokens[1] == "on";
        } else if (directive == "journal") {
            if (tokens.size() != 2) {
                SetError(error, "line " + std::to_string(line_number) +
                                    ": journal requires one path");
                return false;
            }
            config.journal_path = tokens[1];
        } else if (directive == "tray") {
            if (tokens.size() != 2 ||
                (tokens[1] != "on" && tokens[1] != "off")) {
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
    if (!version_seen) {
        SetError(error, "missing schema version (version 1 required)");
        return false;
    }
    out = std::move(config);
    return true;
}

bool SaveManagerConfig(const WorkspaceManagerConfig& config,
                       const std::filesystem::path& path,
                       std::string* error) {
    if (config.schema_version != kConfigSchemaVersion) {
        SetError(error,
                 "config schema version " +
                     std::to_string(config.schema_version) +
                     " is not representable (expected 1)");
        return false;
    }
    // Write to a same-directory temporary and atomically replace so a
    // crash mid-save can never leave a truncated config behind.
    std::filesystem::path temporary = path;
    temporary += L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." +
                 std::to_wstring(GetCurrentThreadId()) + L"." +
                std::to_wstring(GetTickCount64());
    std::ofstream stream(temporary, std::ios::out | std::ios::trunc);
    if (!stream) {
        SetError(error, "cannot open config path for writing: " +
                            path.string());
        return false;
    }
    stream << "version " << kConfigSchemaVersion << "\n";
    for (const WorkspaceConfigEntry& entry : config.monitors) {
        stream << "monitor " << static_cast<std::uint64_t>(entry.monitor)
               << " workspaces " << JoinNames(entry.workspace_names)
               << " active " << entry.active_name << "\n";
    }
    for (const WorkspaceHotkeyBinding& binding : config.bindings) {
        const WorkspaceConfigEntry* monitor_entry =
            FindMonitor(config, binding.monitor);
        std::string workspace_name;
        if (monitor_entry == nullptr ||
            !WorkspaceIdToName(*monitor_entry, binding.workspace,
                               workspace_name)) {
            SetError(error,
                     "binding references an undefined monitor/workspace");
            return false;
        }
        stream << "hotkey " << ModifiersText(binding.hotkey.modifiers) << "+"
               << KeyText(binding.hotkey.vk) << " "
               << static_cast<std::uint64_t>(binding.monitor) << " "
               << workspace_name << "\n";
    }
    stream << "assignment monitor-migration "
           << (config.migration_policy ==
                       MonitorMigrationPolicy::ReassignToDestinationActive
                   ? "reassign"
                   : "fail-closed")
           << "\n";
    switch (config.log_level) {
        case ManagerLogLevel::Debug:
            stream << "log-level debug\n";
            break;
        case ManagerLogLevel::Info:
            stream << "log-level info\n";
            break;
        case ManagerLogLevel::Warn:
            stream << "log-level warn\n";
            break;
        case ManagerLogLevel::Error:
            stream << "log-level error\n";
            break;
    }
    stream << "quarantine " << (config.quarantine_enabled ? "on" : "off")
           << "\n";
    if (!config.journal_path.empty()) {
        stream << "journal " << config.journal_path.generic_string() << "\n";
    }
    stream << "tray " << (config.tray_icon ? "on" : "off") << "\n";
    if (!stream) {
        SetError(error, "failed while writing config: " + path.string());
        return false;
    }
    stream.flush();
    stream.close();
    if (!::MoveFileExW(temporary.c_str(), path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        SetError(error, "cannot replace config path: " + path.string());
        return false;
    }
    return true;
}

bool LoadManagerConfig(const std::filesystem::path& path,
                       WorkspaceManagerConfig& out, std::string* error) {
    std::ifstream stream(path);
    if (!stream) {
        SetError(error, "cannot open config path for reading: " +
                            path.string());
        return false;
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    if (!stream && !stream.eof()) {
        SetError(error, "failed while reading config: " + path.string());
        return false;
    }
    return ParseWorkspaceManagerConfig(buffer.str(), out, error);
}

std::filesystem::path DefaultManagerConfigPath() {
    wchar_t buffer[MAX_PATH] = {};
    const DWORD size =
        ::GetEnvironmentVariableW(L"APPDATA", buffer, MAX_PATH);
    if (size == 0 || size >= MAX_PATH) {
        return std::filesystem::current_path() / "workspace-manager.conf";
    }
    return std::filesystem::path(buffer) / L"vdprobe" /
           L"workspace-manager.conf";
}

bool DeriveManagerRuntimeTopology(
    const WorkspaceManagerConfig& config,
    const std::vector<HMONITOR>& real_monitors,
    ManagerRuntimeTopology& out, std::string* error) {
    if (error != nullptr) error->clear();
    if (config.schema_version != kConfigSchemaVersion) {
        SetError(error,
                 "config schema version " +
                     std::to_string(config.schema_version) +
                     " is not supported (expected 1)");
        return false;
    }
    if (config.monitors.size() > real_monitors.size()) {
        SetError(error,
                 "config defines " + std::to_string(config.monitors.size()) +
                     " monitors but only " +
                     std::to_string(real_monitors.size()) +
                     " are currently present");
        return false;
    }
    ManagerRuntimeTopology topology;
    for (std::size_t i = 0; i < config.monitors.size(); ++i) {
        const WorkspaceConfigEntry& entry = config.monitors[i];
        if (real_monitors[i] == nullptr) {
            SetError(error, "real monitor list contains a null handle");
            return false;
        }
        WorkspaceId local_active = 0;
        if (!WorkspaceNameToId(entry, entry.active_name, local_active)) {
            SetError(error, "configured active workspace '" +
                                entry.active_name +
                                "' is not defined for monitor " +
                                std::to_string(
                                    static_cast<std::uint64_t>(entry.monitor)));
            return false;
        }
        ManagerRuntimeTopology::MonitorBinding binding;
        binding.real_monitor = reinterpret_cast<MonitorId>(real_monitors[i]);
        binding.workspace_count = entry.workspace_names.size();
        binding.active_name = entry.active_name;
        const WorkspaceId offset =
            static_cast<WorkspaceId>(i) * 1000ULL + 1ULL;
        for (std::size_t w = 0; w < entry.workspace_names.size(); ++w) {
            binding.workspace_ids.push_back(offset +
                                            static_cast<WorkspaceId>(w));
        }
        binding.active = offset + static_cast<WorkspaceId>(local_active - 1);
        topology.monitors.push_back(std::move(binding));
    }
    for (const WorkspaceHotkeyBinding& binding : config.bindings) {
        std::size_t index = 0;
        bool found = false;
        for (std::size_t i = 0; i < config.monitors.size(); ++i) {
            if (config.monitors[i].monitor == binding.monitor) {
                index = i;
                found = true;
                break;
            }
        }
        if (!found) {
            SetError(error,
                     "hotkey binding references undefined monitor " +
                         std::to_string(
                             static_cast<std::uint64_t>(binding.monitor)));
            return false;
        }
        WorkspaceHotkeyBinding remapped = binding;
        remapped.monitor = reinterpret_cast<MonitorId>(real_monitors[index]);
        const WorkspaceId offset =
            static_cast<WorkspaceId>(index) * 1000ULL + 1ULL;
        remapped.workspace =
            offset + static_cast<WorkspaceId>(remapped.workspace - 1);
        topology.bindings.push_back(std::move(remapped));
    }
    out = std::move(topology);
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
    Field("scope",
          "deterministic config parsing, validation, persistence, dispatch");
    Field("native mutation", "none");

    const std::string valid =
        "# vdprobe workspace manager\n"
        "version 1\n"
        "monitor 1 workspaces A1,A2,A3 active A1\n"
        "monitor 2 workspaces B1,B2 active B1\n"
        "hotkey Ctrl+Alt+F9 1 A2\n"
        "hotkey Ctrl+Alt+F10 1 A1\n"
        "hotkey Ctrl+Alt+Shift+F9 2 B2\n"
        "assignment monitor-migration fail-closed\n"
        "log-level warn\n"
        "quarantine off\n"
        "journal C:/tmp/vdprobe-manager.journal\n"
        "tray on\n";
    WorkspaceManagerConfig config;
    std::string error;
    bool ok = ParseWorkspaceManagerConfig(valid, config, &error);
    ok = ok && config.schema_version == 1 &&
         config.monitors.size() == 2 &&
         config.monitors[0].monitor == static_cast<MonitorId>(1) &&
         config.monitors[0].workspace_names.size() == 3 &&
         config.monitors[0].workspace_names[0] == "A1" &&
         config.monitors[0].active_name == "A1" &&
         config.monitors[1].workspace_names.size() == 2 &&
         config.monitors[1].active_name == "B1" &&
         config.bindings.size() == 3 &&
         config.bindings[0].hotkey.modifiers == (MOD_CONTROL | MOD_ALT) &&
         config.bindings[0].hotkey.vk == VK_F9 &&
         config.bindings[0].monitor == static_cast<MonitorId>(1) &&
         config.bindings[0].workspace == 2 &&
         config.bindings[2].hotkey.modifiers ==
             (MOD_CONTROL | MOD_ALT | MOD_SHIFT) &&
         config.bindings[2].workspace == 2 &&
         config.migration_policy == MonitorMigrationPolicy::FailClosed &&
         config.log_level == ManagerLogLevel::Warn &&
         !config.quarantine_enabled &&
         config.journal_path == L"C:/tmp/vdprobe-manager.journal" &&
         config.tray_icon;
    Field("valid v1 config parsed", ok ? "PASS" : "FAIL");

    MonitorId monitor = 0;
    WorkspaceId workspace = 0;
    ok = ok &&
         ResolveWorkspaceHotkey(config, MOD_CONTROL | MOD_ALT, VK_F9,
                                monitor, workspace) &&
         monitor == static_cast<MonitorId>(1) && workspace == 2 &&
         ResolveWorkspaceHotkey(config, MOD_CONTROL | MOD_ALT | MOD_SHIFT,
                                VK_F9, monitor, workspace) &&
         monitor == static_cast<MonitorId>(2) && workspace == 2;
    Field("hotkey dispatch resolves bindings", ok ? "PASS" : "FAIL");

    bool unmatched = !ResolveWorkspaceHotkey(config, MOD_CONTROL | MOD_ALT,
                                             VK_F8, monitor, workspace);
    Field("unbound hotkey rejected", unmatched ? "PASS" : "FAIL");
    ok = ok && unmatched;

    const std::string duplicate =
        "version 1\n"
        "monitor 1 workspaces A1,A2 active A1\n"
        "hotkey Ctrl+Alt+F9 1 A2\n"
        "hotkey Ctrl+Alt+F9 1 A1\n";
    WorkspaceManagerConfig ignored;
    const bool duplicate_rejected =
        !ParseWorkspaceManagerConfig(duplicate, ignored, &error) &&
        error.find("duplicate") != std::string::npos;
    Field("duplicate hotkey rejected", duplicate_rejected ? "PASS" : "FAIL");
    ok = ok && duplicate_rejected;

    const std::string missing_version = "monitor 1 workspaces A1 active A1\n";
    const bool missing_version_rejected =
        !ParseWorkspaceManagerConfig(missing_version, ignored, &error) &&
        error.find("version") != std::string::npos;
    Field("missing schema version rejected",
          missing_version_rejected ? "PASS" : "FAIL");
    ok = ok && missing_version_rejected;

    const std::string wrong_version =
        "version 2\nmonitor 1 workspaces A1 active A1\n";
    const bool wrong_version_rejected =
        !ParseWorkspaceManagerConfig(wrong_version, ignored, &error) &&
        error.find("unsupported schema version") != std::string::npos;
    Field("unsupported schema version rejected",
          wrong_version_rejected ? "PASS" : "FAIL");
    ok = ok && wrong_version_rejected;

    const std::string duplicate_monitor =
        "version 1\n"
        "monitor 1 workspaces A1,A2 active A1\n"
        "monitor 1 workspaces B1,B2 active B1\n";
    const bool duplicate_monitor_rejected =
        !ParseWorkspaceManagerConfig(duplicate_monitor, ignored, &error) &&
        error.find("duplicate monitor") != std::string::npos;
    Field("duplicate monitor rejected",
          duplicate_monitor_rejected ? "PASS" : "FAIL");
    ok = ok && duplicate_monitor_rejected;

    const std::string bad_active =
        "version 1\nmonitor 1 workspaces A1,A2 active A3\n";
    const bool bad_active_rejected =
        !ParseWorkspaceManagerConfig(bad_active, ignored, &error) &&
        error.find("active workspace") != std::string::npos;
    Field("undefined active workspace rejected",
          bad_active_rejected ? "PASS" : "FAIL");
    ok = ok && bad_active_rejected;

    const std::string unknown_workspace =
        "version 1\n"
        "monitor 1 workspaces A1,A2 active A1\n"
        "hotkey Ctrl+Alt+F9 1 A9\n";
    const bool unknown_workspace_rejected =
        !ParseWorkspaceManagerConfig(unknown_workspace, ignored, &error) &&
        error.find("undefined workspace") != std::string::npos;
    Field("undefined hotkey workspace rejected",
          unknown_workspace_rejected ? "PASS" : "FAIL");
    ok = ok && unknown_workspace_rejected;

    const std::string bad_migration =
        "version 1\nmonitor 1 workspaces A1 active A1\n"
        "assignment monitor-migration maybe\n";
    const bool bad_migration_rejected =
        !ParseWorkspaceManagerConfig(bad_migration, ignored, &error) &&
        error.find("monitor-migration") != std::string::npos;
    Field("invalid migration policy rejected",
          bad_migration_rejected ? "PASS" : "FAIL");
    ok = ok && bad_migration_rejected;

    const std::string bad_log_level =
        "version 1\nmonitor 1 workspaces A1 active A1\n"
        "log-level chatty\n";
    const bool bad_log_level_rejected =
        !ParseWorkspaceManagerConfig(bad_log_level, ignored, &error) &&
        error.find("log-level") != std::string::npos;
    Field("invalid log level rejected",
          bad_log_level_rejected ? "PASS" : "FAIL");
    ok = ok && bad_log_level_rejected;

    const std::string bad_quarantine =
        "version 1\nmonitor 1 workspaces A1 active A1\n"
        "quarantine maybe\n";
    const bool bad_quarantine_rejected =
        !ParseWorkspaceManagerConfig(bad_quarantine, ignored, &error) &&
        error.find("quarantine") != std::string::npos;
    Field("invalid quarantine value rejected",
          bad_quarantine_rejected ? "PASS" : "FAIL");
    ok = ok && bad_quarantine_rejected;

    const std::string unknown_directive = "version 1\nfrobnicate 1\n";
    const bool unknown_directive_rejected =
        !ParseWorkspaceManagerConfig(unknown_directive, ignored, &error) &&
        error.find("directive") != std::string::npos;
    Field("unknown directive rejected",
          unknown_directive_rejected ? "PASS" : "FAIL");
    ok = ok && unknown_directive_rejected;

    const std::filesystem::path roundtrip_path =
        std::filesystem::temp_directory_path() /
        "vdprobe-manager-config-roundtrip.conf";
    std::error_code remove_error;
    std::filesystem::remove(roundtrip_path, remove_error);
    WorkspaceManagerConfig loaded;
    const bool roundtrip_ok =
        SaveManagerConfig(config, roundtrip_path, &error) &&
        LoadManagerConfig(roundtrip_path, loaded, &error) &&
        loaded.schema_version == config.schema_version &&
        loaded.monitors.size() == config.monitors.size() &&
        loaded.monitors[0].monitor == config.monitors[0].monitor &&
        loaded.monitors[0].workspace_names ==
            config.monitors[0].workspace_names &&
        loaded.monitors[0].active_name == config.monitors[0].active_name &&
        loaded.bindings.size() == config.bindings.size() &&
        loaded.bindings[0].hotkey == config.bindings[0].hotkey &&
        loaded.bindings[0].workspace == config.bindings[0].workspace &&
        loaded.migration_policy == config.migration_policy &&
        loaded.log_level == config.log_level &&
        loaded.quarantine_enabled == config.quarantine_enabled &&
        loaded.journal_path == config.journal_path &&
        loaded.tray_icon == config.tray_icon;
    std::filesystem::remove(roundtrip_path, remove_error);
    Field("config save/load round-trip", roundtrip_ok ? "PASS" : "FAIL");
    ok = ok && roundtrip_ok;

    const std::vector<HMONITOR> real_monitors = {
        reinterpret_cast<HMONITOR>(0x100), reinterpret_cast<HMONITOR>(0x200)};
    ManagerRuntimeTopology topology;
    const bool topology_ok =
        DeriveManagerRuntimeTopology(config, real_monitors, topology, &error) &&
        topology.monitors.size() == 2 &&
        topology.monitors[0].real_monitor ==
            static_cast<MonitorId>(0x100ULL) &&
        topology.monitors[0].workspace_count == 3 &&
        topology.monitors[0].active == 1 &&
        topology.monitors[0].active_name == "A1" &&
        topology.monitors[0].workspace_ids.size() == 3 &&
        topology.monitors[0].workspace_ids[0] == 1 &&
        topology.monitors[0].workspace_ids[2] == 3 &&
        topology.monitors[1].real_monitor ==
            static_cast<MonitorId>(0x200ULL) &&
        topology.monitors[1].active == 1001 &&
        topology.monitors[1].workspace_ids.size() == 2 &&
        topology.monitors[1].workspace_ids[1] == 1002 &&
        topology.bindings.size() == 3 &&
        topology.bindings[0].monitor ==
            static_cast<MonitorId>(0x100ULL) &&
        topology.bindings[0].workspace == 2 &&
        topology.bindings[2].monitor ==
            static_cast<MonitorId>(0x200ULL) &&
        topology.bindings[2].workspace == 1002;
    Field("config derives runtime topology", topology_ok ? "PASS" : "FAIL");
    ok = ok && topology_ok;

    WorkspaceManagerConfig extra_monitors = config;
    extra_monitors.monitors.push_back(
        {static_cast<MonitorId>(3), {"C1"}, "C1"});
    const bool too_many_monitors_rejected =
        !DeriveManagerRuntimeTopology(extra_monitors, real_monitors, topology,
                                      &error) &&
        error.find("only") != std::string::npos;
    Field("extra configured monitors rejected",
          too_many_monitors_rejected ? "PASS" : "FAIL");
    ok = ok && too_many_monitors_rejected;

    Field("result", ok ? "PASS" : "FAIL");
    Print("RESULT={}\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

}  // namespace vd
