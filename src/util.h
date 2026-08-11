// util.h - console/string/GUID/HRESULT helpers shared by every subcommand.
#pragma once

#include <windows.h>
#include <objbase.h>

#include <cstdint>
#include <format>
#include <string>
#include <string_view>

namespace vd {

// ---------------------------------------------------------------- console I/O

// Switches the console to UTF-8 so wide window titles survive printing.
void InitConsole();

void Write(std::string_view text);

template <class... Args>
void Print(std::format_string<Args...> fmt, Args&&... args) {
    Write(std::format(fmt, std::forward<Args>(args)...));
}

// Section header, e.g. "== system =="
void Heading(std::string_view title);

// "key: value" aligned to a fixed column.
void Field(std::string_view key, std::string_view value);

// ------------------------------------------------------------------- strings

std::string ToUtf8(std::wstring_view w);
std::wstring ToWide(std::string_view s);

// Lowercase ASCII copy, used for case-insensitive argument matching.
std::string ToLowerAscii(std::string_view s);

// ------------------------------------------------------------------ GUID/HR

// Canonical registry form: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
std::string GuidToString(const GUID& g);

// Accepts the braced or unbraced canonical form.
bool GuidFromString(std::string_view s, GUID& out);

// "0x80004002 (E_NOINTERFACE)" - well-known codes are named, others are not
// invented.
std::string HrToString(HRESULT hr);

// ------------------------------------------------------------------- modules

// GetFileVersionInfo wrapper. Returns empty string when unavailable.
//
// Windows system binaries routinely carry two different versions: the binary
// VS_FIXEDFILEINFO fields (often 6.2.x for compatibility) and the
// StringFileInfo "FileVersion" string (10.0.x).  Both are reported so the
// difference cannot be mistaken for an error.
struct ModuleVersion {
    std::string fixed;   // from VS_FIXEDFILEINFO
    std::string string_; // from StringFileInfo\<lang>\FileVersion
    bool ok = false;
    // "10.0.26100.8875 (VS_FIXEDFILEINFO 6.2.26100.8875)"
    std::string Describe() const;
};

ModuleVersion VersionOf(const std::wstring& path);

// Convenience for callers that only want one line of text.
std::string FileVersionOf(const std::wstring& path);

// Expands to %SystemRoot%\System32\<name>.
std::wstring System32Path(std::wstring_view name);

// ---------------------------------------------------------------- late bind

// GetProcAddress on an already-loaded-or-loadable module without failing the
// process when the module is missing.
FARPROC TryGetProc(const wchar_t* module, const char* symbol);

template <class Fn>
Fn TryGetProcAs(const wchar_t* module, const char* symbol) {
    return reinterpret_cast<Fn>(TryGetProc(module, symbol));
}

}  // namespace vd
