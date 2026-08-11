#include "util.h"

#include <cstdio>
#include <cwctype>
#include <vector>

namespace vd {
namespace {

constexpr int kFieldWidth = 30;

struct NamedHr {
    HRESULT hr;
    const char* name;
};

// Only codes we actually expect to see are named; unknown codes are printed
// numerically rather than mislabelled.
constexpr HRESULT Hr(unsigned long v) { return static_cast<HRESULT>(v); }

constexpr NamedHr kKnownHr[] = {
    {S_OK, "S_OK"},
    {S_FALSE, "S_FALSE"},
    {E_NOINTERFACE, "E_NOINTERFACE"},
    {E_NOTIMPL, "E_NOTIMPL"},
    {E_POINTER, "E_POINTER"},
    {E_FAIL, "E_FAIL"},
    {E_INVALIDARG, "E_INVALIDARG"},
    {E_ACCESSDENIED, "E_ACCESSDENIED"},
    {E_OUTOFMEMORY, "E_OUTOFMEMORY"},
    {E_UNEXPECTED, "E_UNEXPECTED"},
    {E_ABORT, "E_ABORT (refused by the layout gate)"},
    {Hr(0x80040154), "REGDB_E_CLASSNOTREG"},
    {Hr(0x80040155), "REGDB_E_IIDNOTREG"},
    {Hr(0x800401F0), "CO_E_NOTINITIALIZED"},
    {Hr(0x80070005), "HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)"},
    {Hr(0x80070490), "HRESULT_FROM_WIN32(ERROR_NOT_FOUND)"},
    {Hr(0x8007000E), "HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY)"},
    {Hr(0x800706BA), "RPC_S_SERVER_UNAVAILABLE"},
    {Hr(0x800706BE), "RPC_S_CALL_FAILED"},
    {Hr(0x80010108), "RPC_E_DISCONNECTED"},
    {Hr(0x8001010E), "RPC_E_WRONG_THREAD"},
};

}  // namespace

void InitConsole() {
    ::SetConsoleOutputCP(CP_UTF8);
    // Line buffering keeps interleaved stdout/stderr readable when redirected.
    std::setvbuf(stdout, nullptr, _IOFBF, 1 << 16);
}

void Write(std::string_view text) {
    std::fwrite(text.data(), 1, text.size(), stdout);
}

void Heading(std::string_view title) {
    Print("\n== {} ==\n", title);
}

void Field(std::string_view key, std::string_view value) {
    int pad = kFieldWidth - static_cast<int>(key.size());
    if (pad < 1) pad = 1;
    Print("  {}{}{}\n", key, std::string(static_cast<size_t>(pad), ' '), value);
}

std::string ToUtf8(std::wstring_view w) {
    if (w.empty()) return {};
    int need = ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
                                     nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(static_cast<size_t>(need), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(),
                          need, nullptr, nullptr);
    return out;
}

std::wstring ToWide(std::string_view s) {
    if (s.empty()) return {};
    int need = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                     nullptr, 0);
    if (need <= 0) return {};
    std::wstring out(static_cast<size_t>(need), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(),
                          need);
    return out;
}

std::string ToLowerAscii(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return out;
}

std::string GuidToString(const GUID& g) {
    return std::format(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.Data1, g.Data2, g.Data3, g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
}

bool GuidFromString(std::string_view s, GUID& out) {
    std::string t(s);
    if (t.size() == 38 && t.front() == '{' && t.back() == '}') t = t.substr(1, 36);
    if (t.size() != 36) return false;
    std::wstring w = L"{" + ToWide(t) + L"}";
    return ::IIDFromString(w.c_str(), &out) == S_OK;
}

std::string HrToString(HRESULT hr) {
    for (const NamedHr& k : kKnownHr) {
        if (k.hr == hr) {
            return std::format("0x{:08X} ({})", static_cast<uint32_t>(hr), k.name);
        }
    }
    return std::format("0x{:08X}", static_cast<uint32_t>(hr));
}

std::string ModuleVersion::Describe() const {
    if (!ok) return "(unavailable)";
    if (string_.empty()) return std::format("{} (VS_FIXEDFILEINFO)", fixed);
    if (string_ == fixed) return fixed;
    return std::format("{} (VS_FIXEDFILEINFO {})", string_, fixed);
}

ModuleVersion VersionOf(const std::wstring& path) {
    ModuleVersion out;
    DWORD dummy = 0;
    DWORD size = ::GetFileVersionInfoSizeW(path.c_str(), &dummy);
    if (size == 0) return out;
    std::vector<BYTE> buf(size);
    if (!::GetFileVersionInfoW(path.c_str(), 0, size, buf.data())) return out;

    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT len = 0;
    if (::VerQueryValueW(buf.data(), L"\\", reinterpret_cast<LPVOID*>(&ffi), &len) &&
        ffi != nullptr && len != 0) {
        out.fixed = std::format("{}.{}.{}.{}", HIWORD(ffi->dwFileVersionMS),
                                LOWORD(ffi->dwFileVersionMS),
                                HIWORD(ffi->dwFileVersionLS),
                                LOWORD(ffi->dwFileVersionLS));
        out.ok = true;
    }

    // The StringFileInfo block is keyed by language/codepage, which has to be
    // read from VarFileInfo first.
    struct LangCp {
        WORD lang;
        WORD cp;
    };
    LangCp* trans = nullptr;
    UINT tlen = 0;
    if (::VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation",
                         reinterpret_cast<LPVOID*>(&trans), &tlen) &&
        trans != nullptr && tlen >= sizeof(LangCp)) {
        std::wstring key = std::format(L"\\StringFileInfo\\{:04x}{:04x}\\FileVersion",
                                       trans[0].lang, trans[0].cp);
        wchar_t* value = nullptr;
        UINT vlen = 0;
        if (::VerQueryValueW(buf.data(), key.c_str(),
                             reinterpret_cast<LPVOID*>(&value), &vlen) &&
            value != nullptr && vlen != 0) {
            std::wstring_view sv(value, vlen);
            while (!sv.empty() && (sv.back() == L'\0')) sv.remove_suffix(1);
            // Windows appends a build tag, e.g. " (WinBuild.160101.0800)".
            size_t space = sv.find(L' ');
            if (space != std::wstring_view::npos) sv = sv.substr(0, space);
            out.string_ = ToUtf8(sv);
            out.ok = true;
        }
    }
    return out;
}

std::string FileVersionOf(const std::wstring& path) {
    ModuleVersion v = VersionOf(path);
    return v.ok ? v.Describe() : std::string{};
}

std::wstring System32Path(std::wstring_view name) {
    wchar_t dir[MAX_PATH]{};
    UINT n = ::GetSystemDirectoryW(dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return std::wstring(name);
    std::wstring p(dir, n);
    p += L'\\';
    p += name;
    return p;
}

FARPROC TryGetProc(const wchar_t* module, const char* symbol) {
    HMODULE h = ::GetModuleHandleW(module);
    if (h == nullptr) {
        h = ::LoadLibraryExW(module, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    }
    if (h == nullptr) return nullptr;
    return ::GetProcAddress(h, symbol);
}

}  // namespace vd
