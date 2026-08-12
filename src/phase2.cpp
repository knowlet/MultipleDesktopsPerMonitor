#include "phase2.h"

#include <objectarray.h>
#include <shobjidl.h>
#include <shellapi.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <filesystem>
#include <tlhelp32.h>
#include <unordered_map>

#include "notifysink.h"
#include "phase1.h"
#include "util.h"
#include "workspace_coordinator.h"
#include "workspace_engine.h"
#include "window_discovery.h"

namespace vd {
namespace {

// Upper bound when walking a vtable looking for the end of an interface.  The
// figure is only ever reported, never used to pick a slot.
constexpr unsigned kVtableProbeCap = 256;
// Conventional skip/inconclusive status used by gated probes when the host
// cannot provide the shell access needed to make a meaningful determination.
constexpr int kExitInconclusive = 77;

// HSTRING handling is late-bound: combase.dll is always present on the builds we
// care about, but binding it lazily keeps vdprobe startable everywhere.
using WindowsGetStringRawBufferFn = const wchar_t*(WINAPI*)(void*, UINT32*);
using WindowsDeleteStringFn = HRESULT(WINAPI*)(void*);

std::string TakeHString(void* hs) {
    if (hs == nullptr) return {};
    static auto get_raw = TryGetProcAs<WindowsGetStringRawBufferFn>(
        L"combase.dll", "WindowsGetStringRawBuffer");
    static auto del =
        TryGetProcAs<WindowsDeleteStringFn>(L"combase.dll", "WindowsDeleteString");
    std::string out;
    if (get_raw != nullptr) {
        UINT32 len = 0;
        const wchar_t* p = get_raw(hs, &len);
        if (p != nullptr) out = ToUtf8(std::wstring_view(p, len));
    }
    if (del != nullptr) del(hs);
    return out;
}

// The service id used to reach a logical interface.  IApplicationViewCollection
// is reached using its own IID as the service id, which is how every public
// implementation does it.
const GUID* ServiceIdFor(const char* iface, const GUID* iid) {
    if (std::strcmp(iface, "IVirtualDesktopManagerInternal") == 0) {
        return &SID_VirtualDesktopManagerInternal;
    }
    if (std::strcmp(iface, "IVirtualDesktopPinnedApps") == 0) {
        return &SID_VirtualDesktopPinnedApps;
    }
    if (std::strcmp(iface, "IVirtualDesktopNotificationService") == 0) {
        return &SID_VirtualDesktopNotificationService;
    }
    if (std::strcmp(iface, "IApplicationViewCollection") == 0) return iid;
    return nullptr;  // not reachable via QueryService
}

void DescribeObject(IUnknown* obj, ProbeResult& r) {
    void** vt = VtableOf(obj);
    if (vt != nullptr) r.vtable_module = ModuleOf(vt);
    GUID pid{};
    if (TryReadProxyIid(obj, pid)) {
        r.proxy_iid_ok = true;
        r.proxy_iid = pid;
    }
    r.vtable_run = ProbeVtableCodeRun(obj, kVtableProbeCap);
}

// Explains the vtable-run figure honestly.  On this build the ImmersiveShell
// interfaces are marshalled by combase's generic forwarding table rather than a
// per-interface MIDL CInterfaceProxyVtbl, so the run does NOT terminate at the
// end of the interface and cannot be used as a method count.  Saying so is more
// useful than printing a number that means nothing.
std::string VtableRunText(const ProbeResult& r) {
    if (r.vtable_run >= kVtableProbeCap) {
        return std::format(
            "indeterminate (>= {} consecutive code pointers; generic proxy table, "
            "not a per-interface MIDL vtable)",
            kVtableProbeCap);
    }
    return std::format("{} entries => {} methods after IUnknown", r.vtable_run,
                       r.vtable_run >= 3 ? r.vtable_run - 3 : 0);
}

void PrintProbeRow(const ProbeResult& r) {
    const IidCandidate& c = *r.candidate;
    Print("  {:<7} {} {}\n", r.obtained ? "ACCEPT" : "reject", GuidToString(*c.iid),
          c.builds);
    if (!r.obtained) {
        Print("          hr={}\n", HrToString(r.hr));
        return;
    }
    Print("          vtable module : {}\n",
          r.vtable_module.empty() ? "?" : r.vtable_module);
    Print("          vtable run    : {}\n", VtableRunText(r));
    if (r.proxy_iid_ok) {
        const bool match = ::IsEqualGUID(r.proxy_iid, *c.iid) != FALSE;
        if (match) {
            Print("          MIDL proxy header IID matches the request\n");
        } else {
            Print(
                "          no MIDL CInterfaceProxyVtbl header (vtbl[-1] is not this "
                "IID)\n");
        }
    }
    if (const LayoutTable* t = LayoutForIid(*c.iid)) {
        int max_slot = 0;
        for (const MethodEntry& m : t->methods) {
            if (m.slot > max_slot) max_slot = m.slot;
        }
        Print("          verified layout: {} methods, highest slot {}\n",
              max_slot >= 3 ? max_slot - 2 : 0, max_slot);
    }
}

// ---------------------------------------------------------- registry evidence

void DumpRegValues(HKEY key, const std::string& prefix) {
    DWORD count = 0, max_name = 0, max_data = 0;
    if (::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                           &count, &max_name, &max_data, nullptr,
                           nullptr) != ERROR_SUCCESS) {
        return;
    }
    std::vector<wchar_t> name(max_name + 2);
    std::vector<BYTE> data(max_data + 2);
    for (DWORD i = 0; i < count; ++i) {
        DWORD nlen = static_cast<DWORD>(name.size());
        DWORD dlen = static_cast<DWORD>(data.size());
        DWORD type = 0;
        if (::RegEnumValueW(key, i, name.data(), &nlen, nullptr, &type, data.data(),
                            &dlen) != ERROR_SUCCESS) {
            continue;
        }
        std::string n = ToUtf8(std::wstring_view(name.data(), nlen));
        if (n.empty()) n = "(default)";
        if (type == REG_BINARY && dlen % sizeof(GUID) == 0 && dlen > 0) {
            Print("    {}{} = {} GUID(s):\n", prefix, n, dlen / sizeof(GUID));
            for (DWORD g = 0; g < dlen / sizeof(GUID); ++g) {
                GUID id{};
                std::memcpy(&id, data.data() + g * sizeof(GUID), sizeof(GUID));
                Print("        [{}] {}\n", g, GuidToString(id));
            }
        } else if (type == REG_SZ) {
            Print("    {}{} = \"{}\"\n", prefix, n,
                  ToUtf8(reinterpret_cast<const wchar_t*>(data.data())));
        } else if (type == REG_DWORD && dlen == 4) {
            DWORD v = 0;
            std::memcpy(&v, data.data(), 4);
            Print("    {}{} = {} (dword)\n", prefix, n, v);
        } else {
            Print("    {}{} = <type {}, {} bytes>\n", prefix, n, type, dlen);
        }
    }
}

void DumpRegTree(HKEY root, const std::wstring& path, int depth, int max_depth) {
    HKEY key = nullptr;
    if (::RegOpenKeyExW(root, path.c_str(), 0, KEY_READ, &key) != ERROR_SUCCESS) {
        Print("    (cannot open {})\n", ToUtf8(path));
        return;
    }
    std::string indent(static_cast<size_t>(depth) * 2, ' ');
    DumpRegValues(key, indent);
    if (depth < max_depth) {
        DWORD i = 0;
        wchar_t sub[256];
        DWORD slen = 256;
        while (::RegEnumKeyExW(key, i, sub, &slen, nullptr, nullptr, nullptr, nullptr) ==
               ERROR_SUCCESS) {
            Print("    {}[{}]\n", indent, ToUtf8(std::wstring_view(sub, slen)));
            DumpRegTree(root, path + L"\\" + std::wstring(sub, slen), depth + 1,
                        max_depth);
            ++i;
            slen = 256;
        }
    }
    ::RegCloseKey(key);
}

// --------------------------------------------------- binary presence evidence

// Searches a file on disk for the raw little-endian bytes of a GUID.  This
// distinguishes "the interface revision is present but not registered" (dead
// code) from "the revision is gone from the binary" (removed).  Read-only.
struct GuidScan {
    bool file_ok = false;
    size_t occurrences = 0;
};

GuidScan ScanFileForGuid(const std::wstring& path, const GUID& guid) {
    GuidScan out;
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return out;
    out.file_ok = true;

    unsigned char needle[sizeof(GUID)];
    std::memcpy(needle, &guid, sizeof(GUID));

    constexpr DWORD kChunk = 1u << 20;
    std::vector<unsigned char> buf(kChunk + sizeof(GUID) - 1);
    size_t carry = 0;
    for (;;) {
        DWORD got = 0;
        if (!::ReadFile(h, buf.data() + carry, kChunk, &got, nullptr) || got == 0) break;
        const size_t span = carry + got;
        for (size_t i = 0; i + sizeof(GUID) <= span; ++i) {
            if (buf[i] == needle[0] &&
                std::memcmp(buf.data() + i, needle, sizeof(GUID)) == 0) {
                ++out.occurrences;
            }
        }
        // Keep the tail so a GUID straddling two chunks is still found.
        carry = (span >= sizeof(GUID) - 1) ? sizeof(GUID) - 1 : span;
        std::memmove(buf.data(), buf.data() + span - carry, carry);
    }
    ::CloseHandle(h);
    return out;
}

std::wstring WindowsPath(std::wstring_view name) {
    wchar_t dir[MAX_PATH]{};
    UINT n = ::GetWindowsDirectoryW(dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return std::wstring(name);
    return std::wstring(dir, n) + L"\\" + std::wstring(name);
}

std::wstring SystemExplorerPath() {
    wchar_t dir[MAX_PATH]{};
    UINT n = ::GetWindowsDirectoryW(dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    return std::wstring(dir, n) + L"\\explorer.exe";
}

std::wstring EnvironmentPath(const wchar_t* name) {
    if (name == nullptr) return {};
    DWORD need = ::GetEnvironmentVariableW(name, nullptr, 0);
    if (need == 0) return {};
    std::wstring value(static_cast<size_t>(need), L'\0');
    DWORD got = ::GetEnvironmentVariableW(name, value.data(), need);
    if (got == 0 || got >= need) return {};
    value.resize(got);
    return value;
}

std::wstring NormalizeFilesystemPath(std::wstring value) {
    std::replace(value.begin(), value.end(), L'/', L'\\');
    if (value.rfind(L"\\\\?\\", 0) == 0) value.erase(0, 4);
    while (value.size() > 3 && value.back() == L'\\') value.pop_back();
    return value;
}

std::wstring FullExistingPath(const std::wstring& candidate) {
    if (candidate.empty() ||
        ::GetFileAttributesW(candidate.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return {};
    }
    std::vector<wchar_t> buffer(32768);
    DWORD n = ::GetFullPathNameW(candidate.c_str(),
                                 static_cast<DWORD>(buffer.size()),
                                 buffer.data(), nullptr);
    if (n == 0 || n >= buffer.size()) return {};
    return NormalizeFilesystemPath(std::wstring(buffer.data(), n));
}

std::wstring SystemEdgePath() {
    const std::vector<std::wstring> candidates = {
        EnvironmentPath(L"ProgramFiles(x86)") +
            L"\\Microsoft\\Edge\\Application\\msedge.exe",
        EnvironmentPath(L"ProgramFiles") +
            L"\\Microsoft\\Edge\\Application\\msedge.exe",
        EnvironmentPath(L"LOCALAPPDATA") +
            L"\\Microsoft\\Edge\\Application\\msedge.exe",
        EnvironmentPath(L"ProgramW6432") +
            L"\\Microsoft\\Edge\\Application\\msedge.exe",
    };
    for (const std::wstring& candidate : candidates) {
        const std::wstring resolved = FullExistingPath(candidate);
        if (!resolved.empty()) return resolved;
    }
    return {};
}

bool SameFilesystemPath(const std::wstring& a, const std::wstring& b) {
    const std::wstring na = NormalizeFilesystemPath(a);
    const std::wstring nb = NormalizeFilesystemPath(b);
    return !na.empty() && !nb.empty() && _wcsicmp(na.c_str(), nb.c_str()) == 0;
}

// ------------------------------------------------------- desktop enumeration

struct DesktopInfo {
    GUID id{};
    bool id_ok = false;
    std::string name;
    bool name_ok = false;
    std::string iface_iid;  // which IVirtualDesktop IID the object accepted
};

// Given a raw IVirtualDesktop-ish object, find the IID it answers to and read
// its id/name using only agreed slots.
DesktopInfo InspectDesktop(IUnknown* raw, RawObject* accepted_out = nullptr) {
    DesktopInfo d;
    for (const IidCandidate& c : IidCandidatesFor("IVirtualDesktop")) {
        RawObject probe;
        if (FAILED(raw->QueryInterface(*c.iid, probe.PutVoid()))) continue;
        d.iface_iid = GuidToString(*c.iid);
        const LayoutTable* t = LayoutForIid(*c.iid);
        if (t == nullptr || !t->applicable_to_current_family) continue;

        if (const MethodEntry* m = FindMethod(*t, "GetId")) {
            Gate g = Gate::Ok;
            GUID id{};
            HRESULT hr = InvokeSlot(probe.Get(), *t, *m, g, false, &id);
            if (g == Gate::Ok && SUCCEEDED(hr)) {
                d.id = id;
                d.id_ok = true;
            }
        }
        if (const MethodEntry* m = FindMethod(*t, "GetName")) {
            Gate g = Gate::Ok;
            void* hs = nullptr;
            HRESULT hr = InvokeSlot(probe.Get(), *t, *m, g, false, &hs);
            if (g == Gate::Ok && SUCCEEDED(hr)) {
                d.name = TakeHString(hs);
                d.name_ok = true;
            }
        }
        if (accepted_out != nullptr) {
            *accepted_out = std::move(probe);
        }
        break;
    }
    return d;
}

// Acquires IVirtualDesktopManagerInternal and the layout that goes with it.
struct ManagerInternal {
    RawObject obj;
    const IidCandidate* candidate = nullptr;
    const LayoutTable* layout = nullptr;
    HRESULT hr = E_FAIL;
    unsigned vtable_run = 0;
    std::string vtable_module;
    bool access_denied_seen = false;
};

ManagerInternal AcquireManagerInternal(IServiceProvider* sp) {
    ManagerInternal mi;
    for (const IidCandidate& c : IidCandidatesFor("IVirtualDesktopManagerInternal")) {
        RawObject o;
        HRESULT hr = sp->QueryService(SID_VirtualDesktopManagerInternal, *c.iid,
                                     o.PutVoid());
        if (hr == E_ACCESSDENIED) mi.access_denied_seen = true;
        if (FAILED(hr) || !o) {
            if (mi.candidate == nullptr) mi.hr = hr;
            continue;
        }
        mi.obj = std::move(o);
        mi.candidate = &c;
        mi.layout = LayoutForIid(*c.iid);
        mi.hr = S_OK;
        mi.vtable_run = ProbeVtableCodeRun(mi.obj.Get(), kVtableProbeCap);
        if (void** vt = VtableOf(mi.obj.Get())) mi.vtable_module = ModuleOf(vt);
        break;
    }
    return mi;
}

struct DesktopSnapshot {
    RawObject object;
    GUID id{};
    bool id_ok = false;
};

bool ReadCurrentDesktop(ManagerInternal& mi, DesktopSnapshot& out,
                        HRESULT* call_hr = nullptr) {
    if (call_hr != nullptr) *call_hr = E_ABORT;
    if (mi.layout == nullptr) return false;
    const MethodEntry* m = FindMethod(*mi.layout, "GetCurrentDesktop");
    if (m == nullptr) return false;
    Gate g = Gate::Ok;
    IUnknown* raw = nullptr;
    HRESULT hr = InvokeSlot(mi.obj.Get(), *mi.layout, *m, g, false, &raw);
    if (call_hr != nullptr) *call_hr = hr;
    if (g != Gate::Ok || FAILED(hr) || raw == nullptr) return false;
    RawObject identity;
    identity.Attach(raw);
    DesktopInfo d = InspectDesktop(identity.Get(), &out.object);
    out.id = d.id;
    out.id_ok = d.id_ok;
    return out.id_ok && static_cast<bool>(out.object);
}

bool ReadDesktopList(ManagerInternal& mi, std::vector<DesktopSnapshot>& out,
                     HRESULT* call_hr = nullptr) {
    out.clear();
    if (call_hr != nullptr) *call_hr = E_ABORT;
    if (mi.layout == nullptr) return false;
    const MethodEntry* m = FindMethod(*mi.layout, "GetDesktops");
    if (m == nullptr) return false;
    Gate g = Gate::Ok;
    IObjectArray* arr_raw = nullptr;
    HRESULT hr = InvokeSlot(mi.obj.Get(), *mi.layout, *m, g, false, &arr_raw);
    if (call_hr != nullptr) *call_hr = hr;
    if (g != Gate::Ok || FAILED(hr) || arr_raw == nullptr) return false;
    Com<IObjectArray> arr;
    *arr.Put() = arr_raw;
    UINT count = 0;
    if (FAILED(arr->GetCount(&count))) return false;
    out.reserve(count);
    for (UINT i = 0; i < count; ++i) {
        DesktopSnapshot d;
        RawObject identity;
        if (FAILED(arr->GetAt(i, IID_IUnknown, identity.PutVoid())) || !identity) {
            continue;
        }
        // GetAt(IID_IUnknown) returns the identity pointer.  SwitchDesktop's
        // parameter is IVirtualDesktop*, so retain the actual accepted
        // IVirtualDesktop interface pointer rather than passing identity
        // through an ABI-incompatible vtable.
        DesktopInfo info = InspectDesktop(identity.Get(), &d.object);
        d.id = info.id;
        d.id_ok = info.id_ok;
        if (d.object && d.id_ok) out.push_back(std::move(d));
    }
    return true;
}

bool ReadCurrentDesktopId(ManagerInternal& mi, GUID& out_id) {
    DesktopSnapshot current;
    if (!ReadCurrentDesktop(mi, current)) return false;
    out_id = current.id;
    return true;
}

ULONGLONG QpcNow() {
    LARGE_INTEGER qpc{};
    ::QueryPerformanceCounter(&qpc);
    return static_cast<ULONGLONG>(qpc.QuadPart);
}

double QpcMilliseconds(ULONGLONG start, ULONGLONG end) {
    LARGE_INTEGER freq{};
    if (!::QueryPerformanceFrequency(&freq) || freq.QuadPart <= 0 || end < start) {
        return -1.0;
    }
    return 1000.0 * static_cast<double>(end - start) /
           static_cast<double>(freq.QuadPart);
}

void PumpStaMessages() {
    MSG msg;
    while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        ::TranslateMessage(&msg);
        ::DispatchMessageW(&msg);
    }
}

struct SwitchObservation {
    GUID from{};
    GUID to{};
    ULONGLONG call_start_qpc = 0;
    ULONGLONG call_end_qpc = 0;
    HRESULT switch_hr = E_FAIL;
    bool switch_gate_ok = false;
    GUID observed_current{};
    bool observed_current_ok = false;
    bool matching_callback_ok = false;
    std::vector<NotifyEvent> events;
};

void PrintNotifyEvent(const NotifyEvent& ev, ULONGLONG switch_start_qpc) {
    Print("    callback {}  thread={}  qpc={}", NotifyEventKindText(ev.kind),
          ev.callback_thread_id, ev.timestamp_qpc);
    if (ev.desktop_a_ok) Print("  old={}", GuidToString(ev.desktop_a));
    if (ev.desktop_b_ok) Print("  new={}", GuidToString(ev.desktop_b));
    if (switch_start_qpc != 0) {
        double latency = QpcMilliseconds(switch_start_qpc, ev.timestamp_qpc);
        if (latency >= 0.0) Print("  latency_ms={:.3f}", latency);
    }
    if (!ev.detail.empty()) Print("  {}", ev.detail);
    Print("\n");
}

void DrainAndPrintEvents(NotifySink* sink, ULONGLONG switch_start_qpc,
                         std::vector<NotifyEvent>& out) {
    std::deque<NotifyEvent> batch = sink->DrainEvents();
    for (const NotifyEvent& ev : batch) {
        out.push_back(ev);
        PrintNotifyEvent(ev, switch_start_qpc);
    }
}

bool HasMatchingCurrentDesktopChanged(const std::vector<NotifyEvent>& events,
                                      const GUID& from, const GUID& to,
                                      ULONGLONG switch_start_qpc = 0) {
    for (const NotifyEvent& ev : events) {
        if (ev.kind != NotifyEventKind::CurrentVirtualDesktopChanged) continue;
        if (switch_start_qpc != 0 && ev.timestamp_qpc < switch_start_qpc) continue;
        if (ev.desktop_a_ok && ev.desktop_b_ok && ::IsEqualGUID(ev.desktop_a, from) &&
            ::IsEqualGUID(ev.desktop_b, to)) {
            return true;
        }
    }
    return false;
}

bool WaitForCurrentDesktop(ManagerInternal& mi, const GUID& from, const GUID& expected,
                           NotifySink* sink, ULONGLONG switch_start_qpc,
                           std::vector<NotifyEvent>& events,
                           DWORD timeout_ms = 2000) {
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    bool current_seen = false;
    do {
        PumpStaMessages();
        DrainAndPrintEvents(sink, switch_start_qpc, events);
        GUID current{};
        if (ReadCurrentDesktopId(mi, current) && ::IsEqualGUID(current, expected)) {
            current_seen = true;
        }
        const bool callback_ok =
            HasMatchingCurrentDesktopChanged(events, from, expected, switch_start_qpc);
        if (current_seen && callback_ok) {
            return true;
        }
        ::Sleep(25);
    } while (::GetTickCount64() < deadline);
    PumpStaMessages();
    DrainAndPrintEvents(sink, switch_start_qpc, events);
    if (!current_seen) {
        GUID current{};
        current_seen = ReadCurrentDesktopId(mi, current) &&
                       ::IsEqualGUID(current, expected);
    }
    return current_seen;
}

SwitchObservation SwitchAndVerify(ManagerInternal& mi, IUnknown* desktop,
                                  const GUID& from, const GUID& to, NotifySink* sink,
                                  bool allow_mutating) {
    SwitchObservation observation;
    observation.from = from;
    observation.to = to;
    const MethodEntry* m =
        mi.layout == nullptr ? nullptr : FindMethod(*mi.layout, "SwitchDesktop");
    observation.call_start_qpc = QpcNow();
    if (m != nullptr && desktop != nullptr) {
        Gate gate = Gate::Ok;
        observation.switch_hr =
            InvokeSlot(mi.obj.Get(), *mi.layout, *m, gate, allow_mutating, desktop);
        observation.switch_gate_ok = gate == Gate::Ok;
    } else {
        observation.switch_hr = E_ABORT;
    }
    observation.call_end_qpc = QpcNow();
    Print("  SwitchDesktop {} -> {}\n", GuidToString(from), GuidToString(to));
    Field("    call start qpc", std::format("{}", observation.call_start_qpc));
    Field("    call end qpc", std::format("{}", observation.call_end_qpc));
    Field("    call elapsed ms",
          std::format("{:.3f}",
                      QpcMilliseconds(observation.call_start_qpc,
                                      observation.call_end_qpc)));
    Field("    gate", observation.switch_gate_ok ? "ok" : "refused");
    Field("    HRESULT", HrToString(observation.switch_hr));

    PumpStaMessages();
    DrainAndPrintEvents(sink, observation.call_start_qpc, observation.events);
    observation.observed_current_ok =
        WaitForCurrentDesktop(mi, from, to, sink, observation.call_start_qpc,
                              observation.events);
    observation.matching_callback_ok =
        HasMatchingCurrentDesktopChanged(observation.events, from, to,
                                          observation.call_start_qpc);
    if (observation.observed_current_ok) {
        observation.observed_current = to;
    } else {
        ReadCurrentDesktopId(mi, observation.observed_current);
    }
    Field("    GetCurrentDesktop", observation.observed_current_ok
                                      ? GuidToString(observation.observed_current)
                                      : "(did not reach expected GUID)");
    Field("    CurrentVirtualDesktopChanged",
          observation.matching_callback_ok ? "observed" : "missing");
    return observation;
}

class DesktopRestoreGuard {
   public:
    DesktopRestoreGuard(ManagerInternal& mi, IUnknown* original, bool allow_mutating)
        : mi_(mi), original_(original), allow_mutating_(allow_mutating) {}

    ~DesktopRestoreGuard() noexcept {
        if (armed_) (void)AttemptNow();
    }

    void Arm() noexcept { armed_ = true; }
    void Disarm() noexcept { armed_ = false; }

    HRESULT AttemptNow() noexcept {
        if (!armed_ || original_ == nullptr || mi_.layout == nullptr) return E_ABORT;
        const MethodEntry* m = FindMethod(*mi_.layout, "SwitchDesktop");
        if (m == nullptr) return E_ABORT;
        Gate gate = Gate::Ok;
        return InvokeSlot(mi_.obj.Get(), *mi_.layout, *m, gate, allow_mutating_,
                          original_);
    }

   private:
    ManagerInternal& mi_;
    IUnknown* original_ = nullptr;  // borrowed; outer snapshot outlives this guard
    bool allow_mutating_ = false;
    bool armed_ = false;
};

struct ApplicationViewCollectionBinding {
    RawObject object;
    const LayoutTable* layout = nullptr;
    HRESULT hr = E_FAIL;
    bool access_denied_seen = false;
};

ApplicationViewCollectionBinding AcquireApplicationViewCollection(IServiceProvider* sp) {
    ApplicationViewCollectionBinding out;
    if (sp == nullptr) {
        out.hr = E_POINTER;
        return out;
    }
    for (const IidCandidate& c : IidCandidatesFor("IApplicationViewCollection")) {
        RawObject object;
        const GUID* service_id = ServiceIdFor("IApplicationViewCollection", c.iid);
        if (service_id == nullptr) {
            out.hr = E_NOINTERFACE;
            continue;
        }
        HRESULT hr =
            sp->QueryService(*service_id, *c.iid, object.PutVoid());
        if (hr == E_ACCESSDENIED) out.access_denied_seen = true;
        out.hr = hr;
        if (FAILED(hr) || !object) continue;
        const LayoutTable* layout = LayoutForIid(*c.iid);
        if (layout == nullptr || !layout->applicable_to_current_family) {
            out.hr = E_NOINTERFACE;
            continue;
        }
        out.object = std::move(object);
        out.layout = layout;
        out.hr = S_OK;
        return out;
    }
    return out;
}

struct WindowDesktopState {
    GUID desktop{};
    bool desktop_ok = false;
    bool on_current = false;
    bool on_current_ok = false;
    bool visible = false;
    DWORD cloaked = 0;
};

struct LogicalWindow {
    WindowIdentity identity;
    HMONITOR monitor = nullptr;
    WorkspaceId workspace = 0;
    GUID native_desktop{};
    RECT rect{};
    WINDOWPLACEMENT placement{};
};

bool ReadWindowIdentity(HWND hwnd, WindowIdentity& out) {
    if (hwnd == nullptr || !::IsWindow(hwnd)) return false;
    out = {};
    out.hwnd = hwnd;
    ::GetWindowThreadProcessId(hwnd, &out.pid);
    if (out.pid == 0) return false;

    HANDLE process =
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, out.pid);
    if (process == nullptr) return false;
    FILETIME exit_time{}, kernel_time{}, user_time{};
    const BOOL ok = ::GetProcessTimes(process, &out.process_creation_time,
                                      &exit_time, &kernel_time, &user_time);
    ::CloseHandle(process);
    out.process_creation_time_ok = ok != FALSE;
    return out.process_creation_time_ok;
}

bool ReadWindowPlacement(HWND hwnd, RECT& rect, WINDOWPLACEMENT& placement) {
    if (hwnd == nullptr || !::IsWindow(hwnd)) return false;
    if (!::GetWindowRect(hwnd, &rect)) return false;
    placement = {};
    placement.length = sizeof(placement);
    return ::GetWindowPlacement(hwnd, &placement) != FALSE;
}

bool SameRect(const RECT& a, const RECT& b) {
    return a.left == b.left && a.top == b.top && a.right == b.right &&
           a.bottom == b.bottom;
}

bool SameFileTime(const FILETIME& a, const FILETIME& b) {
    return a.dwLowDateTime == b.dwLowDateTime &&
           a.dwHighDateTime == b.dwHighDateTime;
}

bool PlaceProbeWindowOnMonitor(HWND hwnd, const MonitorRec& monitor, int slot) {
    if (hwnd == nullptr) return false;
    const int work_width = monitor.work.right - monitor.work.left;
    const int work_height = monitor.work.bottom - monitor.work.top;
    if (work_width < 160 || work_height < 120) return false;

    const int width = std::max(120, std::min(640, work_width - 40));
    const int height = std::max(100, std::min(420, work_height - 40));
    const int x_offset = 20 + std::max(0, slot) * 40;
    const int y_offset = 20 + std::max(0, slot) * 40;
    const int max_x_offset = std::max(0, work_width - width - 10);
    const int max_y_offset = std::max(0, work_height - height - 10);
    const int x = monitor.work.left + std::min(x_offset, max_x_offset);
    const int y = monitor.work.top + std::min(y_offset, max_y_offset);

    if (!::SetWindowPos(hwnd, nullptr, x, y, width, height,
                        SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW)) {
        return false;
    }
    return ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL) == monitor.handle;
}

bool WindowStateMatches(const WindowDesktopState& state, const GUID& desktop,
                        bool on_current) {
    return state.desktop_ok && ::IsEqualGUID(state.desktop, desktop) &&
           state.on_current_ok && state.on_current == on_current;
}

using DwmGetWindowAttributeFn =
    HRESULT(WINAPI*)(HWND, DWORD, PVOID, DWORD);

DWORD ReadWindowCloaked(HWND hwnd) {
    static auto get_attribute =
        TryGetProcAs<DwmGetWindowAttributeFn>(L"dwmapi.dll",
                                               "DwmGetWindowAttribute");
    if (get_attribute == nullptr || hwnd == nullptr) return 0;
    constexpr DWORD kDwmwaCloaked = 14;
    DWORD cloaked = 0;
    if (SUCCEEDED(get_attribute(hwnd, kDwmwaCloaked, &cloaked,
                                sizeof(cloaked)))) {
        return cloaked;
    }
    return 0;
}

bool ReadWindowDesktopState(IVirtualDesktopManager* documented_manager, HWND hwnd,
                            WindowDesktopState& out) {
    if (documented_manager == nullptr || hwnd == nullptr) return false;
    out = {};
    HRESULT dhr = documented_manager->GetWindowDesktopId(hwnd, &out.desktop);
    out.desktop_ok = SUCCEEDED(dhr);
    BOOL on_current = FALSE;
    HRESULT chr =
        documented_manager->IsWindowOnCurrentVirtualDesktop(hwnd, &on_current);
    out.on_current_ok = SUCCEEDED(chr);
    out.on_current = on_current != FALSE;
    out.visible = ::IsWindowVisible(hwnd) != FALSE;
    out.cloaked = ReadWindowCloaked(hwnd);
    return out.desktop_ok && out.on_current_ok;
}

bool CaptureLogicalWindow(IVirtualDesktopManager* documented_manager, HWND hwnd,
                          HMONITOR expected_monitor, WorkspaceId workspace,
                          LogicalWindow& out) {
    WindowIdentity identity;
    if (!ReadWindowIdentity(hwnd, identity)) return false;
    if (expected_monitor != nullptr &&
        ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL) != expected_monitor) {
        return false;
    }

    WindowDesktopState desktop_state;
    RECT rect{};
    WINDOWPLACEMENT placement{};
    if (!ReadWindowDesktopState(documented_manager, hwnd, desktop_state) ||
        !ReadWindowPlacement(hwnd, rect, placement)) {
        return false;
    }

    out = {};
    out.identity = identity;
    out.monitor = ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL);
    out.workspace = workspace;
    out.native_desktop = desktop_state.desktop;
    out.rect = rect;
    out.placement = placement;
    return true;
}

struct SpawnedProbeWindow {
    DWORD pid = 0;
    DWORD thread_id = 0;
    HWND hwnd = nullptr;
};

// ---------------------------------------------------------------------------
// Phase 4 controlled ordinary Win32 child application
//
// The first real-application semantics gate intentionally uses a process we
// own rather than an existing user application.  It gives the probe two
// independent top-level windows plus one owned popup, so ordinary
// MoveViewToDesktop grouping/ownership behavior can be observed without
// touching user state.

constexpr wchar_t kRealAppChildClassName[] = L"vdprobe.RealAppChild";
LONG g_real_app_child_window_count = 0;

LRESULT CALLBACK RealAppChildWindowProc(HWND hwnd, UINT message, WPARAM wparam,
                                        LPARAM lparam) {
    if (message == WM_NCCREATE) {
        ::InterlockedIncrement(&g_real_app_child_window_count);
    } else if (message == WM_CLOSE) {
        ::DestroyWindow(hwnd);
        return 0;
    } else if (message == WM_NCDESTROY) {
        if (::InterlockedDecrement(&g_real_app_child_window_count) == 0) {
            ::PostQuitMessage(0);
        }
    }
    return ::DefWindowProcW(hwnd, message, wparam, lparam);
}

bool EnsureRealAppChildClass() {
    static bool registered = false;
    if (registered) return true;

    WNDCLASSEXW klass{};
    klass.cbSize = sizeof(klass);
    klass.hInstance = ::GetModuleHandleW(nullptr);
    klass.lpfnWndProc = &RealAppChildWindowProc;
    klass.lpszClassName = kRealAppChildClassName;
    klass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    klass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (::RegisterClassExW(&klass) == 0 &&
        ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }
    registered = true;
    return true;
}

HWND CreateRealAppChildWindow(const std::wstring& title, DWORD style,
                              DWORD ex_style, HWND owner, int x, int y) {
    HWND hwnd = ::CreateWindowExW(
        ex_style, kRealAppChildClassName, title.c_str(), style, x, y, 560, 340,
        owner, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    if (hwnd != nullptr) {
        ::ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        ::UpdateWindow(hwnd);
    }
    return hwnd;
}

struct SpawnedRealApp {
    HANDLE process = nullptr;
    DWORD pid = 0;
    FILETIME process_creation_time{};
    bool process_creation_time_ok = false;
};

std::wstring CurrentExecutablePath() {
    std::vector<wchar_t> buffer(32768);
    DWORD length = ::GetModuleFileNameW(nullptr, buffer.data(),
                                        static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size()) return {};
    return std::wstring(buffer.data(), length);
}

bool ReadProcessCreationTime(HANDLE process, FILETIME& out) {
    if (process == nullptr) return false;
    FILETIME exit_time{}, kernel_time{}, user_time{};
    return ::GetProcessTimes(process, &out, &exit_time, &kernel_time, &user_time) !=
           FALSE;
}

bool SpawnRealAppChild(SpawnedRealApp& out) {
    out = {};
    const std::wstring exe = CurrentExecutablePath();
    if (exe.empty()) return false;

    std::wstring command =
        L"\"" + exe + L"\" real-app-child --windows 2 --confirm-mutate";
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(exe.c_str(), mutable_command.data(), nullptr, nullptr,
                          FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                          &pi)) {
        return false;
    }
    ::CloseHandle(pi.hThread);

    out.process = pi.hProcess;
    out.pid = pi.dwProcessId;
    out.process_creation_time_ok =
        ReadProcessCreationTime(out.process, out.process_creation_time);
    (void)::WaitForInputIdle(out.process, 2000);
    return out.process_creation_time_ok;
}

struct RealAppWindowInfo {
    HWND hwnd = nullptr;
    HWND owner = nullptr;
    std::wstring title;
    std::wstring class_name;
    WindowIdentity identity;
};

struct RealAppEnumContext {
    DWORD pid = 0;
    FILETIME process_creation_time{};
    std::vector<RealAppWindowInfo>* out = nullptr;
};

BOOL CALLBACK EnumerateRealAppWindowsProc(HWND hwnd, LPARAM lparam) {
    auto* context = reinterpret_cast<RealAppEnumContext*>(lparam);
    if (context == nullptr || context->out == nullptr || !::IsWindow(hwnd)) {
        return TRUE;
    }

    DWORD pid = 0;
    (void)::GetWindowThreadProcessId(hwnd, &pid);
    if (pid != context->pid || !::IsWindowVisible(hwnd)) return TRUE;

    LONG_PTR style = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
    if ((style & WS_CHILD) != 0) return TRUE;

    WindowIdentity identity;
    if (!ReadWindowIdentity(hwnd, identity) ||
        !identity.process_creation_time_ok ||
        !SameFileTime(identity.process_creation_time,
                       context->process_creation_time)) {
        return TRUE;
    }

    wchar_t title[512]{};
    wchar_t class_name[256]{};
    int length = ::GetWindowTextW(hwnd, title, 512);
    int class_length = ::GetClassNameW(hwnd, class_name, 256);
    RealAppWindowInfo info;
    info.hwnd = hwnd;
    info.owner = ::GetWindow(hwnd, GW_OWNER);
    info.title.assign(title, static_cast<size_t>(std::max(length, 0)));
    info.class_name.assign(class_name,
                           static_cast<size_t>(std::max(class_length, 0)));
    info.identity = identity;
    context->out->push_back(std::move(info));
    return TRUE;
}

std::vector<RealAppWindowInfo> EnumerateRealAppWindows(
    const SpawnedRealApp& child) {
    std::vector<RealAppWindowInfo> out;
    if (child.pid == 0 || !child.process_creation_time_ok) return out;
    RealAppEnumContext context{child.pid, child.process_creation_time, &out};
    ::EnumWindows(&EnumerateRealAppWindowsProc,
                  reinterpret_cast<LPARAM>(&context));
    std::sort(out.begin(), out.end(),
              [](const RealAppWindowInfo& a, const RealAppWindowInfo& b) {
                  return a.title < b.title;
              });
    return out;
}

bool WaitForRealAppWindows(const SpawnedRealApp& child,
                           std::vector<RealAppWindowInfo>& out,
                           DWORD timeout_ms = 5000) {
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    do {
        out = EnumerateRealAppWindows(child);
        size_t top_level = 0;
        size_t owned = 0;
        for (const RealAppWindowInfo& info : out) {
            if (info.owner == nullptr) {
                ++top_level;
            } else {
                ++owned;
            }
        }
        if (top_level >= 2 && owned >= 1) return true;
        ::Sleep(25);
    } while (::GetTickCount64() < deadline);
    return false;
}

struct CloseRealAppEnumContext {
    DWORD pid = 0;
};

BOOL CALLBACK CloseRealAppWindowsProc(HWND hwnd, LPARAM lparam) {
    auto* context = reinterpret_cast<CloseRealAppEnumContext*>(lparam);
    if (context == nullptr) return TRUE;
    DWORD pid = 0;
    (void)::GetWindowThreadProcessId(hwnd, &pid);
    if (pid == context->pid) (void)::PostMessageW(hwnd, WM_CLOSE, 0, 0);
    return TRUE;
}

bool CloseRealAppChild(SpawnedRealApp& child) {
    if (child.process == nullptr) return true;
    CloseRealAppEnumContext context{child.pid};
    ::EnumWindows(&CloseRealAppWindowsProc, reinterpret_cast<LPARAM>(&context));
    DWORD wait = ::WaitForSingleObject(child.process, 2000);
    bool closed = wait == WAIT_OBJECT_0;
    if (!closed) {
        // The process was created by this probe, so terminating it is a
        // bounded cleanup fallback and cannot affect an existing user app.
        closed = ::TerminateProcess(child.process, 1) != FALSE;
        (void)::WaitForSingleObject(child.process, 2000);
    }
    ::CloseHandle(child.process);
    child = {};
    return closed;
}

// ---------------------------------------------------------------------------
// Phase 4B-1 Explorer application probe
//
// Explorer is commonly hosted by the user's long-lived shell process.  The
// probe therefore owns HWNDs, not a process: launch requests are correlated
// against a pre-launch HWND snapshot and cleanup sends WM_CLOSE only to the
// newly observed windows.  The shared explorer.exe process is never
// terminated.

struct ExplorerWindowInfo {
    HWND hwnd = nullptr;
    HWND owner = nullptr;
    DWORD pid = 0;
    std::wstring title;
    std::wstring class_name;
    WindowIdentity identity;
    RECT rect{};
    HMONITOR monitor = nullptr;
};

bool IsExplorerProcess(DWORD pid) {
    if (pid == 0) return false;
    HANDLE process =
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return false;
    std::vector<wchar_t> path(32768);
    DWORD length = static_cast<DWORD>(path.size());
    const BOOL ok =
        ::QueryFullProcessImageNameW(process, 0, path.data(), &length);
    ::CloseHandle(process);
    if (!ok || length == 0) return false;
    std::wstring full(path.data(), length);

    const std::wstring expected = SystemExplorerPath();
    if (expected.empty()) return false;

    auto normalize_path = [](std::wstring value) {
        std::replace(value.begin(), value.end(), L'/', L'\\');
        if (value.rfind(L"\\\\?\\", 0) == 0) {
            value.erase(0, 4);
        }
        while (value.size() > 3 && value.back() == L'\\') {
            value.pop_back();
        }
        return value;
    };
    const std::wstring normalized_full = normalize_path(std::move(full));
    const std::wstring normalized_expected = normalize_path(std::move(expected));
    return _wcsicmp(normalized_full.c_str(), normalized_expected.c_str()) == 0;
}

bool IsExplorerPrimaryWindow(const ExplorerWindowInfo& info) {
    return info.class_name == L"CabinetWClass" ||
           info.class_name == L"ExploreWClass";
}

struct ExplorerEnumContext {
    std::vector<ExplorerWindowInfo>* out = nullptr;
    bool include_invisible = false;
};

BOOL CALLBACK EnumerateExplorerWindowsProc(HWND hwnd, LPARAM lparam) {
    auto* context = reinterpret_cast<ExplorerEnumContext*>(lparam);
    if (context == nullptr || context->out == nullptr || !::IsWindow(hwnd) ||
        (!context->include_invisible && !::IsWindowVisible(hwnd))) {
        return TRUE;
    }
    const LONG_PTR style = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
    if ((style & WS_CHILD) != 0) return TRUE;

    DWORD pid = 0;
    (void)::GetWindowThreadProcessId(hwnd, &pid);
    if (!IsExplorerProcess(pid)) return TRUE;

    WindowIdentity identity;
    if (!ReadWindowIdentity(hwnd, identity)) return TRUE;

    wchar_t title[512]{};
    wchar_t class_name[256]{};
    const int title_length = ::GetWindowTextW(hwnd, title, 512);
    const int class_length = ::GetClassNameW(hwnd, class_name, 256);

    ExplorerWindowInfo info;
    info.hwnd = hwnd;
    info.owner = ::GetWindow(hwnd, GW_OWNER);
    info.pid = pid;
    info.title.assign(title, static_cast<size_t>(std::max(title_length, 0)));
    info.class_name.assign(class_name,
                           static_cast<size_t>(std::max(class_length, 0)));
    info.identity = identity;
    (void)::GetWindowRect(hwnd, &info.rect);
    info.monitor = ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL);
    context->out->push_back(std::move(info));
    return TRUE;
}

std::vector<ExplorerWindowInfo> EnumerateExplorerWindows(
    bool include_invisible = false) {
    std::vector<ExplorerWindowInfo> out;
    ExplorerEnumContext context{&out, include_invisible};
    ::EnumWindows(&EnumerateExplorerWindowsProc,
                  reinterpret_cast<LPARAM>(&context));
    std::sort(out.begin(), out.end(),
              [](const ExplorerWindowInfo& a, const ExplorerWindowInfo& b) {
                  return reinterpret_cast<uintptr_t>(a.hwnd) <
                         reinterpret_cast<uintptr_t>(b.hwnd);
              });
    return out;
}

bool SameExplorerIdentity(const ExplorerWindowInfo& a,
                          const ExplorerWindowInfo& b) {
    return a.hwnd == b.hwnd && a.identity.pid == b.identity.pid &&
           a.identity.process_creation_time_ok &&
           b.identity.process_creation_time_ok &&
           SameFileTime(a.identity.process_creation_time,
                        b.identity.process_creation_time);
}

std::vector<ExplorerWindowInfo> NewExplorerWindows(
    const std::vector<ExplorerWindowInfo>& before,
    const std::vector<ExplorerWindowInfo>& after) {
    std::vector<ExplorerWindowInfo> out;
    for (const ExplorerWindowInfo& candidate : after) {
        if (std::none_of(before.begin(), before.end(),
                         [&](const ExplorerWindowInfo& old) {
                             return SameExplorerIdentity(old, candidate);
                         })) {
            out.push_back(candidate);
        }
    }
    return out;
}

bool LaunchExplorerWindow(const std::wstring& path) {
    const std::wstring explorer = SystemExplorerPath();
    if (explorer.empty()) {
        Print("  cannot resolve canonical system Explorer path; refusing launch\n");
        return false;
    }
    std::wstring parameters = L"/n,\"" + path + L"\"";
    SHELLEXECUTEINFOW execute{};
    execute.cbSize = sizeof(execute);
    execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
    execute.lpVerb = L"open";
    execute.lpFile = explorer.c_str();
    execute.lpParameters = parameters.c_str();
    execute.nShow = SW_SHOWNOACTIVATE;
    if (!::ShellExecuteExW(&execute)) {
        Print("  ShellExecuteExW(explorer) failed: {}\n",
              HrToString(HRESULT_FROM_WIN32(::GetLastError())));
        return false;
    }
    if (execute.hProcess != nullptr) {
        (void)::WaitForInputIdle(execute.hProcess, 1500);
        ::CloseHandle(execute.hProcess);
    }
    return true;
}

bool WaitForNewExplorerPrimary(
    const std::vector<ExplorerWindowInfo>& before,
    std::vector<ExplorerWindowInfo>& new_windows,
    ExplorerWindowInfo& selected, bool& ambiguous,
    DWORD timeout_ms = 5000) {
    new_windows.clear();
    selected = {};
    ambiguous = false;
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    do {
        const std::vector<ExplorerWindowInfo> current =
            EnumerateExplorerWindows();
        new_windows = NewExplorerWindows(before, current);
        std::vector<ExplorerWindowInfo> primary;
        for (const ExplorerWindowInfo& info : new_windows) {
            if (info.owner == nullptr && IsExplorerPrimaryWindow(info)) {
                primary.push_back(info);
            }
        }
        if (primary.size() == 1) {
            selected = primary.front();
            return true;
        }
        if (primary.size() > 1) {
            ambiguous = true;
            return false;
        }
        ::Sleep(50);
    } while (::GetTickCount64() < deadline);
    return false;
}

bool IsOwnedByOrThrough(HWND hwnd, HWND owner) {
    HWND current = hwnd;
    for (unsigned depth = 0; current != nullptr && depth < 8; ++depth) {
        if (current == owner) return true;
        current = ::GetWindow(current, GW_OWNER);
    }
    return false;
}

std::vector<ExplorerWindowInfo> CollectProbeExplorerWindows(
    const std::vector<ExplorerWindowInfo>& roots) {
    std::vector<ExplorerWindowInfo> out;
    const std::vector<ExplorerWindowInfo> all = EnumerateExplorerWindows(true);
    for (const ExplorerWindowInfo& info : all) {
        if (std::any_of(roots.begin(), roots.end(),
                        [&](const ExplorerWindowInfo& root) {
                            return SameExplorerIdentity(root, info);
                        })) {
            out.push_back(info);
            continue;
        }
        if (std::any_of(roots.begin(), roots.end(),
                        [&](const ExplorerWindowInfo& root) {
                            return info.owner != nullptr &&
                                   IsOwnedByOrThrough(info.hwnd, root.hwnd);
                        })) {
            out.push_back(info);
        }
    }
    return out;
}

bool CloseExplorerWindow(HWND hwnd, DWORD timeout_ms = 3000) {
    if (hwnd == nullptr || !::IsWindow(hwnd)) return true;
    if (!::PostMessageW(hwnd, WM_CLOSE, 0, 0)) return false;
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    do {
        PumpStaMessages();
        if (!::IsWindow(hwnd)) return true;
        ::Sleep(25);
    } while (::GetTickCount64() < deadline);
    return !::IsWindow(hwnd);
}

bool CloseProbeOwnedExplorerWindows(
    const std::vector<ExplorerWindowInfo>& created_roots) {
    bool all_closed = true;
    const std::vector<ExplorerWindowInfo> current =
        CollectProbeExplorerWindows(created_roots);
    std::vector<ExplorerWindowInfo> close_order;
    close_order.reserve(current.size());
    for (const ExplorerWindowInfo& info : current) {
        close_order.push_back(info);
    }
    std::stable_sort(close_order.begin(), close_order.end(),
                     [](const ExplorerWindowInfo& a,
                        const ExplorerWindowInfo& b) {
        return (a.owner != nullptr) > (b.owner != nullptr);
    });
    for (const ExplorerWindowInfo& info : close_order) {
        const std::vector<ExplorerWindowInfo> latest =
            EnumerateExplorerWindows(true);
        const auto current_it =
            std::find_if(latest.begin(), latest.end(),
                         [&](const ExplorerWindowInfo& candidate) {
                             return SameExplorerIdentity(candidate, info);
                         });
        if (current_it == latest.end()) continue;
        if (!CloseExplorerWindow(info.hwnd)) {
            Print("  cleanup Explorer HWND 0x{:X}: FAILED (window retained)\n",
                  reinterpret_cast<uintptr_t>(info.hwnd));
            all_closed = false;
        }
    }
    return all_closed;
}

// ---------------------------------------------------------------------------
// Phase 4C representative packaged/modern application probe
//
// Windows Terminal is a packaged application with a brokered multi-process
// implementation.  The probe launches two uniquely titled top-level windows,
// attributes only newly observed HWNDs carrying the probe token, and closes
// only those HWNDs during cleanup.  It never terminates WindowsTerminal.exe or
// touches an existing Terminal window.

struct TerminalWindowInfo {
    HWND hwnd = nullptr;
    HWND owner = nullptr;
    DWORD pid = 0;
    std::wstring title;
    std::wstring class_name;
    std::wstring image_path;
    WindowIdentity identity;
};

std::wstring SystemTerminalPath() {
    std::vector<std::wstring> candidates;
    wchar_t search_buffer[32768]{};
    constexpr DWORD kSearchBufferChars =
        static_cast<DWORD>(sizeof(search_buffer) / sizeof(search_buffer[0]));
    DWORD n = ::SearchPathW(nullptr, L"wt.exe", nullptr,
                            kSearchBufferChars,
                            search_buffer, nullptr);
    if (n != 0 && n < kSearchBufferChars) {
        candidates.emplace_back(search_buffer, n);
    }
    const std::wstring local_appdata = EnvironmentPath(L"LOCALAPPDATA");
    if (!local_appdata.empty()) {
        candidates.push_back(local_appdata +
                             L"\\Microsoft\\WindowsApps\\wt.exe");
        candidates.push_back(local_appdata +
                             L"\\Microsoft\\WindowsApps\\WindowsTerminal.exe");
    }
    const std::wstring program_files = EnvironmentPath(L"ProgramFiles");
    if (!program_files.empty()) {
        candidates.push_back(program_files +
                             L"\\WindowsApps\\WindowsTerminal.exe");
    }
    for (const std::wstring& candidate : candidates) {
        const std::wstring resolved = FullExistingPath(candidate);
        if (!resolved.empty()) return resolved;
    }
    return {};
}

std::wstring ProcessImagePath(DWORD pid) {
    if (pid == 0) return {};
    HANDLE process =
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return {};
    std::vector<wchar_t> path(32768);
    DWORD length = static_cast<DWORD>(path.size());
    const BOOL ok =
        ::QueryFullProcessImageNameW(process, 0, path.data(), &length);
    ::CloseHandle(process);
    if (!ok || length == 0) return {};
    return NormalizeFilesystemPath(std::wstring(path.data(), length));
}

bool IsWindowsTerminalImagePath(const std::wstring& path) {
    if (path.empty()) return false;
    const std::wstring normalized = NormalizeFilesystemPath(path);
    std::wstring lower = normalized;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](wchar_t c) { return std::towlower(c); });
    const bool package_path =
        lower.find(L"\\microsoft.windowsterminal_") != std::wstring::npos &&
        lower.find(L"\\windowsterminal.exe") != std::wstring::npos;
    const bool alias_path =
        lower.find(L"\\microsoft\\windowsapps\\wt.exe") != std::wstring::npos ||
        lower.find(L"\\microsoft\\windowsapps\\windowsterminal.exe") !=
            std::wstring::npos;
    return package_path || alias_path;
}

bool IsTerminalTopLevelWindow(const TerminalWindowInfo& info,
                              const std::wstring& token) {
    if (info.owner != nullptr || token.empty()) return false;
    if (info.title.find(token) == std::wstring::npos) return false;
    return info.class_name == L"CASCADIA_HOSTING_WINDOW_CLASS" ||
           info.class_name == L"Windows.UI.Core.CoreWindow";
}

struct TerminalEnumContext {
    const std::wstring* token = nullptr;
    std::vector<TerminalWindowInfo>* out = nullptr;
    bool include_invisible = false;
};

BOOL CALLBACK EnumerateTerminalWindowsProc(HWND hwnd, LPARAM lparam) {
    auto* context = reinterpret_cast<TerminalEnumContext*>(lparam);
    if (context == nullptr || context->out == nullptr ||
        context->token == nullptr || !::IsWindow(hwnd) ||
        (!context->include_invisible && !::IsWindowVisible(hwnd))) {
        return TRUE;
    }
    const LONG_PTR style = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
    if ((style & WS_CHILD) != 0) return TRUE;

    DWORD pid = 0;
    (void)::GetWindowThreadProcessId(hwnd, &pid);
    const std::wstring image_path = ProcessImagePath(pid);
    if (!IsWindowsTerminalImagePath(image_path)) return TRUE;

    WindowIdentity identity;
    if (!ReadWindowIdentity(hwnd, identity)) return TRUE;
    wchar_t title[512]{};
    wchar_t class_name[256]{};
    const int title_length = ::GetWindowTextW(hwnd, title, 512);
    const int class_length = ::GetClassNameW(hwnd, class_name, 256);

    TerminalWindowInfo info;
    info.hwnd = hwnd;
    info.owner = ::GetWindow(hwnd, GW_OWNER);
    info.pid = pid;
    info.title.assign(title, static_cast<size_t>(std::max(title_length, 0)));
    info.class_name.assign(
        class_name, static_cast<size_t>(std::max(class_length, 0)));
    info.image_path = image_path;
    info.identity = identity;
    context->out->push_back(std::move(info));
    return TRUE;
}

std::vector<TerminalWindowInfo> EnumerateTerminalWindows(
    const std::wstring& token, bool include_invisible = false) {
    std::vector<TerminalWindowInfo> out;
    TerminalEnumContext context{&token, &out, include_invisible};
    ::EnumWindows(&EnumerateTerminalWindowsProc,
                  reinterpret_cast<LPARAM>(&context));
    std::sort(out.begin(), out.end(),
              [](const TerminalWindowInfo& a, const TerminalWindowInfo& b) {
                  return reinterpret_cast<uintptr_t>(a.hwnd) <
                         reinterpret_cast<uintptr_t>(b.hwnd);
              });
    return out;
}

bool SameTerminalIdentity(const TerminalWindowInfo& a,
                          const TerminalWindowInfo& b) {
    return a.hwnd == b.hwnd && a.identity.pid == b.identity.pid &&
           a.identity.process_creation_time_ok &&
           b.identity.process_creation_time_ok &&
           SameFileTime(a.identity.process_creation_time,
                        b.identity.process_creation_time);
}

std::vector<TerminalWindowInfo> NewTerminalWindows(
    const std::vector<TerminalWindowInfo>& before,
    const std::vector<TerminalWindowInfo>& after) {
    std::vector<TerminalWindowInfo> out;
    for (const TerminalWindowInfo& candidate : after) {
        if (std::none_of(before.begin(), before.end(),
                         [&](const TerminalWindowInfo& old) {
                             return SameTerminalIdentity(old, candidate);
                         })) {
            out.push_back(candidate);
        }
    }
    return out;
}

bool LaunchTerminalWindow(const std::wstring& executable,
                          const std::wstring& token) {
    if (executable.empty() || token.empty()) return false;
    const std::wstring command =
        L"\"" + executable + L"\" -w new --title \"" + token +
        L"\" cmd.exe /k \"title " + token + L"\"";
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(executable.c_str(), mutable_command.data(), nullptr,
                          nullptr, FALSE, 0, nullptr, nullptr, &startup, &pi)) {
        return false;
    }
    (void)::WaitForInputIdle(pi.hProcess, 5000);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return true;
}

bool WaitForNewTerminalWindow(
    const std::vector<TerminalWindowInfo>& before, const std::wstring& token,
    std::vector<TerminalWindowInfo>& new_windows,
    TerminalWindowInfo& selected, bool& ambiguous, DWORD timeout_ms = 10000) {
    new_windows.clear();
    selected = {};
    ambiguous = false;
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    do {
        const std::vector<TerminalWindowInfo> current =
            EnumerateTerminalWindows(token);
        new_windows = NewTerminalWindows(before, current);
        std::vector<TerminalWindowInfo> primary;
        for (const TerminalWindowInfo& info : new_windows) {
            if (IsTerminalTopLevelWindow(info, token)) primary.push_back(info);
        }
        if (primary.size() == 1) {
            selected = primary.front();
            return true;
        }
        if (primary.size() > 1) {
            ambiguous = true;
            return false;
        }
        ::Sleep(100);
    } while (::GetTickCount64() < deadline);
    return false;
}

bool CloseTerminalWindow(HWND hwnd, DWORD timeout_ms = 5000) {
    if (hwnd == nullptr || !::IsWindow(hwnd)) return true;
    if (!::PostMessageW(hwnd, WM_CLOSE, 0, 0)) return false;
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    do {
        PumpStaMessages();
        if (!::IsWindow(hwnd)) return true;
        ::Sleep(50);
    } while (::GetTickCount64() < deadline);
    return !::IsWindow(hwnd);
}

bool CloseProbeOwnedTerminalWindows(
    const std::vector<TerminalWindowInfo>& roots,
    const std::wstring& token) {
    bool all_closed = true;
    const std::vector<TerminalWindowInfo> current =
        EnumerateTerminalWindows(token, true);
    for (const TerminalWindowInfo& root : roots) {
        const auto it =
            std::find_if(current.begin(), current.end(),
                         [&](const TerminalWindowInfo& candidate) {
                             return SameTerminalIdentity(root, candidate);
                         });
        if (it == current.end()) continue;
        if (!CloseTerminalWindow(root.hwnd)) {
            Print("  cleanup Terminal HWND 0x{:X}: FAILED (window retained)\n",
                  reinterpret_cast<uintptr_t>(root.hwnd));
            all_closed = false;
        }
    }
    return all_closed;
}

// ---------------------------------------------------------------------------
// Phase 4B-2A Chromium application probe
//
// Chromium is multi-process and may share a long-lived browser executable with
// unrelated user windows.  Attribution therefore requires all of:
//   * a newly observed top-level HWND;
//   * the canonical Edge executable path; and
//   * a command line containing this probe's unique temporary profile path.
// A class name is only evidence used to identify normal browser roots.

struct ChromiumWindowInfo {
    HWND hwnd = nullptr;
    HWND owner = nullptr;
    DWORD pid = 0;
    bool visible = false;
    std::wstring title;
    std::wstring class_name;
    std::wstring command_line;
    WindowIdentity identity;
    RECT rect{};
    HMONITOR monitor = nullptr;
};

using NtQueryInformationProcessFn =
    LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct NativeUnicodeString {
    USHORT length = 0;
    USHORT maximum_length = 0;
    PWSTR buffer = nullptr;
};

bool ReadProcessCommandLine(DWORD pid, std::wstring& out) {
    out.clear();
    if (pid == 0) return false;
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return false;
    auto query = TryGetProcAs<NtQueryInformationProcessFn>(
        L"ntdll.dll", "NtQueryInformationProcess");
    if (query == nullptr) {
        ::CloseHandle(process);
        return false;
    }

    constexpr ULONG kProcessCommandLineInformation = 60;
    ULONG length = 0;
    (void)query(process, kProcessCommandLineInformation, nullptr, 0, &length);
    if (length < sizeof(NativeUnicodeString) || length > (1u << 20)) {
        ::CloseHandle(process);
        return false;
    }
    std::vector<unsigned char> buffer(length);
    const LONG status =
        query(process, kProcessCommandLineInformation, buffer.data(), length,
              &length);
    ::CloseHandle(process);
    if (status < 0 || buffer.size() < sizeof(NativeUnicodeString)) return false;

    const auto* command =
        reinterpret_cast<const NativeUnicodeString*>(buffer.data());
    if (command->buffer == nullptr || command->length == 0 ||
        command->length % sizeof(wchar_t) != 0) {
        return false;
    }
    const size_t chars = command->length / sizeof(wchar_t);
    const wchar_t* begin = command->buffer;
    const wchar_t* end = begin + chars;
    const uintptr_t buffer_begin =
        reinterpret_cast<uintptr_t>(buffer.data());
    const uintptr_t buffer_end = buffer_begin + buffer.size();
    const uintptr_t string_begin = reinterpret_cast<uintptr_t>(begin);
    const uintptr_t string_end = reinterpret_cast<uintptr_t>(end);
    if (string_begin < buffer_begin || string_end > buffer_end ||
        string_end < string_begin) {
        // The documented information class normally returns an inline string;
        // refuse an unexpected pointer rather than reading arbitrary memory.
        return false;
    }
    out.assign(begin, end);
    return true;
}

bool CommandLineContainsProfile(const std::wstring& command_line,
                                const std::wstring& profile) {
    if (command_line.empty() || profile.empty()) return false;
    std::wstring cmd = NormalizeFilesystemPath(command_line);
    std::wstring needle = NormalizeFilesystemPath(profile);
    std::transform(cmd.begin(), cmd.end(), cmd.begin(),
                   [](wchar_t c) { return std::towlower(c); });
    std::transform(needle.begin(), needle.end(), needle.begin(),
                   [](wchar_t c) { return std::towlower(c); });
    return cmd.find(needle) != std::wstring::npos;
}

enum class ChromiumProcessMatch { NoMatch, Match, Inconclusive };

ChromiumProcessMatch ClassifyChromiumProcess(
    DWORD pid, const std::wstring& executable, const std::wstring& profile,
    std::wstring* command_line_out = nullptr) {
    if (pid == 0 || executable.empty() || profile.empty()) {
        return ChromiumProcessMatch::Inconclusive;
    }
    HANDLE process =
        ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return ChromiumProcessMatch::Inconclusive;
    std::vector<wchar_t> path(32768);
    DWORD length = static_cast<DWORD>(path.size());
    const BOOL path_ok =
        ::QueryFullProcessImageNameW(process, 0, path.data(), &length);
    ::CloseHandle(process);
    if (!path_ok || length == 0) return ChromiumProcessMatch::Inconclusive;
    const std::wstring full(path.data(), length);
    if (!SameFilesystemPath(full, executable)) {
        return ChromiumProcessMatch::NoMatch;
    }

    std::wstring command_line;
    if (!ReadProcessCommandLine(pid, command_line)) {
        return ChromiumProcessMatch::Inconclusive;
    }
    if (!CommandLineContainsProfile(command_line, profile)) {
        return ChromiumProcessMatch::NoMatch;
    }
    if (command_line_out != nullptr) *command_line_out = command_line;
    return ChromiumProcessMatch::Match;
}

bool IsChromiumProcess(DWORD pid, const std::wstring& executable,
                       const std::wstring& profile,
                       std::wstring* command_line_out = nullptr) {
    return ClassifyChromiumProcess(pid, executable, profile,
                                   command_line_out) ==
           ChromiumProcessMatch::Match;
}

bool IsChromiumTopLevelWindow(const ChromiumWindowInfo& info) {
    if (info.owner != nullptr) return false;
    if (info.class_name == L"Chrome_WidgetWin_1" ||
        info.class_name == L"Chrome_WidgetWin_0") {
        return true;
    }
    return info.class_name.rfind(L"Chrome_WidgetWin_", 0) == 0;
}

struct ChromiumEnumContext {
    const std::wstring* executable = nullptr;
    const std::wstring* profile = nullptr;
    std::vector<ChromiumWindowInfo>* out = nullptr;
    bool include_invisible = false;
};

BOOL CALLBACK EnumerateChromiumWindowsProc(HWND hwnd, LPARAM lparam) {
    auto* context = reinterpret_cast<ChromiumEnumContext*>(lparam);
    if (context == nullptr || context->out == nullptr ||
        context->executable == nullptr || context->profile == nullptr ||
        !::IsWindow(hwnd) ||
        (!context->include_invisible && !::IsWindowVisible(hwnd))) {
        return TRUE;
    }
    const LONG_PTR style = ::GetWindowLongPtrW(hwnd, GWL_STYLE);
    if ((style & WS_CHILD) != 0) return TRUE;

    DWORD pid = 0;
    (void)::GetWindowThreadProcessId(hwnd, &pid);
    std::wstring command_line;
    if (!IsChromiumProcess(pid, *context->executable, *context->profile,
                            &command_line)) {
        return TRUE;
    }

    WindowIdentity identity;
    if (!ReadWindowIdentity(hwnd, identity)) return TRUE;
    wchar_t title[512]{};
    wchar_t class_name[256]{};
    const int title_length = ::GetWindowTextW(hwnd, title, 512);
    const int class_length = ::GetClassNameW(hwnd, class_name, 256);

    ChromiumWindowInfo info;
    info.hwnd = hwnd;
    info.owner = ::GetWindow(hwnd, GW_OWNER);
    info.pid = pid;
    info.visible = ::IsWindowVisible(hwnd) != FALSE;
    info.title.assign(title, static_cast<size_t>(std::max(title_length, 0)));
    info.class_name.assign(class_name,
                           static_cast<size_t>(std::max(class_length, 0)));
    info.command_line = std::move(command_line);
    info.identity = identity;
    (void)::GetWindowRect(hwnd, &info.rect);
    info.monitor = ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL);
    context->out->push_back(std::move(info));
    return TRUE;
}

std::vector<ChromiumWindowInfo> EnumerateChromiumWindows(
    const std::wstring& executable, const std::wstring& profile,
    bool include_invisible = false) {
    std::vector<ChromiumWindowInfo> out;
    ChromiumEnumContext context{&executable, &profile, &out,
                                include_invisible};
    ::EnumWindows(&EnumerateChromiumWindowsProc,
                  reinterpret_cast<LPARAM>(&context));
    std::sort(out.begin(), out.end(),
              [](const ChromiumWindowInfo& a, const ChromiumWindowInfo& b) {
                  return reinterpret_cast<uintptr_t>(a.hwnd) <
                         reinterpret_cast<uintptr_t>(b.hwnd);
              });
    return out;
}

bool SameChromiumIdentity(const ChromiumWindowInfo& a,
                          const ChromiumWindowInfo& b) {
    return a.hwnd == b.hwnd && a.identity.pid == b.identity.pid &&
           a.identity.process_creation_time_ok &&
           b.identity.process_creation_time_ok &&
           SameFileTime(a.identity.process_creation_time,
                        b.identity.process_creation_time);
}

std::vector<ChromiumWindowInfo> NewChromiumWindows(
    const std::vector<ChromiumWindowInfo>& before,
    const std::vector<ChromiumWindowInfo>& after) {
    std::vector<ChromiumWindowInfo> out;
    for (const ChromiumWindowInfo& candidate : after) {
        if (std::none_of(before.begin(), before.end(),
                         [&](const ChromiumWindowInfo& old) {
                             return SameChromiumIdentity(old, candidate);
                         })) {
            out.push_back(candidate);
        }
    }
    return out;
}

bool CreateProbeProfileDirectory(std::wstring& out) {
    out.clear();
    std::wstring temp = EnvironmentPath(L"TEMP");
    if (temp.empty()) temp = EnvironmentPath(L"TMP");
    if (temp.empty()) {
        wchar_t buffer[MAX_PATH]{};
        DWORD n = ::GetTempPathW(MAX_PATH, buffer);
        if (n == 0 || n >= MAX_PATH) return false;
        temp.assign(buffer, n);
    }
    while (temp.size() > 3 && (temp.back() == L'\\' || temp.back() == L'/')) {
        temp.pop_back();
    }
    GUID id{};
    if (FAILED(::CoCreateGuid(&id))) return false;
    const std::wstring name = L"vdprobe-edge-" + ToWide(GuidToString(id));
    out = temp + L"\\" + name;
    return ::CreateDirectoryW(out.c_str(), nullptr) != FALSE;
}

struct TrackedChromiumProcess {
    HANDLE process = nullptr;
    DWORD pid = 0;
    DWORD parent_pid = 0;
    FILETIME creation_time{};
};

struct ChromiumProcessTree {
    std::vector<TrackedChromiumProcess> processes;
    bool identity_capture_failed = false;

    ChromiumProcessTree() = default;
    ChromiumProcessTree(const ChromiumProcessTree&) = delete;
    ChromiumProcessTree& operator=(const ChromiumProcessTree&) = delete;

    ~ChromiumProcessTree() {
        for (const TrackedChromiumProcess& process : processes) {
            if (process.process != nullptr) ::CloseHandle(process.process);
        }
    }
};

bool LaunchChromiumWindow(const std::wstring& executable,
                          const std::wstring& profile,
                          ChromiumProcessTree& process_tree) {
    if (executable.empty() || profile.empty()) return false;
    std::wstring command =
        L"\"" + executable + L"\" --user-data-dir=\"" + profile +
        L"\" --no-first-run --no-default-browser-check "
        L"--disable-background-mode --new-window about:blank";
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessW(executable.c_str(), mutable_command.data(), nullptr,
                          nullptr, FALSE, 0, nullptr, nullptr, &startup, &pi)) {
        return false;
    }
    ::CloseHandle(pi.hThread);

    TrackedChromiumProcess launched;
    launched.process = pi.hProcess;
    launched.pid = pi.dwProcessId;
    if (!ReadProcessCreationTime(pi.hProcess, launched.creation_time)) {
        // The launch succeeded, but without its creation identity a recycled PID
        // cannot be distinguished from this probe's root.  Keep the handle (and
        // therefore the PID) stable, but force fail-closed profile retention.
        process_tree.identity_capture_failed = true;
    }
    process_tree.processes.push_back(launched);
    (void)::WaitForInputIdle(pi.hProcess, 4000);
    return true;
}

bool WaitForNewChromiumPrimary(
    const std::vector<ChromiumWindowInfo>& before,
    const std::wstring& executable, const std::wstring& profile,
    std::vector<ChromiumWindowInfo>& new_windows,
    ChromiumWindowInfo& selected, bool& ambiguous, DWORD timeout_ms = 10000) {
    new_windows.clear();
    selected = {};
    ambiguous = false;
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    do {
        const std::vector<ChromiumWindowInfo> current =
            EnumerateChromiumWindows(executable, profile);
        new_windows = NewChromiumWindows(before, current);
        std::vector<ChromiumWindowInfo> primary;
        for (const ChromiumWindowInfo& info : new_windows) {
            if (IsChromiumTopLevelWindow(info)) primary.push_back(info);
        }
        if (primary.size() == 1) {
            selected = primary.front();
            return true;
        }
        if (primary.size() > 1) {
            ambiguous = true;
            return false;
        }
        ::Sleep(100);
    } while (::GetTickCount64() < deadline);
    return false;
}

bool RemoveProbeProfileDirectory(const std::wstring& path,
                                 DWORD timeout_ms = 15000) {
    if (path.empty()) return true;

    // Edge can keep a short-lived profile lock after the last top-level
    // window has processed WM_CLOSE.  Retry only this probe-owned directory;
    // never terminate a process or remove an existing browser profile.
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    for (;;) {
        std::error_code ec;
        (void)std::filesystem::remove_all(path, ec);
        const DWORD attributes = ::GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            const DWORD error = ::GetLastError();
            if (error == ERROR_FILE_NOT_FOUND ||
                error == ERROR_PATH_NOT_FOUND) {
                return true;
            }
        }

        if (::GetTickCount64() >= deadline) return false;
        PumpStaMessages();
        ::Sleep(100);
    }
}

enum class ProbeChromiumProcessScanResult {
    Clean,
    MatchesRemain,
    Inconclusive,
};

struct ChromiumProcessSnapshotEntry {
    DWORD pid = 0;
    DWORD parent_pid = 0;
    FILETIME creation_time{};
    bool creation_time_ok = false;
};

struct ChromiumProcessBaseline {
    std::vector<ChromiumProcessSnapshotEntry> processes;
    bool capture_ok = false;
};

bool SnapshotChromiumProcesses(const std::wstring& executable,
                               std::vector<ChromiumProcessSnapshotEntry>& out) {
    out.clear();
    if (executable.empty()) return false;
    const size_t separator = executable.find_last_of(L"\\/");
    const std::wstring executable_name =
        executable.substr(separator == std::wstring::npos ? 0 : separator + 1);
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Process32FirstW(snapshot, &entry)) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(snapshot);
        return error == ERROR_NO_MORE_FILES;
    }
    for (;;) {
        if (_wcsicmp(entry.szExeFile, executable_name.c_str()) == 0) {
            ChromiumProcessSnapshotEntry process;
            process.pid = entry.th32ProcessID;
            process.parent_pid = entry.th32ParentProcessID;
            HANDLE handle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                          FALSE, process.pid);
            if (handle != nullptr) {
                process.creation_time_ok =
                    ReadProcessCreationTime(handle, process.creation_time);
                ::CloseHandle(handle);
            }
            out.push_back(process);
        }
        ::SetLastError(ERROR_SUCCESS);
        if (!::Process32NextW(snapshot, &entry)) break;
    }
    const DWORD enumeration_error = ::GetLastError();
    ::CloseHandle(snapshot);
    return enumeration_error == ERROR_NO_MORE_FILES;
}

ChromiumProcessBaseline CaptureChromiumProcessBaseline(
    const std::wstring& executable) {
    ChromiumProcessBaseline baseline;
    baseline.capture_ok = SnapshotChromiumProcesses(executable,
                                                    baseline.processes);
    return baseline;
}

const TrackedChromiumProcess* FindTrackedChromiumProcess(
    const ChromiumProcessTree& process_tree, DWORD pid) {
    const auto it = std::find_if(
        process_tree.processes.begin(), process_tree.processes.end(),
        [pid](const TrackedChromiumProcess& process) {
            return process.pid == pid;
        });
    return it == process_tree.processes.end() ? nullptr : &*it;
}

ProbeChromiumProcessScanResult ScanProbeChromiumProcesses(
    ChromiumProcessTree& process_tree, const std::wstring& executable,
    const std::wstring& profile, const ChromiumProcessBaseline& baseline) {
    if (process_tree.identity_capture_failed || !baseline.capture_ok) {
        return ProbeChromiumProcessScanResult::Inconclusive;
    }
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return ProbeChromiumProcessScanResult::Inconclusive;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (!::Process32FirstW(snapshot, &entry)) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(snapshot);
        return error == ERROR_NO_MORE_FILES
                   ? ProbeChromiumProcessScanResult::Clean
                   : ProbeChromiumProcessScanResult::Inconclusive;
    }

    std::vector<ChromiumProcessSnapshotEntry> snapshot_entries;
    for (;;) {
        snapshot_entries.push_back({entry.th32ProcessID,
                                    entry.th32ParentProcessID, {}, false});

        ::SetLastError(ERROR_SUCCESS);
        if (!::Process32NextW(snapshot, &entry)) break;
    }
    const DWORD enumeration_error = ::GetLastError();
    ::CloseHandle(snapshot);
    if (enumeration_error != ERROR_NO_MORE_FILES) {
        return ProbeChromiumProcessScanResult::Inconclusive;
    }

    // Retained handles prevent every known tree PID from being recycled.  A
    // snapshot entry whose parent PID names a known process and whose creation
    // time is not older than that parent can therefore be added to the exact
    // launch tree without consulting unrelated msedge.exe processes.
    bool added = false;
    do {
        added = false;
        for (const ChromiumProcessSnapshotEntry& candidate : snapshot_entries) {
            if (candidate.pid == 0 || candidate.pid == candidate.parent_pid ||
                FindTrackedChromiumProcess(process_tree, candidate.pid) !=
                    nullptr) {
                continue;
            }
            const TrackedChromiumProcess* parent =
                FindTrackedChromiumProcess(process_tree, candidate.parent_pid);
            if (parent == nullptr) continue;

            HANDLE process = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE,
                candidate.pid);
            if (process == nullptr) {
                // It may have exited between the snapshot and OpenProcess after
                // spawning a still-live child.  Retain the profile rather than
                // guessing that this branch is drained.
                return ProbeChromiumProcessScanResult::Inconclusive;
            }
            FILETIME creation_time{};
            if (!ReadProcessCreationTime(process, creation_time)) {
                ::CloseHandle(process);
                return ProbeChromiumProcessScanResult::Inconclusive;
            }
            if (::CompareFileTime(&creation_time, &parent->creation_time) < 0) {
                // The snapshot's parent PID refers to an older, unrelated
                // process that existed before this tracked PID incarnation.
                ::CloseHandle(process);
                continue;
            }

            process_tree.processes.push_back(
                {process, candidate.pid, candidate.parent_pid, creation_time});
            added = true;
        }
    } while (added);

    for (const TrackedChromiumProcess& process : process_tree.processes) {
        const DWORD wait = ::WaitForSingleObject(process.process, 0);
        if (wait == WAIT_TIMEOUT) {
            return ProbeChromiumProcessScanResult::MatchesRemain;
        }
        if (wait != WAIT_OBJECT_0) {
            return ProbeChromiumProcessScanResult::Inconclusive;
        }
    }

    // A short-lived intermediate can disappear before the parent-link walk and
    // leave a live orphan outside the observed tree.  Backstop the tree with a
    // global Edge snapshot, but exempt only identities already present before
    // this probe launched.  This avoids querying unrelated unchanged Edge
    // processes during cleanup while ensuring every new/reused Edge PID keeps
    // the profile fail-closed unless it can be positively matched.
    std::vector<ChromiumProcessSnapshotEntry> current_edge;
    if (!SnapshotChromiumProcesses(executable, current_edge)) {
        return ProbeChromiumProcessScanResult::Inconclusive;
    }
    for (const ChromiumProcessSnapshotEntry& current : current_edge) {
        const auto old = std::find_if(
            baseline.processes.begin(), baseline.processes.end(),
            [&](const ChromiumProcessSnapshotEntry& candidate) {
                return candidate.pid == current.pid;
            });
        if (old != baseline.processes.end()) {
            if (old->creation_time_ok && current.creation_time_ok &&
                SameFileTime(old->creation_time, current.creation_time)) {
                continue;
            }
        }

        const ChromiumProcessMatch match =
            ClassifyChromiumProcess(current.pid, executable, profile);
        if (match == ChromiumProcessMatch::Match) {
            return ProbeChromiumProcessScanResult::MatchesRemain;
        }
        // A new/reused Edge identity may be an orphan whose short-lived parent
        // escaped the tree walk.  Even a readable non-match is not safe evidence
        // that every profile-owning descendant was observed, so retain.
        return ProbeChromiumProcessScanResult::Inconclusive;
    }
    return ProbeChromiumProcessScanResult::Clean;
}

ProbeChromiumProcessScanResult WaitForProbeChromiumProcessesToExit(
    ChromiumProcessTree& process_tree, const std::wstring& executable,
    const std::wstring& profile, const ChromiumProcessBaseline& baseline,
    DWORD timeout_ms = 15000) {
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    for (;;) {
        const ProbeChromiumProcessScanResult scan =
            ScanProbeChromiumProcesses(process_tree, executable, profile,
                                       baseline);
        if (scan == ProbeChromiumProcessScanResult::Clean ||
            ::GetTickCount64() >= deadline) {
            return scan;
        }
        PumpStaMessages();
        ::Sleep(100);
    }
}

bool CloseChromiumWindow(HWND hwnd, DWORD timeout_ms = 5000) {
    if (hwnd == nullptr || !::IsWindow(hwnd)) return true;
    if (!::PostMessageW(hwnd, WM_CLOSE, 0, 0)) return false;
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    do {
        PumpStaMessages();
        if (!::IsWindow(hwnd)) return true;
        ::Sleep(50);
    } while (::GetTickCount64() < deadline);
    return !::IsWindow(hwnd);
}

bool CloseProbeOwnedChromiumWindows(
    const std::vector<ChromiumWindowInfo>& roots,
    const std::wstring& executable, const std::wstring& profile) {
    bool all_closed = true;
    const std::vector<ChromiumWindowInfo> current =
        EnumerateChromiumWindows(executable, profile, true);
    for (const ChromiumWindowInfo& root : roots) {
        const auto it =
            std::find_if(current.begin(), current.end(),
                         [&](const ChromiumWindowInfo& candidate) {
                             return SameChromiumIdentity(root, candidate);
                         });
        if (it == current.end()) continue;
        if (!CloseChromiumWindow(root.hwnd)) {
            Print("  cleanup Chromium HWND 0x{:X}: FAILED (window retained)\n",
                  reinterpret_cast<uintptr_t>(root.hwnd));
            all_closed = false;
        }
    }
    return all_closed;
}

struct RealAppWindowSnapshot {
    RealAppWindowInfo info;
    RawObject view;
    RECT rect{};
    HMONITOR monitor = nullptr;
    WindowDesktopState desktop{};
    bool state_ok = false;
    bool snapshot_ok = false;
};

bool CaptureRealAppWindowSnapshot(const RealAppWindowInfo& info,
                                  IVirtualDesktopManager* documented_manager,
                                  RealAppWindowSnapshot& out) {
    out = {};
    out.info = info;
    out.monitor = ::MonitorFromWindow(info.hwnd, MONITOR_DEFAULTTONULL);
    out.state_ok =
        ReadWindowDesktopState(documented_manager, info.hwnd, out.desktop) &&
        ::GetWindowRect(info.hwnd, &out.rect);
    out.snapshot_ok =
        out.state_ok && out.monitor != nullptr &&
        ::GetWindow(info.hwnd, GW_OWNER) == info.owner;
    return out.snapshot_ok;
}

bool RealAppWindowIdentityUnchanged(const RealAppWindowSnapshot& baseline,
                                   const RealAppWindowSnapshot& current) {
    return baseline.info.hwnd == current.info.hwnd &&
           baseline.info.identity.pid == current.info.identity.pid &&
           baseline.info.identity.process_creation_time_ok &&
           current.info.identity.process_creation_time_ok &&
           SameFileTime(baseline.info.identity.process_creation_time,
                        current.info.identity.process_creation_time);
}

const char* DesktopRelationText(const RealAppWindowSnapshot& before,
                                const RealAppWindowSnapshot& after) {
    if (!before.state_ok || !after.state_ok) return "unavailable";
    const bool guid_equal =
        ::IsEqualGUID(before.desktop.desktop, after.desktop.desktop) != FALSE;
    const bool current_equal = before.desktop.on_current == after.desktop.on_current;
    static const GUID kZeroGuid{};
    if (guid_equal && current_equal) {
        return "unchanged";
    }
    if (::IsEqualGUID(before.desktop.desktop, kZeroGuid) &&
        ::IsEqualGUID(after.desktop.desktop, kZeroGuid)) {
        return "CHANGED (GUID_NULL; current status changed)";
    }
    return "CHANGED";
}

bool IsWindowDesktopAssignmentChanged(const RealAppWindowSnapshot& before,
                                      const RealAppWindowSnapshot& after) {
    if (!before.state_ok || !after.state_ok) return false;
    return ::IsEqualGUID(before.desktop.desktop, after.desktop.desktop) == FALSE ||
           before.desktop.on_current != after.desktop.on_current;
}

bool IsWindowStateOnCarrier(const RealAppWindowInfo& info,
                            const WindowDesktopState& state, bool state_ok,
                            const GUID& carrier) {
    if (!state_ok || !state.on_current) return false;
    if (info.owner != nullptr) {
        static const GUID kZeroGuid{};
        return ::IsEqualGUID(state.desktop, carrier) ||
               ::IsEqualGUID(state.desktop, kZeroGuid);
    }
    return ::IsEqualGUID(state.desktop, carrier) != FALSE;
}

bool IsRealAppWindowOnCarrier(const RealAppWindowSnapshot& snapshot,
                              const GUID& carrier) {
    return IsWindowStateOnCarrier(snapshot.info, snapshot.desktop,
                                  snapshot.state_ok, carrier);
}


LRESULT CALLBACK ProbeWindowProc(HWND hwnd, UINT message, WPARAM wparam,
                                 LPARAM lparam) {
    if (message == WM_CLOSE) {
        ::DestroyWindow(hwnd);
        return 0;
    }
    return ::DefWindowProcW(hwnd, message, wparam, lparam);
}

bool EnsureProbeWindowClass() {
    static constexpr wchar_t kClassName[] = L"vdprobe.LogicalWorkspaceProbe";
    static bool registered = false;
    if (registered) return true;

    WNDCLASSEXW klass{};
    klass.cbSize = sizeof(klass);
    klass.hInstance = ::GetModuleHandleW(nullptr);
    klass.lpfnWndProc = &ProbeWindowProc;
    klass.lpszClassName = kClassName;
    klass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    klass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    if (::RegisterClassExW(&klass) == 0 &&
        ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }
    registered = true;
    return true;
}

bool SpawnThrowawayProbeWindow(SpawnedProbeWindow& out) {
    out = {};
    if (!EnsureProbeWindowClass()) {
        Print("  RegisterClassExW(probe window) failed: {}\n",
              HrToString(HRESULT_FROM_WIN32(::GetLastError())));
        return false;
    }

    static unsigned sequence = 0;
    const std::wstring title =
        L"vdprobe logical workspace probe " + std::to_wstring(++sequence);
    constexpr wchar_t kClassName[] = L"vdprobe.LogicalWorkspaceProbe";
    HWND hwnd = ::CreateWindowExW(
        WS_EX_APPWINDOW, kClassName, title.c_str(), WS_OVERLAPPEDWINDOW,
        120, 120, 520, 320, nullptr, nullptr, ::GetModuleHandleW(nullptr),
        nullptr);
    if (hwnd == nullptr) {
        Print("  CreateWindowExW(probe window) failed: {}\n",
              HrToString(HRESULT_FROM_WIN32(::GetLastError())));
        return false;
    }

    ::ShowWindow(hwnd, SW_SHOWNOACTIVATE);
    ::UpdateWindow(hwnd);
    out.hwnd = hwnd;
    out.pid = ::GetCurrentProcessId();
    DWORD owner_pid = 0;
    out.thread_id = ::GetWindowThreadProcessId(hwnd, &owner_pid);
    if (out.thread_id == 0 || out.pid == 0 || owner_pid != out.pid) {
        ::DestroyWindow(hwnd);
        out = {};
        return false;
    }
    Print("  spawned vdprobe probe pid={} tid={} hwnd=0x{:X}\n", out.pid,
          out.thread_id, reinterpret_cast<uintptr_t>(out.hwnd));
    return true;
}

bool CloseThrowawayProbeWindow(SpawnedProbeWindow& process) {
    bool closed = true;
    if (process.hwnd != nullptr && ::IsWindow(process.hwnd)) {
        closed = ::DestroyWindow(process.hwnd) != FALSE;
    }
    process.hwnd = nullptr;
    process.pid = 0;
    process.thread_id = 0;
    return closed;
}

bool MoveViewToDesktopAndWait(ManagerInternal& mi, IUnknown* view,
                              IUnknown* target_desktop, HWND hwnd,
                              IVirtualDesktopManager* documented_manager,
                              const GUID& expected_desktop,
                              const GUID& carrier, bool allow_mutating,
                              Gate& out_gate, HRESULT& out_hr,
                              DWORD timeout_ms = 2000) {
    out_gate = Gate::Ok;
    out_hr = E_ABORT;
    const MethodEntry* method =
        mi.layout == nullptr ? nullptr : FindMethod(*mi.layout, "MoveViewToDesktop");
    if (method == nullptr || view == nullptr || target_desktop == nullptr) {
        out_gate = Gate::NoSuchMethod;
        return false;
    }

    out_hr = InvokeSlot(mi.obj.Get(), *mi.layout, *method, out_gate,
                         allow_mutating, view, target_desktop);
    if (out_gate != Gate::Ok || FAILED(out_hr)) return false;

    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    bool matched = false;
    do {
        PumpStaMessages();
        WindowDesktopState state;
        GUID current{};
        const bool state_ok =
            ReadWindowDesktopState(documented_manager, hwnd, state) &&
            WindowStateMatches(state, expected_desktop,
                               ::IsEqualGUID(expected_desktop, carrier) != FALSE);
        const bool current_ok =
            ReadCurrentDesktopId(mi, current) && ::IsEqualGUID(current, carrier);
        matched = state_ok && current_ok;
        if (matched) break;
        ::Sleep(25);
    } while (::GetTickCount64() < deadline);
    return matched;
}

bool ViewEventsOnlyExpected(const std::vector<NotifyEvent>& events,
                            ULONGLONG not_before_qpc, HWND a1, HWND a2) {
    for (const NotifyEvent& event : events) {
        if (event.timestamp_qpc < not_before_qpc ||
            event.kind != NotifyEventKind::ViewVirtualDesktopChanged) {
            continue;
        }
        if (event.hwnd != a1 && event.hwnd != a2) return false;
    }
    return true;
}

bool ViewEventsWithinScope(const std::vector<NotifyEvent>& events,
                           ULONGLONG not_before_qpc,
                           const std::vector<HWND>& allowed_hwnds) {
    for (const NotifyEvent& event : events) {
        if (event.timestamp_qpc < not_before_qpc ||
            event.kind != NotifyEventKind::ViewVirtualDesktopChanged) {
            continue;
        }
        if (std::find(allowed_hwnds.begin(), allowed_hwnds.end(), event.hwnd) ==
            allowed_hwnds.end()) {
            return false;
        }
    }
    return true;
}

bool HasMatchingViewCallback(const std::vector<NotifyEvent>& events,
                             ULONGLONG not_before_qpc, HWND hwnd) {
    for (const NotifyEvent& event : events) {
        if (event.timestamp_qpc >= not_before_qpc &&
            event.kind == NotifyEventKind::ViewVirtualDesktopChanged &&
            event.hwnd == hwnd) {
            return true;
        }
    }
    return false;
}

bool VerifyLogicalModel(const WorkspaceEngine& model,
                        const std::vector<const LogicalWindow*>& windows,
                        IVirtualDesktopManager* documented_manager,
                        const GUID& carrier, const GUID& parking) {
    bool all_ok = true;
    for (const LogicalWindow* window : windows) {
        if (window == nullptr || window->identity.hwnd == nullptr) {
            all_ok = false;
            continue;
        }
        const MonitorId monitor_id =
            reinterpret_cast<MonitorId>(window->monitor);
        const MonitorWorkspaceState* monitor = model.Monitor(monitor_id);
        if (monitor == nullptr) {
            all_ok = false;
            continue;
        }
        const bool active = monitor->active == window->workspace;
        const GUID& expected_desktop = active ? carrier : parking;

        WindowIdentity identity;
        RECT rect{};
        WindowDesktopState state;
        const bool identity_ok =
            ReadWindowIdentity(window->identity.hwnd, identity) &&
            identity.hwnd == window->identity.hwnd &&
            identity.pid == window->identity.pid &&
            identity.process_creation_time_ok &&
            window->identity.process_creation_time_ok &&
            SameFileTime(identity.process_creation_time,
                         window->identity.process_creation_time);
        const bool rect_ok = ::GetWindowRect(window->identity.hwnd, &rect) &&
                            SameRect(rect, window->rect);
        const bool monitor_ok =
            ::MonitorFromWindow(window->identity.hwnd, MONITOR_DEFAULTTONULL) ==
            window->monitor;
        const bool native_ok =
            ReadWindowDesktopState(documented_manager, window->identity.hwnd,
                                   state) &&
            WindowStateMatches(state, expected_desktop, active);
        const bool pass = identity_ok && rect_ok && monitor_ok && native_ok;
        Field(std::format("    logical window {}",
                          GuidToString(window->native_desktop)),
              pass ? "PASS" : "FAIL");
        Field("      active workspace",
              active ? std::format("{}", window->workspace) : "inactive");
        Field("      expected native desktop", GuidToString(expected_desktop));
        if (!pass) {
            Field("      identity", identity_ok ? "unchanged" : "CHANGED");
            Field("      rect", rect_ok ? "unchanged" : "CHANGED");
            Field("      monitor", monitor_ok ? "unchanged" : "CHANGED");
            Field("      native state", native_ok ? "matches" : "MISMATCH");
        }
        all_ok = all_ok && pass;
    }
    return all_ok;
}

bool VerifyControlWindowUnchanged(const LogicalWindow& control,
                                  const WindowDesktopState& baseline,
                                  IVirtualDesktopManager* documented_manager,
                                  const GUID& carrier) {
    WindowIdentity identity;
    RECT rect{};
    WindowDesktopState state;
    const bool identity_ok =
        ReadWindowIdentity(control.identity.hwnd, identity) &&
        identity.hwnd == control.identity.hwnd &&
        identity.pid == control.identity.pid &&
        identity.process_creation_time_ok &&
        control.identity.process_creation_time_ok &&
        SameFileTime(identity.process_creation_time,
                     control.identity.process_creation_time);
    const bool rect_ok = ::GetWindowRect(control.identity.hwnd, &rect) &&
                        SameRect(rect, control.rect);
    const bool monitor_ok =
        ::MonitorFromWindow(control.identity.hwnd, MONITOR_DEFAULTTONULL) ==
        control.monitor;
    const bool desktop_ok =
        ReadWindowDesktopState(documented_manager, control.identity.hwnd, state) &&
        WindowStateMatches(state, carrier, true);
    const bool visibility_ok =
        state.visible == baseline.visible && state.cloaked == baseline.cloaked;
    const bool pass =
        identity_ok && rect_ok && monitor_ok && desktop_ok && visibility_ok;
    Field("    control B1 HWND", identity_ok ? "unchanged" : "CHANGED");
    Field("    control B1 RECT", rect_ok ? "unchanged" : "CHANGED");
    Field("    control B1 monitor", monitor_ok ? "unchanged" : "CHANGED");
    Field("    control B1 desktop", desktop_ok ? "unchanged" : "CHANGED");
    Field("    control B1 visibility", visibility_ok ? "unchanged" : "CHANGED");
    return pass;
}

struct WindowMoveObservation {
    GUID from{};
    GUID to{};
    ULONGLONG call_start_qpc = 0;
    ULONGLONG call_end_qpc = 0;
    HRESULT move_hr = E_FAIL;
    bool move_gate_ok = false;
    GUID observed_current{};
    bool observed_current_ok = false;
    WindowDesktopState observed_window{};
    bool observed_window_ok = false;
    bool view_callback_ok = false;
    size_t current_changed_count = 0;
    NotifyEvent matching_view_event{};
    bool matching_view_event_ok = false;
    bool view_callback_scope_ok = true;
    std::vector<NotifyEvent> events;
};

const NotifyEvent* FindMatchingViewCallback(const std::vector<NotifyEvent>& events,
                                            HWND hwnd, ULONGLONG start_qpc) {
    for (const NotifyEvent& event : events) {
        if (event.kind != NotifyEventKind::ViewVirtualDesktopChanged ||
            event.timestamp_qpc < start_qpc || event.hwnd != hwnd) {
            continue;
        }
        return &event;
    }
    return nullptr;
}

size_t CountCurrentDesktopChanged(const std::vector<NotifyEvent>& events,
                                  ULONGLONG start_qpc) {
    size_t count = 0;
    for (const NotifyEvent& event : events) {
        if (event.kind == NotifyEventKind::CurrentVirtualDesktopChanged &&
            event.timestamp_qpc >= start_qpc) {
            ++count;
        }
    }
    return count;
}

void PrintWindowDesktopState(const WindowDesktopState& state) {
    Field("    window desktop",
          state.desktop_ok ? GuidToString(state.desktop) : "(unavailable)");
    Field("    IsWindowOnCurrentVirtualDesktop",
          state.on_current_ok ? (state.on_current ? "true" : "false")
                              : "(unavailable)");
    Field("    visible", state.visible ? "true" : "false");
    Field("    cloaked", std::format("{}", state.cloaked));
}

WindowMoveObservation MoveViewAndVerify(
    ManagerInternal& mi, IUnknown* view, IUnknown* target_desktop,
    const GUID& from, const GUID& to, const GUID& carrier, HWND hwnd,
    IVirtualDesktopManager* documented_manager, NotifySink* sink,
    bool allow_mutating) {
    WindowMoveObservation observation;
    observation.from = from;
    observation.to = to;
    const MethodEntry* method =
        mi.layout == nullptr ? nullptr : FindMethod(*mi.layout, "MoveViewToDesktop");
    observation.call_start_qpc = QpcNow();
    if (method != nullptr && view != nullptr && target_desktop != nullptr) {
        Gate gate = Gate::Ok;
        observation.move_hr = InvokeSlot(mi.obj.Get(), *mi.layout, *method, gate,
                                         allow_mutating, view, target_desktop);
        observation.move_gate_ok = gate == Gate::Ok;
    } else {
        observation.move_hr = E_ABORT;
    }
    observation.call_end_qpc = QpcNow();

    Print("  MoveViewToDesktop {} -> {}\n", GuidToString(from), GuidToString(to));
    Field("    call start qpc", std::format("{}", observation.call_start_qpc));
    Field("    call end qpc", std::format("{}", observation.call_end_qpc));
    Field("    call elapsed ms",
          std::format("{:.3f}",
                      QpcMilliseconds(observation.call_start_qpc,
                                      observation.call_end_qpc)));
    Field("    gate", observation.move_gate_ok ? "ok" : "refused");
    Field("    HRESULT", HrToString(observation.move_hr));

    const ULONGLONG deadline = ::GetTickCount64() + 2000;
    bool state_seen = false;
    while (::GetTickCount64() < deadline) {
        PumpStaMessages();
        DrainAndPrintEvents(sink, observation.call_start_qpc, observation.events);

        WindowDesktopState window_state;
        if (ReadWindowDesktopState(documented_manager, hwnd, window_state)) {
            observation.observed_window = window_state;
            observation.observed_window_ok = true;
            state_seen = ::IsEqualGUID(window_state.desktop, to) != FALSE;
        }
        GUID current{};
        if (ReadCurrentDesktopId(mi, current)) {
            observation.observed_current = current;
            observation.observed_current_ok = ::IsEqualGUID(current, carrier) != FALSE;
        }
        observation.current_changed_count =
            CountCurrentDesktopChanged(observation.events,
                                       observation.call_start_qpc);
        const NotifyEvent* callback =
            FindMatchingViewCallback(observation.events, hwnd,
                                     observation.call_start_qpc);
        if (callback != nullptr) {
            observation.matching_view_event = *callback;
            observation.matching_view_event_ok = true;
        }
        if (state_seen && observation.matching_view_event_ok) break;
        ::Sleep(25);
    }

    PumpStaMessages();
    DrainAndPrintEvents(sink, observation.call_start_qpc, observation.events);
    if (ReadWindowDesktopState(documented_manager, hwnd,
                               observation.observed_window)) {
        observation.observed_window_ok = true;
    }
    if (ReadCurrentDesktopId(mi, observation.observed_current)) {
        observation.observed_current_ok =
            ::IsEqualGUID(observation.observed_current, carrier) != FALSE;
    }
    observation.current_changed_count =
        CountCurrentDesktopChanged(observation.events, observation.call_start_qpc);
    if (const NotifyEvent* callback =
            FindMatchingViewCallback(observation.events, hwnd,
                                     observation.call_start_qpc)) {
        observation.matching_view_event = *callback;
        observation.matching_view_event_ok = true;
    }
    observation.view_callback_ok = observation.matching_view_event_ok;

    Field("    current desktop",
          observation.observed_current_ok
              ? GuidToString(observation.observed_current)
              : "(not carrier or unavailable)");
    if (observation.observed_window_ok) {
        PrintWindowDesktopState(observation.observed_window);
    }
    Field("    ViewVirtualDesktopChanged",
          observation.view_callback_ok ? "observed" : "missing");
    if (observation.matching_view_event_ok) {
        Field("    callback qpc",
              std::format("{}", observation.matching_view_event.timestamp_qpc));
        Field("    callback thread",
              std::format("{}", observation.matching_view_event.callback_thread_id));
        Field("    callback latency ms",
              std::format("{:.3f}",
                          QpcMilliseconds(observation.call_start_qpc,
                                          observation.matching_view_event.timestamp_qpc)));
    }
    Field("    CurrentVirtualDesktopChanged count",
          std::format("{}", observation.current_changed_count));
    return observation;
}

class ViewRestoreGuard {
   public:
    ViewRestoreGuard(ManagerInternal& mi, IUnknown* view, IUnknown* target,
                     bool allow_mutating)
        : mi_(mi), view_(view), target_(target), allow_mutating_(allow_mutating) {}

    ~ViewRestoreGuard() noexcept {
        if (armed_) (void)AttemptNow();
    }

    void Arm() noexcept { armed_ = true; }
    void Disarm() noexcept { armed_ = false; }

    HRESULT AttemptNow() noexcept {
        if (!armed_ || view_ == nullptr || target_ == nullptr ||
            mi_.layout == nullptr) {
            return E_ABORT;
        }
        const MethodEntry* method = FindMethod(*mi_.layout, "MoveViewToDesktop");
        if (method == nullptr) return E_ABORT;
        Gate gate = Gate::Ok;
        return InvokeSlot(mi_.obj.Get(), *mi_.layout, *method, gate,
                          allow_mutating_, view_, target_);
    }

    private:
    ManagerInternal& mi_;
    IUnknown* view_ = nullptr;     // borrowed; outer scope outlives guard
    IUnknown* target_ = nullptr;   // borrowed; outer scope outlives guard
    bool allow_mutating_ = false;
    bool armed_ = false;
};

void ReportManagerHeader(const ManagerInternal& mi) {
    if (mi.candidate == nullptr) {
        Field("IVirtualDesktopManagerInternal",
              std::format("NOT OBTAINED (last hr {})", HrToString(mi.hr)));
        return;
    }
    Field("IVirtualDesktopManagerInternal", "obtained");
    Field("  accepted IID", GuidToString(*mi.candidate->iid));
    Field("  IID known for", mi.candidate->builds);
    Field("  IID source", mi.candidate->source);
    Field("  vtable module", mi.vtable_module.empty() ? "?" : mi.vtable_module);
    Field("  layout registered", mi.layout ? "yes" : "NO - cannot call anything");
    if (mi.layout != nullptr) {
        int max_slot = 0;
        for (const MethodEntry& m : mi.layout->methods) {
            if (m.slot > max_slot) max_slot = m.slot;
        }
        Field("  verified method count",
              std::format("{} (slots 3..{})", max_slot >= 3 ? max_slot - 2 : 0,
                          max_slot));
        Field("  layout monitor-aware",
              mi.layout->monitor == MonitorAware::Yes
                  ? "YES"
                  : (mi.layout->monitor == MonitorAware::No ? "no" : "unknown"));
    }
}

}  // namespace

// ------------------------------------------------------------ immersive shell
HRESULT GetImmersiveShell(Com<IServiceProvider>& out) {
    return ::CoCreateInstance(CLSID_ImmersiveShell, nullptr,
                              CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER,
                              IID_IServiceProvider_Shell, out.PutVoid());
}

std::vector<ProbeResult> ProbeInterface(IServiceProvider* sp, const char* iface) {
    std::vector<ProbeResult> results;
    for (const IidCandidate& c : IidCandidatesFor(iface)) {
        ProbeResult r;
        r.candidate = &c;
        const GUID* sid = ServiceIdFor(iface, c.iid);
        if (sid == nullptr) {
            r.hr = E_NOTIMPL;  // not reachable via QueryService
            results.push_back(std::move(r));
            continue;
        }
        RawObject o;
        r.hr = sp->QueryService(*sid, *c.iid, o.PutVoid());
        if (SUCCEEDED(r.hr) && o) {
            r.obtained = true;
            DescribeObject(o.Get(), r);
        }
        results.push_back(std::move(r));
    }
    return results;
}

const ProbeResult* FirstObtained(const std::vector<ProbeResult>& results) {
    for (const ProbeResult& r : results) {
        if (r.obtained) return &r;
    }
    return nullptr;
}

// -------------------------------------------------------- notification sink

NotificationRegistration::NotificationRegistration(IServiceProvider* sp, NotifySink* sink,
                                                    bool confirm_register)
    : sink_(sink) {
    if (!confirm_register) {
        gate_ = Gate::Mutating;
        hr_ = E_ABORT;
        return;
    }
    if (sp == nullptr || sink == nullptr) {
        gate_ = Gate::NoObject;
        hr_ = E_ABORT;
        return;
    }
    for (const IidCandidate& c : IidCandidatesFor("IVirtualDesktopNotificationService")) {
        RawObject o;
        HRESULT qhr = sp->QueryService(SID_VirtualDesktopNotificationService, *c.iid,
                                       o.PutVoid());
        if (FAILED(qhr) || !o) {
            hr_ = qhr;
            continue;
        }
        const LayoutTable* t = LayoutForIid(*c.iid);
        if (t == nullptr) continue;
        const MethodEntry* m = FindMethod(*t, "Register");
        if (m == nullptr) continue;

        Gate g = Gate::Ok;
        DWORD cookie = 0;
        HRESULT rhr = InvokeSlot(o.Get(), *t, *m, g, /*allow_mutating=*/true,
                                 sink->AsUnknown(), &cookie);
        gate_ = g;
        hr_ = rhr;
        if (g == Gate::Ok && SUCCEEDED(rhr) && cookie != 0) {
            notif_svc_ = std::move(o);
            layout_ = t;
            cookie_ = cookie;
            registered_ = true;
        }
        break;
    }
}

NotificationRegistration::~NotificationRegistration() {
    UnregisterNow();
}

HRESULT NotificationRegistration::UnregisterNow() {
    if (!registered_) return unregister_attempted_ ? unregister_hr_ : E_ABORT;
    unregister_attempted_ = true;
    if (!notif_svc_ || layout_ == nullptr) {
        unregister_gate_ = Gate::NoObject;
        unregister_hr_ = E_ABORT;
        return unregister_hr_;
    }
    const MethodEntry* m = FindMethod(*layout_, "Unregister");
    if (m == nullptr) {
        unregister_gate_ = Gate::NoSuchMethod;
        unregister_hr_ = E_ABORT;
        return unregister_hr_;
    }
    // Best-effort: Unregister is itself gated as mutating, so it must be
    // unlocked here too.  There is no scenario in which failing to unregister
    // should be silently treated as read-only-safe.
    unregister_gate_ = Gate::Ok;
    unregister_hr_ =
        InvokeSlot(notif_svc_.Get(), *layout_, *m, unregister_gate_, /*allow_mutating=*/true,
                   cookie_);
    if (unregister_gate_ == Gate::Ok && SUCCEEDED(unregister_hr_)) {
        registered_ = false;
        cookie_ = 0;
        layout_ = nullptr;
        notif_svc_.Reset();
    }
    return unregister_hr_;
}

// ------------------------------------------------------------ private-status

int CmdPrivateStatus() {
    BuildInfo b = GetBuildInfo();
    BuildFamily fam = ClassifyBuild(b);

    Heading("private-status");
    Field("build", std::format("{}.{}.{}.{}", b.major, b.minor, b.build, b.ubr));
    Field("build family", fam.name);

    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    Field("CLSID_ImmersiveShell", GuidToString(CLSID_ImmersiveShell));
    Field("IServiceProvider", SUCCEEDED(hr) ? "obtained"
                                            : std::format("FAILED {}", HrToString(hr)));
    if (FAILED(hr)) {
        Print(
            "\n  Without IServiceProvider nothing else in phase 2 can run.  This "
            "usually\n  means explorer.exe is not running in this session.\n");
        return 1;
    }
    if (void** vt = VtableOf(sp.Get())) {
        Field("  vtable module", ModuleOf(vt));
    }

    Print(
        "\n  Probing is QueryService/QueryInterface only.  No method on any private\n"
        "  interface is invoked by this subcommand.\n");

    for (const char* iface : KnownInterfaces()) {
        Heading(iface);
        if (std::strcmp(iface, "IVirtualDesktopManager") == 0) {
            Com<IUnknown> doc;
            HRESULT dhr = ::CoCreateInstance(CLSID_VirtualDesktopManager, nullptr,
                                             CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER,
                                             IID_IVirtualDesktopManager, doc.PutVoid());
            Print("  {:<7} {} {}\n", SUCCEEDED(dhr) ? "ACCEPT" : "reject",
                  GuidToString(IID_IVirtualDesktopManager),
                  "documented, CoCreateInstance(CLSID_VirtualDesktopManager)");
            if (FAILED(dhr)) Print("          hr={}\n", HrToString(dhr));
            continue;
        }
        if (std::strcmp(iface, "IVirtualDesktop") == 0) {
            Print(
                "  not reachable via QueryService; obtained only from\n"
                "  IVirtualDesktopManagerInternal::GetCurrentDesktop/GetDesktops.\n"
                "  See 'vdprobe desktops'.\n");
            continue;
        }
        if (std::strcmp(iface, "IApplicationView") == 0) {
            Print(
                "  not reachable via QueryService; obtained only from\n"
                "  IApplicationViewCollection.  Not exercised in the read-only "
                "milestone.\n");
            continue;
        }
        if (std::strcmp(iface, "IVirtualDesktopNotification") == 0) {
            Print(
                "  not reachable via QueryService/QueryInterface at all: this is the\n"
                "  sink interface vdprobe implements so the shell can call back into it\n"
                "  after Register.  See 'vdprobe notify-watch --confirm-register'.\n");
            continue;
        }
        std::vector<ProbeResult> results = ProbeInterface(sp.Get(), iface);
        if (results.empty()) {
            Print("  no candidate IIDs recorded\n");
            continue;
        }
        for (const ProbeResult& r : results) PrintProbeRow(r);
        if (FirstObtained(results) == nullptr) {
            Print("  => interface NOT available under any recorded IID\n");
        }
    }

    Heading("summary");
    std::vector<ProbeResult> vdmi = ProbeInterface(sp.Get(), "IVirtualDesktopManagerInternal");
    const ProbeResult* ok = FirstObtained(vdmi);
    if (ok != nullptr) {
        Field("accepted VDMI IID", GuidToString(*ok->candidate->iid));
        Field("that IID's layout is",
              ok->candidate->monitor == MonitorAware::Yes ? "MONITOR-AWARE"
                                                          : "not monitor-aware");
    } else {
        Field("accepted VDMI IID", "none");
    }
    return 0;
}

// ----------------------------------------------------------------- desktops

int CmdDesktops() {
    Heading("desktops");
    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    if (FAILED(hr)) {
        Field("IServiceProvider", std::format("FAILED {}", HrToString(hr)));
        return 1;
    }
    ManagerInternal mi = AcquireManagerInternal(sp.Get());
    ReportManagerHeader(mi);
    if (mi.candidate == nullptr || mi.layout == nullptr) return 1;

    // --- GetCount -----------------------------------------------------------
    const MethodEntry* count_m = FindMethod(*mi.layout, "GetCount");
    if (count_m != nullptr) {
        Gate g = Gate::Ok;
        UINT count = 0;
        HRESULT chr = InvokeSlot(mi.obj.Get(), *mi.layout, *count_m, g, false, &count);
        Heading("GetCount");
        Field("slot", std::format("{}", count_m->slot));
        Field("signature", count_m->signature);
        Field("confidence", ConfidenceText(count_m->confidence));
        Field("evidence", count_m->evidence);
        Field("gate", GateText(g));
        if (g == Gate::Ok) {
            Field("hr", HrToString(chr));
            if (SUCCEEDED(chr)) Field("desktop count", std::format("{}", count));
        }
    }

    // --- GetDesktops --------------------------------------------------------
    const MethodEntry* list_m = FindMethod(*mi.layout, "GetDesktops");
    if (list_m == nullptr) {
        Print("\n  GetDesktops not present in the layout registry.\n");
        return 1;
    }
    Heading("GetDesktops");
    Field("slot", std::format("{}", list_m->slot));
    Field("signature", list_m->signature);
    Field("confidence", ConfidenceText(list_m->confidence));
    Field("evidence", list_m->evidence);

    Gate g = Gate::Ok;
    IObjectArray* arr_raw = nullptr;
    HRESULT ghr = InvokeSlot(mi.obj.Get(), *mi.layout, *list_m, g, false, &arr_raw);
    Field("gate", GateText(g));
    if (g != Gate::Ok) return 1;
    Field("hr", HrToString(ghr));
    if (FAILED(ghr) || arr_raw == nullptr) return 1;

    Com<IObjectArray> arr;
    *arr.Put() = arr_raw;

    UINT n = 0;
    if (FAILED(arr->GetCount(&n))) {
        Print("  IObjectArray::GetCount failed\n");
        return 1;
    }
    Field("array count", std::format("{}", n));

    Print("\n  {:<4} {:<40} {:<24} {}\n", "idx", "GUID", "name", "IVirtualDesktop IID");
    Print("  {}\n", std::string(108, '-'));
    for (UINT i = 0; i < n; ++i) {
        RawObject item;
        if (FAILED(arr->GetAt(i, IID_IUnknown, item.PutVoid())) || !item) continue;
        DesktopInfo d = InspectDesktop(item.Get());
        Print("  {:<4} {:<40} {:<24} {}\n", i,
              d.id_ok ? GuidToString(d.id) : "(GetId unavailable)",
              d.name_ok ? (d.name.empty() ? "(unnamed)" : d.name) : "(GetName unavailable)",
              d.iface_iid.empty() ? "(no recorded IID matched)" : d.iface_iid);
    }
    return 0;
}

// ----------------------------------------------------------- current-desktop

int CmdCurrentDesktop() {
    Heading("current-desktop");
    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    if (FAILED(hr)) {
        Field("IServiceProvider", std::format("FAILED {}", HrToString(hr)));
        return 1;
    }
    ManagerInternal mi = AcquireManagerInternal(sp.Get());
    ReportManagerHeader(mi);
    if (mi.candidate == nullptr || mi.layout == nullptr) return 1;

    const MethodEntry* m = FindMethod(*mi.layout, "GetCurrentDesktop");
    if (m == nullptr) {
        Print("\n  GetCurrentDesktop not present in the layout registry.\n");
        return 1;
    }
    Heading("GetCurrentDesktop");
    Field("slot", std::format("{}", m->slot));
    Field("signature", m->signature);
    Field("confidence", ConfidenceText(m->confidence));
    Field("evidence", m->evidence);
    if (m->note) Field("note", m->note);

    Gate g = Gate::Ok;
    IUnknown* raw = nullptr;
    HRESULT chr = InvokeSlot(mi.obj.Get(), *mi.layout, *m, g, false, &raw);
    Field("gate", GateText(g));
    if (g != Gate::Ok) return 1;
    Field("hr", HrToString(chr));
    if (FAILED(chr) || raw == nullptr) return 1;
    RawObject cur;
    cur.Attach(raw);

    DesktopInfo d = InspectDesktop(cur.Get());
    Field("desktop GUID", d.id_ok ? GuidToString(d.id) : "(unavailable)");
    Field("desktop name", d.name_ok ? (d.name.empty() ? "(unnamed)" : d.name)
                                    : "(unavailable)");
    Field("answered IVirtualDesktop IID",
          d.iface_iid.empty() ? "(none matched)" : d.iface_iid);

    // Cross-check against the documented API, which reports the desktop of a
    // window rather than of a monitor.
    Heading("cross-check vs documented IVirtualDesktopManager");
    std::vector<WindowRec> wins = EnumerateTopLevelWindows(false);
    HRESULT ahr = AnnotateWithDesktopIds(wins);
    if (FAILED(ahr)) {
        Field("IVirtualDesktopManager", std::format("FAILED {}", HrToString(ahr)));
        return 0;
    }
    int agree = 0, null_guid = 0, differ = 0;
    static const GUID kZeroGuid{};
    for (const WindowRec& w : wins) {
        if (!w.desktop_id_ok || !w.on_current_desktop) continue;
        if (::IsEqualGUID(w.desktop_id, kZeroGuid)) {
            ++null_guid;
        } else if (d.id_ok && ::IsEqualGUID(w.desktop_id, d.id)) {
            ++agree;
        } else {
            ++differ;
        }
    }
    Field("windows on current desktop, GUID matches", std::format("{}", agree));
    Field("windows on current desktop, GUID is all-zero",
          std::format("{} (UWP/cloaked hosts report GUID_NULL)", null_guid));
    Field("windows on current desktop, GUID differs", std::format("{}", differ));
    if (differ == 0 && agree > 0) {
        Print(
            "  => the private GetCurrentDesktop GUID matches the documented API for "
            "every\n     window that reports a real desktop GUID.  The all-zero "
            "entries are\n     windows the shell does not associate with a desktop; "
            "they are not\n     disagreements.\n");
    }

    // With no HMONITOR parameter there can only be one "current" desktop.
    std::vector<MonitorRec> mons = EnumerateMonitors();
    Heading("per-monitor check");
    Field("monitors attached", std::format("{}", mons.size()));
    Field("GetCurrentDesktop arity",
          mi.layout->monitor == MonitorAware::Yes ? "takes a monitor argument"
                                                  : "takes NO monitor argument");
    if (mi.layout->monitor != MonitorAware::Yes) {
        Print(
            "  => the shell exposes exactly one current desktop for the whole "
            "session;\n     there is no API surface to ask 'current desktop on "
            "monitor N'.\n");
    }
    return 0;
}

// -------------------------------------------------------- per-monitor-status

int CmdPerMonitorStatus() {
    BuildInfo b = GetBuildInfo();
    BuildFamily fam = ClassifyBuild(b);

    Heading("per-monitor-status");
    Field("build", std::format("{}.{}.{}.{}", b.major, b.minor, b.build, b.ubr));
    Field("build family", fam.name);
    Field("per-monitor expected (public sources)", fam.per_monitor_expected ? "yes" : "no");
    Print("  rationale: {}\n", fam.rationale);

    // ---- 1. which IID does the live shell accept? --------------------------
    Heading("1. IID acceptance (QueryService only, no methods called)");
    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    if (FAILED(hr)) {
        Field("IServiceProvider", std::format("FAILED {}", HrToString(hr)));
        return 1;
    }
    std::vector<ProbeResult> vdmi =
        ProbeInterface(sp.Get(), "IVirtualDesktopManagerInternal");
    bool monitor_aware_iid_accepted = false;
    for (const ProbeResult& r : vdmi) {
        Print("  {:<7} {}  monitor-aware-layout={}  {}\n",
              r.obtained ? "ACCEPT" : "reject", GuidToString(*r.candidate->iid),
              r.candidate->monitor == MonitorAware::Yes ? "YES" : "no",
              r.candidate->builds);
        if (!r.obtained) Print("          hr={}\n", HrToString(r.hr));
        if (r.obtained && r.candidate->monitor == MonitorAware::Yes) {
            monitor_aware_iid_accepted = true;
        }
    }
    const ProbeResult* accepted = FirstObtained(vdmi);

    // ---- 2. method-count corroboration ------------------------------------
    Heading("2. interface shape of the accepted IID");
    if (accepted == nullptr) {
        Field("result", "no VDMI interface obtained");
    } else {
        const LayoutTable* t = LayoutForIid(*accepted->candidate->iid);
        int max_slot = 0;
        int verified = 0;
        for (const MethodEntry& m : t ? t->methods : std::span<const MethodEntry>{}) {
            if (m.slot > max_slot) max_slot = m.slot;
            if (m.confidence == Confidence::Verified) ++verified;
        }
        Field("accepted IID", GuidToString(*accepted->candidate->iid));
        Field("vtable module", accepted->vtable_module.empty()
                                   ? "?"
                                   : accepted->vtable_module);
        Field("live vtable run", VtableRunText(*accepted));
        Field("verified method count",
              std::format("{} (slots 3..{}), {} slots symbol-verified",
                          max_slot >= 3 ? max_slot - 2 : 0, max_slot, verified));
        Print(
            "  Published method counts for comparison: 19 for the monitor-aware\n"
            "  {{B2F925B9-...}} layout, 14 for Server 2022 {{094AFE11-...}},\n"
            "  10 for Windows 10 {{F31574D6-...}}.\n");
    }

    // ---- 3. per-method verdict from the registry --------------------------
    Heading("3. monitor-aware method surface");
    struct Want {
        const char* method;
        const char* alias;  // binary may use a decorated name
    };
    constexpr Want kWanted[] = {
        {"GetDesktopIsPerMonitor", nullptr},
        {"SetDesktopIsPerMonitor", nullptr},
        {"GetCurrentDesktop", nullptr},
        {"GetDesktops", nullptr},
        {"SwitchDesktop", nullptr},
        {"CreateDesktop", "CreateDesktopW"},
        {"GetCount", nullptr},
    };
    const LayoutTable* cur_layout =
        accepted ? LayoutForIid(*accepted->candidate->iid) : nullptr;
    for (const Want& w : kWanted) {
        if (cur_layout == nullptr) {
            Print("  {:<26} : no layout for the accepted IID\n", w.method);
            continue;
        }
        const MethodEntry* m = FindMethod(*cur_layout, w.method);
        if (m == nullptr && w.alias != nullptr) m = FindMethod(*cur_layout, w.alias);
        if (m == nullptr) {
            Print("  {:<26} : ABSENT from this IID's layout\n", w.method);
            continue;
        }
        const bool has_monitor_param = std::string_view(m->signature).find("HMONITOR") !=
                                       std::string_view::npos;
        Print("  {:<26} : slot {:>3}  monitor-param={}  confidence={}\n", m->method,
              m->slot == kUnknownSlot ? std::string("?") : std::format("{}", m->slot),
              has_monitor_param ? "YES" : "no", ConfidenceText(m->confidence));
        Print("  {:<26}   sig      {}\n", "", m->signature);
        Print("  {:<26}   evidence {}\n", "", m->evidence);
        if (m->note) Print("  {:<26}   note     {}\n", "", m->note);
    }

    // ---- 4. historical comparison ----------------------------------------
    Heading("4. what the monitor-aware generation looked like");
    for (const LayoutTable& t : LayoutsFor("IVirtualDesktopManagerInternal")) {
        if (t.monitor != MonitorAware::Yes) continue;
        Print("  {}  ({})\n", t.iid ? GuidToString(*t.iid) : "(iid unresolved)",
              t.builds);
        for (const MethodEntry& m : t.methods) {
            if (std::string_view(m.method).find("PerMonitor") == std::string_view::npos &&
                std::string_view(m.signature).find("HMONITOR") ==
                    std::string_view::npos) {
                continue;
            }
            Print("      slot {:>3}  {}\n",
                  m.slot == kUnknownSlot ? std::string("?") : std::format("{}", m.slot),
                  m.signature);
        }
    }

    // ---- 5. observable behaviour -----------------------------------------
    Heading("5. observable behaviour on this machine");
    std::vector<MonitorRec> mons = EnumerateMonitors();
    Field("monitors attached", std::format("{}", mons.size()));
    std::vector<WindowRec> wins = EnumerateTopLevelWindows(false);
    HRESULT ahr = AnnotateWithDesktopIds(wins);
    if (SUCCEEDED(ahr)) {
        std::vector<GUID> distinct;
        for (const WindowRec& w : wins) {
            if (!w.desktop_id_ok) continue;
            bool seen = false;
            for (const GUID& g : distinct) {
                if (::IsEqualGUID(g, w.desktop_id)) {
                    seen = true;
                    break;
                }
            }
            if (!seen) distinct.push_back(w.desktop_id);
        }
        Field("distinct desktop GUIDs across all windows",
              std::format("{}", distinct.size()));
        for (const GUID& g : distinct) Print("      {}\n", GuidToString(g));
    }

    Heading("6. persisted virtual desktop state (read-only registry)");
    Print("  HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VirtualDesktops\n");
    DumpRegTree(HKEY_CURRENT_USER,
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VirtualDesktops",
                0, 2);
    Print(
        "\n  A per-monitor implementation would need per-monitor desktop lists here.\n"
        "  Look for any value keyed by monitor/display id rather than a single flat\n"
        "  VirtualDesktopIDs list.\n");

    // ---- 7. dead code, or removed? ---------------------------------------
    Heading("7. is the monitor-aware revision still in the binaries?");
    Print(
        "  Scanning shipped modules for the raw 16 bytes of each historical IID.\n"
        "  Bytes present but QueryService failing would mean dormant/dead code;\n"
        "  bytes absent means the revision was removed from the build.\n\n");
    struct ModuleSpec {
        const wchar_t* name;
        bool in_windows_dir;
    };
    constexpr ModuleSpec kModules[] = {
        {L"twinui.pcshell.dll", false},
        {L"twinui.dll", false},
        {L"actxprxy.dll", false},
        {L"explorer.exe", true},
    };
    bool monitor_aware_bytes_present = false;
    for (const IidCandidate& c : IidCandidatesFor("IVirtualDesktopManagerInternal")) {
        size_t total = 0;
        std::string detail;
        for (const ModuleSpec& ms : kModules) {
            std::wstring path =
                ms.in_windows_dir ? WindowsPath(ms.name) : System32Path(ms.name);
            GuidScan s = ScanFileForGuid(path, *c.iid);
            if (!s.file_ok) continue;
            total += s.occurrences;
            if (s.occurrences > 0) {
                if (!detail.empty()) detail += ", ";
                detail += std::format("{}x in {}", s.occurrences, ToUtf8(ms.name));
            }
        }
        if (total > 0 && c.monitor == MonitorAware::Yes) {
            monitor_aware_bytes_present = true;
        }
        Print("  {}  monitor-aware={:<7}  {}\n", GuidToString(*c.iid),
              MonitorAwareText(c.monitor),
              total == 0 ? std::string("ABSENT from all scanned modules") : detail);
    }

    // ---- verdict ---------------------------------------------------------
    Heading("verdict");
    Field("monitor-aware IID accepted by live shell",
          monitor_aware_iid_accepted ? "YES" : "no");
    Field("monitor-aware IID bytes found in binaries",
          monitor_aware_bytes_present ? "YES (dormant code)" : "no (removed)");
    Field("GetDesktopIsPerMonitor reachable", "no");
    Field("SetDesktopIsPerMonitor reachable", "no");
    if (!monitor_aware_iid_accepted && accepted != nullptr) {
        Print(
            "  The shell answers only to the non-monitor-aware IID, and the "
            "monitor-aware\n"
            "  IIDs do not appear anywhere in the shipped shell binaries.  The "
            "per-monitor\n"
            "  entry points are therefore not dormant code that could be re-enabled: "
            "they\n"
            "  are absent from this build.\n");
    }
    return 0;
}

// ------------------------------------------------------------- notify-watch

int CmdNotifyWatch(bool confirm_register, bool self_trigger, bool confirm_mutate,
                   int duration_seconds) {
    Heading("notify-watch");
    Field("what this does",
          "registers an IVirtualDesktopNotification sink and logs shell callbacks");
    Field("mutation",
          self_trigger
              ? "Register/Unregister plus one outbound switch and required restoration attempts"
              : "Register/Unregister a callback (small, self-contained, undone on exit)");

    if (!confirm_register) {
        Field("gate", GateText(Gate::Mutating));
        Print(
            "\n  Refusing to register without --confirm-register.  Registering IS a\n"
            "  mutation of shell state (it adds a callback registration for this\n"
            "  process), even though it changes no desktop or window.  Re-run as:\n"
            "\n      vdprobe notify-watch --confirm-register [--seconds N]\n");
        return 1;
    }
    if (self_trigger && !confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print(
            "\n  Refusing --self-trigger without --confirm-mutate.  This performs one\n"
            "  existing-desktop original -> other -> original global switch, plus any\n"
            "  required restoration attempt.  Re-run:\n"
            "\n      vdprobe notify-watch --confirm-register --self-trigger "
            "--confirm-mutate\n");
        return 1;
    }

    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    if (FAILED(hr)) {
        Field("IServiceProvider", std::format("FAILED {}", HrToString(hr)));
        return 1;
    }

    // Preflight is read-only.  No SwitchDesktop call is made until after the
    // notification sink has successfully registered below.
    ManagerInternal mi;
    DesktopSnapshot original;
    DesktopSnapshot other;
    if (self_trigger) {
        mi = AcquireManagerInternal(sp.Get());
        ReportManagerHeader(mi);
        if (mi.candidate == nullptr || mi.layout == nullptr) {
            Print("\n  self-trigger refused: usable VDMI layout unavailable.\n");
            return 1;
        }
        if (!ReadCurrentDesktop(mi, original)) {
            Print("\n  self-trigger refused: GetCurrentDesktop did not return a GUID.\n");
            return 1;
        }
        Field("originalCurrentDesktop GUID", GuidToString(original.id));

        std::vector<DesktopSnapshot> desktops;
        if (!ReadDesktopList(mi, desktops)) {
            Print("\n  self-trigger refused: GetDesktops failed.\n");
            return 1;
        }
        size_t valid_count = 0;
        for (const DesktopSnapshot& d : desktops) {
            if (d.id_ok) ++valid_count;
        }
        Field("existing desktops", std::format("{}", desktops.size()));
        Field("desktops with GUIDs", std::format("{}", valid_count));
        if (valid_count < 2) {
            Print(
                "\n  self-trigger refused: at least two existing desktops with valid GUIDs\n"
                "  are required; no desktop will be created.\n");
            return 1;
        }
        for (DesktopSnapshot& d : desktops) {
            if (d.id_ok && !::IsEqualGUID(d.id, original.id)) {
                other = std::move(d);
                break;
            }
        }
        if (!other.object || !other.id_ok) {
            Print("\n  self-trigger refused: no existing non-current desktop was found.\n");
            return 1;
        }
        Field("selected other desktop GUID", GuidToString(other.id));
    }

    NotifySink* sink = new NotifySink();
    int rc = 0;
    bool release_sink = true;
    {
        // Scoped so explicit UnregisterNow()/the destructor runs before
        // sink->Release(), while sink is still valid.
        NotificationRegistration reg(sp.Get(), sink, /*confirm_register=*/true);
        Field("gate", GateText(reg.gate()));
        Field("Register hr", HrToString(reg.hr()));
        Field("Register cookie", std::format("{}", reg.cookie()));
        if (!reg.ok()) {
            Print("\n  Register failed or returned an invalid cookie; nothing was watched.\n");
            rc = 1;
        } else if (self_trigger) {
            Print(
                "  registered OK. Self-trigger will perform one existing-desktop\n"
                "  round-trip plus required restoration attempts; --seconds is not used\n"
                "  as a benchmark duration.\n");
            Field("watcher STA thread", std::format("{}", ::GetCurrentThreadId()));

            bool restored = false;
            bool outbound_pass = false;
            bool inbound_pass = false;
            {
                DesktopRestoreGuard restore_guard(mi, original.object.Get(),
                                                   confirm_mutate);
                restore_guard.Arm();

                SwitchObservation outbound =
                    SwitchAndVerify(mi, other.object.Get(), original.id, other.id, sink,
                                    confirm_mutate);
                outbound_pass =
                    outbound.switch_gate_ok && SUCCEEDED(outbound.switch_hr) &&
                    outbound.observed_current_ok && outbound.matching_callback_ok;

                GUID current_before_restore{};
                bool current_before_restore_ok =
                    ReadCurrentDesktopId(mi, current_before_restore);
                if (!current_before_restore_ok) current_before_restore = other.id;
                SwitchObservation inbound =
                    SwitchAndVerify(mi, original.object.Get(), current_before_restore,
                                    original.id, sink, confirm_mutate);
                inbound_pass =
                    inbound.switch_gate_ok && SUCCEEDED(inbound.switch_hr) &&
                    inbound.observed_current_ok && inbound.matching_callback_ok;

                GUID current_at_exit{};
                if (ReadCurrentDesktopId(mi, current_at_exit) &&
                    ::IsEqualGUID(current_at_exit, original.id)) {
                    restored = true;
                    restore_guard.Disarm();
                } else {
                    Print(
                        "\n  currentDesktop != originalCurrentDesktop at exit; attempting "
                        "fail-safe restore.\n");
                    if (!ReadCurrentDesktopId(mi, current_at_exit)) {
                        current_at_exit = other.id;
                    }
                    SwitchObservation retry =
                        SwitchAndVerify(mi, original.object.Get(), current_at_exit,
                                         original.id, sink, confirm_mutate);
                    (void)retry;
                    if (ReadCurrentDesktopId(mi, current_at_exit) &&
                        ::IsEqualGUID(current_at_exit, original.id)) {
                        restored = true;
                        restore_guard.Disarm();
                    }
                }
            }

            // If the guard had to make a last-chance raw restore in its
            // destructor, verify the visible state before unregistering.
            if (!restored) {
                GUID current_after_guard{};
                if (ReadCurrentDesktopId(mi, current_after_guard) &&
                    ::IsEqualGUID(current_after_guard, original.id)) {
                    restored = true;
                }
            }

            Heading("self-trigger summary");
            Field("outbound switch", outbound_pass ? "PASS" : "FAIL");
            Field("inbound switch", inbound_pass ? "PASS" : "FAIL");
            Field("original restored", restored ? "yes" : "NO");
            Field("total events observed", std::format("{}", sink->TotalEventCount()));
            if (!restored) {
                Print("  CRITICAL RESTORE FAILURE\n");
                rc = 1;
            }
            if (!outbound_pass || !inbound_pass) rc = 1;
        } else {
            Field("watcher STA thread", std::format("{}", ::GetCurrentThreadId()));
            Print("  registered OK. Watching for {} second(s)...\n", duration_seconds);
            Print(
                "  Trigger events yourself now: create/close/switch a virtual desktop,\n"
                "  drag a window between desktops, etc.\n");

            auto start = std::chrono::steady_clock::now();
            auto deadline = start + std::chrono::seconds(duration_seconds);
            size_t printed = 0;
            while (std::chrono::steady_clock::now() < deadline) {
                PumpStaMessages();
                std::deque<NotifyEvent> batch = sink->DrainEvents();
                for (const NotifyEvent& ev : batch) {
                    ++printed;
                    Print("  [{}] {}", printed, NotifyEventKindText(ev.kind));
                    if (ev.desktop_a_ok) Print("  a={}", GuidToString(ev.desktop_a));
                    if (ev.desktop_b_ok) Print("  b={}", GuidToString(ev.desktop_b));
                    if (ev.hwnd != nullptr) {
                        Print("  hwnd=0x{:X}", reinterpret_cast<uintptr_t>(ev.hwnd));
                    }
                    Print("  qpc={}", ev.timestamp_qpc);
                    Print("  thread={}", ev.callback_thread_id);
                    if (!ev.detail.empty()) Print("  {}", ev.detail);
                    Print("\n");
                }
                ::Sleep(50);
            }

            PumpStaMessages();
            std::vector<NotifyEvent> final_events;
            DrainAndPrintEvents(sink, 0, final_events);
            Heading("summary");
            Field("total events observed", std::format("{}", sink->TotalEventCount()));
            if (sink->TotalEventCount() == 0) {
                Print(
                    "\n  No events fired.  This can mean either that nothing happened, "
                    "or that\n  the registration/marshalling did not actually work -- "
                    "trigger a desktop\n  switch manually (Win+Ctrl+Right) while this "
                    "is running to confirm the\n  sink is alive before drawing "
                    "conclusions from a longer test.\n");
            }
        }
        if (reg.ok()) {
            PumpStaMessages();
            std::vector<NotifyEvent> pre_unregister_events;
            DrainAndPrintEvents(sink, 0, pre_unregister_events);
            HRESULT uhr = reg.UnregisterNow();
            Field("Unregister gate", GateText(reg.unregister_gate()));
            Field("Unregister hr", HrToString(uhr));
            if (FAILED(uhr)) {
                rc = 1;
                release_sink = false;
            }
            PumpStaMessages();
            std::vector<NotifyEvent> post_unregister_events;
            DrainAndPrintEvents(sink, 0, post_unregister_events);
        }
    }
    if (release_sink) {
        sink->Release();
    } else {
        Print("  sink retained because Unregister failed; avoiding possible late-callback UAF.\n");
    }
    return rc;
}

// ------------------------------------------------------ carrier-parking-test

int CmdCarrierParkingTest(bool confirm_mutate) {
    Heading("carrier-parking-test");
    Field("what this does",
          "moves one vdprobe-owned probe window carrier -> parking -> carrier");
    Field("global desktop switch", "never called");

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print(
            "\n  Refusing to move a window without --confirm-mutate.  This test "
            "changes\n  the desktop assignment of one vdprobe-owned disposable "
            "probe window.\n\n      vdprobe carrier-parking-test --confirm-mutate\n");
        return 1;
    }

    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    if (FAILED(hr)) {
        Field("IServiceProvider", std::format("FAILED {}", HrToString(hr)));
        return 1;
    }

    ManagerInternal mi = AcquireManagerInternal(sp.Get());
    ReportManagerHeader(mi);
    if (mi.candidate == nullptr || mi.layout == nullptr) {
        Print("\n  carrier/parking refused: usable VDMI layout unavailable.\n");
        return 1;
    }

    DesktopSnapshot carrier;
    if (!ReadCurrentDesktop(mi, carrier)) {
        Print("\n  carrier/parking refused: GetCurrentDesktop did not return a GUID.\n");
        return 1;
    }
    Field("carrier/current desktop", GuidToString(carrier.id));

    std::vector<DesktopSnapshot> desktops;
    if (!ReadDesktopList(mi, desktops)) {
        Print("\n  carrier/parking refused: GetDesktops failed.\n");
        return 1;
    }
    Field("existing desktops", std::format("{}", desktops.size()));
    if (desktops.size() < 2) {
        Print(
            "\n  carrier/parking refused: at least two existing desktops are "
            "required.\n  No desktop will be created.\n");
        return 1;
    }

    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.object || !parking.id_ok ||
        ::IsEqualGUID(parking.id, carrier.id)) {
        Print(
            "\n  carrier/parking refused: no existing non-current desktop was "
            "found.\n");
        return 1;
    }
    Field("parking desktop", GuidToString(parking.id));

    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    Field("IApplicationViewCollection",
          views.layout != nullptr ? "obtained" : HrToString(views.hr));
    if (!views.object || views.layout == nullptr) {
        Print("\n  carrier/parking refused: IApplicationViewCollection unavailable.\n");
        return 1;
    }

    Com<IVirtualDesktopManager> documented_manager;
    HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER, IID_IVirtualDesktopManager,
        documented_manager.PutVoid());
    Field("IVirtualDesktopManager",
          SUCCEEDED(documented_hr) ? "obtained" : HrToString(documented_hr));
    if (FAILED(documented_hr) || !documented_manager) return 1;

    SpawnedProbeWindow notepad;
    if (!SpawnThrowawayProbeWindow(notepad)) {
        Print("\n  carrier/parking failed: could not spawn a vdprobe probe window.\n");
        (void)CloseThrowawayProbeWindow(notepad);
        return 1;
    }
    auto cleanup_notepad = [&]() {
        const bool closed = CloseThrowawayProbeWindow(notepad);
        Field("probe window closed", closed ? "yes" : "NO");
    };

    DWORD observed_pid = 0;
    (void)::GetWindowThreadProcessId(notepad.hwnd, &observed_pid);
    Field("spawned PID", std::format("{}", notepad.pid));
    Field("test HWND", std::format("0x{:X}",
                                   reinterpret_cast<uintptr_t>(notepad.hwnd)));
    Field("HWND PID", std::format("{}", observed_pid));
    if (observed_pid != notepad.pid) {
        Print("\n  carrier/parking refused: test HWND is not owned by spawned PID.\n");
        cleanup_notepad();
        return 1;
    }

    HMONITOR test_monitor =
        ::MonitorFromWindow(notepad.hwnd, MONITOR_DEFAULTTONULL);
    Field("test window monitor",
          test_monitor == nullptr
              ? "(unavailable)"
              : std::format("0x{:X}", reinterpret_cast<uintptr_t>(test_monitor)));

    RawObject view;
    const MethodEntry* get_view =
        FindMethod(*views.layout, "GetViewForHwnd");
    Gate view_gate = Gate::Ok;
    HRESULT view_hr = E_ABORT;
    if (get_view != nullptr) {
        view_hr = InvokeSlot(views.object.Get(), *views.layout, *get_view,
                             view_gate, false, notepad.hwnd, view.PutVoid());
    }
    Field("GetViewForHwnd gate", GateText(view_gate));
    Field("GetViewForHwnd hr", HrToString(view_hr));
    if (view_gate != Gate::Ok || FAILED(view_hr) || !view) {
        cleanup_notepad();
        return 1;
    }

    const MethodEntry* can_move =
        FindMethod(*mi.layout, "CanViewMoveDesktops");
    Gate can_move_gate = Gate::Ok;
    BOOL can_move_value = FALSE;
    HRESULT can_move_hr = E_ABORT;
    if (can_move != nullptr) {
        can_move_hr = InvokeSlot(mi.obj.Get(), *mi.layout, *can_move,
                                 can_move_gate, false, view.Get(),
                                 &can_move_value);
    }
    Field("CanViewMoveDesktops gate", GateText(can_move_gate));
    Field("CanViewMoveDesktops hr", HrToString(can_move_hr));
    Field("CanViewMoveDesktops", can_move_value ? "TRUE" : "FALSE");
    if (can_move_gate != Gate::Ok || FAILED(can_move_hr) || !can_move_value) {
        cleanup_notepad();
        return 1;
    }

    WindowDesktopState initial_window_state;
    if (!ReadWindowDesktopState(documented_manager.Get(), notepad.hwnd,
                                initial_window_state)) {
        Print("\n  carrier/parking refused: documented window desktop state unavailable.\n");
        cleanup_notepad();
        return 1;
    }
    Heading("initial state");
    PrintWindowDesktopState(initial_window_state);
    Field("initial matches carrier",
          ::IsEqualGUID(initial_window_state.desktop, carrier.id) ? "yes" : "NO");
    if (!::IsEqualGUID(initial_window_state.desktop, carrier.id)) {
        Print("\n  carrier/parking refused: spawned window did not start on carrier.\n");
        cleanup_notepad();
        return 1;
    }

    NotifySink* sink = new NotifySink();
    int rc = 0;
    bool release_sink = true;
    {
        // Phase 2B has one explicit mutating flag.  It covers both the
        // short-lived callback registration and the two MoveViewToDesktop
        // calls; no global desktop switch is ever reachable here.
        NotificationRegistration reg(sp.Get(), sink, confirm_mutate);
        Field("Register gate", GateText(reg.gate()));
        Field("Register hr", HrToString(reg.hr()));
        Field("Register cookie", std::format("{}", reg.cookie()));
        if (!reg.ok()) {
            Print("\n  carrier/parking refused: notification registration failed.\n");
            rc = 1;
        } else {
            PumpStaMessages();
            std::vector<NotifyEvent> registration_events;
            DrainAndPrintEvents(sink, 0, registration_events);
            Field("watcher STA thread", std::format("{}", ::GetCurrentThreadId()));

            bool first_core_pass = false;
            bool second_core_pass = false;
            bool first_callback_pass = false;
            bool second_callback_pass = false;
            bool restored = false;
            {
                ViewRestoreGuard restore_guard(mi, view.Get(), carrier.object.Get(),
                                               confirm_mutate);
                restore_guard.Arm();

                WindowMoveObservation outbound = MoveViewAndVerify(
                    mi, view.Get(), parking.object.Get(), carrier.id, parking.id,
                    carrier.id, notepad.hwnd, documented_manager.Get(), sink,
                    confirm_mutate);
                first_core_pass =
                    outbound.move_gate_ok && SUCCEEDED(outbound.move_hr) &&
                    outbound.observed_current_ok &&
                    ::IsEqualGUID(outbound.observed_current, carrier.id) &&
                    outbound.observed_window_ok &&
                    ::IsEqualGUID(outbound.observed_window.desktop, parking.id) &&
                    !outbound.observed_window.on_current &&
                    outbound.current_changed_count == 0;
                first_callback_pass = outbound.view_callback_ok;
                Field("  carrier -> parking core", first_core_pass ? "PASS" : "FAIL");
                Field("  carrier -> parking callback",
                      first_callback_pass ? "PASS" : "MISSING");

                WindowMoveObservation inbound = MoveViewAndVerify(
                    mi, view.Get(), carrier.object.Get(), parking.id, carrier.id,
                    carrier.id, notepad.hwnd, documented_manager.Get(), sink,
                    confirm_mutate);
                second_core_pass =
                    inbound.move_gate_ok && SUCCEEDED(inbound.move_hr) &&
                    inbound.observed_current_ok &&
                    ::IsEqualGUID(inbound.observed_current, carrier.id) &&
                    inbound.observed_window_ok &&
                    ::IsEqualGUID(inbound.observed_window.desktop, carrier.id) &&
                    inbound.observed_window.on_current &&
                    inbound.current_changed_count == 0;
                second_callback_pass = inbound.view_callback_ok;
                Field("  parking -> carrier core",
                      second_core_pass ? "PASS" : "FAIL");
                Field("  parking -> carrier callback",
                      second_callback_pass ? "PASS" : "MISSING");

                WindowDesktopState final_window_state;
                GUID final_current{};
                if (ReadWindowDesktopState(documented_manager.Get(), notepad.hwnd,
                                           final_window_state) &&
                    ReadCurrentDesktopId(mi, final_current) &&
                    ::IsEqualGUID(final_window_state.desktop, carrier.id) &&
                    final_window_state.on_current &&
                    ::IsEqualGUID(final_current, carrier.id)) {
                    restored = true;
                    restore_guard.Disarm();
                }
            }

            // Allow any in-flight view notification to be delivered before
            // the summary and before Unregister.  This is a bounded callback
            // drain, not a latency/stress benchmark.
            const ULONGLONG grace_deadline = ::GetTickCount64() + 250;
            while (::GetTickCount64() < grace_deadline) {
                PumpStaMessages();
                std::vector<NotifyEvent> grace_events;
                DrainAndPrintEvents(sink, 0, grace_events);
                ::Sleep(25);
            }
            PumpStaMessages();
            std::vector<NotifyEvent> final_events;
            DrainAndPrintEvents(sink, 0, final_events);

            if (!restored) {
                Print("  CRITICAL VIEW RESTORE FAILURE\n");
                rc = 1;
            }

            const bool core_pass = first_core_pass && second_core_pass;
            const bool callback_pass = first_callback_pass && second_callback_pass;
            Heading("verdict");
            if (core_pass && callback_pass) {
                Field("GO/NO-GO", "GO-CARRIER");
            } else if (core_pass) {
                Field("GO/NO-GO", "GO-WITH-LIMITATIONS");
                Print(
                    "  Window movement and global-current preservation passed, but "
                    "one or\n  both ViewVirtualDesktopChanged callbacks were missing.\n");
                rc = 1;
            } else {
                Field("GO/NO-GO", "NO-GO");
                Print(
                    "  The carrier/parking primitive did not satisfy the required "
                    "round-trip\n  invariants.  Do not proceed to workspace-manager "
                    "design.\n");
                rc = 1;
            }
            Field("global current desktop changed", "no (required)");
            Field("total events observed", std::format("{}", sink->TotalEventCount()));
        }

        if (reg.ok()) {
            PumpStaMessages();
            std::vector<NotifyEvent> pre_unregister_events;
            DrainAndPrintEvents(sink, 0, pre_unregister_events);
            HRESULT unregister_hr = reg.UnregisterNow();
            Field("Unregister gate", GateText(reg.unregister_gate()));
            Field("Unregister hr", HrToString(unregister_hr));
            if (FAILED(unregister_hr)) {
                rc = 1;
                release_sink = false;
            }
            PumpStaMessages();
            std::vector<NotifyEvent> post_unregister_events;
            DrainAndPrintEvents(sink, 0, post_unregister_events);
        }
    }

    cleanup_notepad();
    if (release_sink) {
        sink->Release();
    } else {
        Print("  sink retained because Unregister failed; avoiding possible late-callback UAF.\n");
    }
    return rc;
}

// ---------------------------------------------- workspace-live-discovery-test

int CmdWorkspaceLiveDiscovery(bool bootstrap_engine,
                              bool bootstrap_coordinator = false) {
    Heading(bootstrap_coordinator
                ? "workspace-live-coordinator-bootstrap-test"
                : bootstrap_engine ? "workspace-live-bootstrap-test"
                                   : "workspace-live-discovery-test");
    Field("operation", "one complete read-only live window snapshot");
    Field("workspace assignment",
          bootstrap_engine ? "synthetic in-memory validation only" : "none");
    Field("native mutation", "none");

    auto environment_blocked = [](std::string_view reason) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", reason);
        Field("mutation_started", "no");
        Print("mutation_started=no\n");
        Print("RESULT=ENVIRONMENT-BLOCKED\n");
        return kExitInconclusive;
    };
    auto failed = [](std::string_view reason) {
        Field("result", "ERROR");
        Field("reason", reason);
        Field("mutation_started", "no");
        Print("mutation_started=no\n");
        Print("RESULT=ERROR\n");
        return 1;
    };

    Com<IServiceProvider> sp;
    const HRESULT shell_hr = GetImmersiveShell(sp);
    if (shell_hr == E_ACCESSDENIED) {
        return environment_blocked("ImmersiveShell E_ACCESSDENIED");
    }
    if (FAILED(shell_hr) || !sp) {
        return failed(std::format("ImmersiveShell unavailable ({})",
                                  HrToString(shell_hr)));
    }

    ManagerInternal manager = AcquireManagerInternal(sp.Get());
    ReportManagerHeader(manager);
    if (!manager.obj || manager.layout == nullptr) {
        if (manager.access_denied_seen || manager.hr == E_ACCESSDENIED) {
            return environment_blocked(
                "IVirtualDesktopManagerInternal E_ACCESSDENIED");
        }
        return failed("usable IVirtualDesktopManagerInternal unavailable");
    }

    DesktopSnapshot carrier;
    HRESULT current_hr = E_ABORT;
    if (!ReadCurrentDesktop(manager, carrier, &current_hr)) {
        if (current_hr == E_ACCESSDENIED) {
            return environment_blocked("GetCurrentDesktop E_ACCESSDENIED");
        }
        return failed("current Carrier unavailable");
    }
    std::vector<DesktopSnapshot> desktops;
    HRESULT desktops_hr = E_ABORT;
    if (!ReadDesktopList(manager, desktops, &desktops_hr)) {
        if (desktops_hr == E_ACCESSDENIED) {
            return environment_blocked("GetDesktops E_ACCESSDENIED");
        }
        return failed("existing desktop enumeration failed");
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.id_ok || !parking.object) {
        return failed("no existing inactive Parking desktop");
    }
    Field("Carrier", GuidToString(carrier.id));
    Field("Parking", GuidToString(parking.id));

    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    if (!views.object || views.layout == nullptr) {
        if (views.access_denied_seen || views.hr == E_ACCESSDENIED) {
            return environment_blocked(
                "IApplicationViewCollection E_ACCESSDENIED");
        }
        return failed("usable IApplicationViewCollection unavailable");
    }
    const MethodEntry* get_view =
        FindMethod(*views.layout, "GetViewForHwnd");
    const MethodEntry* can_move =
        FindMethod(*manager.layout, "CanViewMoveDesktops");
    if (get_view == nullptr || can_move == nullptr) {
        return failed("required read-only capability slots are unavailable");
    }

    bool capability_access_denied = false;
    Win32WindowDiscoveryOptions options;
    options.carrier = carrier.id;
    options.parking = parking.id;
    options.augment_capabilities =
        [&](HWND hwnd, const WindowDiscoveryObservation& observation,
            WindowCapabilities& capabilities, std::string* error) {
            // Owned/tool/ambiguous HWNDs already fail closed. Avoid private
            // calls when they cannot affect the final classification.
            if (!observation.capabilities.independent_top_level ||
                !observation.desktop_ok ||
                observation.native_role == NativeDesktopRole::Unknown) {
                return true;
            }

            RawObject view;
            Gate view_gate = Gate::Ok;
            const HRESULT view_hr = InvokeSlot(
                views.object.Get(), *views.layout, *get_view, view_gate, false,
                hwnd, view.PutVoid());
            if (view_hr == E_ACCESSDENIED) {
                capability_access_denied = true;
                if (error != nullptr) {
                    *error = "GetViewForHwnd returned E_ACCESSDENIED";
                }
                return false;
            }
            if (view_gate != Gate::Ok || FAILED(view_hr) || !view) {
                return true;
            }
            capabilities.has_application_view = true;

            Gate move_gate = Gate::Ok;
            BOOL value = FALSE;
            const HRESULT move_hr = InvokeSlot(
                manager.obj.Get(), *manager.layout, *can_move, move_gate,
                false, view.Get(), &value);
            if (move_hr == E_ACCESSDENIED) {
                capability_access_denied = true;
                if (error != nullptr) {
                    *error = "CanViewMoveDesktops returned E_ACCESSDENIED";
                }
                return false;
            }
            if (move_gate == Gate::Ok && SUCCEEDED(move_hr)) {
                capabilities.can_move_desktops = value != FALSE;
            }
            return true;
        };

    std::string error;
    HRESULT documented_hr = S_OK;
    auto backend = CreateSystemWindowDiscoveryBackend(
        std::move(options), &error, &documented_hr);
    if (!backend) {
        if (documented_hr == E_ACCESSDENIED) {
            return environment_blocked(
                "documented IVirtualDesktopManager E_ACCESSDENIED");
        }
        return failed(error.empty() ? "system discovery backend unavailable"
                                    : error);
    }

    WindowDiscovery discovery(std::move(*backend));
    std::vector<DiscoveredWindow> windows;
    if (!discovery.Discover(windows, &error)) {
        if (capability_access_denied) {
            return environment_blocked(error);
        }
        return failed(error.empty() ? "complete discovery failed" : error);
    }

    if (bootstrap_engine) {
        // This mapping is deliberately synthetic: it proves only that a live,
        // capability-augmented discovery snapshot can populate the engine's
        // in-memory model.  It is not a user workspace assignment policy.
        struct SyntheticMonitor {
            MonitorId monitor = 0;
            WorkspaceId carrier_workspace = 0;
            WorkspaceId parking_workspace = 0;
        };
        std::vector<SyntheticMonitor> synthetic_monitors;
        for (const DiscoveredWindow& window : windows) {
            const MonitorId monitor =
                reinterpret_cast<MonitorId>(window.monitor);
            if (monitor == 0) {
                return failed("live snapshot contains a window without a monitor");
            }
            const auto found = std::find_if(
                synthetic_monitors.begin(), synthetic_monitors.end(),
                [monitor](const SyntheticMonitor& item) {
                    return item.monitor == monitor;
                });
            if (found == synthetic_monitors.end()) {
                const WorkspaceId base =
                    static_cast<WorkspaceId>(synthetic_monitors.size()) * 2 + 1;
                synthetic_monitors.push_back({monitor, base, base + 1});
            }
        }

        WorkspaceEngine engine(carrier.id, parking.id);
        for (const SyntheticMonitor& monitor : synthetic_monitors) {
            if (!engine.AddMonitor(monitor.monitor, monitor.carrier_workspace,
                                   {monitor.carrier_workspace,
                                    monitor.parking_workspace},
                                   &error)) {
                return failed(error.empty() ? "synthetic monitor setup failed"
                                            : error);
            }
        }
        auto convert_snapshot =
            [&](const std::vector<DiscoveredWindow>& snapshot,
                std::vector<WindowRecord>& records,
                std::string* conversion_error) {
                for (const DiscoveredWindow& window : snapshot) {
                    const MonitorId monitor =
                        reinterpret_cast<MonitorId>(window.monitor);
                    if (monitor == 0) {
                        if (conversion_error != nullptr) {
                            *conversion_error =
                                "live snapshot contains a window without a monitor";
                        }
                        return false;
                    }
                    auto synthetic = std::find_if(
                        synthetic_monitors.begin(), synthetic_monitors.end(),
                        [monitor](const SyntheticMonitor& item) {
                            return item.monitor == monitor;
                        });
                    if (synthetic == synthetic_monitors.end()) {
                        if (conversion_error != nullptr) {
                            *conversion_error =
                                "live snapshot monitor changed after synthetic "
                                "topology was frozen";
                        }
                        return false;
                    }

                    WindowRecord record;
                    record.identity = window.identity;
                    record.monitor = monitor;
                    record.workspace =
                        window.native_role == NativeDesktopRole::Parking
                            ? synthetic->parking_workspace
                            : synthetic->carrier_workspace;
                    record.native_role = window.native_role;
                    record.capabilities = window.capabilities;
                    record.presentation = window.presentation;
                    record.disposition = window.disposition;
                    records.push_back(std::move(record));
                }
                return true;
            };

        // Seed only the synthetic monitor definitions here. The coordinator
        // mode obtains a fresh authoritative snapshot inside its quiet
        // lifecycle boundary before any records enter the engine.
        std::vector<WindowRecord> records;
        records.reserve(windows.size());
        if (!convert_snapshot(windows, records, &error)) {
            return failed(error.empty() ? "synthetic monitor setup failed"
                                        : error);
        }

        if (bootstrap_coordinator) {
            WinEventLifecycleSource lifecycle_source;
            if (!lifecycle_source.Start(&error)) {
                return environment_blocked(
                    error.empty() ? "WinEvent lifecycle source unavailable"
                                  : error);
            }

            // The initial records were used only to establish synthetic
            // in-memory monitor/workspace IDs. They are intentionally not
            // reconciled; the coordinator callback supplies the authoritative
            // complete snapshot.
            records.clear();
            WindowLifecycleAdapter lifecycle(engine, {});
            WorkspaceCoordinator coordinator(
                engine, lifecycle, lifecycle_source,
                [&](std::vector<WindowRecord>& observed,
                    std::string* discovery_error) {
                    PumpStaMessages();
                    std::vector<DiscoveredWindow> latest;
                    if (!discovery.Discover(latest, discovery_error)) {
                        return false;
                    }
                    PumpStaMessages();
                    std::vector<WindowRecord> converted;
                    converted.reserve(latest.size());
                    if (!convert_snapshot(latest, converted, discovery_error)) {
                        return false;
                    }
                    windows = std::move(latest);
                    observed = std::move(converted);
                    return true;
                },
                {}, {});

            const CoordinatorResult reconcile =
                coordinator.ReconcileDiscovery();
            lifecycle_source.Stop();
            if (!lifecycle_source.shutdown_ok()) {
                return failed("WinEvent lifecycle source shutdown failed");
            }
            if (!reconcile.succeeded()) {
                const std::string reason = std::format(
                    "coordinator {}: {}",
                    CoordinatorResultCodeText(reconcile.code), reconcile.error);
                if (capability_access_denied ||
                    reconcile.code == CoordinatorResultCode::DiscoveryUnstable ||
                    reconcile.code ==
                        CoordinatorResultCode::LifecycleUnavailable) {
                    return environment_blocked(reason);
                }
                return failed(reason);
            }
            if (!engine.CheckInvariant(&error)) {
                return failed(error.empty()
                                  ? "coordinator engine invariant failed"
                                  : error);
            }
            Field("coordinator discovery attempts",
                  std::format("{}", reconcile.discovery_attempts));
            Field("lifecycle hints",
                  std::format("{}", reconcile.lifecycle.events));
            Field("move callback", "not installed");
            Print("COORDINATOR_RECONCILE=OK\n");
            Print("DISCOVERY_ATTEMPTS={}\n", reconcile.discovery_attempts);
            Print("MOVE_CALLBACK_INSTALLED=0\n");
            Print("LIFECYCLE_STOPPED=1\n");
        } else {
            DiscoveryReconcileResult reconcile;
            if (!engine.ReconcileDiscoverySnapshot(std::move(records),
                                                   &reconcile, &error) ||
                !engine.CheckInvariant(&error)) {
                return failed(error.empty()
                                  ? "synthetic engine bootstrap failed"
                                  : error);
            }
        }
        Field("synthetic monitors",
              std::format("{}", synthetic_monitors.size()));
        Field("engine windows", std::format("{}", engine.Windows().size()));
        Print("SYNTHETIC_ASSIGNMENT=1\n");
        Print("MONITOR_COUNT={}\n", synthetic_monitors.size());
        Print("ENGINE_WINDOW_COUNT={}\n", engine.Windows().size());
        Print("ENGINE_INVARIANT=OK\n");
    }
    std::size_t managed = 0;
    std::size_t unsupported = 0;
    std::size_t ambiguous = 0;
    for (const DiscoveredWindow& window : windows) {
        switch (window.disposition) {
            case WindowDisposition::Managed: ++managed; break;
            case WindowDisposition::Unsupported: ++unsupported; break;
            case WindowDisposition::Ambiguous: ++ambiguous; break;
            case WindowDisposition::Closed: ++ambiguous; break;
        }
    }
    Field("total windows", std::format("{}", windows.size()));
    Field("managed", std::format("{}", managed));
    Field("unsupported", std::format("{}", unsupported));
    Field("ambiguous", std::format("{}", ambiguous));
    Field("result", "OK");
    Field("mutation_started", "no");
    Print("mutation_started=no\n");
    Print("RESULT=OK\n");
    Print("TOTAL_COUNT={}\n", windows.size());
    Print("MANAGED_COUNT={}\n", managed);
    Print("UNSUPPORTED_COUNT={}\n", unsupported);
    Print("AMBIGUOUS_COUNT={}\n", ambiguous);
    return 0;
}

int CmdWorkspaceLiveDiscoveryTest() {
    return CmdWorkspaceLiveDiscovery(false);
}

int CmdWorkspaceLiveBootstrapTest() {
    return CmdWorkspaceLiveDiscovery(true);
}

int CmdWorkspaceLiveCoordinatorBootstrapTest() {
    return CmdWorkspaceLiveDiscovery(true, true);
}

// ---------------------------------------------------- logical-workspace-test

int CmdLogicalWorkspaceTest(bool confirm_mutate) {
    Heading("logical-workspace-test");
    Field("what this does",
          "moves one monitor's logical workspace A1 -> A2 -> A1");
    Field("native model", "one current Carrier + one shared inactive Parking");
    Field("global desktop switch", "never called");
    Field("desktop lifecycle", "no create/remove");

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print(
            "\n  Refusing to move probe windows without --confirm-mutate.  This "
            "test\n  changes the desktop assignment of three vdprobe-owned "
            "disposable probe windows.\n\n      vdprobe "
            "logical-workspace-test --confirm-mutate\n");
        return 1;
    }

    const std::vector<MonitorRec> monitors = EnumerateMonitors();
    if (monitors.size() < 2) {
        Print("\n  logical workspace refused: at least two monitors are required.\n");
        return 1;
    }
    const MonitorRec& monitor_a = monitors[0];
    const MonitorRec& monitor_b = monitors[1];
    Field("monitor A", ToUtf8(monitor_a.device));
    Field("monitor B", ToUtf8(monitor_b.device));

    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    if (FAILED(hr)) {
        Field("IServiceProvider", std::format("FAILED {}", HrToString(hr)));
        if (hr == E_ACCESSDENIED) {
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "ImmersiveShell E_ACCESSDENIED");
            Field("mutation_started", "no");
            return kExitInconclusive;
        }
        return 1;
    }

    ManagerInternal mi = AcquireManagerInternal(sp.Get());
    ReportManagerHeader(mi);
    if (mi.candidate == nullptr || mi.layout == nullptr) {
        Print("\n  logical workspace refused: usable VDMI layout unavailable.\n");
        return 1;
    }

    DesktopSnapshot carrier;
    if (!ReadCurrentDesktop(mi, carrier)) {
        Print("\n  logical workspace refused: current Carrier unavailable.\n");
        return 1;
    }
    std::vector<DesktopSnapshot> desktops;
    if (!ReadDesktopList(mi, desktops) || desktops.size() < 2) {
        Print(
            "\n  logical workspace refused: at least two existing desktops are "
            "required.\n  No desktop will be created.\n");
        return 1;
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.object || !parking.id_ok) {
        Print("\n  logical workspace refused: no existing Parking desktop found.\n");
        return 1;
    }
    Field("Carrier", GuidToString(carrier.id));
    Field("Parking", GuidToString(parking.id));

    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    if (!views.object || views.layout == nullptr) {
        Print("\n  logical workspace refused: IApplicationViewCollection unavailable.\n");
        return 1;
    }
    Com<IVirtualDesktopManager> documented_manager;
    HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER, IID_IVirtualDesktopManager,
        documented_manager.PutVoid());
    if (FAILED(documented_hr) || !documented_manager) {
        Field("IVirtualDesktopManager", HrToString(documented_hr));
        return 1;
    }

    SpawnedProbeWindow a1;
    SpawnedProbeWindow a2;
    SpawnedProbeWindow b1;
    bool a1_started = false;
    bool a2_started = false;
    bool b1_started = false;
    auto cleanup = [&]() {
        if (a1.hwnd != nullptr) (void)CloseThrowawayProbeWindow(a1);
        if (a2.hwnd != nullptr) (void)CloseThrowawayProbeWindow(a2);
        if (b1.hwnd != nullptr) (void)CloseThrowawayProbeWindow(b1);
    };
    if (!(a1_started = SpawnThrowawayProbeWindow(a1)) ||
        !(a2_started = SpawnThrowawayProbeWindow(a2)) ||
        !(b1_started = SpawnThrowawayProbeWindow(b1))) {
        Print("\n  logical workspace failed: could not spawn three vdprobe probe windows.\n");
        cleanup();
        return 1;
    }

    if (!PlaceProbeWindowOnMonitor(a1.hwnd, monitor_a, 0) ||
        !PlaceProbeWindowOnMonitor(a2.hwnd, monitor_a, 1) ||
        !PlaceProbeWindowOnMonitor(b1.hwnd, monitor_b, 0)) {
        Print("\n  logical workspace refused: could not place probe windows on "
              "two distinct monitors.\n");
        cleanup();
        return 1;
    }
    Field("A1 HWND", std::format("0x{:X}", reinterpret_cast<uintptr_t>(a1.hwnd)));
    Field("A2 HWND", std::format("0x{:X}", reinterpret_cast<uintptr_t>(a2.hwnd)));
    Field("B1 HWND", std::format("0x{:X}", reinterpret_cast<uintptr_t>(b1.hwnd)));

    auto acquire_view = [&](HWND hwnd, RawObject& out) -> bool {
        const MethodEntry* method = FindMethod(*views.layout, "GetViewForHwnd");
        if (method == nullptr) return false;
        const ULONGLONG deadline = ::GetTickCount64() + 2000;
        HRESULT last_hr = E_ABORT;
        Gate last_gate = Gate::Ok;
        do {
            PumpStaMessages();
            Gate gate = Gate::Ok;
            HRESULT view_hr =
                InvokeSlot(views.object.Get(), *views.layout, *method, gate,
                           false, hwnd, out.PutVoid());
            last_hr = view_hr;
            last_gate = gate;
            if (gate == Gate::Ok && SUCCEEDED(view_hr) && out) return true;
            ::Sleep(25);
        } while (::GetTickCount64() < deadline);
        Print("  GetViewForHwnd hwnd=0x{:X} gate={} hr={} after retry\n",
              reinterpret_cast<uintptr_t>(hwnd), GateText(last_gate),
              HrToString(last_hr));
        return false;
    };
    RawObject a1_view;
    RawObject a2_view;
    RawObject b1_view;
    if (!acquire_view(a1.hwnd, a1_view) || !acquire_view(a2.hwnd, a2_view) ||
        !acquire_view(b1.hwnd, b1_view)) {
        Print("\n  logical workspace failed: GetViewForHwnd did not resolve all "
              "probe windows.\n");
        cleanup();
        return 1;
    }

    const MethodEntry* can_move = FindMethod(*mi.layout, "CanViewMoveDesktops");
    auto can_move_view = [&](IUnknown* view) -> bool {
        if (can_move == nullptr) return false;
        Gate gate = Gate::Ok;
        BOOL value = FALSE;
        const HRESULT can_hr = InvokeSlot(mi.obj.Get(), *mi.layout, *can_move,
                                           gate, false, view, &value);
        return gate == Gate::Ok && SUCCEEDED(can_hr) && value != FALSE;
    };
    if (!can_move_view(a1_view.Get()) || !can_move_view(a2_view.Get()) ||
        !can_move_view(b1_view.Get())) {
        Print("\n  logical workspace refused: at least one probe view cannot move "
              "between desktops.\n");
        cleanup();
        return 1;
    }

    // Establish the requested native initial state before the logical model is
    // exercised: A1 and B1 remain on Carrier, while inactive A2 is parked.
    Gate initial_a2_gate = Gate::Ok;
    HRESULT initial_a2_hr = E_ABORT;
    const bool initial_a2_ok = MoveViewToDesktopAndWait(
        mi, a2_view.Get(), parking.object.Get(), a2.hwnd,
        documented_manager.Get(), parking.id, carrier.id, confirm_mutate,
        initial_a2_gate, initial_a2_hr);
    Field("initial A2 -> Parking", initial_a2_ok ? "PASS" : "FAIL");
    Field("  initial A2 gate", GateText(initial_a2_gate));
    Field("  initial A2 hr", HrToString(initial_a2_hr));
    if (!initial_a2_ok) {
        cleanup();
        return 1;
    }

    WindowDesktopState a1_baseline{};
    WindowDesktopState a2_baseline{};
    WindowDesktopState b1_baseline{};
    if (!ReadWindowDesktopState(documented_manager.Get(), a1.hwnd, a1_baseline) ||
        !ReadWindowDesktopState(documented_manager.Get(), a2.hwnd, a2_baseline) ||
        !ReadWindowDesktopState(documented_manager.Get(), b1.hwnd, b1_baseline) ||
        !::IsEqualGUID(a1_baseline.desktop, carrier.id) ||
        !::IsEqualGUID(a2_baseline.desktop, parking.id) ||
        !::IsEqualGUID(b1_baseline.desktop, carrier.id)) {
        Print("\n  logical workspace refused: native initial state did not match "
              "Carrier(A1,B1)/Parking(A2).\n");
        cleanup();
        return 1;
    }

    const WorkspaceId a1_id = 1;
    const WorkspaceId a2_id = 2;
    const WorkspaceId b1_id = 3;
    const MonitorId monitor_a_id =
        reinterpret_cast<MonitorId>(monitor_a.handle);
    const MonitorId monitor_b_id =
        reinterpret_cast<MonitorId>(monitor_b.handle);

    LogicalWindow logical_a1;
    LogicalWindow logical_a2;
    LogicalWindow logical_b1;
    if (!CaptureLogicalWindow(documented_manager.Get(), a1.hwnd, monitor_a.handle,
                              a1_id, logical_a1) ||
        !CaptureLogicalWindow(documented_manager.Get(), a2.hwnd, monitor_a.handle,
                              a2_id, logical_a2) ||
        !CaptureLogicalWindow(documented_manager.Get(), b1.hwnd, monitor_b.handle,
                              b1_id, logical_b1)) {
        Print("\n  logical workspace refused: could not capture logical window state.\n");
        cleanup();
        return 1;
    }
    std::vector<const LogicalWindow*> all_windows = {
        &logical_a1, &logical_a2, &logical_b1};

    // The transaction engine owns the logical state.  This controlled test
    // supplies its live shell operations through callbacks below; it does not
    // retain an IApplicationView across a move, so each operation resolves a
    // fresh view for the verified HWND generation.
    WorkspaceEngine engine(carrier.id, parking.id);
    std::string engine_error;
    if (!engine.AddMonitor(monitor_a_id, a1_id, {a1_id, a2_id}, &engine_error) ||
        !engine.AddMonitor(monitor_b_id, b1_id, {b1_id}, &engine_error)) {
        Print("\n  logical workspace refused: could not initialize workspace "
              "engine: {}\n",
              engine_error);
        cleanup();
        return 1;
    }

    const WindowCapabilities probe_capabilities{
        true, true, true, true, true};
    auto add_probe_record = [&](const LogicalWindow& logical,
                                MonitorId monitor,
                                NativeDesktopRole role) -> bool {
        WindowRecord record{};
        record.identity = logical.identity;
        record.monitor = monitor;
        record.workspace = logical.workspace;
        record.native_role = role;
        record.capabilities = probe_capabilities;
        record.presentation.rect = logical.rect;
        record.presentation.placement = logical.placement;
        record.presentation.rect_valid = true;
        record.presentation.placement_valid = true;
        record.presentation.foreground = false;
        record.disposition = WindowDisposition::Managed;
        record.present = true;
        const UpsertResult result = engine.UpsertWindow(std::move(record),
                                                        &engine_error);
        if (result == UpsertResult::Added) return true;
        Print("  workspace engine rejected probe HWND 0x{:X}: {}\n",
              reinterpret_cast<uintptr_t>(logical.identity.hwnd), engine_error);
        return false;
    };
    if (!add_probe_record(logical_a1, monitor_a_id,
                          NativeDesktopRole::Carrier) ||
        !add_probe_record(logical_a2, monitor_a_id,
                          NativeDesktopRole::Parking) ||
        !add_probe_record(logical_b1, monitor_b_id,
                          NativeDesktopRole::Carrier) ||
        !engine.CheckInvariant(&engine_error)) {
        Print("\n  logical workspace refused: workspace engine initialization "
              "failed: {}\n",
              engine_error);
        cleanup();
        return 1;
    }
    // The presentation executor is restricted to this explicitly created
    // probe set.  Each logical workspace contains one root here, but recording
    // the complete order keeps the test on the same code path as a multi-window
    // caller.  Foreground restoration is only attempted after --confirm-mutate.
    if (!engine.SetZOrder(monitor_a_id, a1_id, {logical_a1.identity},
                          &engine_error) ||
        !engine.SetZOrder(monitor_a_id, a2_id, {logical_a2.identity},
                          &engine_error) ||
        !engine.SetZOrder(monitor_b_id, b1_id, {logical_b1.identity},
                          &engine_error) ||
        !engine.SetLastForeground(monitor_a_id, a1_id, logical_a1.identity,
                                  &engine_error) ||
        !engine.SetLastForeground(monitor_a_id, a2_id, logical_a2.identity,
                                  &engine_error) ||
        !engine.SetLastForeground(monitor_b_id, b1_id, logical_b1.identity,
                                  &engine_error)) {
        Print("\n  logical workspace refused: could not capture probe-only "
              "presentation state: {}\n", engine_error);
        cleanup();
        return 1;
    }

    NotifySink* sink = new NotifySink();
    int rc = 0;
    bool release_sink = true;
    {
        NotificationRegistration reg(sp.Get(), sink, confirm_mutate);
        Field("Register gate", GateText(reg.gate()));
        Field("Register hr", HrToString(reg.hr()));
        Field("Register cookie", std::format("{}", reg.cookie()));
        if (!reg.ok()) {
            Print("\n  logical workspace refused: notification registration failed.\n");
            rc = 1;
        } else {
            PumpStaMessages();
            std::vector<NotifyEvent> initial_events;
            DrainAndPrintEvents(sink, 0, initial_events);
            Field("watcher STA thread", std::format("{}", ::GetCurrentThreadId()));

            auto drain_for = [&](std::vector<NotifyEvent>& events,
                                 ULONGLONG start_qpc,
                                 DWORD timeout_ms) {
                const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
                do {
                    PumpStaMessages();
                    DrainAndPrintEvents(sink, start_qpc, events);
                    ::Sleep(25);
                } while (::GetTickCount64() < deadline);
                PumpStaMessages();
                DrainAndPrintEvents(sink, start_qpc, events);
            };
            auto observe_role = [&](const WindowRecord& record) {
                WindowIdentity identity;
                WindowDesktopState state;
                if (!ReadWindowIdentity(record.identity.hwnd, identity) ||
                    identity != record.identity ||
                    !ReadWindowDesktopState(documented_manager.Get(),
                                            record.identity.hwnd, state)) {
                    return NativeDesktopRole::Unknown;
                }
                if (::IsEqualGUID(state.desktop, carrier.id) &&
                    state.on_current) {
                    return NativeDesktopRole::Carrier;
                }
                if (::IsEqualGUID(state.desktop, parking.id) &&
                    !state.on_current) {
                    return NativeDesktopRole::Parking;
                }
                return NativeDesktopRole::Unknown;
            };
            auto move_to_role = [&](const WindowRecord& record,
                                    NativeDesktopRole target) -> bool {
                WindowIdentity identity;
                if (!ReadWindowIdentity(record.identity.hwnd, identity) ||
                    identity != record.identity) {
                    Print("  native move refused: HWND 0x{:X} identity changed\n",
                          reinterpret_cast<uintptr_t>(record.identity.hwnd));
                    return false;
                }
                RawObject view;
                if (!acquire_view(record.identity.hwnd, view)) return false;
                IUnknown* const desktop =
                    target == NativeDesktopRole::Carrier ? carrier.object.Get()
                    : target == NativeDesktopRole::Parking ? parking.object.Get()
                                                            : nullptr;
                const GUID& expected = target == NativeDesktopRole::Carrier
                                           ? carrier.id
                                           : parking.id;
                Gate gate = Gate::Ok;
                HRESULT move_hr = E_ABORT;
                const bool moved = MoveViewToDesktopAndWait(
                    mi, view.Get(), desktop, record.identity.hwnd,
                    documented_manager.Get(), expected, carrier.id,
                    confirm_mutate, gate, move_hr);
                Print("  engine MoveViewToDesktop HWND 0x{:X} -> {}\n",
                      reinterpret_cast<uintptr_t>(record.identity.hwnd),
                      NativeDesktopRoleText(target));
                Field("    gate", GateText(gate));
                Field("    HRESULT", HrToString(move_hr));
                Field("    verified", moved ? "yes" : "NO");
                return moved;
            };

            auto probe_identity_is_current = [&](const WindowRecord& record) {
                // `all_windows` is the ownership boundary. Never apply a
                // native presentation operation to an HWND merely because it
                // happens to have the same class, title, or process.
                const bool owned = std::any_of(
                    all_windows.begin(), all_windows.end(),
                    [&](const LogicalWindow* logical) {
                        return logical != nullptr &&
                               logical->identity == record.identity;
                    });
                WindowIdentity current;
                RawObject view;
                return owned && record.capabilities.Manageable() &&
                       record.capabilities.owner_state_observable &&
                       ReadWindowIdentity(record.identity.hwnd, current) &&
                       current == record.identity &&
                       ::MonitorFromWindow(record.identity.hwnd,
                                           MONITOR_DEFAULTTONULL) ==
                           reinterpret_cast<HMONITOR>(record.monitor) &&
                       acquire_view(record.identity.hwnd, view) &&
                       can_move_view(view.Get());
            };
            auto apply_probe_presentation =
                [&](const WindowRecord& record,
                    const PresentationOperation& operation) -> bool {
                // ExecutePresentationRestore has just identity-revalidated
                // this record. Recheck at the native boundary as well so a
                // recycled HWND fails closed between callbacks.
                if (!probe_identity_is_current(record) ||
                    record.identity != operation.identity) {
                    return false;
                }
                switch (operation.kind) {
                    case PresentationOperationKind::RestorePlacement:
                        if (!operation.presentation.placement_valid) return false;
                        return ::SetWindowPlacement(
                                   record.identity.hwnd,
                                   &operation.presentation.placement) != FALSE;
                    case PresentationOperationKind::RestoreZOrder:
                        // Plans are bottom-to-top; HWND_TOP therefore gives a
                        // deterministic relative order without activation.
                        return ::SetWindowPos(
                                   record.identity.hwnd, HWND_TOP, 0, 0, 0, 0,
                                   SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE |
                                       SWP_NOOWNERZORDER) != FALSE;
                    case PresentationOperationKind::RestoreForeground:
                        // This test is confirmation-gated and records only
                        // vdprobe-owned roots; no user HWND can reach here.
                        return ::SetForegroundWindow(record.identity.hwnd) != FALSE;
                    default:
                        return false;
                }
            };

            WinEventLifecycleSource lifecycle_source;
            std::string lifecycle_error;
            const bool lifecycle_started =
                lifecycle_source.Start(&lifecycle_error);
            Field("WinEvent lifecycle source",
                  lifecycle_started ? "started" : "FAILED");
            if (!lifecycle_error.empty()) {
                Field("  lifecycle error", lifecycle_error);
            }

            auto observe_owned_window =
                [&](HWND hwnd) -> std::optional<WindowRecord> {
                const LogicalWindow* logical = nullptr;
                for (const LogicalWindow* candidate : all_windows) {
                    if (candidate != nullptr && candidate->identity.hwnd == hwnd) {
                        logical = candidate;
                        break;
                    }
                }
                if (logical == nullptr) return std::nullopt;

                WindowIdentity identity;
                if (!ReadWindowIdentity(hwnd, identity) ||
                    identity != logical->identity) {
                    return std::nullopt;
                }
                const HMONITOR monitor =
                    ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL);
                if (monitor == nullptr || monitor != logical->monitor) {
                    return std::nullopt;
                }

                RawObject view;
                if (!acquire_view(hwnd, view) || !can_move_view(view.Get())) {
                    return std::nullopt;
                }
                WindowRecord record{};
                record.identity = identity;
                record.monitor = reinterpret_cast<MonitorId>(monitor);
                record.workspace = logical->workspace;
                record.native_role = observe_role(record);
                if (record.native_role == NativeDesktopRole::Unknown) {
                    return std::nullopt;
                }
                record.capabilities = probe_capabilities;
                record.presentation.rect_valid =
                    ::GetWindowRect(hwnd, &record.presentation.rect) != FALSE;
                record.presentation.placement = {};
                record.presentation.placement.length =
                    sizeof(record.presentation.placement);
                record.presentation.placement_valid =
                    ::GetWindowPlacement(hwnd, &record.presentation.placement) !=
                    FALSE;
                record.presentation.foreground =
                    ::GetForegroundWindow() == hwnd;
                record.disposition = WindowDisposition::Managed;
                record.present = true;
                return record;
            };
            WindowLifecycleAdapter lifecycle(engine, observe_owned_window);
            auto discover_owned_windows =
                [&](std::vector<WindowRecord>& observed,
                    std::string* error) -> bool {
                observed.clear();
                observed.reserve(all_windows.size());
                // WinEvent hooks are out-of-context on this STA. Pump before
                // taking the authoritative snapshot so the coordinator can
                // establish a meaningful quiet boundary around discovery.
                PumpStaMessages();
                for (const LogicalWindow* logical : all_windows) {
                    const std::optional<WindowRecord> record =
                        logical == nullptr
                            ? std::nullopt
                            : observe_owned_window(logical->identity.hwnd);
                    if (!record) {
                        if (error) {
                            *error = "vdprobe-owned complete discovery failed";
                        }
                        observed.clear();
                        return false;
                    }
                    observed.push_back(*record);
                }
                return true;
            };

            const std::filesystem::path journal_path =
                std::filesystem::temp_directory_path() /
                ("vdprobe-live-coordinator-" +
                 std::to_string(::GetCurrentProcessId()) + ".journal");
            std::error_code journal_remove_error;
            std::filesystem::remove(journal_path, journal_remove_error);
            WorkspaceJournal journal(journal_path);
            WorkspaceCoordinator coordinator(
                engine, lifecycle, lifecycle_source, discover_owned_windows,
                move_to_role, observe_role, &journal, 3);

            auto switch_logical = [&](WorkspaceId outgoing,
                                       WorkspaceId incoming) -> bool {
                const ULONGLONG start_qpc = QpcNow();
                std::vector<NotifyEvent> events;
                const CoordinatorResult coordinated =
                    coordinator.Switch(monitor_a_id, incoming);
                const TransactionResult& transaction = coordinated.transaction;
                drain_for(events, start_qpc, 250);

                Field(std::format("  logical switch {} -> {}", outgoing, incoming),
                      coordinated.succeeded() ? "coordinator PASS"
                                              : "coordinator FAIL");
                Field("    coordinator",
                      CoordinatorResultCodeText(coordinated.code));
                Field("    discovery attempts",
                      std::format("{}", coordinated.discovery_attempts));
                Field("    engine committed", transaction.committed ? "yes" : "NO");
                if (!coordinated.error.empty()) {
                    Field("    coordinator error", coordinated.error);
                }
                if (!transaction.error.empty()) {
                    Field("    transaction error", transaction.error);
                }
                if (transaction.rollback_attempted) {
                    Field("    rollback", transaction.rollback_succeeded
                                            ? "succeeded" : "FAILED");
                }
                Field("    recovery required",
                      transaction.recovery_required ? "YES" : "no");
                Field("    current changed count",
                      std::format("{}", CountCurrentDesktopChanged(events, start_qpc)));
                Field("    view callback scope",
                      ViewEventsOnlyExpected(events, start_qpc, a1.hwnd, a2.hwnd)
                          ? "A1/A2 only"
                          : "UNEXPECTED WINDOW");

                const bool callback_scope_ok =
                    ViewEventsOnlyExpected(events, start_qpc, a1.hwnd, a2.hwnd);
                const bool outgoing_callback_ok =
                    HasMatchingViewCallback(events, start_qpc,
                                            outgoing == a1_id ? a1.hwnd : a2.hwnd);
                const bool incoming_callback_ok =
                    HasMatchingViewCallback(events, start_qpc,
                                            incoming == a1_id ? a1.hwnd : a2.hwnd);
                Field("    outgoing ViewVirtualDesktopChanged",
                      outgoing_callback_ok ? "observed" : "MISSING");
                Field("    incoming ViewVirtualDesktopChanged",
                      incoming_callback_ok ? "observed" : "MISSING");
                const bool control_ok =
                    VerifyControlWindowUnchanged(logical_b1, b1_baseline,
                                                 documented_manager.Get(),
                                                 carrier.id);
                const bool state_ok =
                    VerifyLogicalModel(engine, all_windows,
                                       documented_manager.Get(), carrier.id,
                                       parking.id);
                const bool global_current_ok = [&]() {
                    GUID current{};
                    return ReadCurrentDesktopId(mi, current) &&
                           ::IsEqualGUID(current, carrier.id);
                }();
                std::string presentation_error;
                const std::optional<PresentationPlan> presentation_plan =
                    coordinated.succeeded()
                        ? engine.PreparePresentationRestore(
                              monitor_a_id, incoming, &presentation_error)
                        : std::nullopt;
                const PresentationResult presentation =
                    presentation_plan
                        ? engine.ExecutePresentationRestore(
                              *presentation_plan, probe_identity_is_current,
                              apply_probe_presentation)
                        : PresentationResult{};
                Field("    probe presentation restore",
                      presentation.completed ? "PASS" : "FAIL");
                Field("    presentation operations",
                      std::format("{}/{}", presentation.applied,
                                  presentation_plan
                                      ? presentation_plan->operations.size()
                                      : 0));
                if (!presentation_error.empty()) {
                    Field("    presentation preparation error", presentation_error);
                }
                if (!presentation.error.empty()) {
                    Field("    presentation execution error", presentation.error);
                }
                Field("    global current desktop", global_current_ok ? "unchanged"
                                                                        : "CHANGED");
                const bool pass = lifecycle_started && coordinated.succeeded() &&
                                  transaction.committed &&
                                  CountCurrentDesktopChanged(events, start_qpc) == 0 &&
                                  callback_scope_ok && outgoing_callback_ok &&
                                  incoming_callback_ok && control_ok && state_ok &&
                                  global_current_ok && presentation.completed;
                Field("    logical switch verdict", pass ? "PASS" : "FAIL");
                return pass;
            };

            std::optional<ViewRestoreGuard> restore_a1;
            restore_a1.emplace(mi, a1_view.Get(), carrier.object.Get(),
                               confirm_mutate);
            // A2 starts in shared Parking, so its fail-safe target is Parking;
            // A1 starts on Carrier.  Keeping these targets distinct preserves
            // the native initial state even if the round-trip aborts midway.
            std::optional<ViewRestoreGuard> restore_a2;
            restore_a2.emplace(mi, a2_view.Get(), parking.object.Get(),
                               confirm_mutate);
            restore_a1->Arm();
            restore_a2->Arm();

            // A1 -> A2: outgoing A1 goes to Parking, incoming A2 comes to Carrier.
            const bool first = switch_logical(a1_id, a2_id);
            // A2 -> A1: restore the original logical assignment.  Do not issue
            // the reverse plan after a failed first transaction: ExecuteSwitch
            // already attempted rollback and the guards remain armed.
            const bool second = first && switch_logical(a2_id, a1_id);

            // Persist a real A1 -> A2 plan and apply one operation, then
            // discard the running logical state. Recovery is deliberately
            // driven by a newly constructed engine/coordinator pair: the
            // journal is the only transaction handoff, while native callbacks
            // still revalidate the vdprobe-owned HWND generation before every
            // operation. A complete snapshot follows recovery to make the
            // replacement model authoritative again.
            bool recovery_exercised = false;
            std::string recovery_error;
            const std::optional<SwitchPlan> interrupted =
                first && second && lifecycle_started
                    ? engine.PrepareSwitch(monitor_a_id, a2_id, &recovery_error)
                    : std::nullopt;
            bool journal_began =
                interrupted && journal.Begin(*interrupted, &recovery_error);
            bool interrupted_move = false;
            if (journal_began && !interrupted->operations.empty()) {
                const SwitchOperation& operation = interrupted->operations.front();
                const WindowRecord* window = engine.FindWindow(operation.identity);
                interrupted_move =
                    window != nullptr && move_to_role(*window, operation.to);
            }
            CoordinatorResult recovered;
            CoordinatorResult recovery_reconciled;
            bool fresh_recovery_model = false;
            if (journal_began) {
                WorkspaceEngine recovered_engine(carrier.id, parking.id);
                fresh_recovery_model =
                    recovered_engine.AddMonitor(monitor_a_id, a1_id,
                                                {a1_id, a2_id},
                                                &recovery_error) &&
                    recovered_engine.AddMonitor(monitor_b_id, b1_id, {b1_id},
                                                &recovery_error);
                auto add_recovery_record = [&](const LogicalWindow& logical,
                                               MonitorId monitor,
                                               NativeDesktopRole role) {
                    if (!fresh_recovery_model) return;
                    WindowRecord record{};
                    record.identity = logical.identity;
                    record.monitor = monitor;
                    record.workspace = logical.workspace;
                    // The journal plan is relative to the pre-interruption
                    // logical model. Seed those expected roles, not the
                    // partially-mutated native roles; RecoverPending observes
                    // the latter through observe_role before restoring each
                    // operation.
                    record.native_role = role;
                    record.capabilities = probe_capabilities;
                    record.presentation.rect = logical.rect;
                    record.presentation.placement = logical.placement;
                    record.presentation.rect_valid = true;
                    record.presentation.placement_valid = true;
                    record.disposition = WindowDisposition::Managed;
                    record.present = true;
                    fresh_recovery_model =
                        recovered_engine.UpsertWindow(std::move(record),
                                                      &recovery_error) !=
                        UpsertResult::Rejected;
                };
                add_recovery_record(logical_a1, monitor_a_id,
                                    NativeDesktopRole::Carrier);
                add_recovery_record(logical_a2, monitor_a_id,
                                    NativeDesktopRole::Parking);
                add_recovery_record(logical_b1, monitor_b_id,
                                    NativeDesktopRole::Carrier);
                fresh_recovery_model =
                    fresh_recovery_model && recovered_engine.CheckInvariant(
                                                &recovery_error);
                if (fresh_recovery_model) {
                    WindowLifecycleAdapter recovery_lifecycle(
                        recovered_engine, observe_owned_window);
                    WorkspaceCoordinator recovery_coordinator(
                        recovered_engine, recovery_lifecycle, lifecycle_source,
                        discover_owned_windows, move_to_role, observe_role,
                        &journal, 3);
                    recovered = recovery_coordinator.RecoverPending();
                    if (recovered.succeeded()) {
                        recovery_reconciled =
                            recovery_coordinator.ReconcileDiscovery();
                    }
                    fresh_recovery_model =
                        fresh_recovery_model && recovered_engine.CheckInvariant(
                                                   &recovery_error);
                }
            }
            std::string pending_error;
            const std::optional<SwitchPlan> pending_after_recovery =
                journal.ReadPending(&pending_error);
            recovery_exercised =
                journal_began && interrupted_move && fresh_recovery_model &&
                recovered.succeeded() && recovery_reconciled.succeeded() &&
                recovered.recovery.recovered && !pending_after_recovery &&
                pending_error.empty() &&
                recovery_reconciled.lifecycle.discovery.updated == 3 &&
                VerifyLogicalModel(engine, all_windows,
                                   documented_manager.Get(), carrier.id,
                                   parking.id);
            Field("durable journal fresh-engine recovery simulation",
                  recovery_exercised ? "PASS" : "FAIL");
            if (!recovery_error.empty()) {
                Field("  recovery setup error", recovery_error);
            }
            if (!recovered.error.empty()) {
                Field("  coordinator recovery error", recovered.error);
            }
            if (!recovery_reconciled.error.empty()) {
                Field("  replacement reconciliation error",
                      recovery_reconciled.error);
            }
            if (!pending_error.empty()) {
                Field("  journal readback error", pending_error);
            }

            const bool model_consistent = VerifyLogicalModel(
                engine, all_windows, documented_manager.Get(), carrier.id,
                parking.id);
            // A failed reverse transaction may roll back successfully to its
            // own A2-active baseline.  That is internally consistent with the
            // engine, but it is not the original A1-active state promised by
            // this round-trip test, so leave the fail-safe guards armed.
            const bool restored = first && second && recovery_exercised &&
                                  model_consistent;
            if (!restored) {
                Print("  CRITICAL LOGICAL RESTORE FAILURE\n");
                rc = 1;
            } else {
                restore_a1->Disarm();
                restore_a2->Disarm();
            }

            PumpStaMessages();
            std::vector<NotifyEvent> final_events;
            DrainAndPrintEvents(sink, 0, final_events);
            Heading("verdict");
            if (first && second && restored) {
                Field("GO/NO-GO", "GO-LOGICAL-WORKSPACE");
            } else {
                Field("GO/NO-GO", "NO-GO");
                rc = 1;
            }
            Field("global current desktop changed", "no (required)");
            Field("total events observed", std::format("{}", sink->TotalEventCount()));

            // Destroy armed guards while lifecycle collection is still live;
            // a failed test's last native restoration attempts must precede
            // hook shutdown. Disarmed guards are no-ops here.
            restore_a2.reset();
            restore_a1.reset();
            PumpStaMessages();
            lifecycle_source.Stop();
            Field("WinEvent lifecycle shutdown",
                  lifecycle_source.shutdown_ok() ? "PASS" : "FAIL");
            if (!lifecycle_source.shutdown_ok()) rc = 1;
            std::string cleanup_journal_error;
            const std::optional<SwitchPlan> pending_at_cleanup =
                journal.ReadPending(&cleanup_journal_error);
            if (!pending_at_cleanup && cleanup_journal_error.empty()) {
                journal_remove_error.clear();
                std::filesystem::remove(journal_path, journal_remove_error);
                if (journal_remove_error) {
                    Field("journal cleanup error",
                          journal_remove_error.message());
                    rc = 1;
                }
            } else {
                Field("pending recovery journal retained",
                      journal_path.string());
                if (!cleanup_journal_error.empty()) {
                    Field("  journal cleanup error", cleanup_journal_error);
                }
                rc = 1;
            }
        }

        if (reg.ok()) {
            PumpStaMessages();
            std::vector<NotifyEvent> pre_unregister_events;
            DrainAndPrintEvents(sink, 0, pre_unregister_events);
            const HRESULT unregister_hr = reg.UnregisterNow();
            Field("Unregister gate", GateText(reg.unregister_gate()));
            Field("Unregister hr", HrToString(unregister_hr));
            if (FAILED(unregister_hr)) {
                rc = 1;
                release_sink = false;
            }
            PumpStaMessages();
            std::vector<NotifyEvent> post_unregister_events;
            DrainAndPrintEvents(sink, 0, post_unregister_events);
        }
    }

    cleanup();
    if (release_sink) {
        sink->Release();
    } else {
        Print("  sink retained because Unregister failed; avoiding possible late-callback UAF.\n");
    }
    return rc;
}

// ------------------------------------------------ real-app-semantics-test

int CmdRealAppChild(int window_count, bool create_owned_window,
                    bool confirm_mutate) {
    if (!confirm_mutate) {
        Print(
            "real-app-child: refusing to create windows without "
            "--confirm-mutate\n");
        return 1;
    }
    if (window_count < 2) window_count = 2;
    window_count = std::min(window_count, 3);
    if (!EnsureRealAppChildClass()) {
        Print("real-app-child: RegisterClassExW failed: {}\n",
              HrToString(HRESULT_FROM_WIN32(::GetLastError())));
        return 1;
    }

    std::vector<HWND> roots;
    roots.reserve(static_cast<size_t>(window_count));
    for (int i = 0; i < window_count; ++i) {
        const std::wstring title =
            L"vdprobe real app top-level " + std::to_wstring(i + 1);
        HWND hwnd = CreateRealAppChildWindow(
            title, WS_OVERLAPPEDWINDOW, WS_EX_APPWINDOW, nullptr,
            160 + i * 70, 140 + i * 55);
        if (hwnd == nullptr) {
            for (HWND root : roots) {
                if (::IsWindow(root)) ::DestroyWindow(root);
            }
            return 1;
        }
        roots.push_back(hwnd);
    }

    HWND owned = nullptr;
    if (create_owned_window && !roots.empty()) {
        owned = CreateRealAppChildWindow(
            L"vdprobe real app owned popup",
            WS_POPUP | WS_CAPTION | WS_SYSMENU, WS_EX_TOOLWINDOW, roots.front(),
            240, 520);
        if (owned == nullptr) {
            for (HWND root : roots) {
                if (::IsWindow(root)) ::DestroyWindow(root);
            }
            return 1;
        }
    }

    Print("real-app-child pid={} top_level_windows={} owned_window={}\n",
          ::GetCurrentProcessId(), roots.size(), owned != nullptr ? "yes" : "no");
    MSG message{};
    while (::GetMessageW(&message, nullptr, 0, 0) > 0) {
        ::TranslateMessage(&message);
        ::DispatchMessageW(&message);
    }

    if (owned != nullptr && ::IsWindow(owned)) ::DestroyWindow(owned);
    for (HWND root : roots) {
        if (::IsWindow(root)) ::DestroyWindow(root);
    }
    return 0;
}

int CmdRealAppSemanticsTest(bool confirm_mutate) {
    Heading("real-app-semantics-test");
    Field("what this does",
          "moves one top-level window in a probe-owned ordinary Win32 app and "
          "records sibling/owned-window grouping");
    Field("scope", "ordinary Win32 child app; no existing user windows");
    Field("native model", "one current Carrier + one shared inactive Parking");
    Field("global desktop switch", "never called");
    Field("desktop lifecycle", "no create/remove");

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print(
            "\n  Refusing to launch or move a real-app child without "
            "--confirm-mutate.\n"
            "  Only a vdprobe-owned child process/window set is affected.\n\n"
            "      vdprobe real-app-semantics-test --confirm-mutate\n");
        return 1;
    }

    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    if (FAILED(hr)) {
        Field("IServiceProvider", std::format("FAILED {}", HrToString(hr)));
        if (hr == E_ACCESSDENIED) {
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "ImmersiveShell E_ACCESSDENIED");
            Field("mutation_started", "no");
            return kExitInconclusive;
        }
        return 1;
    }

    ManagerInternal mi = AcquireManagerInternal(sp.Get());
    ReportManagerHeader(mi);
    if (mi.candidate == nullptr || mi.layout == nullptr) {
        Print("\n  real-app semantics refused: usable VDMI layout unavailable.\n");
        return 1;
    }

    DesktopSnapshot carrier;
    if (!ReadCurrentDesktop(mi, carrier)) {
        Print("\n  real-app semantics refused: current Carrier unavailable.\n");
        return 1;
    }
    std::vector<DesktopSnapshot> desktops;
    if (!ReadDesktopList(mi, desktops) || desktops.size() < 2) {
        Print(
            "\n  real-app semantics refused: at least two existing desktops are "
            "required.\n  No desktop will be created.\n");
        return 1;
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.object || !parking.id_ok) {
        Print("\n  real-app semantics refused: no existing Parking desktop found.\n");
        return 1;
    }
    Field("Carrier", GuidToString(carrier.id));
    Field("Parking", GuidToString(parking.id));

    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    if (!views.object || views.layout == nullptr) {
        Print(
            "\n  real-app semantics refused: IApplicationViewCollection "
            "unavailable.\n");
        return 1;
    }
    Com<IVirtualDesktopManager> documented_manager;
    HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER, IID_IVirtualDesktopManager,
        documented_manager.PutVoid());
    if (FAILED(documented_hr) || !documented_manager) {
        Field("IVirtualDesktopManager", HrToString(documented_hr));
        return 1;
    }

    SpawnedRealApp child;
    if (!SpawnRealAppChild(child)) {
        Print("\n  real-app semantics failed: could not launch vdprobe-owned "
              "child.\n");
        (void)CloseRealAppChild(child);
        return 1;
    }
    Field("spawned child PID", std::format("{}", child.pid));
    Field("spawned child creation time",
          child.process_creation_time_ok ? "captured" : "unavailable");

    int rc = 0;
    std::vector<RealAppWindowInfo> windows;
    if (!WaitForRealAppWindows(child, windows)) {
        Print(
            "\n  real-app semantics failed: child did not expose two top-level "
            "and one owned window.\n");
        rc = 1;
    }

    std::vector<RealAppWindowInfo> top_level;
    std::vector<RealAppWindowInfo> owned;
    for (const RealAppWindowInfo& info : windows) {
        if (info.owner == nullptr) {
            top_level.push_back(info);
        } else {
            owned.push_back(info);
        }
    }
    if (top_level.size() < 2 || owned.empty()) {
        Field("window shape", "FAIL");
        rc = 1;
    } else {
        Field("window shape", "two top-level + one owned popup");
    }
    const HWND target_hwnd =
        top_level.empty() ? nullptr : top_level.front().hwnd;

    if (rc == 0) {
        const MonitorRec* monitor_a = nullptr;
        const std::vector<MonitorRec> monitors = EnumerateMonitors();
        if (!monitors.empty()) monitor_a = &monitors.front();
        if (monitor_a == nullptr) {
            Print("\n  real-app semantics refused: no monitor available.\n");
            rc = 1;
        } else {
            // Keep all controlled windows together on one monitor.  This is a
            // grouping test, not the independent-monitor gate already covered
            // by logical-workspace-test.
            for (size_t i = 0; i < top_level.size(); ++i) {
                (void)PlaceProbeWindowOnMonitor(
                    top_level[i].hwnd, *monitor_a, static_cast<int>(i));
            }
            (void)PlaceProbeWindowOnMonitor(owned.front().hwnd, *monitor_a, 2);
        }
    }

    std::vector<RealAppWindowSnapshot> baseline;
    std::vector<RealAppWindowSnapshot> current;
    baseline.reserve(windows.size());
    current.reserve(windows.size());
    auto acquire_view = [&](HWND hwnd, RawObject& out) -> bool {
        const MethodEntry* method = FindMethod(*views.layout, "GetViewForHwnd");
        if (method == nullptr) return false;
        const ULONGLONG deadline = ::GetTickCount64() + 3000;
        do {
            PumpStaMessages();
            Gate gate = Gate::Ok;
            HRESULT view_hr =
                InvokeSlot(views.object.Get(), *views.layout, *method, gate,
                           false, hwnd, out.PutVoid());
            if (gate == Gate::Ok && SUCCEEDED(view_hr) && out) return true;
            ::Sleep(25);
        } while (::GetTickCount64() < deadline);
        return false;
    };

    for (const RealAppWindowInfo& info : windows) {
        RealAppWindowSnapshot snapshot;
        if (!CaptureRealAppWindowSnapshot(info, documented_manager.Get(),
                                          snapshot)) {
            Field(std::format("  window 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  "snapshot FAIL");
            rc = 1;
            continue;
        }
        const bool is_owned_popup = info.owner != nullptr;
        const bool is_target = info.hwnd == target_hwnd;
        if (is_owned_popup) {
            Field(std::format("  owned popup 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  "observation-only; independent IApplicationView not required");
            baseline.push_back(std::move(snapshot));
            continue;
        }

        if (!acquire_view(info.hwnd, snapshot.view)) {
            Field(std::format("  view 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  is_target ? "FAIL (target view unavailable)"
                            : "observation-only (sibling view unavailable)");
            if (is_target) rc = 1;
            baseline.push_back(std::move(snapshot));
            continue;
        }

        const MethodEntry* can_move =
            FindMethod(*mi.layout, "CanViewMoveDesktops");
        Gate gate = Gate::Ok;
        BOOL can_move_value = FALSE;
        HRESULT can_hr = E_ABORT;
        if (can_move != nullptr) {
            can_hr = InvokeSlot(mi.obj.Get(), *mi.layout, *can_move, gate, false,
                                 snapshot.view.Get(), &can_move_value);
        }
        const bool can_move_ok =
            gate == Gate::Ok && SUCCEEDED(can_hr) && can_move_value != FALSE;
        Field(std::format("  CanViewMoveDesktops 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
              can_move_ok ? "TRUE" : "FALSE");
        if (is_target && !can_move_ok) {
            rc = 1;
        }
        baseline.push_back(std::move(snapshot));
    }

    if (baseline.size() != windows.size()) rc = 1;
    if (rc == 0) {
        for (const RealAppWindowSnapshot& snapshot : baseline) {
            if (!IsRealAppWindowOnCarrier(snapshot, carrier.id)) {
                Field("initial native state", "FAIL (not all on Carrier)");
                rc = 1;
                break;
            }
        }
    }

    NotifySink* sink = new NotifySink();
    bool release_sink = true;
    if (rc == 0) {
        NotificationRegistration reg(sp.Get(), sink, confirm_mutate);
        Field("Register gate", GateText(reg.gate()));
        Field("Register hr", HrToString(reg.hr()));
        Field("Register cookie", std::format("{}", reg.cookie()));
        if (!reg.ok()) {
            Print("\n  real-app semantics refused: notification registration failed.\n");
            rc = 1;
        } else {
            Field("watcher STA thread", std::format("{}", ::GetCurrentThreadId()));
            PumpStaMessages();
            std::vector<NotifyEvent> registration_events;
            DrainAndPrintEvents(sink, 0, registration_events);

            // Select the first independent top-level window as the target and
            // leave the sibling top-level plus owned popup untouched by the
            // caller.  Any movement observed on them is therefore genuine
            // shell grouping/ownership behavior.
            auto target_it = std::find_if(
                baseline.begin(), baseline.end(),
                [target_hwnd](const RealAppWindowSnapshot& s) {
                    return s.info.hwnd == target_hwnd;
                });
            if (target_it == baseline.end()) {
                Print("\n  real-app semantics failed: target view snapshot missing.\n");
                rc = 1;
            } else {
                ViewRestoreGuard restore_guard(
                    mi, target_it->view.Get(), carrier.object.Get(),
                    confirm_mutate);
                restore_guard.Arm();
                WindowMoveObservation outbound = MoveViewAndVerify(
                    mi, target_it->view.Get(), parking.object.Get(), carrier.id,
                    parking.id, carrier.id, target_hwnd, documented_manager.Get(),
                    sink, confirm_mutate);

                current.clear();
                for (const RealAppWindowInfo& info : windows) {
                    RealAppWindowSnapshot snapshot;
                    if (!CaptureRealAppWindowSnapshot(info,
                                                      documented_manager.Get(),
                                                      snapshot)) {
                        rc = 1;
                    }
                    current.push_back(std::move(snapshot));
                }

                size_t current_changed_count = outbound.current_changed_count;
                std::vector<HWND> moved_windows;
                std::vector<HWND> child_hwnds;
                child_hwnds.reserve(windows.size());
                for (const RealAppWindowInfo& info : windows) {
                    child_hwnds.push_back(info.hwnd);
                }
                const bool callback_scope_ok =
                    ViewEventsWithinScope(outbound.events,
                                          outbound.call_start_qpc, child_hwnds);
                outbound.view_callback_scope_ok = callback_scope_ok;
                // An unrelated ViewVirtualDesktopChanged HWND contaminates
                // the observation window.  A CurrentVirtualDesktopChanged
                // event is different: it is directly contrary to the
                // Carrier/Parking contract and therefore remains a real
                // semantics failure.
                const bool callback_contaminated = !callback_scope_ok;
                for (size_t i = 0; i < baseline.size() && i < current.size();
                     ++i) {
                    const bool moved =
                        IsWindowDesktopAssignmentChanged(baseline[i], current[i]);
                    if (moved) {
                        moved_windows.push_back(baseline[i].info.hwnd);
                    }
                    const bool identity_ok =
                        RealAppWindowIdentityUnchanged(baseline[i], current[i]);
                    const bool owner_ok =
                        ::GetWindow(current[i].info.hwnd, GW_OWNER) ==
                        baseline[i].info.owner;
                    const bool rect_ok =
                        baseline[i].state_ok && current[i].state_ok &&
                        SameRect(baseline[i].rect, current[i].rect);
                    const bool monitor_ok =
                        baseline[i].monitor == current[i].monitor;
                    Field(std::format("  window 0x{:X} desktop",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          DesktopRelationText(baseline[i], current[i]));
                    Field(std::format("    identity 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          identity_ok ? "unchanged" : "CHANGED");
                    Field(std::format("    owner 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          owner_ok ? "unchanged" : "CHANGED");
                    Field(std::format("    RECT 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          rect_ok ? "unchanged" : "CHANGED");
                    Field(std::format("    monitor 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          monitor_ok ? "unchanged" : "CHANGED");
                    if (!identity_ok || !owner_ok || !rect_ok || !monitor_ok) {
                        rc = 1;
                    }
                }

                const bool target_moved =
                    std::find(moved_windows.begin(), moved_windows.end(),
                              target_hwnd) != moved_windows.end();
                const HWND sibling_hwnd = top_level.size() > 1
                                               ? top_level[1].hwnd
                                               : nullptr;
                const bool sibling_moved =
                    std::find(moved_windows.begin(), moved_windows.end(),
                              sibling_hwnd) != moved_windows.end();
                const HWND owned_hwnd = owned.front().hwnd;
                const bool owned_moved =
                    std::find(moved_windows.begin(), moved_windows.end(),
                              owned_hwnd) != moved_windows.end();
                const bool scope_ok = !sibling_moved;
                Field("  target moved to Parking", target_moved ? "yes" : "NO");
                Field("  sibling top-level moved",
                      sibling_moved ? "yes (unexpected)" : "no");
                Field("  owned popup moved with owner",
                      owned_moved ? "yes (grouped)" : "no (independent)");
                Field("  callback HWND scope",
                      callback_scope_ok ? "probe-owned only" : "OUT OF SCOPE");
                Field("  observation contamination",
                      callback_contaminated ? "yes (inconclusive)" : "none");
                Field("  CurrentVirtualDesktopChanged count",
                      std::format("{}", current_changed_count));
                Field("  ViewVirtualDesktopChanged target",
                      outbound.view_callback_ok ? "observed" : "missing");

                const bool target_core =
                    outbound.move_gate_ok && SUCCEEDED(outbound.move_hr) &&
                    outbound.observed_current_ok &&
                    ::IsEqualGUID(outbound.observed_current, carrier.id) &&
                    outbound.observed_window_ok &&
                    ::IsEqualGUID(outbound.observed_window.desktop, parking.id) &&
                    !outbound.observed_window.on_current;
                const bool target_callback = outbound.view_callback_ok;
                const bool global_current_ok =
                    outbound.observed_current_ok && current_changed_count == 0;
                const bool grouping_pass = target_core && target_callback &&
                                           target_moved && scope_ok &&
                                           global_current_ok;

                // Restore every child window whose desktop changed.  The
                // target guard covers the normal target path; explicit
                // per-window restoration also handles owned-popup propagation.
                for (size_t i = 0; i < baseline.size() && i < current.size();
                     ++i) {
                    if (!baseline[i].state_ok || !current[i].state_ok) {
                        rc = 1;
                        continue;
                    }
                    if (!IsWindowDesktopAssignmentChanged(baseline[i],
                                                           current[i])) {
                        continue;
                    }
                    if (!baseline[i].view) {
                        if (baseline[i].info.owner != nullptr) {
                            Field(std::format(
                                      "  restore 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                                  "deferred to owner/group restore");
                        } else {
                            Field(std::format(
                                      "  restore 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                                  "unavailable (top-level view missing)");
                            rc = 1;
                        }
                        continue;
                    }
                    {
                        Gate gate = Gate::Ok;
                        HRESULT restore_hr = E_ABORT;
                        const bool restored_window = MoveViewToDesktopAndWait(
                            mi, baseline[i].view.Get(), carrier.object.Get(),
                            baseline[i].info.hwnd, documented_manager.Get(),
                            carrier.id, carrier.id, confirm_mutate, gate,
                            restore_hr);
                        if (!restored_window) rc = 1;
                    }
                }
                PumpStaMessages();
                std::vector<NotifyEvent> restore_events;
                DrainAndPrintEvents(sink, 0, restore_events);

                bool restored = true;
                GUID current_desktop{};
                if (!ReadCurrentDesktopId(mi, current_desktop) ||
                    !::IsEqualGUID(current_desktop, carrier.id)) {
                    restored = false;
                }
                for (const RealAppWindowSnapshot& snapshot : baseline) {
                    WindowDesktopState state;
                    const bool state_ok =
                        ReadWindowDesktopState(documented_manager.Get(),
                                               snapshot.info.hwnd, state);
                    if (!IsWindowStateOnCarrier(snapshot.info, state, state_ok,
                                                carrier.id)) {
                        restored = false;
                    }
                }
                if (!restored) {
                    Print("  CRITICAL REAL-APP RESTORE FAILURE\n");
                    rc = 1;
                } else {
                    restore_guard.Disarm();
                }

                Heading("semantics verdict");
                if (!restored) {
                    Field("result", "SEMANTICS-FAILED");
                    Field("GO/NO-GO", "NO-GO");
                    rc = 1;
                } else if (rc != 0) {
                    Field("result", "SEMANTICS-FAILED");
                    Field("GO/NO-GO", "NO-GO");
                } else if (callback_contaminated) {
                    Field("result", "INCONCLUSIVE-CONTAMINATED");
                    Field("GO/NO-GO", "INCONCLUSIVE");
                    rc = kExitInconclusive;
                } else if (grouping_pass) {
                    Field("result", "GROUPING-OBSERVED");
                    Field("GO/NO-GO", "GO-WITH-LIMITATIONS");
                } else {
                    Field("result", "SEMANTICS-FAILED");
                    Field("GO/NO-GO", "NO-GO");
                    rc = 1;
                }
                Field("interpretation",
                      owned_moved
                          ? "ordinary MoveViewToDesktop propagated to the owned "
                            "popup; keep owner-group behavior in the Phase 4 model"
                          : "top-level move stayed independent from the owned popup");
                Field("total events observed",
                      std::format("{}", sink->TotalEventCount()));
            }
        }

        if (reg.ok()) {
            PumpStaMessages();
            std::vector<NotifyEvent> pre_unregister_events;
            DrainAndPrintEvents(sink, 0, pre_unregister_events);
            const HRESULT unregister_hr = reg.UnregisterNow();
            Field("Unregister gate", GateText(reg.unregister_gate()));
            Field("Unregister hr", HrToString(unregister_hr));
            if (FAILED(unregister_hr)) {
                rc = 1;
                release_sink = false;
            }
            PumpStaMessages();
            std::vector<NotifyEvent> post_unregister_events;
            DrainAndPrintEvents(sink, 0, post_unregister_events);
        }
    }

    if (release_sink) {
        sink->Release();
    } else {
        Print(
            "  sink retained because Unregister failed; avoiding possible "
            "late-callback UAF.\n");
    }
    const bool child_closed = CloseRealAppChild(child);
    Field("probe-owned child closed", child_closed ? "yes" : "NO");
    if (!child_closed) rc = 1;
    return rc;
}

// ------------------------------------------------ explorer-semantics-test

int CmdExplorerSemanticsTest(bool confirm_mutate) {
    Heading("explorer-semantics-test");
    Field("what this does",
          "launches two newly observed Explorer windows and moves one "
          "top-level view Carrier -> Parking");
    Field("scope",
          "only HWNDs created by this probe; shared explorer.exe is never "
          "terminated");
    Field("native model", "one current Carrier + one shared inactive Parking");
    Field("global desktop switch", "never called");
    Field("desktop lifecycle", "no create/remove");

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print(
            "\n  Refusing to launch Explorer windows or move a view without "
            "--confirm-mutate.\n"
            "  Only newly observed Explorer HWNDs are eligible for cleanup.\n\n"
            "      vdprobe explorer-semantics-test --confirm-mutate\n");
        return 1;
    }

    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    if (FAILED(hr)) {
        Field("IServiceProvider", std::format("FAILED {}", HrToString(hr)));
        if (hr == E_ACCESSDENIED) {
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "ImmersiveShell E_ACCESSDENIED");
            Field("mutation_started", "no");
            return kExitInconclusive;
        }
        return 1;
    }

    ManagerInternal mi = AcquireManagerInternal(sp.Get());
    ReportManagerHeader(mi);
    if (mi.candidate == nullptr || mi.layout == nullptr) {
        Print("\n  Explorer semantics refused: usable VDMI layout unavailable.\n");
        return 1;
    }

    DesktopSnapshot carrier;
    if (!ReadCurrentDesktop(mi, carrier)) {
        Print("\n  Explorer semantics refused: current Carrier unavailable.\n");
        return 1;
    }
    std::vector<DesktopSnapshot> desktops;
    if (!ReadDesktopList(mi, desktops) || desktops.size() < 2) {
        Print(
            "\n  Explorer semantics refused: at least two existing desktops "
            "are required.\n  No desktop will be created.\n");
        return 1;
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.object || !parking.id_ok) {
        Print("\n  Explorer semantics refused: no existing Parking desktop found.\n");
        return 1;
    }
    Field("Carrier", GuidToString(carrier.id));
    Field("Parking", GuidToString(parking.id));

    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    if (!views.object || views.layout == nullptr) {
        Print(
            "\n  Explorer semantics refused: IApplicationViewCollection "
            "unavailable.\n");
        return 1;
    }
    Com<IVirtualDesktopManager> documented_manager;
    HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER, IID_IVirtualDesktopManager,
        documented_manager.PutVoid());
    if (FAILED(documented_hr) || !documented_manager) {
        Field("IVirtualDesktopManager", HrToString(documented_hr));
        return 1;
    }

    const std::vector<MonitorRec> monitors = EnumerateMonitors();
    if (monitors.empty()) {
        Print("\n  Explorer semantics refused: no monitor available.\n");
        return 1;
    }
    const MonitorRec& monitor_a = monitors.front();

    std::vector<ExplorerWindowInfo> created_roots;
    auto cleanup = [&]() {
        const bool closed = CloseProbeOwnedExplorerWindows(created_roots);
        Field("probe-owned Explorer cleanup", closed ? "passed" : "FAILED");
        return closed;
    };

    const std::vector<std::wstring> explorer_paths = {
        WindowsPath(L""), WindowsPath(L"System32")};
    for (const std::wstring& path : explorer_paths) {
        const std::vector<ExplorerWindowInfo> before =
            EnumerateExplorerWindows(true);
        Field("Explorer launch path", ToUtf8(path));
        if (!LaunchExplorerWindow(path)) {
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "Explorer launch request failed");
            Field("mutation_started", created_roots.empty() ? "no" : "yes");
            const bool closed = cleanup();
            return closed ? kExitInconclusive : 1;
        }

        std::vector<ExplorerWindowInfo> new_windows;
        ExplorerWindowInfo selected;
        bool ambiguous = false;
        if (!WaitForNewExplorerPrimary(before, new_windows, selected,
                                       ambiguous)) {
            Field("Explorer HWND discovery",
                  ambiguous ? "ambiguous" : "no new primary window");
            Field("result", "INCONCLUSIVE-ENVIRONMENT");
            Field("reason",
                  ambiguous
                      ? "multiple new Explorer primary HWNDs appeared for one "
                        "launch request"
                      : "Explorer reused/redirected the launch request without "
                        "one attributable new primary HWND");
            if (ambiguous || !new_windows.empty()) {
                Field("cleanup_scope", "incomplete");
                Field("unattributed_new_windows",
                      std::format("{}", new_windows.size()));
                Print(
                    "  Newly observed Explorer HWNDs are intentionally retained "
                    "because attribution is not proven; they will not be "
                    "closed by this probe.\n");
            } else {
                Field("cleanup_scope", "attributable probe HWNDs only");
                Field("unattributed_new_windows", "0");
            }
            const bool closed = cleanup();
            return closed ? kExitInconclusive : 1;
        }
        created_roots.push_back(selected);
        Field("created Explorer HWND",
              std::format("0x{:X}", reinterpret_cast<uintptr_t>(selected.hwnd)));
        Field("created Explorer PID", std::format("{}", selected.pid));
        Field("created Explorer class", ToUtf8(selected.class_name));
    }

    if (created_roots.size() != 2) {
        const bool closed = cleanup();
        return closed ? kExitInconclusive : 1;
    }
    for (size_t i = 0; i < created_roots.size(); ++i) {
        if (!PlaceProbeWindowOnMonitor(created_roots[i].hwnd, monitor_a,
                                       static_cast<int>(i))) {
            Print("\n  Explorer semantics refused: could not place probe "
                  "windows on one monitor.\n");
            const bool closed = cleanup();
            return closed ? 1 : 1;
        }
    }

    const std::vector<ExplorerWindowInfo> created_windows =
        CollectProbeExplorerWindows(created_roots);
    std::vector<RealAppWindowInfo> windows;
    windows.reserve(created_windows.size());
    for (const ExplorerWindowInfo& info : created_windows) {
        RealAppWindowInfo converted;
        converted.hwnd = info.hwnd;
        converted.owner = info.owner;
        converted.title = info.title;
        converted.identity = info.identity;
        windows.push_back(std::move(converted));
    }
    std::vector<RealAppWindowInfo> top_level;
    std::vector<RealAppWindowInfo> owned;
    for (const RealAppWindowInfo& info : windows) {
        if (info.owner == nullptr) {
            top_level.push_back(info);
        } else {
            owned.push_back(info);
        }
    }
    Field("new Explorer top-level windows",
          std::format("{}", top_level.size()));
    Field("new Explorer owned windows", std::format("{}", owned.size()));
    if (top_level.size() != 2) {
        Field("result", "INCONCLUSIVE-ENVIRONMENT");
        Field("reason",
              "the two launch requests did not yield exactly two attributable "
              "top-level Explorer HWNDs");
        const bool closed = cleanup();
        return closed ? kExitInconclusive : 1;
    }

    const HWND target_hwnd = created_roots.front().hwnd;
    const HWND sibling_hwnd = created_roots.back().hwnd;
    auto acquire_view = [&](HWND hwnd, RawObject& out) -> bool {
        const MethodEntry* method = FindMethod(*views.layout, "GetViewForHwnd");
        if (method == nullptr) return false;
        const ULONGLONG deadline = ::GetTickCount64() + 4000;
        do {
            PumpStaMessages();
            Gate gate = Gate::Ok;
            HRESULT view_hr =
                InvokeSlot(views.object.Get(), *views.layout, *method, gate,
                           false, hwnd, out.PutVoid());
            if (gate == Gate::Ok && SUCCEEDED(view_hr) && out) return true;
            ::Sleep(25);
        } while (::GetTickCount64() < deadline);
        return false;
    };

    std::vector<RealAppWindowSnapshot> baseline;
    baseline.reserve(windows.size());
    int rc = 0;
    bool precondition_failed = false;
    std::string precondition_reason;
    auto fail_precondition = [&](std::string reason) {
        rc = 1;
        precondition_failed = true;
        if (precondition_reason.empty()) {
            precondition_reason = std::move(reason);
        }
    };
    for (const RealAppWindowInfo& info : windows) {
        RealAppWindowSnapshot snapshot;
        const bool is_owned = info.owner != nullptr;
        const bool is_target = info.hwnd == target_hwnd;
        if (!CaptureRealAppWindowSnapshot(info, documented_manager.Get(),
                                          snapshot)) {
            Field(std::format("  window 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  is_owned ? "observation unavailable" : "snapshot FAIL");
            if (!is_owned) {
                fail_precondition(is_target
                                      ? "required target Explorer snapshot unavailable"
                                      : "required sibling Explorer snapshot unavailable");
            }
            baseline.push_back(std::move(snapshot));
            continue;
        }
        if (is_owned) {
            Field(std::format("  owned Explorer window 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  "observation-only; independent IApplicationView not required");
            baseline.push_back(std::move(snapshot));
            continue;
        }
        if (!acquire_view(info.hwnd, snapshot.view)) {
            Field(std::format("  Explorer view 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  is_target ? "FAIL (target view unavailable)"
                            : "observation-only (sibling view unavailable)");
            if (is_target) {
                fail_precondition("required target Explorer view unavailable");
            }
            baseline.push_back(std::move(snapshot));
            continue;
        }
        const MethodEntry* can_move =
            FindMethod(*mi.layout, "CanViewMoveDesktops");
        Gate gate = Gate::Ok;
        BOOL can_move_value = FALSE;
        HRESULT can_hr = E_ABORT;
        if (can_move != nullptr) {
            can_hr = InvokeSlot(mi.obj.Get(), *mi.layout, *can_move, gate, false,
                                 snapshot.view.Get(), &can_move_value);
        }
        const bool can_move_ok =
            gate == Gate::Ok && SUCCEEDED(can_hr) && can_move_value != FALSE;
        Field(std::format("  CanViewMoveDesktops 0x{:X}",
                          reinterpret_cast<uintptr_t>(info.hwnd)),
              can_move_ok ? "TRUE" : "FALSE");
        if (is_target && !can_move_ok) {
            fail_precondition(
                "required target Explorer view cannot move between desktops");
        }
        baseline.push_back(std::move(snapshot));
    }

    if (baseline.size() != windows.size()) {
        fail_precondition("required Explorer window baseline is incomplete");
    }
    if (rc == 0) {
        for (const RealAppWindowSnapshot& snapshot : baseline) {
            if (snapshot.info.owner != nullptr && !snapshot.snapshot_ok) {
                Field(std::format("  initial native state 0x{:X}",
                                  reinterpret_cast<uintptr_t>(
                                      snapshot.info.hwnd)),
                      "observation unavailable");
                continue;
            }
            if (!IsRealAppWindowOnCarrier(snapshot, carrier.id)) {
                Field("initial native state", "FAIL (not all on Carrier)");
                fail_precondition(
                    snapshot.info.owner != nullptr
                        ? "an observable owned Explorer window was not on Carrier"
                        : (snapshot.info.hwnd == target_hwnd
                               ? "target Explorer window was not on Carrier"
                               : "sibling Explorer window was not on Carrier"));
                break;
            }
        }
    }

    if (precondition_failed) {
        Field("result", "INCONCLUSIVE-PRECONDITION");
        Field("mutation_started", "no");
        Field("reason", precondition_reason.empty()
                            ? "required Explorer observation unavailable"
                            : precondition_reason);
        const bool closed = cleanup();
        return closed ? kExitInconclusive : 1;
    }

    NotifySink* sink = new NotifySink();
    bool release_sink = true;
    {
        NotificationRegistration reg(sp.Get(), sink, confirm_mutate);
        Field("Register gate", GateText(reg.gate()));
        Field("Register hr", HrToString(reg.hr()));
        Field("Register cookie", std::format("{}", reg.cookie()));
        if (!reg.ok()) {
            Print("\n  Explorer semantics refused: notification registration failed.\n");
            rc = 1;
        } else if (rc == 0) {
            Field("watcher STA thread",
                  std::format("{}", ::GetCurrentThreadId()));
            PumpStaMessages();
            std::vector<NotifyEvent> registration_events;
            DrainAndPrintEvents(sink, 0, registration_events);

            auto target_it = std::find_if(
                baseline.begin(), baseline.end(),
                [target_hwnd](const RealAppWindowSnapshot& snapshot) {
                    return snapshot.info.hwnd == target_hwnd;
                });
            if (target_it == baseline.end() || !target_it->view) {
                Print("\n  Explorer semantics failed: target view snapshot missing.\n");
                rc = 1;
            } else {
                ViewRestoreGuard restore_guard(
                    mi, target_it->view.Get(), carrier.object.Get(),
                    confirm_mutate);
                restore_guard.Arm();
                WindowMoveObservation outbound = MoveViewAndVerify(
                    mi, target_it->view.Get(), parking.object.Get(), carrier.id,
                    parking.id, carrier.id, target_hwnd, documented_manager.Get(),
                    sink, confirm_mutate);

                std::vector<RealAppWindowSnapshot> current;
                current.reserve(windows.size());
                for (const RealAppWindowInfo& info : windows) {
                    RealAppWindowSnapshot snapshot;
                    if (!CaptureRealAppWindowSnapshot(info,
                                                      documented_manager.Get(),
                                                      snapshot)) {
                        Field(std::format("  post-move window 0x{:X}",
                                          reinterpret_cast<uintptr_t>(info.hwnd)),
                              info.owner != nullptr ? "observation unavailable"
                                                    : "snapshot unavailable");
                        if (info.owner == nullptr) {
                            rc = 1;
                        }
                    }
                    current.push_back(std::move(snapshot));
                }

                std::vector<HWND> allowed_hwnds;
                for (const RealAppWindowInfo& info : windows) {
                    allowed_hwnds.push_back(info.hwnd);
                }
                const bool callback_scope_ok =
                    ViewEventsWithinScope(outbound.events,
                                          outbound.call_start_qpc,
                                          allowed_hwnds);
                const bool callback_contaminated = !callback_scope_ok;
                std::vector<HWND> moved_windows;
                size_t owned_observable_count = 0;
                size_t owned_moved_count = 0;
                for (size_t i = 0; i < baseline.size() && i < current.size();
                     ++i) {
                    const bool is_owned = baseline[i].info.owner != nullptr;
                    const bool full_observation =
                        baseline[i].snapshot_ok && current[i].snapshot_ok;
                    if (!full_observation) {
                        Field(std::format("  window 0x{:X} desktop",
                                          reinterpret_cast<uintptr_t>(
                                              baseline[i].info.hwnd)),
                              is_owned ? "observation unavailable"
                                       : "snapshot unavailable");
                        if (!is_owned) {
                            rc = 1;
                        }
                        continue;
                    }
                    if (is_owned) ++owned_observable_count;
                    const bool moved = IsWindowDesktopAssignmentChanged(
                        baseline[i], current[i]);
                    if (moved) {
                        moved_windows.push_back(baseline[i].info.hwnd);
                    }
                    if (is_owned && moved) ++owned_moved_count;
                    const bool identity_ok =
                        RealAppWindowIdentityUnchanged(baseline[i], current[i]);
                    const bool owner_ok =
                        ::GetWindow(current[i].info.hwnd, GW_OWNER) ==
                        baseline[i].info.owner;
                    const bool rect_ok =
                        baseline[i].state_ok && current[i].state_ok &&
                        SameRect(baseline[i].rect, current[i].rect);
                    const bool monitor_ok =
                        baseline[i].monitor == current[i].monitor;
                    Field(std::format("  window 0x{:X} desktop",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          DesktopRelationText(baseline[i], current[i]));
                    Field(std::format("    identity 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          identity_ok ? "unchanged" : "CHANGED");
                    Field(std::format("    owner 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          owner_ok ? "unchanged" : "CHANGED");
                    Field(std::format("    RECT 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          rect_ok ? "unchanged" : "CHANGED");
                    Field(std::format("    monitor 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          monitor_ok ? "unchanged" : "CHANGED");
                    if (!is_owned &&
                        (!identity_ok || !owner_ok || !rect_ok ||
                         !monitor_ok)) {
                        rc = 1;
                    }
                }

                const bool target_moved =
                    std::find(moved_windows.begin(), moved_windows.end(),
                              target_hwnd) != moved_windows.end();
                const bool sibling_moved =
                    std::find(moved_windows.begin(), moved_windows.end(),
                              sibling_hwnd) != moved_windows.end();
                const std::string owned_semantics =
                    owned.empty()
                        ? "none-observed"
                        : owned_observable_count == 0
                            ? "unavailable"
                            : owned_observable_count < owned.size()
                                ? "partially-observed"
                                : owned_moved_count != 0
                                    ? "grouped"
                                    : "independent";
                Field("  target moved to Parking", target_moved ? "yes" : "NO");
                Field("  sibling top-level moved",
                      sibling_moved ? "yes (unexpected)" : "no");
                Field("  owned windows total", std::format("{}", owned.size()));
                Field("  owned windows observable",
                      std::format("{}", owned_observable_count));
                Field("  owned windows moved",
                      std::format("{}", owned_moved_count));
                Field("  owned window semantics", owned_semantics);
                Field("  callback HWND scope",
                      callback_scope_ok ? "probe-owned only" : "OUT OF SCOPE");
                Field("  observation contamination",
                      callback_contaminated ? "yes (inconclusive)" : "none");
                Field("  CurrentVirtualDesktopChanged count",
                      std::format("{}", outbound.current_changed_count));
                Field("  ViewVirtualDesktopChanged target",
                      outbound.view_callback_ok ? "observed" : "missing");

                const bool target_core =
                    outbound.move_gate_ok && SUCCEEDED(outbound.move_hr) &&
                    outbound.observed_current_ok &&
                    ::IsEqualGUID(outbound.observed_current, carrier.id) &&
                    outbound.observed_window_ok &&
                    ::IsEqualGUID(outbound.observed_window.desktop, parking.id) &&
                    !outbound.observed_window.on_current;
                const bool global_current_ok =
                    outbound.observed_current_ok &&
                    outbound.current_changed_count == 0;
                const bool explorer_pass =
                    target_core && outbound.view_callback_ok && target_moved &&
                    !sibling_moved && global_current_ok;

                for (size_t i = 0; i < baseline.size() && i < current.size();
                     ++i) {
                    const bool is_owned = baseline[i].info.owner != nullptr;
                    if (!baseline[i].snapshot_ok ||
                        !current[i].snapshot_ok) {
                        Field(std::format("  restore 0x{:X}",
                                          reinterpret_cast<uintptr_t>(
                                              baseline[i].info.hwnd)),
                              is_owned ? "observation unavailable"
                                       : "snapshot unavailable");
                        if (!is_owned) {
                            rc = 1;
                        }
                        continue;
                    }
                    if (!IsWindowDesktopAssignmentChanged(baseline[i],
                                                          current[i])) {
                        continue;
                    }
                    if (!baseline[i].view) {
                        if (baseline[i].info.owner != nullptr) {
                            Field(std::format(
                                      "  restore 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                                  "deferred to owner/group restore");
                        } else {
                            Field(std::format(
                                      "  restore 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                                  "unavailable (top-level view missing)");
                            rc = 1;
                        }
                        continue;
                    }
                    Gate restore_gate = Gate::Ok;
                    HRESULT restore_hr = E_ABORT;
                    const bool restored_window = MoveViewToDesktopAndWait(
                        mi, baseline[i].view.Get(), carrier.object.Get(),
                        baseline[i].info.hwnd, documented_manager.Get(),
                        carrier.id, carrier.id, confirm_mutate, restore_gate,
                        restore_hr);
                    Field(std::format("  restore 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          restored_window ? "PASS" : HrToString(restore_hr));
                    if (!restored_window) rc = 1;
                }
                PumpStaMessages();
                std::vector<NotifyEvent> restore_events;
                DrainAndPrintEvents(sink, 0, restore_events);

                bool restored = true;
                GUID current_desktop{};
                if (!ReadCurrentDesktopId(mi, current_desktop) ||
                    !::IsEqualGUID(current_desktop, carrier.id)) {
                    restored = false;
                }
                for (const RealAppWindowSnapshot& snapshot : baseline) {
                    WindowDesktopState state;
                    const bool state_ok =
                        ReadWindowDesktopState(documented_manager.Get(),
                                               snapshot.info.hwnd, state);
                    if (!state_ok) {
                        Field(std::format("  final restore 0x{:X}",
                                          reinterpret_cast<uintptr_t>(
                                              snapshot.info.hwnd)),
                              snapshot.info.owner != nullptr
                                  ? "observation unavailable"
                                  : "snapshot unavailable");
                        if (snapshot.info.owner == nullptr) {
                            restored = false;
                        }
                        continue;
                    }
                    if (!IsWindowStateOnCarrier(snapshot.info, state,
                                                 state_ok, carrier.id)) {
                        if (snapshot.info.owner != nullptr) {
                            Field(std::format("  final restore 0x{:X}",
                                              reinterpret_cast<uintptr_t>(
                                                  snapshot.info.hwnd)),
                                  "observation: not on Carrier");
                            continue;
                        }
                        restored = false;
                    }
                }
                if (!restored) {
                    Print("  CRITICAL EXPLORER RESTORE FAILURE\n");
                    rc = 1;
                } else {
                    restore_guard.Disarm();
                }

                Heading("Explorer semantics verdict");
                if (!restored || rc != 0) {
                    Field("result", "SEMANTICS-FAILED");
                    Field("GO/NO-GO", "NO-GO");
                    rc = 1;
                } else if (callback_contaminated) {
                    Field("result", "INCONCLUSIVE-CONTAMINATED");
                    Field("GO/NO-GO", "INCONCLUSIVE");
                    rc = kExitInconclusive;
                } else if (explorer_pass) {
                    Field("result", "EXPLORER-SEMANTICS-OBSERVED");
                    Field("GO/NO-GO", "GO-WITH-LIMITATIONS");
                } else {
                    Field("result", "SEMANTICS-FAILED");
                    Field("GO/NO-GO", "NO-GO");
                    rc = 1;
                }
                Field("total events observed",
                      std::format("{}", sink->TotalEventCount()));
            }
        }

        if (reg.ok()) {
            PumpStaMessages();
            std::vector<NotifyEvent> pre_unregister_events;
            DrainAndPrintEvents(sink, 0, pre_unregister_events);
            const HRESULT unregister_hr = reg.UnregisterNow();
            Field("Unregister gate", GateText(reg.unregister_gate()));
            Field("Unregister hr", HrToString(unregister_hr));
            if (FAILED(unregister_hr)) {
                rc = 1;
                release_sink = false;
            }
            PumpStaMessages();
            std::vector<NotifyEvent> post_unregister_events;
            DrainAndPrintEvents(sink, 0, post_unregister_events);
        }
    }

    if (release_sink) {
        sink->Release();
    } else {
        Print(
            "  sink retained because Unregister failed; avoiding possible "
            "late-callback UAF.\n");
    }
    const bool explorer_closed = cleanup();
    if (!explorer_closed) rc = 1;
    return rc;
}

// ------------------------------------------------ chromium-semantics-test

int CmdChromiumSemanticsTest(const std::string& browser,
                             bool confirm_mutate) {
    Heading("chromium-semantics-test");
    Field("what this does",
          "launches one isolated Edge profile with two top-level windows and "
          "moves one view Carrier -> Parking -> Carrier");
    Field("browser", browser.empty() ? "(missing)" : browser);
    Field("profile_scope", "probe-temporary");
    Field("scope", "only HWNDs attributed to this temporary browser profile");
    Field("native model", "one current Carrier + one shared inactive Parking");
    Field("global desktop switch", "never called");
    Field("desktop lifecycle", "no create/remove");

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print(
            "\n  Refusing to launch or move an isolated Chromium profile "
            "without --confirm-mutate.\n"
            "      vdprobe chromium-semantics-test --browser edge "
            "--confirm-mutate\n\n");
        return 1;
    }
    if (browser != "edge") {
        Field("result", "INCONCLUSIVE-ATTRIBUTION");
        Field("reason", "Phase 4B-2A supports only --browser edge");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }

    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    if (FAILED(hr)) {
        Field("IServiceProvider", std::format("FAILED {}", HrToString(hr)));
        if (hr == E_ACCESSDENIED) {
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "ImmersiveShell E_ACCESSDENIED");
            Field("mutation_started", "no");
            return kExitInconclusive;
        }
        return 1;
    }

    ManagerInternal mi = AcquireManagerInternal(sp.Get());
    ReportManagerHeader(mi);
    if (mi.candidate == nullptr || mi.layout == nullptr) {
        Print("\n  Chromium semantics refused: usable VDMI layout unavailable.\n");
        return 1;
    }

    DesktopSnapshot carrier;
    if (!ReadCurrentDesktop(mi, carrier)) {
        Print("\n  Chromium semantics refused: current Carrier unavailable.\n");
        return 1;
    }
    std::vector<DesktopSnapshot> desktops;
    if (!ReadDesktopList(mi, desktops) || desktops.size() < 2) {
        Print(
            "\n  Chromium semantics refused: at least two existing desktops "
            "are required. No desktop will be created.\n");
        return 1;
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.object || !parking.id_ok) {
        Print("\n  Chromium semantics refused: no existing Parking desktop "
              "found.\n");
        return 1;
    }
    Field("Carrier", GuidToString(carrier.id));
    Field("Parking", GuidToString(parking.id));

    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    if (!views.object || views.layout == nullptr) {
        Print("\n  Chromium semantics refused: IApplicationViewCollection "
              "unavailable.\n");
        return 1;
    }
    Com<IVirtualDesktopManager> documented_manager;
    HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER, IID_IVirtualDesktopManager,
        documented_manager.PutVoid());
    if (FAILED(documented_hr) || !documented_manager) {
        Field("IVirtualDesktopManager", HrToString(documented_hr));
        return 1;
    }

    const std::wstring executable = SystemEdgePath();
    if (executable.empty()) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "canonical Microsoft Edge executable not found");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }
    Field("browser executable", ToUtf8(executable));

    const ChromiumProcessBaseline process_baseline =
        CaptureChromiumProcessBaseline(executable);
    if (!process_baseline.capture_ok) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "could not capture pre-launch Edge process baseline");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }

    std::wstring profile;
    if (!CreateProbeProfileDirectory(profile)) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "could not create probe temporary profile directory");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }
    Field("probe profile", ToUtf8(profile));

    std::vector<ChromiumWindowInfo> created_roots;
    ChromiumProcessTree process_tree;
    bool retain_profile = false;
    auto cleanup = [&]() {
        const bool closed =
            CloseProbeOwnedChromiumWindows(created_roots, executable, profile);
        const bool no_profile_windows =
            EnumerateChromiumWindows(executable, profile, true).empty();
        bool profile_removed = false;
        ProbeChromiumProcessScanResult process_scan =
            ProbeChromiumProcessScanResult::Inconclusive;
        if (no_profile_windows && !retain_profile) {
            process_scan = WaitForProbeChromiumProcessesToExit(
                process_tree, executable, profile, process_baseline);
        }
        const bool profile_processes_gone =
            process_scan == ProbeChromiumProcessScanResult::Clean;
        if (no_profile_windows && profile_processes_gone && !retain_profile) {
            profile_removed = RemoveProbeProfileDirectory(profile);
        }
        const bool complete =
            closed && no_profile_windows && profile_processes_gone &&
            !retain_profile && profile_removed;
        Field("probe-owned Chromium cleanup",
              closed ? "passed" : "incomplete (retained)");
        if (profile_removed) {
            Field("temporary profile cleanup", "passed");
        } else if (retain_profile || !no_profile_windows ||
                   !profile_processes_gone) {
            Field("temporary profile cleanup", "incomplete (retained)");
        } else {
            Field("temporary profile cleanup", "incomplete (profile retained)");
        }
        if (!no_profile_windows) {
            Field("temporary profile process drain",
                  "not run (attributed profile windows remain)");
        } else if (retain_profile) {
            Field("temporary profile process drain",
                  "not run (attribution incomplete; profile retained)");
        } else {
            switch (process_scan) {
                case ProbeChromiumProcessScanResult::Clean:
                    Field("temporary profile process drain", "passed");
                    break;
                case ProbeChromiumProcessScanResult::MatchesRemain:
                    Field("temporary profile process drain",
                          "incomplete (attributed probe processes remain)");
                    break;
                case ProbeChromiumProcessScanResult::Inconclusive:
                    Field("temporary profile process drain",
                          "inconclusive (profile retained)");
                    break;
            }
        }
        return complete;
    };

    auto inconclusive_attribution = [&](const char* reason,
                                        const std::vector<ChromiumWindowInfo>&
                                            unattributed) {
        Field("result", "INCONCLUSIVE-ATTRIBUTION");
        Field("reason", reason);
        Field("mutation_started", created_roots.empty() ? "no" : "yes");
        Field("target_attribution",
              created_roots.size() >= 1 ? "unique" : "not-established");
        Field("sibling_attribution",
              created_roots.size() >= 2 ? "unique" : "not-established");
        if (!unattributed.empty()) {
            retain_profile = true;
            Field("cleanup_scope", "incomplete");
            Field("unattributed_new_windows",
                  std::format("{}", unattributed.size()));
            Print("  Unattributed Chromium HWNDs are intentionally retained "
                  "because ownership is not proven.\n");
        }
        (void)cleanup();
        return kExitInconclusive;
    };

    const std::vector<std::wstring> launch_args = {L"about:blank", L"about:blank"};
    for (size_t launch_index = 0; launch_index < launch_args.size();
         ++launch_index) {
        const std::vector<ChromiumWindowInfo> before =
            EnumerateChromiumWindows(executable, profile, true);
        Field("Edge launch", std::format("{}", launch_index + 1));
        if (!LaunchChromiumWindow(executable, profile, process_tree)) {
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "Edge launch request failed");
            Field("mutation_started", created_roots.empty() ? "no" : "yes");
            (void)cleanup();
            return kExitInconclusive;
        }

        std::vector<ChromiumWindowInfo> new_windows;
        ChromiumWindowInfo selected;
        bool ambiguous = false;
        if (!WaitForNewChromiumPrimary(before, executable, profile,
                                       new_windows, selected, ambiguous)) {
            return inconclusive_attribution(
                ambiguous
                    ? "multiple new Chromium top-level HWNDs appeared for one "
                      "launch request"
                    : "Edge launch did not yield one attributable new top-level "
                      "HWND",
                new_windows);
        }
        created_roots.push_back(selected);
        Field("created Chromium HWND",
              std::format("0x{:X}", reinterpret_cast<uintptr_t>(selected.hwnd)));
        Field("created Chromium PID", std::format("{}", selected.pid));
        Field("created Chromium class", ToUtf8(selected.class_name));
        Field("created Chromium command line",
              selected.command_line.empty() ? "(unavailable)"
                                             : ToUtf8(selected.command_line));
    }

    Field("target_attribution", "unique");
    Field("sibling_attribution", "unique");
    const std::vector<ChromiumWindowInfo> all_windows =
        EnumerateChromiumWindows(executable, profile, true);
    std::vector<ChromiumWindowInfo> top_level;
    for (const ChromiumWindowInfo& info : all_windows) {
        if (info.visible && IsChromiumTopLevelWindow(info)) {
            top_level.push_back(info);
        }
    }
    if (top_level.size() != 2) {
        return inconclusive_attribution(
            "isolated Edge profile did not expose exactly two attributable "
            "normal top-level windows",
            all_windows);
    }
    for (const ChromiumWindowInfo& root : created_roots) {
        if (std::none_of(top_level.begin(), top_level.end(),
                         [&](const ChromiumWindowInfo& candidate) {
                             return SameChromiumIdentity(root, candidate);
                         })) {
            return inconclusive_attribution(
                "a created Edge root was not present in the final attributable "
                "top-level set",
                all_windows);
        }
    }

    std::vector<RealAppWindowInfo> windows;
    windows.reserve(all_windows.size());
    for (const ChromiumWindowInfo& info : all_windows) {
        RealAppWindowInfo converted;
        converted.hwnd = info.hwnd;
        converted.owner = info.owner;
        converted.title = info.title;
        converted.class_name = info.class_name;
        converted.identity = info.identity;
        windows.push_back(std::move(converted));
    }
    const HWND target_hwnd = created_roots.front().hwnd;
    const HWND sibling_hwnd = created_roots.back().hwnd;
    auto print_window_snapshot = [&](const RealAppWindowSnapshot& snapshot,
                                     const char* role) {
        Field(std::format("  {} HWND", role),
              std::format("0x{:X}",
                          reinterpret_cast<uintptr_t>(snapshot.info.hwnd)));
        Field(std::format("  {} PID", role),
              std::format("{}", snapshot.info.identity.pid));
        Field(std::format("  {} process creation", role),
              snapshot.info.identity.process_creation_time_ok ? "captured"
                                                              : "unavailable");
        Field(std::format("  {} title", role),
              ToUtf8(snapshot.info.title.empty() ? L"(untitled)"
                                                  : snapshot.info.title));
        Field(std::format("  {} class", role),
              ToUtf8(snapshot.info.class_name.empty()
                         ? L"(unavailable)"
                         : snapshot.info.class_name));
        Field(std::format("  {} RECT", role),
              std::format("({},{})-({},{})", snapshot.rect.left,
                          snapshot.rect.top, snapshot.rect.right,
                          snapshot.rect.bottom));
        Field(std::format("  {} monitor", role),
              snapshot.monitor != nullptr
                  ? std::format("0x{:X}",
                                reinterpret_cast<uintptr_t>(snapshot.monitor))
                  : "(unavailable)");
        Field(std::format("  {} desktop", role),
              snapshot.desktop.desktop_ok
                  ? GuidToString(snapshot.desktop.desktop)
                  : "(unavailable)");
        Field(std::format("  {} on_current", role),
              snapshot.desktop.on_current_ok
                  ? (snapshot.desktop.on_current ? "true" : "false")
                  : "(unavailable)");
    };
    auto acquire_view = [&](HWND hwnd, RawObject& out) -> bool {
        const MethodEntry* method = FindMethod(*views.layout, "GetViewForHwnd");
        if (method == nullptr) return false;
        const ULONGLONG deadline = ::GetTickCount64() + 5000;
        do {
            PumpStaMessages();
            Gate gate = Gate::Ok;
            HRESULT view_hr =
                InvokeSlot(views.object.Get(), *views.layout, *method, gate,
                           false, hwnd, out.PutVoid());
            if (gate == Gate::Ok && SUCCEEDED(view_hr) && out) return true;
            ::Sleep(25);
        } while (::GetTickCount64() < deadline);
        return false;
    };

    int rc = 0;
    std::vector<RealAppWindowSnapshot> baseline;
    baseline.reserve(windows.size());
    auto fail_precondition = [&](const std::string& reason) {
        Field("result", "INCONCLUSIVE-PRECONDITION");
        Field("mutation_started", "no");
        Field("reason", reason);
        const bool cleaned = cleanup();
        rc = cleaned ? kExitInconclusive : 1;
    };

    for (const RealAppWindowInfo& info : windows) {
        RealAppWindowSnapshot snapshot;
        const bool is_top_level = info.hwnd == target_hwnd ||
                                   info.hwnd == sibling_hwnd;
        if (!CaptureRealAppWindowSnapshot(info, documented_manager.Get(),
                                          snapshot)) {
            Field(std::format("  window 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  is_top_level ? "snapshot FAIL" : "observation unavailable");
            if (is_top_level) {
                fail_precondition(
                    info.hwnd == target_hwnd
                        ? "required target Chromium snapshot unavailable"
                        : "required sibling Chromium snapshot unavailable");
                return rc;
            }
            baseline.push_back(std::move(snapshot));
            continue;
        }
        print_window_snapshot(
            snapshot, info.hwnd == target_hwnd
                          ? "target"
                          : (info.hwnd == sibling_hwnd ? "sibling"
                                                       : "internal"));
        if (info.hwnd != target_hwnd && info.hwnd != sibling_hwnd) {
            Field(std::format("  owned/internal HWND 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  "observation-only; independent IApplicationView not required");
            baseline.push_back(std::move(snapshot));
            continue;
        }

        if (!acquire_view(info.hwnd, snapshot.view)) {
            Field(std::format("  view 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  info.hwnd == target_hwnd
                      ? "FAIL (target view unavailable)"
                      : "observation-only (sibling view unavailable)");
            if (info.hwnd == target_hwnd) {
                fail_precondition("required target Chromium view unavailable");
                return rc;
            }
            baseline.push_back(std::move(snapshot));
            continue;
        }

        const MethodEntry* can_move =
            FindMethod(*mi.layout, "CanViewMoveDesktops");
        Gate gate = Gate::Ok;
        BOOL can_move_value = FALSE;
        HRESULT can_hr = E_ABORT;
        if (can_move != nullptr) {
            can_hr = InvokeSlot(mi.obj.Get(), *mi.layout, *can_move, gate, false,
                                 snapshot.view.Get(), &can_move_value);
        }
        const bool can_move_ok =
            gate == Gate::Ok && SUCCEEDED(can_hr) && can_move_value != FALSE;
        Field(std::format("  CanViewMoveDesktops 0x{:X}",
                          reinterpret_cast<uintptr_t>(info.hwnd)),
              can_move_ok ? "TRUE" : "FALSE");
        if (info.hwnd == target_hwnd && !can_move_ok) {
            fail_precondition(
                "required target Chromium view cannot move between desktops");
            return rc;
        }
        baseline.push_back(std::move(snapshot));
    }

    for (const RealAppWindowSnapshot& snapshot : baseline) {
        const bool is_root = snapshot.info.hwnd == target_hwnd ||
                             snapshot.info.hwnd == sibling_hwnd;
        if (!is_root) continue;
        if (!IsRealAppWindowOnCarrier(snapshot, carrier.id)) {
            fail_precondition(
                snapshot.info.hwnd == target_hwnd
                    ? "target Chromium window was not initially on Carrier"
                    : "sibling Chromium window was not initially on Carrier");
            return rc;
        }
    }

    NotifySink* sink = new NotifySink();
    bool release_sink = true;
    {
        NotificationRegistration reg(sp.Get(), sink, confirm_mutate);
        Field("Register gate", GateText(reg.gate()));
        Field("Register hr", HrToString(reg.hr()));
        Field("Register cookie", std::format("{}", reg.cookie()));
        if (!reg.ok()) {
            Print("\n  Chromium semantics refused: notification registration "
                  "failed.\n");
            rc = 1;
        } else {
            Field("watcher STA thread",
                  std::format("{}", ::GetCurrentThreadId()));
            PumpStaMessages();
            std::vector<NotifyEvent> registration_events;
            DrainAndPrintEvents(sink, 0, registration_events);

            auto target_it = std::find_if(
                baseline.begin(), baseline.end(),
                [target_hwnd](const RealAppWindowSnapshot& snapshot) {
                    return snapshot.info.hwnd == target_hwnd;
                });
            if (target_it == baseline.end() || !target_it->view) {
                Print("\n  Chromium semantics failed: target view snapshot "
                      "missing.\n");
                rc = 1;
            } else {
                ViewRestoreGuard restore_guard(
                    mi, target_it->view.Get(), carrier.object.Get(),
                    confirm_mutate);
                restore_guard.Arm();
                WindowMoveObservation outbound = MoveViewAndVerify(
                    mi, target_it->view.Get(), parking.object.Get(), carrier.id,
                    parking.id, carrier.id, target_hwnd,
                    documented_manager.Get(), sink, confirm_mutate);

                std::vector<RealAppWindowSnapshot> current;
                current.reserve(windows.size());
                for (const RealAppWindowInfo& info : windows) {
                    RealAppWindowSnapshot snapshot;
                    if (!CaptureRealAppWindowSnapshot(
                            info, documented_manager.Get(), snapshot)) {
                        Field(std::format("  post-move window 0x{:X}",
                                          reinterpret_cast<uintptr_t>(info.hwnd)),
                              (info.hwnd == target_hwnd ||
                               info.hwnd == sibling_hwnd)
                                  ? "snapshot unavailable"
                                  : "observation unavailable");
                        if (info.hwnd == target_hwnd ||
                            info.hwnd == sibling_hwnd) {
                            rc = 1;
                        }
                    }
                    current.push_back(std::move(snapshot));
                }

                std::vector<HWND> allowed_hwnds;
                for (const RealAppWindowInfo& info : windows) {
                    allowed_hwnds.push_back(info.hwnd);
                }
                const bool callback_scope_ok =
                    ViewEventsWithinScope(outbound.events,
                                          outbound.call_start_qpc,
                                          allowed_hwnds);
                const bool callback_contaminated = !callback_scope_ok;
                bool target_moved = false;
                bool sibling_moved = false;
                size_t internal_observable = 0;
                size_t internal_moved = 0;
                for (size_t i = 0; i < baseline.size() && i < current.size();
                     ++i) {
                    const bool is_root =
                        baseline[i].info.hwnd == target_hwnd ||
                        baseline[i].info.hwnd == sibling_hwnd;
                    const bool full_observation =
                        baseline[i].snapshot_ok && current[i].snapshot_ok;
                    if (!full_observation) {
                        if (is_root) rc = 1;
                        continue;
                    }
                    const bool moved = IsWindowDesktopAssignmentChanged(
                        baseline[i], current[i]);
                    if (baseline[i].info.hwnd == target_hwnd) {
                        target_moved = moved;
                    } else if (baseline[i].info.hwnd == sibling_hwnd) {
                        sibling_moved = moved;
                    } else {
                        ++internal_observable;
                        if (moved) ++internal_moved;
                    }
                    const bool identity_ok =
                        RealAppWindowIdentityUnchanged(baseline[i], current[i]);
                    const bool owner_ok =
                        ::GetWindow(current[i].info.hwnd, GW_OWNER) ==
                        baseline[i].info.owner;
                    const bool rect_ok =
                        baseline[i].state_ok && current[i].state_ok &&
                        SameRect(baseline[i].rect, current[i].rect);
                    const bool monitor_ok =
                        baseline[i].monitor == current[i].monitor;
                    if (is_root && baseline[i].info.hwnd == sibling_hwnd &&
                        (!identity_ok || !owner_ok || !rect_ok || !monitor_ok)) {
                        rc = 1;
                    }
                    Field(std::format("  window 0x{:X} desktop",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          DesktopRelationText(baseline[i], current[i]));
                    if (is_root) {
                        Field(std::format("    identity 0x{:X}",
                                          reinterpret_cast<uintptr_t>(
                                              baseline[i].info.hwnd)),
                              identity_ok ? "unchanged" : "CHANGED");
                        Field(std::format("    RECT 0x{:X}",
                                          reinterpret_cast<uintptr_t>(
                                              baseline[i].info.hwnd)),
                              rect_ok ? "unchanged" : "CHANGED");
                        Field(std::format("    monitor 0x{:X}",
                                          reinterpret_cast<uintptr_t>(
                                              baseline[i].info.hwnd)),
                              monitor_ok ? "unchanged" : "CHANGED");
                    }
                }

                Field("target moved to Parking", target_moved ? "yes" : "NO");
                Field("sibling top-level moved",
                      sibling_moved ? "yes (unexpected)" : "no");
                Field("internal windows observable",
                      std::format("{}", internal_observable));
                Field("internal windows moved",
                      std::format("{}", internal_moved));
                Field("callback HWND scope",
                      callback_scope_ok ? "probe-profile only"
                                         : "OUT OF SCOPE");
                Field("observation contamination",
                      callback_contaminated ? "yes (inconclusive)" : "none");
                Field("CurrentVirtualDesktopChanged count",
                      std::format("{}", outbound.current_changed_count));
                Field("ViewVirtualDesktopChanged target",
                      outbound.view_callback_ok ? "observed" : "missing");

                const bool target_core =
                    outbound.move_gate_ok && SUCCEEDED(outbound.move_hr) &&
                    outbound.observed_current_ok &&
                    ::IsEqualGUID(outbound.observed_current, carrier.id) &&
                    outbound.observed_window_ok &&
                    ::IsEqualGUID(outbound.observed_window.desktop,
                                  parking.id) &&
                    !outbound.observed_window.on_current;
                const bool global_current_ok =
                    outbound.observed_current_ok &&
                    outbound.current_changed_count == 0;
                const bool chromium_pass =
                    target_core && outbound.view_callback_ok && target_moved &&
                    !sibling_moved && global_current_ok;

                for (size_t i = 0; i < baseline.size() && i < current.size();
                     ++i) {
                    const bool is_root =
                        baseline[i].info.hwnd == target_hwnd ||
                        baseline[i].info.hwnd == sibling_hwnd;
                    if (!is_root ||
                        !IsWindowDesktopAssignmentChanged(baseline[i],
                                                           current[i])) {
                        continue;
                    }
                    if (!baseline[i].view) {
                        if (baseline[i].info.hwnd == sibling_hwnd) {
                            rc = 1;
                        }
                        continue;
                    }
                    Gate restore_gate = Gate::Ok;
                    HRESULT restore_hr = E_ABORT;
                    const bool restored_window = MoveViewToDesktopAndWait(
                        mi, baseline[i].view.Get(), carrier.object.Get(),
                        baseline[i].info.hwnd, documented_manager.Get(),
                        carrier.id, carrier.id, confirm_mutate, restore_gate,
                        restore_hr);
                    Field(std::format("restore 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          restored_window ? "PASS" : HrToString(restore_hr));
                    if (!restored_window) rc = 1;
                }
                PumpStaMessages();
                std::vector<NotifyEvent> restore_events;
                DrainAndPrintEvents(sink, 0, restore_events);

                bool restored = true;
                GUID current_desktop{};
                if (!ReadCurrentDesktopId(mi, current_desktop) ||
                    !::IsEqualGUID(current_desktop, carrier.id)) {
                    restored = false;
                }
                for (const RealAppWindowSnapshot& snapshot : baseline) {
                    if (snapshot.info.hwnd != target_hwnd &&
                        snapshot.info.hwnd != sibling_hwnd) {
                        continue;
                    }
                    WindowDesktopState state;
                    if (!ReadWindowDesktopState(documented_manager.Get(),
                                                snapshot.info.hwnd, state) ||
                        !IsWindowStateOnCarrier(snapshot.info, state, true,
                                                carrier.id)) {
                        restored = false;
                    }
                }
                if (!restored) {
                    Print("  CRITICAL CHROMIUM RESTORE FAILURE\n");
                    rc = 1;
                } else {
                    restore_guard.Disarm();
                }

                Heading("Chromium semantics verdict");
                if (!restored || rc != 0) {
                    Field("result", "SEMANTICS-FAILED");
                    Field("GO/NO-GO", "NO-GO");
                    rc = 1;
                } else if (callback_contaminated) {
                    Field("result", "INCONCLUSIVE-CONTAMINATED");
                    Field("GO/NO-GO", "INCONCLUSIVE");
                    rc = kExitInconclusive;
                } else if (chromium_pass) {
                    Field("result", "CHROMIUM-SEMANTICS-OBSERVED");
                    Field("GO/NO-GO", "GO-WITH-LIMITATIONS");
                } else {
                    Field("result", "SEMANTICS-FAILED");
                    Field("GO/NO-GO", "NO-GO");
                    rc = 1;
                }
                Field("total events observed",
                      std::format("{}", sink->TotalEventCount()));
            }
        }

        if (reg.ok()) {
            PumpStaMessages();
            std::vector<NotifyEvent> pre_unregister_events;
            DrainAndPrintEvents(sink, 0, pre_unregister_events);
            const HRESULT unregister_hr = reg.UnregisterNow();
            Field("Unregister gate", GateText(reg.unregister_gate()));
            Field("Unregister hr", HrToString(unregister_hr));
            if (FAILED(unregister_hr)) {
                rc = 1;
                release_sink = false;
            }
            PumpStaMessages();
            std::vector<NotifyEvent> post_unregister_events;
            DrainAndPrintEvents(sink, 0, post_unregister_events);
        }
    }

    if (release_sink) {
        sink->Release();
    } else {
        Print("  sink retained because Unregister failed; avoiding possible "
              "late-callback UAF.\n");
    }
    const bool cleaned = cleanup();
    if (!cleaned && rc == 0) {
        Heading("Chromium semantics cleanup verdict");
        Field("result", "INCONCLUSIVE-CLEANUP");
        Field("GO/NO-GO", "INCONCLUSIVE");
        rc = kExitInconclusive;
    }
    return rc;
}

// ------------------------------------------------ terminal-semantics-test

int CmdTerminalSemanticsTest(bool confirm_mutate) {
    Heading("terminal-semantics-test");
    Field("what this does",
          "launches two newly observed Windows Terminal windows and moves one "
          "top-level view Carrier -> Parking -> Carrier");
    Field("representative type", "packaged/modern Windows application");
    Field("scope",
          "only HWNDs carrying this probe's unique title token; existing "
          "Terminal windows and processes are never terminated");
    Field("native model", "one current Carrier + one shared inactive Parking");
    Field("global desktop switch", "never called");
    Field("desktop lifecycle", "no create/remove");

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print(
            "\n  Refusing to launch Windows Terminal or move a view without "
            "--confirm-mutate.\n"
            "      vdprobe terminal-semantics-test --confirm-mutate\n\n");
        return 1;
    }

    Com<IServiceProvider> sp;
    HRESULT hr = GetImmersiveShell(sp);
    if (FAILED(hr)) {
        Field("IServiceProvider", std::format("FAILED {}", HrToString(hr)));
        if (hr == E_ACCESSDENIED) {
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "ImmersiveShell E_ACCESSDENIED");
            Field("mutation_started", "no");
            return kExitInconclusive;
        }
        return 1;
    }

    ManagerInternal mi = AcquireManagerInternal(sp.Get());
    ReportManagerHeader(mi);
    if (mi.candidate == nullptr || mi.layout == nullptr) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "usable VDMI layout unavailable");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }

    DesktopSnapshot carrier;
    if (!ReadCurrentDesktop(mi, carrier)) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "current Carrier unavailable");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }
    std::vector<DesktopSnapshot> desktops;
    if (!ReadDesktopList(mi, desktops) || desktops.size() < 2) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "at least two existing desktops are required");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.object || !parking.id_ok) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "no existing Parking desktop found");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }
    Field("Carrier", GuidToString(carrier.id));
    Field("Parking", GuidToString(parking.id));

    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    if (!views.object || views.layout == nullptr) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "IApplicationViewCollection unavailable");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }
    Com<IVirtualDesktopManager> documented_manager;
    HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER, IID_IVirtualDesktopManager,
        documented_manager.PutVoid());
    if (FAILED(documented_hr) || !documented_manager) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason",
              std::format("IVirtualDesktopManager unavailable ({})",
                          HrToString(documented_hr)));
        Field("mutation_started", "no");
        return kExitInconclusive;
    }

    const std::wstring executable = SystemTerminalPath();
    if (executable.empty()) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "Windows Terminal executable/alias not found");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }
    Field("Windows Terminal launch path", ToUtf8(executable));

    GUID token_id{};
    if (FAILED(::CoCreateGuid(&token_id))) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "could not create unique attribution token");
        Field("mutation_started", "no");
        return kExitInconclusive;
    }
    const std::wstring token =
        L"vdprobe-terminal-" + ToWide(GuidToString(token_id));
    Field("probe title token", ToUtf8(token));

    std::vector<TerminalWindowInfo> created_roots;
    auto cleanup = [&]() {
        const bool closed = CloseProbeOwnedTerminalWindows(created_roots, token);
        Field("probe-owned Terminal cleanup", closed ? "passed" : "incomplete");
        return closed;
    };

    for (size_t launch_index = 0; launch_index < 2; ++launch_index) {
        const std::vector<TerminalWindowInfo> before =
            EnumerateTerminalWindows(token, true);
        Field("Windows Terminal launch",
              std::format("{}", launch_index + 1));
        if (!LaunchTerminalWindow(executable, token)) {
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "Windows Terminal launch request failed");
            Field("mutation_started", created_roots.empty() ? "no" : "yes");
            const bool closed = cleanup();
            return closed ? kExitInconclusive : 1;
        }

        std::vector<TerminalWindowInfo> new_windows;
        TerminalWindowInfo selected;
        bool ambiguous = false;
        if (!WaitForNewTerminalWindow(before, token, new_windows, selected,
                                      ambiguous)) {
            Field("result", "INCONCLUSIVE-ATTRIBUTION");
            Field("reason",
                  ambiguous
                      ? "multiple new Windows Terminal top-level HWNDs appeared "
                        "for one launch request"
                      : "Windows Terminal launch did not yield one attributable "
                        "top-level HWND");
            Field("mutation_started",
                  created_roots.empty() ? "no" : "yes");
            Field("cleanup_scope",
                  new_windows.empty() ? "attributable roots only"
                                       : "incomplete");
            Field("unattributed_new_windows",
                  std::format("{}", new_windows.size()));
            if (!new_windows.empty()) {
                Print("  Unattributed Terminal HWNDs are intentionally retained "
                      "because ownership is not proven.\n");
            }
            const bool closed = cleanup();
            return closed ? kExitInconclusive : 1;
        }
        created_roots.push_back(selected);
        Field("created Terminal HWND",
              std::format("0x{:X}", reinterpret_cast<uintptr_t>(selected.hwnd)));
        Field("created Terminal PID", std::format("{}", selected.pid));
        Field("created Terminal class", ToUtf8(selected.class_name));
        Field("created Terminal image", ToUtf8(selected.image_path));
    }

    const std::vector<TerminalWindowInfo> all_windows =
        EnumerateTerminalWindows(token, true);
    std::vector<TerminalWindowInfo> top_level;
    for (const TerminalWindowInfo& info : all_windows) {
        if (IsTerminalTopLevelWindow(info, token)) top_level.push_back(info);
    }
    Field("new Terminal top-level windows",
          std::format("{}", top_level.size()));
    if (top_level.size() != 2) {
        Field("result", "INCONCLUSIVE-ATTRIBUTION");
        Field("reason",
              "the launch requests did not yield exactly two attributable "
              "Terminal top-level windows");
        Field("mutation_started", "no");
        const bool closed = cleanup();
        return closed ? kExitInconclusive : 1;
    }

    for (const TerminalWindowInfo& root : created_roots) {
        if (std::none_of(top_level.begin(), top_level.end(),
                         [&](const TerminalWindowInfo& candidate) {
                             return SameTerminalIdentity(root, candidate);
                         })) {
            Field("result", "INCONCLUSIVE-ATTRIBUTION");
            Field("reason",
                  "a created Terminal root was not present in the final "
                  "attributable top-level set");
            Field("mutation_started", "no");
            const bool closed = cleanup();
            return closed ? kExitInconclusive : 1;
        }
    }

    const HWND target_hwnd = created_roots.front().hwnd;
    const HWND sibling_hwnd = created_roots.back().hwnd;
    std::vector<RealAppWindowInfo> windows;
    windows.reserve(all_windows.size());
    for (const TerminalWindowInfo& info : all_windows) {
        RealAppWindowInfo converted;
        converted.hwnd = info.hwnd;
        converted.owner = info.owner;
        converted.title = info.title;
        converted.class_name = info.class_name;
        converted.identity = info.identity;
        windows.push_back(std::move(converted));
    }

    auto acquire_view = [&](HWND hwnd, RawObject& out) -> bool {
        const MethodEntry* method = FindMethod(*views.layout, "GetViewForHwnd");
        if (method == nullptr) return false;
        const ULONGLONG deadline = ::GetTickCount64() + 5000;
        do {
            PumpStaMessages();
            Gate gate = Gate::Ok;
            HRESULT view_hr =
                InvokeSlot(views.object.Get(), *views.layout, *method, gate,
                           false, hwnd, out.PutVoid());
            if (gate == Gate::Ok && SUCCEEDED(view_hr) && out) return true;
            ::Sleep(25);
        } while (::GetTickCount64() < deadline);
        return false;
    };

    std::vector<RealAppWindowSnapshot> baseline;
    baseline.reserve(windows.size());
    int rc = 0;
    std::string precondition_reason;
    for (const RealAppWindowInfo& info : windows) {
        RealAppWindowSnapshot snapshot;
        const bool is_target = info.hwnd == target_hwnd;
        const bool is_sibling = info.hwnd == sibling_hwnd;
        const bool is_root = is_target || is_sibling;
        if (!CaptureRealAppWindowSnapshot(info, documented_manager.Get(),
                                          snapshot)) {
            Field(std::format("  window 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  is_root ? "snapshot FAIL" : "observation unavailable");
            if (is_root) {
                precondition_reason =
                    is_target ? "required target Terminal snapshot unavailable"
                              : "required sibling Terminal snapshot unavailable";
            }
            baseline.push_back(std::move(snapshot));
            continue;
        }
        Field(std::format("  {} HWND", is_target ? "target"
                                                 : (is_sibling ? "sibling"
                                                               : "owned")),
              std::format("0x{:X}", reinterpret_cast<uintptr_t>(info.hwnd)));
        Field(std::format("  {} desktop", is_target ? "target"
                                                    : (is_sibling ? "sibling"
                                                                  : "auxiliary")),
              snapshot.desktop.desktop_ok
                  ? GuidToString(snapshot.desktop.desktop)
                  : "(unavailable)");
        Field(std::format("  {} on_current", is_target ? "target"
                                                       : (is_sibling ? "sibling"
                                                                     : "auxiliary")),
              snapshot.desktop.on_current_ok
                  ? (snapshot.desktop.on_current ? "true" : "false")
                  : "(unavailable)");
        if (!is_root) {
            baseline.push_back(std::move(snapshot));
            continue;
        }
        if (!acquire_view(info.hwnd, snapshot.view)) {
            Field(std::format("  view 0x{:X}",
                              reinterpret_cast<uintptr_t>(info.hwnd)),
                  is_target ? "FAIL (target view unavailable)"
                            : "observation-only (sibling view unavailable)");
            if (is_target) {
                precondition_reason = "required target Terminal view unavailable";
            }
            baseline.push_back(std::move(snapshot));
            continue;
        }
        const MethodEntry* can_move =
            FindMethod(*mi.layout, "CanViewMoveDesktops");
        Gate gate = Gate::Ok;
        BOOL can_move_value = FALSE;
        HRESULT can_hr = E_ABORT;
        if (can_move != nullptr) {
            can_hr = InvokeSlot(mi.obj.Get(), *mi.layout, *can_move, gate, false,
                                snapshot.view.Get(), &can_move_value);
        }
        const bool can_move_ok =
            gate == Gate::Ok && SUCCEEDED(can_hr) && can_move_value != FALSE;
        Field(std::format("  CanViewMoveDesktops 0x{:X}",
                          reinterpret_cast<uintptr_t>(info.hwnd)),
              can_move_ok ? "TRUE" : "FALSE");
        if (is_target && !can_move_ok) {
            precondition_reason =
                "required target Terminal view cannot move between desktops";
        }
        baseline.push_back(std::move(snapshot));
    }

    if (!precondition_reason.empty()) {
        Field("result", "INCONCLUSIVE-PRECONDITION");
        Field("mutation_started", "no");
        Field("reason", precondition_reason);
        const bool closed = cleanup();
        return closed ? kExitInconclusive : 1;
    }
    for (const RealAppWindowSnapshot& snapshot : baseline) {
        const bool is_root = snapshot.info.hwnd == target_hwnd ||
                             snapshot.info.hwnd == sibling_hwnd;
        if (!is_root) continue;
        if (!IsRealAppWindowOnCarrier(snapshot, carrier.id)) {
            Field("result", "INCONCLUSIVE-PRECONDITION");
            Field("mutation_started", "no");
            Field("reason",
                  snapshot.info.hwnd == target_hwnd
                      ? "target Terminal window was not initially on Carrier"
                      : "sibling Terminal window was not initially on Carrier");
            const bool closed = cleanup();
            return closed ? kExitInconclusive : 1;
        }
    }

    NotifySink* sink = new NotifySink();
    bool release_sink = true;
    {
        NotificationRegistration reg(sp.Get(), sink, confirm_mutate);
        Field("Register gate", GateText(reg.gate()));
        Field("Register hr", HrToString(reg.hr()));
        Field("Register cookie", std::format("{}", reg.cookie()));
        if (!reg.ok()) {
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "notification registration failed");
            rc = kExitInconclusive;
        } else {
            Field("watcher STA thread",
                  std::format("{}", ::GetCurrentThreadId()));
            PumpStaMessages();
            std::vector<NotifyEvent> registration_events;
            DrainAndPrintEvents(sink, 0, registration_events);

            auto target_it = std::find_if(
                baseline.begin(), baseline.end(),
                [target_hwnd](const RealAppWindowSnapshot& snapshot) {
                    return snapshot.info.hwnd == target_hwnd;
                });
            if (target_it == baseline.end() || !target_it->view) {
                Field("result", "INCONCLUSIVE-PRECONDITION");
                Field("reason", "target Terminal view snapshot missing");
                rc = kExitInconclusive;
            } else {
                ViewRestoreGuard restore_guard(
                    mi, target_it->view.Get(), carrier.object.Get(),
                    confirm_mutate);
                restore_guard.Arm();
                WindowMoveObservation outbound = MoveViewAndVerify(
                    mi, target_it->view.Get(), parking.object.Get(), carrier.id,
                    parking.id, carrier.id, target_hwnd,
                    documented_manager.Get(), sink, confirm_mutate);

                std::vector<RealAppWindowSnapshot> current;
                current.reserve(windows.size());
                for (const RealAppWindowInfo& info : windows) {
                    RealAppWindowSnapshot snapshot;
                    if (!CaptureRealAppWindowSnapshot(
                            info, documented_manager.Get(), snapshot)) {
                        Field(std::format("  post-move window 0x{:X}",
                                          reinterpret_cast<uintptr_t>(info.hwnd)),
                              (info.hwnd == target_hwnd ||
                               info.hwnd == sibling_hwnd)
                                  ? "snapshot unavailable"
                                  : "observation unavailable");
                        if (info.hwnd == target_hwnd ||
                            info.hwnd == sibling_hwnd) {
                            rc = 1;
                        }
                    }
                    current.push_back(std::move(snapshot));
                }

                std::vector<HWND> allowed_hwnds;
                for (const RealAppWindowInfo& info : windows) {
                    allowed_hwnds.push_back(info.hwnd);
                }
                const bool callback_scope_ok =
                    ViewEventsWithinScope(outbound.events,
                                          outbound.call_start_qpc,
                                          allowed_hwnds);
                const bool callback_contaminated = !callback_scope_ok;
                bool target_moved = false;
                bool sibling_moved = false;
                size_t owned_observable = 0;
                size_t owned_moved = 0;
                for (size_t i = 0; i < baseline.size() && i < current.size();
                     ++i) {
                    const bool is_owned = baseline[i].info.owner != nullptr;
                    const bool is_root =
                        baseline[i].info.hwnd == target_hwnd ||
                        baseline[i].info.hwnd == sibling_hwnd;
                    if (!baseline[i].snapshot_ok || !current[i].snapshot_ok) {
                        if (is_root) rc = 1;
                        continue;
                    }
                    const bool moved =
                        IsWindowDesktopAssignmentChanged(baseline[i], current[i]);
                    if (baseline[i].info.hwnd == target_hwnd) {
                        target_moved = moved;
                    } else if (baseline[i].info.hwnd == sibling_hwnd) {
                        sibling_moved = moved;
                    } else if (is_owned) {
                        ++owned_observable;
                        if (moved) ++owned_moved;
                    }
                    const bool identity_ok =
                        RealAppWindowIdentityUnchanged(baseline[i], current[i]);
                    const bool owner_ok =
                        ::GetWindow(current[i].info.hwnd, GW_OWNER) ==
                        baseline[i].info.owner;
                    const bool rect_ok =
                        baseline[i].state_ok && current[i].state_ok &&
                        SameRect(baseline[i].rect, current[i].rect);
                    const bool monitor_ok =
                        baseline[i].monitor == current[i].monitor;
                    if (is_root && baseline[i].info.hwnd == sibling_hwnd &&
                        (!identity_ok || !owner_ok || !rect_ok || !monitor_ok)) {
                        rc = 1;
                    }
                    Field(std::format("  window 0x{:X} desktop",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          DesktopRelationText(baseline[i], current[i]));
                    if (is_root) {
                        Field(std::format("    identity 0x{:X}",
                                          reinterpret_cast<uintptr_t>(
                                              baseline[i].info.hwnd)),
                              identity_ok ? "unchanged" : "CHANGED");
                        Field(std::format("    RECT 0x{:X}",
                                          reinterpret_cast<uintptr_t>(
                                              baseline[i].info.hwnd)),
                              rect_ok ? "unchanged" : "CHANGED");
                        Field(std::format("    monitor 0x{:X}",
                                          reinterpret_cast<uintptr_t>(
                                              baseline[i].info.hwnd)),
                              monitor_ok ? "unchanged" : "CHANGED");
                    }
                }

                Field("target moved to Parking", target_moved ? "yes" : "NO");
                Field("sibling top-level moved",
                      sibling_moved ? "yes (unexpected)" : "no");
                Field("owned windows observable",
                      std::format("{}", owned_observable));
                Field("owned windows moved", std::format("{}", owned_moved));
                Field("callback HWND scope",
                      callback_scope_ok ? "probe-token only" : "OUT OF SCOPE");
                Field("observation contamination",
                      callback_contaminated ? "yes (inconclusive)" : "none");
                Field("CurrentVirtualDesktopChanged count",
                      std::format("{}", outbound.current_changed_count));
                Field("ViewVirtualDesktopChanged target",
                      outbound.view_callback_ok ? "observed" : "missing");

                const bool target_core =
                    outbound.move_gate_ok && SUCCEEDED(outbound.move_hr) &&
                    outbound.observed_current_ok &&
                    ::IsEqualGUID(outbound.observed_current, carrier.id) &&
                    outbound.observed_window_ok &&
                    ::IsEqualGUID(outbound.observed_window.desktop,
                                  parking.id) &&
                    !outbound.observed_window.on_current;
                const bool global_current_ok =
                    outbound.observed_current_ok &&
                    outbound.current_changed_count == 0;
                const bool terminal_pass =
                    target_core && outbound.view_callback_ok && target_moved &&
                    !sibling_moved && global_current_ok;

                for (size_t i = 0; i < baseline.size() && i < current.size();
                     ++i) {
                    const bool is_owned = baseline[i].info.owner != nullptr;
                    const bool is_root =
                        baseline[i].info.hwnd == target_hwnd ||
                        baseline[i].info.hwnd == sibling_hwnd;
                    if (!is_root ||
                        !IsWindowDesktopAssignmentChanged(baseline[i],
                                                           current[i])) {
                        continue;
                    }
                    if (!baseline[i].view) {
                        if (!is_owned) rc = 1;
                        continue;
                    }
                    Gate restore_gate = Gate::Ok;
                    HRESULT restore_hr = E_ABORT;
                    const bool restored_window = MoveViewToDesktopAndWait(
                        mi, baseline[i].view.Get(), carrier.object.Get(),
                        baseline[i].info.hwnd, documented_manager.Get(),
                        carrier.id, carrier.id, confirm_mutate, restore_gate,
                        restore_hr);
                    Field(std::format("restore 0x{:X}",
                                      reinterpret_cast<uintptr_t>(
                                          baseline[i].info.hwnd)),
                          restored_window ? "PASS" : HrToString(restore_hr));
                    if (!restored_window) rc = 1;
                }
                PumpStaMessages();
                std::vector<NotifyEvent> restore_events;
                DrainAndPrintEvents(sink, 0, restore_events);

                bool restored = true;
                GUID current_desktop{};
                if (!ReadCurrentDesktopId(mi, current_desktop) ||
                    !::IsEqualGUID(current_desktop, carrier.id)) {
                    restored = false;
                }
                for (const RealAppWindowSnapshot& snapshot : baseline) {
                    const bool is_root =
                        snapshot.info.hwnd == target_hwnd ||
                        snapshot.info.hwnd == sibling_hwnd;
                    if (!is_root) continue;
                    WindowDesktopState state;
                    if (!ReadWindowDesktopState(documented_manager.Get(),
                                                snapshot.info.hwnd, state) ||
                        !IsWindowStateOnCarrier(snapshot.info, state, true,
                                                carrier.id)) {
                        restored = false;
                    }
                }
                if (!restored) {
                    Print("  CRITICAL TERMINAL RESTORE FAILURE\n");
                    rc = 1;
                } else {
                    restore_guard.Disarm();
                }

                Heading("Terminal semantics verdict");
                if (!restored || rc != 0) {
                    Field("result", "SEMANTICS-FAILED");
                    Field("GO/NO-GO", "NO-GO");
                    rc = 1;
                } else if (callback_contaminated) {
                    Field("result", "INCONCLUSIVE-CONTAMINATED");
                    Field("GO/NO-GO", "INCONCLUSIVE");
                    rc = kExitInconclusive;
                } else if (terminal_pass) {
                    Field("result", "TERMINAL-SEMANTICS-OBSERVED");
                    Field("GO/NO-GO", "GO-WITH-LIMITATIONS");
                } else {
                    Field("result", "SEMANTICS-FAILED");
                    Field("GO/NO-GO", "NO-GO");
                    rc = 1;
                }
                Field("total events observed",
                      std::format("{}", sink->TotalEventCount()));
            }
        }

        if (reg.ok()) {
            PumpStaMessages();
            std::vector<NotifyEvent> pre_unregister_events;
            DrainAndPrintEvents(sink, 0, pre_unregister_events);
            const HRESULT unregister_hr = reg.UnregisterNow();
            Field("Unregister gate", GateText(reg.unregister_gate()));
            Field("Unregister hr", HrToString(unregister_hr));
            if (FAILED(unregister_hr)) {
                rc = 1;
                release_sink = false;
            }
            PumpStaMessages();
            std::vector<NotifyEvent> post_unregister_events;
            DrainAndPrintEvents(sink, 0, post_unregister_events);
        }
    }

    if (release_sink) {
        sink->Release();
    } else {
        Print("  sink retained because Unregister failed; avoiding possible "
              "late-callback UAF.\n");
    }
    const bool terminal_closed = cleanup();
    if (!terminal_closed && rc == 0) {
        Heading("Terminal semantics cleanup verdict");
        Field("result", "INCONCLUSIVE-CLEANUP");
        Field("GO/NO-GO", "INCONCLUSIVE");
        rc = kExitInconclusive;
    }
    return rc;
}

// ------------------------------------------------------------------- matrix

int CmdMatrix() {
    Print("# Interface matrix\n\n");
    Print(
        "Generated by `vdprobe matrix`.  Slot indices are absolute vtable indices\n"
        "(0=QueryInterface, 1=AddRef, 2=Release).  `slot ?` means published sources\n"
        "disagree, and the probe refuses to invoke such a method.\n");

    BuildInfo b = GetBuildInfo();
    Print("\nProbe host build: {}.{}.{}.{} ({})\n\n", b.major, b.minor, b.build, b.ubr,
          ClassifyBuild(b).name);

    for (const char* iface : KnownInterfaces()) {
        std::span<const LayoutTable> layouts = LayoutsFor(iface);
        if (layouts.empty()) continue;
        Print("\n## {}\n", iface);
        for (const LayoutTable& t : layouts) {
            Print("\n### IID {}\n\n", t.iid ? GuidToString(*t.iid) : "(unresolved)");
            Print("- Builds: {}\n", t.builds);
            Print("- Monitor-aware layout: {}\n",
                  t.monitor == MonitorAware::Yes
                      ? "yes"
                      : (t.monitor == MonitorAware::No ? "no" : "unknown"));
            Print("- Applies to probe host: {}\n\n",
                  t.applicable_to_current_family ? "yes" : "no (historical reference)");
            Print("| slot | method | signature | confidence | read-only | evidence | note |\n");
            Print("|---|---|---|---|---|---|---|\n");
            for (const MethodEntry& m : t.methods) {
                Print("| {} | {} | `{}` | {} | {} | {} | {} |\n",
                      m.slot == kUnknownSlot ? std::string("?")
                                             : std::format("{}", m.slot),
                      m.method, m.signature, ConfidenceText(m.confidence),
                      m.read_only ? "yes" : "no", m.evidence, m.note ? m.note : "");
            }
        }
    }
    return 0;
}

}  // namespace vd
