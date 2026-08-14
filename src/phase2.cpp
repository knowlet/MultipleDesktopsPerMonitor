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
#include "workspace_assignment.h"
#include "window_discovery.h"
#include "workspace_readonly_host.h"
#include "workspace_manager.h"
#include "workspace_host_resilience.h"

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

bool WaitForNoProbeChromiumWindows(const std::wstring& executable,
                                   const std::wstring& profile,
                                   DWORD timeout_ms = 5000) {
    const ULONGLONG deadline = ::GetTickCount64() + timeout_ms;
    for (;;) {
        if (EnumerateChromiumWindows(executable, profile, true).empty()) {
            return true;
        }
        if (::GetTickCount64() >= deadline) return false;
        PumpStaMessages();
        ::Sleep(50);
    }
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
        if (!closed && !::IsWindow(process.hwnd)) {
            closed = true;
        }
    }
    if (closed || process.hwnd == nullptr || !::IsWindow(process.hwnd)) {
        process.hwnd = nullptr;
        process.pid = 0;
        process.thread_id = 0;
    }
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
            case WindowDisposition::Quarantined: ++unsupported; break;
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

int CmdWorkspaceLiveReadOnlyHostTest() {
    Heading("workspace-live-readonly-host-test");
    Field("scope",
          "one bounded system-backed read-only host startup/reconcile");
    Field("native mutation", "none");
    Field("move callback", "not installed");
    Field("observe callback", "not installed");
    Field("window close", "none");
    Field("desktop lifecycle", "no create/remove");

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

    const std::vector<MonitorRec> monitors = EnumerateMonitors();
    if (monitors.empty()) {
        return failed("no monitors available for read-only assignment topology");
    }
    std::vector<ReadOnlyMonitorConfiguration> topology;
    topology.reserve(monitors.size());
    for (std::size_t index = 0; index < monitors.size(); ++index) {
        const MonitorId monitor =
            reinterpret_cast<MonitorId>(monitors[index].handle);
        const WorkspaceId active =
            static_cast<WorkspaceId>(index * 2 + 1);
        topology.push_back({monitor, active, {active, active + 1}});
    }

    const std::filesystem::path journal_path =
        std::filesystem::temp_directory_path() /
        ("vdprobe-live-readonly-host-" +
         std::to_string(GetCurrentProcessId()) + ".journal");
    std::error_code remove_error;
    std::filesystem::remove(journal_path, remove_error);
    if (remove_error) {
        return failed("unable to prepare temporary read-only journal path");
    }

    WorkspaceReadOnlyHost host(
        carrier.id, parking.id, std::move(topology), std::move(*backend),
        journal_path);
    const ReadOnlyHostResult started = host.Start();
    if (!started.succeeded()) {
        const std::string reason =
            std::string(ReadOnlyHostResultCodeText(started.code)) + ": " +
            started.error;
        std::error_code cleanup_error;
        std::filesystem::remove(journal_path, cleanup_error);
        if (started.code == ReadOnlyHostResultCode::StartupBlocked &&
            (started.error.find("E_ACCESSDENIED") != std::string::npos ||
             started.error.find("unavailable") != std::string::npos)) {
            return environment_blocked(reason);
        }
        return failed(reason);
    }

    const ReadOnlyHostResult reconciled = host.Reconcile();
    if (!reconciled.succeeded()) {
        const std::string reason =
            std::string(ReadOnlyHostResultCodeText(reconciled.code)) + ": " +
            reconciled.error;
        (void)host.Stop();
        std::error_code cleanup_error;
        std::filesystem::remove(journal_path, cleanup_error);
        if (reconciled.code == ReadOnlyHostResultCode::ReconcileFailed &&
            (reconciled.error.find("E_ACCESSDENIED") != std::string::npos ||
             reconciled.error.find("unstable") != std::string::npos ||
             reconciled.error.find("lifecycle") != std::string::npos)) {
            return environment_blocked(reason);
        }
        return failed(reason);
    }

    std::size_t managed = 0;
    std::size_t unsupported = 0;
    std::size_t ambiguous = 0;
    for (const WindowRecord* window : host.engine().Windows()) {
        if (window == nullptr) continue;
        switch (window->disposition) {
            case WindowDisposition::Managed: ++managed; break;
            case WindowDisposition::Unsupported: ++unsupported; break;
            case WindowDisposition::Ambiguous: ++ambiguous; break;
            case WindowDisposition::Closed: ++ambiguous; break;
            case WindowDisposition::Quarantined: ++unsupported; break;
        }
    }
    const ReadOnlyHostResult stopped = host.Stop();
    std::error_code cleanup_error;
    const bool journal_removed =
        std::filesystem::remove(journal_path, cleanup_error) ||
        !std::filesystem::exists(journal_path);
    if (!stopped.succeeded() || cleanup_error || !journal_removed) {
        return failed("read-only host shutdown or journal cleanup failed");
    }

    Field("managed", std::format("{}", managed));
    Field("unsupported", std::format("{}", unsupported));
    Field("ambiguous", std::format("{}", ambiguous));
    Field("discovery attempts",
          std::format("{}", reconciled.coordinator.discovery_attempts));
    Field("lifecycle hints",
          std::format("{}", reconciled.coordinator.lifecycle.events));
    Field("result", "OK");
    Field("mutation_started", "no");
    Print("MANAGED_COUNT={}\n", managed);
    Print("UNSUPPORTED_COUNT={}\n", unsupported);
    Print("AMBIGUOUS_COUNT={}\n", ambiguous);
    Print("DISCOVERY_ATTEMPTS={}\n",
          reconciled.coordinator.discovery_attempts);
    Print("MOVE_CALLBACK_INSTALLED=0\n");
    Print("OBSERVE_CALLBACK_INSTALLED=0\n");
    Print("mutation_started=no\n");
    Print("RESULT=OK\n");
    return 0;
}

// ------------------------------------------------ workspace-live-manager-test

int CmdWorkspaceLiveManagerTest(bool confirm_mutate, int rounds) {
    Heading("workspace-live-manager-test");
    Field("scope", "three vdprobe-owned windows; A1 -> A2 -> A1");
    Field("discovery", "complete system EnumWindows + capability augmentation");
    Field("global desktop switch", "never called");
    Field("desktop lifecycle", "no create/remove");

    auto environment_blocked = [](const std::string& reason) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", reason);
        Field("mutation_started", "no");
        Print("mutation_started=no\n");
        Print("RESULT=ENVIRONMENT-BLOCKED\n");
        return kExitInconclusive;
    };

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print("\n  Refusing the probe-owned workspace round-trip without "
              "--confirm-mutate.\n\n      vdprobe workspace-live-manager-test "
              "--confirm-mutate\n");
        return 1;
    }

    const std::vector<MonitorRec> monitors = EnumerateMonitors();
    if (monitors.size() < 2) {
        return environment_blocked("at least two monitors are required");
    }
    const MonitorRec& monitor_a = monitors[0];
    const MonitorRec& monitor_b = monitors[1];
    const MonitorId monitor_a_id =
        reinterpret_cast<MonitorId>(monitor_a.handle);
    const MonitorId monitor_b_id =
        reinterpret_cast<MonitorId>(monitor_b.handle);
    WorkspaceId kA1 = 1;
    WorkspaceId kA2 = 2;
    WorkspaceId kB1 = 3;
    Field("monitor A", ToUtf8(monitor_a.device));
    Field("monitor B", ToUtf8(monitor_b.device));

    // This name is deliberately process-independent. A prior incomplete
    // transaction is preserved and blocks all mutation rather than being
    // hidden by a PID-specific path or unconditional deletion.
    const std::filesystem::path journal_path =
        std::filesystem::temp_directory_path() /
        "vdprobe-workspace-live-manager.journal";
    WorkspaceJournal journal(journal_path);
    std::string journal_error;
    const std::optional<SwitchPlan> existing_pending =
        journal.ReadPending(&journal_error);
    if (!journal_error.empty() || existing_pending) {
        Field("journal", journal_path.string());
        return environment_blocked(
            !journal_error.empty()
                ? "stable journal could not be read: " + journal_error
                : "stable journal contains a pending transaction");
    }
    Field("journal", journal_path.string());

    Com<IServiceProvider> sp;
    const HRESULT shell_hr = GetImmersiveShell(sp);
    if (FAILED(shell_hr) || !sp) {
        const std::string reason = std::format("ImmersiveShell unavailable ({})",
                                               HrToString(shell_hr));
        if (shell_hr == E_ACCESSDENIED) return environment_blocked(reason);
        Field("result", "ERROR");
        Field("reason", reason);
        Field("mutation_started", "no");
        return 1;
    }

    ManagerInternal manager = AcquireManagerInternal(sp.Get());
    if (!manager.obj || manager.layout == nullptr) {
        if (manager.access_denied_seen) {
            return environment_blocked(
                "usable IVirtualDesktopManagerInternal unavailable");
        }
        Field("result", "ERROR");
        Field("reason", "usable IVirtualDesktopManagerInternal unavailable");
        Field("mutation_started", "no");
        return 1;
    }
    DesktopSnapshot carrier;
    HRESULT current_hr = E_ABORT;
    if (!ReadCurrentDesktop(manager, carrier, &current_hr)) {
        if (current_hr == E_ACCESSDENIED) {
            return environment_blocked("current Carrier unavailable");
        }
        Field("result", "ERROR");
        Field("reason", "current Carrier unavailable");
        Field("mutation_started", "no");
        return 1;
    }
    std::vector<DesktopSnapshot> desktops;
    HRESULT desktops_hr = E_ABORT;
    if (!ReadDesktopList(manager, desktops, &desktops_hr)) {
        if (desktops_hr == E_ACCESSDENIED) {
            return environment_blocked("existing desktop enumeration failed");
        }
        Field("result", "ERROR");
        Field("reason", "existing desktop enumeration failed");
        Field("mutation_started", "no");
        return 1;
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.id_ok || !parking.object) {
        return environment_blocked("no existing inactive Parking desktop");
    }

    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    const MethodEntry* get_view =
        views.layout == nullptr ? nullptr
                                : FindMethod(*views.layout, "GetViewForHwnd");
    const MethodEntry* can_move =
        FindMethod(*manager.layout, "CanViewMoveDesktops");
    if (!views.object || get_view == nullptr || can_move == nullptr) {
        if (views.access_denied_seen) {
            return environment_blocked(
                "application-view capability APIs unavailable");
        }
        Field("result", "ERROR");
        Field("reason", "application-view capability APIs unavailable");
        Field("mutation_started", "no");
        return 1;
    }

    Com<IVirtualDesktopManager> documented_manager;
    const HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER,
        IID_IVirtualDesktopManager, documented_manager.PutVoid());
    if (FAILED(documented_hr) || !documented_manager) {
        const std::string reason = std::format(
            "IVirtualDesktopManager unavailable ({})", HrToString(documented_hr));
        if (documented_hr == E_ACCESSDENIED) return environment_blocked(reason);
        Field("result", "ERROR");
        Field("reason", reason);
        Field("mutation_started", "no");
        return 1;
    }

    auto acquire_view = [&](HWND hwnd, RawObject& out,
                            std::string* error = nullptr) -> bool {
        const ULONGLONG deadline = ::GetTickCount64() + 2000;
        HRESULT last_hr = E_ABORT;
        Gate last_gate = Gate::Ok;
        do {
            PumpStaMessages();
            last_gate = Gate::Ok;
            last_hr = InvokeSlot(views.object.Get(), *views.layout, *get_view,
                                 last_gate, false, hwnd, out.PutVoid());
            if (last_gate == Gate::Ok && SUCCEEDED(last_hr) && out) return true;
            ::Sleep(25);
        } while (::GetTickCount64() < deadline);
        if (error != nullptr) {
            *error = std::format("GetViewForHwnd 0x{:X} failed: gate={} hr={}",
                                 reinterpret_cast<std::uintptr_t>(hwnd),
                                 GateText(last_gate), HrToString(last_hr));
        }
        return false;
    };
    auto view_can_move = [&](IUnknown* view, std::string* error = nullptr) {
        Gate gate = Gate::Ok;
        BOOL value = FALSE;
        const HRESULT hr = InvokeSlot(manager.obj.Get(), *manager.layout,
                                      *can_move, gate, false, view, &value);
        if (gate == Gate::Ok && SUCCEEDED(hr) && value != FALSE) return true;
        if (error != nullptr) {
            *error = std::format("CanViewMoveDesktops failed: gate={} hr={}",
                                 GateText(gate), HrToString(hr));
        }
        return false;
    };

    SpawnedProbeWindow a1;
    SpawnedProbeWindow a2;
    SpawnedProbeWindow b1;
    auto close_probes = [&]() {
        const bool b1_closed = CloseThrowawayProbeWindow(b1);
        const bool a2_closed = CloseThrowawayProbeWindow(a2);
        const bool a1_closed = CloseThrowawayProbeWindow(a1);
        const bool closed = b1_closed && a2_closed && a1_closed;
        Field("probe window close", closed ? "PASS" : "FAIL");
        return closed;
    };
    if (!SpawnThrowawayProbeWindow(a1) || !SpawnThrowawayProbeWindow(a2) ||
        !SpawnThrowawayProbeWindow(b1) ||
        !PlaceProbeWindowOnMonitor(a1.hwnd, monitor_a, 0) ||
        !PlaceProbeWindowOnMonitor(a2.hwnd, monitor_a, 1) ||
        !PlaceProbeWindowOnMonitor(b1.hwnd, monitor_b, 0)) {
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not create and place three probe windows");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "no");
        return 1;
    }

    LogicalWindow logical_a1;
    LogicalWindow logical_a2;
    LogicalWindow logical_b1;
    if (!CaptureLogicalWindow(documented_manager.Get(), a1.hwnd,
                              monitor_a.handle, kA1, logical_a1) ||
        !CaptureLogicalWindow(documented_manager.Get(), a2.hwnd,
                              monitor_a.handle, kA2, logical_a2) ||
        !CaptureLogicalWindow(documented_manager.Get(), b1.hwnd,
                              monitor_b.handle, kB1, logical_b1)) {
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not capture exact probe identities");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "no");
        return 1;
    }
    WindowDesktopState b1_baseline_state;
    if (!ReadWindowDesktopState(documented_manager.Get(), b1.hwnd,
                                b1_baseline_state) ||
        !WindowStateMatches(b1_baseline_state, carrier.id, true)) {
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "control probe baseline is not on Carrier");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "no");
        return 1;
    }
    const std::vector<const LogicalWindow*> owned{
        &logical_a1, &logical_a2, &logical_b1};
    auto owned_logical = [&](const WindowIdentity& identity)
        -> const LogicalWindow* {
        const auto found = std::find_if(
            owned.begin(), owned.end(), [&](const LogicalWindow* logical) {
                return logical != nullptr && logical->identity == identity;
            });
        return found == owned.end() ? nullptr : *found;
    };

    auto observe_role = [&](const WindowRecord& record) {
        if (owned_logical(record.identity) == nullptr) {
            return NativeDesktopRole::Unknown;
        }
        const LogicalWindow* logical = owned_logical(record.identity);
        WindowIdentity current;
        WindowDesktopState state;
        if (!ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity ||
            logical == nullptr ||
            ::MonitorFromWindow(record.identity.hwnd,
                                MONITOR_DEFAULTTONULL) != logical->monitor ||
            !ReadWindowDesktopState(documented_manager.Get(),
                                    record.identity.hwnd, state)) {
            return NativeDesktopRole::Unknown;
        }
        if (::IsEqualGUID(state.desktop, carrier.id) && state.on_current) {
            return NativeDesktopRole::Carrier;
        }
        if (::IsEqualGUID(state.desktop, parking.id) && !state.on_current) {
            return NativeDesktopRole::Parking;
        }
        return NativeDesktopRole::Unknown;
    };
    auto move_to_role = [&](const WindowRecord& record,
                            NativeDesktopRole target) -> bool {
        const LogicalWindow* logical = owned_logical(record.identity);
        WindowIdentity current;
        if (logical == nullptr ||
            !ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity ||
            ::MonitorFromWindow(record.identity.hwnd,
                                MONITOR_DEFAULTTONULL) != logical->monitor) {
            return false;
        }
        RawObject view;
        std::string error;
        if (!acquire_view(record.identity.hwnd, view, &error) ||
            !view_can_move(view.Get(), &error)) {
            if (!error.empty()) Field("native move error", error);
            return false;
        }
        IUnknown* target_object =
            target == NativeDesktopRole::Carrier ? carrier.object.Get()
            : target == NativeDesktopRole::Parking ? parking.object.Get()
                                                     : nullptr;
        const GUID* target_id =
            target == NativeDesktopRole::Carrier ? &carrier.id
            : target == NativeDesktopRole::Parking ? &parking.id : nullptr;
        if (target_object == nullptr || target_id == nullptr) return false;
        Gate gate = Gate::Ok;
        HRESULT hr = E_ABORT;
        const bool moved = MoveViewToDesktopAndWait(
            manager, view.Get(), target_object, record.identity.hwnd,
            documented_manager.Get(), *target_id, carrier.id, confirm_mutate,
            gate, hr);
        Field(std::format("move 0x{:X} -> {}",
                          reinterpret_cast<std::uintptr_t>(record.identity.hwnd),
                          NativeDesktopRoleText(target)),
              moved ? "verified" : "FAILED");
        return moved;
    };

    bool mutation_started = false;
    // Establish the explicit inactive A2 assignment. This setup move is still
    // restricted to an exact probe identity and a freshly resolved view.
    WindowRecord setup_a2{};
    setup_a2.identity = logical_a2.identity;
    setup_a2.monitor = monitor_a_id;
    setup_a2.workspace = kA2;
    setup_a2.native_role = NativeDesktopRole::Carrier;
    setup_a2.capabilities = {true, true, true, true, true};
    mutation_started = true;
    if (!move_to_role(setup_a2, NativeDesktopRole::Parking)) {
        // The mutating call may have taken effect even when bounded
        // verification timed out. Re-observe and make one identity-checked
        // restore attempt before destroying the disposable HWND.
        const bool setup_restored =
            observe_role(setup_a2) == NativeDesktopRole::Carrier ||
            move_to_role(setup_a2, NativeDesktopRole::Carrier);
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not establish A2 on Parking");
        Field("setup restoration",
              setup_restored ? "PASS" : "FAILED (probe destroyed)");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "yes");
        return 1;
    }

    auto restore_and_close = [&]() {
        bool restored = true;
        for (const LogicalWindow* logical : owned) {
            if (logical == nullptr) continue;
            WindowRecord record{};
            record.identity = logical->identity;
            record.monitor = reinterpret_cast<MonitorId>(logical->monitor);
            record.workspace = logical->workspace;
            record.capabilities = {true, true, true, true, true};
            const NativeDesktopRole role = observe_role(record);
            if (role != NativeDesktopRole::Carrier &&
                !move_to_role(record, NativeDesktopRole::Carrier)) {
                restored = false;
            }
        }
        return restored && close_probes();
    };

    bool restoration_done = false;
    bool restored_result = true;
    int integration_rc = 1;
    try {
    integration_rc = [&]() -> int {
        bool capability_access_denied = false;
        Win32WindowDiscoveryOptions options;
        options.carrier = carrier.id;
        options.parking = parking.id;
        options.augment_capabilities =
            [&](HWND hwnd, const WindowDiscoveryObservation& observation,
                WindowCapabilities& capabilities, std::string* error) {
                const LogicalWindow* logical = owned_logical(observation.identity);
                if (logical == nullptr) {
                    // Complete system discovery remains authoritative, but no
                    // pre-existing user HWND is promoted to Managed.
                    return true;
                }
                if (hwnd != logical->identity.hwnd ||
                    ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL) !=
                        logical->monitor) {
                    if (error != nullptr) {
                        *error = "owned probe identity or monitor changed";
                    }
                    return false;
                }
                RawObject view;
                if (!acquire_view(hwnd, view, error)) return false;
                capabilities.has_application_view = true;
                Gate gate = Gate::Ok;
                BOOL value = FALSE;
                const HRESULT hr = InvokeSlot(
                    manager.obj.Get(), *manager.layout, *can_move, gate, false,
                    view.Get(), &value);
                if (hr == E_ACCESSDENIED) capability_access_denied = true;
                if (gate != Gate::Ok || FAILED(hr)) {
                    if (error != nullptr) {
                        *error = std::format(
                            "CanViewMoveDesktops failed: gate={} hr={}",
                            GateText(gate), HrToString(hr));
                    }
                    return false;
                }
                capabilities.can_move_desktops = value != FALSE;
                return true;
            };

        std::string error;
        HRESULT backend_hr = S_OK;
        auto backend = CreateSystemWindowDiscoveryBackend(
            std::move(options), &error, &backend_hr);
        if (!backend) {
            Field("integration error", error);
            return backend_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
        }
        WindowDiscovery discovery(std::move(*backend));

        WorkspaceEngine engine(carrier.id, parking.id);
        if (!engine.AddMonitor(monitor_a_id, kA1, {kA1, kA2}, &error) ||
            !engine.AddMonitor(monitor_b_id, kB1, {kB1}, &error)) {
            Field("integration error", error);
            return 1;
        }
        WorkspaceAssignmentAdapter assignment(engine);
        if (!assignment.ConfigureMonitor(monitor_a_id, kA1, {kA1, kA2},
                                         &error) ||
            !assignment.ConfigureMonitor(monitor_b_id, kB1, {kB1}, &error)) {
            Field("assignment error", error);
            return 1;
        }

        std::vector<DiscoveredWindow> initial;
        if (!discovery.Discover(initial, &error)) {
            Field("discovery error", error);
            return capability_access_denied ? kExitInconclusive : 1;
        }
        for (const LogicalWindow* logical : owned) {
            const auto found = std::find_if(
                initial.begin(), initial.end(), [&](const DiscoveredWindow& item) {
                    return logical != nullptr &&
                           item.identity == logical->identity;
                });
            const NativeDesktopRole expected =
                logical == &logical_a2 ? NativeDesktopRole::Parking
                                       : NativeDesktopRole::Carrier;
            if (found == initial.end() ||
                found->disposition != WindowDisposition::Managed ||
                found->native_role != expected ||
                !found->capabilities.Manageable()) {
                Field("integration error",
                      "system discovery did not prove all owned probes");
                return 1;
            }
            WindowRecord record{};
            record.identity = found->identity;
            record.monitor = reinterpret_cast<MonitorId>(found->monitor);
            record.workspace = logical->workspace;
            record.native_role = found->native_role;
            record.capabilities = found->capabilities;
            record.presentation = found->presentation;
            record.disposition = WindowDisposition::Managed;
            record.present = true;
            if (engine.UpsertWindow(std::move(record), &error) !=
                UpsertResult::Added) {
                Field("assignment error", error);
                return 1;
            }
        }
        if (!engine.CheckInvariant(&error)) {
            Field("integration error", error);
            return 1;
        }

        auto discover_assigned = [&](std::vector<WindowRecord>& records,
                                     std::string* local_error) {
            std::vector<DiscoveredWindow> complete;
            if (!discovery.Discover(complete, local_error) ||
                !assignment.ConvertCompleteSnapshot(complete, records,
                                                    local_error)) {
                return false;
            }
            // Defense in depth: even if policy changes later, a system HWND
            // outside this exact ownership set can never reach the coordinator.
            if (records.size() != owned.size() ||
                std::any_of(records.begin(), records.end(),
                            [&](const WindowRecord& record) {
                                return owned_logical(record.identity) == nullptr;
                            })) {
                if (local_error != nullptr) {
                    *local_error =
                        "assigned snapshot escaped the probe ownership boundary";
                }
                return false;
            }
            return true;
        };
        auto observe_owned = [&](HWND hwnd) -> std::optional<WindowRecord> {
            std::vector<WindowRecord> records;
            std::string local_error;
            if (!discover_assigned(records, &local_error)) return std::nullopt;
            const auto found = std::find_if(
                records.begin(), records.end(),
                [hwnd](const WindowRecord& record) {
                    return record.identity.hwnd == hwnd;
                });
            return found == records.end() ? std::nullopt
                                          : std::optional<WindowRecord>(*found);
        };

        WindowLifecycleAdapter lifecycle(engine, observe_owned);
        WinEventLifecycleSource source;
        if (!source.Start(&error)) {
            Field("lifecycle error", error);
            return 1;
        }
        auto coordinator_discovery = [&](std::vector<WindowRecord>& records,
                                         std::string* local_error) {
            if (!source.PumpOwnerThreadMessages(local_error)) return false;
            return discover_assigned(records, local_error);
        };
        WorkspaceCoordinator coordinator(
            engine, lifecycle, source, coordinator_discovery, move_to_role,
            observe_role, &journal, 10, 5);

        auto control_unchanged = [&]() {
            WindowIdentity identity;
            WindowDesktopState state;
            RECT rect{};
            GUID current{};
            return ReadWindowIdentity(logical_b1.identity.hwnd, identity) &&
                   identity == logical_b1.identity &&
                   ::MonitorFromWindow(logical_b1.identity.hwnd,
                                       MONITOR_DEFAULTTONULL) == monitor_b.handle &&
                   ::GetWindowRect(logical_b1.identity.hwnd, &rect) &&
                   SameRect(rect, logical_b1.rect) &&
                   ReadWindowDesktopState(documented_manager.Get(),
                                          logical_b1.identity.hwnd, state) &&
                   WindowStateMatches(state, carrier.id, true) &&
                   state.visible == b1_baseline_state.visible &&
                   state.cloaked == b1_baseline_state.cloaked &&
                   ReadCurrentDesktopId(manager, current) &&
                   ::IsEqualGUID(current, carrier.id);
        };
        auto report_coordinator = [&](const char* label,
                                      const CoordinatorResult& result) {
            Field(label, result.succeeded() ? "PASS" : "FAIL");
            Field("  coordinator", CoordinatorResultCodeText(result.code));
            Field("  discovery attempts",
                  std::format("{}", result.discovery_attempts));
            if (!result.error.empty()) Field("  error", result.error);
        };

        bool ok = true;
        const CoordinatorResult reconciled = coordinator.ReconcileDiscovery();
        report_coordinator("initial authoritative reconcile", reconciled);
        ok = reconciled.succeeded() && control_unchanged();
        CoordinatorResult forward;
        CoordinatorResult reverse;
        auto switch_gate = [&](WorkspaceId target,
                               CoordinatorResult& result) {
            result = coordinator.Switch(monitor_a_id, target);
            if (!result.succeeded() &&
                result.transaction.rollback_succeeded &&
                !result.transaction.recovery_required &&
                result.code != CoordinatorResultCode::PlanRejected) {
                result = coordinator.Switch(monitor_a_id, target);
            }
            return result.succeeded() && result.transaction.committed;
        };
        for (int round = 1; round <= rounds && ok; ++round) {
            for (int attempt = 1; attempt <= 3; ++attempt) {
                ok = true;
                const bool switched = switch_gate(kA2, forward);
                report_coordinator(
                    std::format("A1 -> A2 (round {}/{})", round, rounds)
                        .c_str(),
                    forward);
                const bool forward_control_unchanged = control_unchanged();
                ok = switched &&
                     engine.Monitor(monitor_a_id)->active == kA2 &&
                     engine.Monitor(monitor_b_id)->active == kB1 &&
                     forward_control_unchanged;
                if (ok) {
                    const bool switched_back = switch_gate(kA1, reverse);
                    report_coordinator(
                        std::format("A2 -> A1 (round {}/{})", round, rounds)
                            .c_str(),
                        reverse);
                    const bool reverse_control_unchanged =
                        control_unchanged();
                    ok = switched_back &&
                         engine.Monitor(monitor_a_id)->active == kA1 &&
                         engine.Monitor(monitor_b_id)->active == kB1 &&
                         reverse_control_unchanged;
                }
                if (ok) break;
                if (attempt < 3) {
                    Field("  transient noise; retrying round", "");
                    (void)coordinator.ReconcileDiscovery();
                }
            }
        }
        std::string pending_error;
        const std::optional<SwitchPlan> pending =
            journal.ReadPending(&pending_error);
        ok = ok && !pending && pending_error.empty() &&
             observe_role(setup_a2) == NativeDesktopRole::Parking &&
             engine.CheckInvariant(&error);
        const bool final_control_unchanged = control_unchanged();
        ok = ok && final_control_unchanged;
        const bool restored_here = restore_and_close();
        restoration_done = true;
        restored_result = restored_here;
        ok = ok && restored_here;
        source.Stop();
        const bool lifecycle_stopped = source.shutdown_ok();
        ok = ok && lifecycle_stopped;
        bool journal_cleaned = false;
        std::error_code remove_error;
        std::error_code exists_error;
        if (!pending && pending_error.empty() && lifecycle_stopped &&
            restored_here) {
            const bool removed =
                std::filesystem::remove(journal_path, remove_error);
            if (removed) {
                journal_cleaned = true;
            } else if (!remove_error) {
                const bool exists =
                    std::filesystem::exists(journal_path, exists_error);
                journal_cleaned = !exists_error && !exists;
            }
            ok = ok && journal_cleaned;
        }
        Field("monitor B unchanged",
              final_control_unchanged ? "PASS" : "FAIL");
        Field("stable journal pending", pending ? "YES" : "no");
        Field("stable journal cleanup",
              journal_cleaned ? "PASS" : pending ? "retained (pending)"
                                                   : "FAILED");
        if (!pending_error.empty()) Field("journal error", pending_error);
        if (remove_error) {
            Field("journal cleanup error", remove_error.message());
        }
        if (exists_error) {
            Field("journal existence error", exists_error.message());
        }
        if (!error.empty()) Field("engine error", error);
        return ok ? 0 : 1;
    }();
    } catch (const std::exception& exception) {
        Field("integration error", std::format("exception: {}", exception.what()));
    } catch (...) {
        Field("integration error", "unknown exception");
    }

    const bool restored =
        restoration_done ? restored_result : restore_and_close();
    const bool blocked = integration_rc == kExitInconclusive && restored;
    const bool passed = integration_rc == 0 && restored;
    Field("probe cleanup/restoration", restored ? "PASS" : "FAIL");
    Field("mutation_started", mutation_started ? "yes" : "no");
    Field("result", passed ? "PASS" : blocked ? "ENVIRONMENT-BLOCKED"
                                             : "FAIL");
    Print("mutation_started={}\n", mutation_started ? "yes" : "no");
    Print("RESULT={}\n", passed ? "PASS" : blocked ? "ENVIRONMENT-BLOCKED"
                                                 : "FAIL");
    return passed ? 0 : (blocked ? kExitInconclusive : 1);
}

// ------------------------------------------- workspace-live-focus-restore-test

int CmdWorkspaceLiveFocusRestoreTest(bool confirm_mutate) {
    Heading("workspace-live-focus-restore-test");
    Field("scope",
          "four vdprobe-owned windows; live placement/Z-order restore on each "
          "monitor-local switch");
    Field("discovery", "complete system EnumWindows + capability augmentation");
    Field("global desktop switch", "never called");
    Field("desktop lifecycle", "no create/remove");

    auto environment_blocked = [](const std::string& reason) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", reason);
        Field("mutation_started", "no");
        Print("mutation_started=no\n");
        Print("RESULT=ENVIRONMENT-BLOCKED\n");
        return kExitInconclusive;
    };

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print("\n  Refusing the probe-owned focus-restore round-trip without "
              "--confirm-mutate.\n\n      vdprobe workspace-live-focus-restore-test "
              "--confirm-mutate\n");
        return 1;
    }

    const std::vector<MonitorRec> monitors = EnumerateMonitors();
    if (monitors.size() < 2) {
        return environment_blocked("at least two monitors are required");
    }
    const MonitorRec& monitor_a = monitors[0];
    const MonitorRec& monitor_b = monitors[1];
    const MonitorId monitor_a_id =
        reinterpret_cast<MonitorId>(monitor_a.handle);
    const MonitorId monitor_b_id =
        reinterpret_cast<MonitorId>(monitor_b.handle);
    constexpr WorkspaceId kA1 = 1;
    constexpr WorkspaceId kA2 = 2;
    constexpr WorkspaceId kB1 = 3;
    Field("monitor A", ToUtf8(monitor_a.device));
    Field("monitor B", ToUtf8(monitor_b.device));

    const std::filesystem::path journal_path =
        std::filesystem::temp_directory_path() /
        "vdprobe-workspace-live-focus-restore.journal";
    WorkspaceJournal journal(journal_path);
    std::string journal_error;
    const std::optional<SwitchPlan> existing_pending =
        journal.ReadPending(&journal_error);
    if (!journal_error.empty() || existing_pending) {
        Field("journal", journal_path.string());
        return environment_blocked(
            !journal_error.empty()
                ? "stable journal could not be read: " + journal_error
                : "stable journal contains a pending transaction");
    }
    Field("journal", journal_path.string());

    Com<IServiceProvider> sp;
    const HRESULT shell_hr = GetImmersiveShell(sp);
    if (FAILED(shell_hr) || !sp) {
        const std::string reason = std::format("ImmersiveShell unavailable ({})",
                                               HrToString(shell_hr));
        if (shell_hr == E_ACCESSDENIED) return environment_blocked(reason);
        Field("result", "ERROR");
        Field("reason", reason);
        Field("mutation_started", "no");
        return 1;
    }

    ManagerInternal manager = AcquireManagerInternal(sp.Get());
    if (!manager.obj || manager.layout == nullptr) {
        if (manager.access_denied_seen) {
            return environment_blocked(
                "usable IVirtualDesktopManagerInternal unavailable");
        }
        Field("result", "ERROR");
        Field("reason", "usable IVirtualDesktopManagerInternal unavailable");
        Field("mutation_started", "no");
        return 1;
    }
    DesktopSnapshot carrier;
    HRESULT current_hr = E_ABORT;
    if (!ReadCurrentDesktop(manager, carrier, &current_hr)) {
        if (current_hr == E_ACCESSDENIED) {
            return environment_blocked("current Carrier unavailable");
        }
        Field("result", "ERROR");
        Field("reason", "current Carrier unavailable");
        Field("mutation_started", "no");
        return 1;
    }
    std::vector<DesktopSnapshot> desktops;
    HRESULT desktops_hr = E_ABORT;
    if (!ReadDesktopList(manager, desktops, &desktops_hr)) {
        if (desktops_hr == E_ACCESSDENIED) {
            return environment_blocked("existing desktop enumeration failed");
        }
        Field("result", "ERROR");
        Field("reason", "existing desktop enumeration failed");
        Field("mutation_started", "no");
        return 1;
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.id_ok || !parking.object) {
        return environment_blocked("no existing inactive Parking desktop");
    }

    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    const MethodEntry* get_view =
        views.layout == nullptr ? nullptr
                                : FindMethod(*views.layout, "GetViewForHwnd");
    const MethodEntry* can_move =
        FindMethod(*manager.layout, "CanViewMoveDesktops");
    if (!views.object || get_view == nullptr || can_move == nullptr) {
        if (views.access_denied_seen) {
            return environment_blocked(
                "application-view capability APIs unavailable");
        }
        Field("result", "ERROR");
        Field("reason", "application-view capability APIs unavailable");
        Field("mutation_started", "no");
        return 1;
    }

    Com<IVirtualDesktopManager> documented_manager;
    const HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER,
        IID_IVirtualDesktopManager, documented_manager.PutVoid());
    if (FAILED(documented_hr) || !documented_manager) {
        const std::string reason = std::format(
            "IVirtualDesktopManager unavailable ({})", HrToString(documented_hr));
        if (documented_hr == E_ACCESSDENIED) return environment_blocked(reason);
        Field("result", "ERROR");
        Field("reason", reason);
        Field("mutation_started", "no");
        return 1;
    }

    auto acquire_view = [&](HWND hwnd, RawObject& out,
                            std::string* error = nullptr) -> bool {
        const ULONGLONG deadline = ::GetTickCount64() + 2000;
        HRESULT last_hr = E_ABORT;
        Gate last_gate = Gate::Ok;
        do {
            PumpStaMessages();
            last_gate = Gate::Ok;
            last_hr = InvokeSlot(views.object.Get(), *views.layout, *get_view,
                                 last_gate, false, hwnd, out.PutVoid());
            if (last_gate == Gate::Ok && SUCCEEDED(last_hr) && out) return true;
            ::Sleep(25);
        } while (::GetTickCount64() < deadline);
        if (error != nullptr) {
            *error = std::format("GetViewForHwnd 0x{:X} failed: gate={} hr={}",
                                 reinterpret_cast<std::uintptr_t>(hwnd),
                                 GateText(last_gate), HrToString(last_hr));
        }
        return false;
    };
    auto view_can_move = [&](IUnknown* view, std::string* error = nullptr) {
        Gate gate = Gate::Ok;
        BOOL value = FALSE;
        const HRESULT hr = InvokeSlot(manager.obj.Get(), *manager.layout,
                                      *can_move, gate, false, view, &value);
        if (gate == Gate::Ok && SUCCEEDED(hr) && value != FALSE) return true;
        if (error != nullptr) {
            *error = std::format("CanViewMoveDesktops failed: gate={} hr={}",
                                 GateText(gate), HrToString(hr));
        }
        return false;
    };

    SpawnedProbeWindow a1_top;
    SpawnedProbeWindow a1_bot;
    SpawnedProbeWindow a2;
    SpawnedProbeWindow b1;
    auto close_probes = [&]() {
        const bool b1_closed = CloseThrowawayProbeWindow(b1);
        const bool a2_closed = CloseThrowawayProbeWindow(a2);
        const bool a1_bot_closed = CloseThrowawayProbeWindow(a1_bot);
        const bool a1_top_closed = CloseThrowawayProbeWindow(a1_top);
        const bool closed = b1_closed && a2_closed && a1_bot_closed &&
                            a1_top_closed;
        Field("probe window close", closed ? "PASS" : "FAIL");
        return closed;
    };
    if (!SpawnThrowawayProbeWindow(a1_top) ||
        !SpawnThrowawayProbeWindow(a1_bot) || !SpawnThrowawayProbeWindow(a2) ||
        !SpawnThrowawayProbeWindow(b1) ||
        !PlaceProbeWindowOnMonitor(a1_top.hwnd, monitor_a, 0) ||
        !PlaceProbeWindowOnMonitor(a1_bot.hwnd, monitor_a, 1) ||
        !PlaceProbeWindowOnMonitor(a2.hwnd, monitor_a, 2) ||
        !PlaceProbeWindowOnMonitor(b1.hwnd, monitor_b, 0)) {
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not create and place four probe windows");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "no");
        return 1;
    }

    LogicalWindow logical_a1_top;
    LogicalWindow logical_a1_bot;
    LogicalWindow logical_a2;
    LogicalWindow logical_b1;
    if (!CaptureLogicalWindow(documented_manager.Get(), a1_top.hwnd,
                              monitor_a.handle, kA1, logical_a1_top) ||
        !CaptureLogicalWindow(documented_manager.Get(), a1_bot.hwnd,
                              monitor_a.handle, kA1, logical_a1_bot) ||
        !CaptureLogicalWindow(documented_manager.Get(), a2.hwnd,
                              monitor_a.handle, kA2, logical_a2) ||
        !CaptureLogicalWindow(documented_manager.Get(), b1.hwnd,
                              monitor_b.handle, kB1, logical_b1)) {
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not capture exact probe identities");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "no");
        return 1;
    }
    WindowDesktopState b1_baseline_state;
    if (!ReadWindowDesktopState(documented_manager.Get(), b1.hwnd,
                                b1_baseline_state) ||
        !WindowStateMatches(b1_baseline_state, carrier.id, true)) {
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "control probe baseline is not on Carrier");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "no");
        return 1;
    }

    const LogicalWindow* all_windows[] = {&logical_a1_top, &logical_a1_bot,
                                          &logical_a2, &logical_b1};
    auto owned_logical = [&](const WindowIdentity& identity) {
        for (const LogicalWindow* logical : all_windows) {
            if (logical != nullptr && logical->identity == identity) {
                return logical;
            }
        }
        return static_cast<const LogicalWindow*>(nullptr);
    };
    auto observe_role = [&](const WindowRecord& record) {
        const LogicalWindow* logical = owned_logical(record.identity);
        WindowIdentity current;
        if (logical == nullptr ||
            !ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity) {
            return NativeDesktopRole::Unknown;
        }
        WindowDesktopState state;
        if (!ReadWindowDesktopState(documented_manager.Get(),
                                    record.identity.hwnd, state)) {
            return NativeDesktopRole::Unknown;
        }
        if (::IsEqualGUID(state.desktop, carrier.id) && state.on_current) {
            return NativeDesktopRole::Carrier;
        }
        if (::IsEqualGUID(state.desktop, parking.id) && !state.on_current) {
            return NativeDesktopRole::Parking;
        }
        return NativeDesktopRole::Unknown;
    };
    auto move_to_role = [&](const WindowRecord& record,
                            NativeDesktopRole target) -> bool {
        const LogicalWindow* logical = owned_logical(record.identity);
        WindowIdentity current;
        if (logical == nullptr ||
            !ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity ||
            ::MonitorFromWindow(record.identity.hwnd,
                                MONITOR_DEFAULTTONULL) != logical->monitor) {
            return false;
        }
        RawObject view;
        std::string error;
        if (!acquire_view(record.identity.hwnd, view, &error) ||
            !view_can_move(view.Get(), &error)) {
            if (!error.empty()) Field("native move error", error);
            return false;
        }
        IUnknown* target_object =
            target == NativeDesktopRole::Carrier ? carrier.object.Get()
            : target == NativeDesktopRole::Parking ? parking.object.Get()
                                                    : nullptr;
        const GUID* target_id =
            target == NativeDesktopRole::Carrier ? &carrier.id
            : target == NativeDesktopRole::Parking ? &parking.id : nullptr;
        if (target_object == nullptr || target_id == nullptr) return false;
        Gate gate = Gate::Ok;
        HRESULT hr = E_ABORT;
        const bool moved = MoveViewToDesktopAndWait(
            manager, view.Get(), target_object, record.identity.hwnd,
            documented_manager.Get(), *target_id, carrier.id, confirm_mutate,
            gate, hr);
        Field(std::format("move 0x{:X} -> {}",
                          reinterpret_cast<std::uintptr_t>(record.identity.hwnd),
                          NativeDesktopRoleText(target)),
              moved ? "verified" : "FAILED");
        return moved;
    };

    bool mutation_started = false;
    WindowRecord setup_a2{};
    setup_a2.identity = logical_a2.identity;
    setup_a2.monitor = monitor_a_id;
    setup_a2.workspace = kA2;
    setup_a2.native_role = NativeDesktopRole::Carrier;
    setup_a2.capabilities = {true, true, true, true, true};
    mutation_started = true;
    if (!move_to_role(setup_a2, NativeDesktopRole::Parking)) {
        const bool setup_restored =
            observe_role(setup_a2) == NativeDesktopRole::Carrier ||
            move_to_role(setup_a2, NativeDesktopRole::Carrier);
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not establish A2 on Parking");
        Field("setup restoration",
              setup_restored ? "PASS" : "FAILED (probe destroyed)");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "yes");
        return 1;
    }

    auto restore_and_close = [&]() {
        bool restored = true;
        for (const LogicalWindow* logical : all_windows) {
            if (logical == nullptr) continue;
            WindowRecord record{};
            record.identity = logical->identity;
            record.monitor = reinterpret_cast<MonitorId>(logical->monitor);
            record.workspace = logical->workspace;
            record.capabilities = {true, true, true, true, true};
            const NativeDesktopRole role = observe_role(record);
            if (role != NativeDesktopRole::Carrier &&
                !move_to_role(record, NativeDesktopRole::Carrier)) {
                restored = false;
            }
        }
        return restored && close_probes();
    };

    bool restoration_done = false;
    bool restored_result = true;
    int integration_rc = 1;
    try {
    integration_rc = [&]() -> int {
        bool capability_access_denied = false;
        Win32WindowDiscoveryOptions options;
        options.carrier = carrier.id;
        options.parking = parking.id;
        options.augment_capabilities =
            [&](HWND hwnd, const WindowDiscoveryObservation& observation,
                WindowCapabilities& capabilities, std::string* error) {
                const LogicalWindow* logical = owned_logical(observation.identity);
                if (logical == nullptr) return true;
                if (hwnd != logical->identity.hwnd ||
                    ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL) !=
                        logical->monitor) {
                    if (error != nullptr) {
                        *error = "owned probe identity or monitor changed";
                    }
                    return false;
                }
                RawObject view;
                if (!acquire_view(hwnd, view, error)) return false;
                capabilities.has_application_view = true;
                Gate gate = Gate::Ok;
                BOOL value = FALSE;
                const HRESULT hr = InvokeSlot(
                    manager.obj.Get(), *manager.layout, *can_move, gate, false,
                    view.Get(), &value);
                if (hr == E_ACCESSDENIED) capability_access_denied = true;
                if (gate != Gate::Ok || FAILED(hr)) {
                    if (error != nullptr) {
                        *error = std::format(
                            "CanViewMoveDesktops failed: gate={} hr={}",
                            GateText(gate), HrToString(hr));
                    }
                    return false;
                }
                capabilities.can_move_desktops = value != FALSE;
                return true;
            };

        std::string error;
        HRESULT backend_hr = S_OK;
        auto backend = CreateSystemWindowDiscoveryBackend(
            std::move(options), &error, &backend_hr);
        if (!backend) {
            Field("integration error", error);
            return backend_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
        }
        WindowDiscovery discovery(std::move(*backend));

        WorkspaceEngine engine(carrier.id, parking.id);
        if (!engine.AddMonitor(monitor_a_id, kA1, {kA1, kA2}, &error) ||
            !engine.AddMonitor(monitor_b_id, kB1, {kB1}, &error)) {
            Field("integration error", error);
            return 1;
        }
        WorkspaceAssignmentAdapter assignment(engine);
        if (!assignment.ConfigureMonitor(monitor_a_id, kA1, {kA1, kA2},
                                         &error) ||
            !assignment.ConfigureMonitor(monitor_b_id, kB1, {kB1}, &error)) {
            Field("assignment error", error);
            return 1;
        }

        std::vector<DiscoveredWindow> initial;
        if (!discovery.Discover(initial, &error)) {
            Field("discovery error", error);
            return capability_access_denied ? kExitInconclusive : 1;
        }
        const struct {
            const LogicalWindow* logical;
            NativeDesktopRole expected;
        } expectations[] = {
            {&logical_a1_top, NativeDesktopRole::Carrier},
            {&logical_a1_bot, NativeDesktopRole::Carrier},
            {&logical_a2, NativeDesktopRole::Parking},
            {&logical_b1, NativeDesktopRole::Carrier},
        };
        for (const auto& expectation : expectations) {
            const auto found = std::find_if(
                initial.begin(), initial.end(),
                [&](const DiscoveredWindow& item) {
                    return item.identity == expectation.logical->identity;
                });
            if (found == initial.end() ||
                found->disposition != WindowDisposition::Managed ||
                found->native_role != expectation.expected ||
                !found->capabilities.Manageable()) {
                Field("integration error",
                      "system discovery did not prove all owned probes");
                return 1;
            }
            WindowRecord record{};
            record.identity = found->identity;
            record.monitor = reinterpret_cast<MonitorId>(found->monitor);
            record.workspace = expectation.logical->workspace;
            record.native_role = found->native_role;
            record.capabilities = found->capabilities;
            record.presentation = found->presentation;
            record.disposition = WindowDisposition::Managed;
            record.present = true;
            if (engine.UpsertWindow(std::move(record), &error) !=
                UpsertResult::Added) {
                Field("assignment error", error);
                return 1;
            }
        }
        if (!engine.CheckInvariant(&error)) {
            Field("integration error", error);
            return 1;
        }

        // Per-workspace focus snapshot from the authoritative live discovery.
        // Probe-owned policy: the explicitly placed windows define the
        // workspace Z-order, and each workspace's single foreground target is
        // confirmation-gated to a probe-owned window.
        if (!engine.SetZOrder(monitor_a_id, kA1,
                              {logical_a1_top.identity,
                               logical_a1_bot.identity},
                              &error) ||
            !engine.SetLastForeground(monitor_a_id, kA1,
                                      logical_a1_top.identity, &error) ||
            !engine.SetZOrder(monitor_a_id, kA2, {logical_a2.identity},
                              &error) ||
            !engine.SetLastForeground(monitor_a_id, kA2,
                                      logical_a2.identity, &error) ||
            !engine.SetZOrder(monitor_b_id, kB1, {logical_b1.identity},
                              &error) ||
            !engine.SetLastForeground(monitor_b_id, kB1,
                                      logical_b1.identity, &error)) {
            Field("integration error", error);
            return 1;
        }

        auto discover_assigned = [&](std::vector<WindowRecord>& records,
                                     std::string* local_error) {
            std::vector<DiscoveredWindow> complete;
            if (!discovery.Discover(complete, local_error) ||
                !assignment.ConvertCompleteSnapshot(complete, records,
                                                    local_error)) {
                return false;
            }
            if (records.size() != std::size(all_windows) ||
                std::any_of(records.begin(), records.end(),
                            [&](const WindowRecord& record) {
                                return owned_logical(record.identity) == nullptr;
                            })) {
                if (local_error != nullptr) {
                    *local_error =
                        "assigned snapshot escaped the probe ownership boundary";
                }
                return false;
            }
            return true;
        };
        auto observe_owned = [&](HWND hwnd) -> std::optional<WindowRecord> {
            std::vector<WindowRecord> records;
            std::string local_error;
            if (!discover_assigned(records, &local_error)) return std::nullopt;
            const auto found = std::find_if(
                records.begin(), records.end(),
                [hwnd](const WindowRecord& record) {
                    return record.identity.hwnd == hwnd;
                });
            return found == records.end() ? std::nullopt
                                          : std::optional<WindowRecord>(*found);
        };

        WindowLifecycleAdapter lifecycle(engine, observe_owned);
        WinEventLifecycleSource source;
        if (!source.Start(&error)) {
            Field("lifecycle error", error);
            return 1;
        }
        auto coordinator_discovery = [&](std::vector<WindowRecord>& records,
                                         std::string* local_error) {
            if (!source.PumpOwnerThreadMessages(local_error)) return false;
            return discover_assigned(records, local_error);
        };
        WorkspaceCoordinator coordinator(
            engine, lifecycle, source, coordinator_discovery, move_to_role,
            observe_role, &journal, 10, 5);

        auto control_unchanged = [&]() {
            WindowIdentity identity;
            WindowDesktopState state;
            RECT rect{};
            GUID current{};
            return ReadWindowIdentity(logical_b1.identity.hwnd, identity) &&
                   identity == logical_b1.identity &&
                   ::MonitorFromWindow(logical_b1.identity.hwnd,
                                       MONITOR_DEFAULTTONULL) ==
                       monitor_b.handle &&
                   ::GetWindowRect(logical_b1.identity.hwnd, &rect) &&
                   SameRect(rect, logical_b1.rect) &&
                   ReadWindowDesktopState(documented_manager.Get(),
                                          logical_b1.identity.hwnd, state) &&
                   WindowStateMatches(state, carrier.id, true) &&
                   state.visible == b1_baseline_state.visible &&
                   state.cloaked == b1_baseline_state.cloaked &&
                   ReadCurrentDesktopId(manager, current) &&
                   ::IsEqualGUID(current, carrier.id);
        };
        auto probe_identity_is_current = [&](const WindowRecord& record) {
            const LogicalWindow* logical = owned_logical(record.identity);
            WindowIdentity current;
            RawObject view;
            return logical != nullptr &&
                   record.capabilities.Manageable() &&
                   record.capabilities.owner_state_observable &&
                   ReadWindowIdentity(record.identity.hwnd, current) &&
                   current == record.identity &&
                   ::MonitorFromWindow(record.identity.hwnd,
                                       MONITOR_DEFAULTTONULL) ==
                       logical->monitor &&
                   acquire_view(record.identity.hwnd, view) &&
                   view_can_move(view.Get());
        };
        auto apply_live_presentation =
            [&](const WindowRecord& record,
                const PresentationOperation& operation) -> bool {
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
                    return ::SetWindowPos(
                               record.identity.hwnd, HWND_TOP, 0, 0, 0, 0,
                               SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE |
                                   SWP_NOOWNERZORDER) != FALSE;
                case PresentationOperationKind::RestoreForeground:
                    return ::SetForegroundWindow(record.identity.hwnd) != FALSE;
            }
            return false;
        };
        auto verify_placement = [&](const LogicalWindow& logical) {
            RECT rect{};
            return ::GetWindowRect(logical.identity.hwnd, &rect) &&
                   SameRect(rect, logical.rect);
        };
        auto probe_above = [](HWND above, HWND below) {
            HWND current = ::GetWindow(above, GW_HWNDNEXT);
            while (current != nullptr) {
                if (current == below) return true;
                current = ::GetWindow(current, GW_HWNDNEXT);
            }
            return false;
        };
        auto run_restore = [&](WorkspaceId workspace,
                               const std::vector<const LogicalWindow*>& members)
            -> std::pair<bool, std::size_t> {
            std::string restore_error;
            const std::optional<PresentationPlan> plan =
                engine.PreparePresentationRestore(monitor_a_id, workspace,
                                                  &restore_error);
            if (!plan) {
                Field("  restore plan error", restore_error);
                return {false, 0};
            }
            const PresentationResult result =
                engine.ExecutePresentationRestore(
                    *plan, probe_identity_is_current, apply_live_presentation);
            Field("  presentation operations",
                  std::format("{}/{}", result.applied, plan->operations.size()));
            Field("  foreground best-effort failures",
                  std::format("{}", result.best_effort_failed));
            if (!result.error.empty()) {
                Field("  presentation execution error", result.error);
            }
            bool ok = result.completed;
            for (const LogicalWindow* member : members) {
                if (member == nullptr) continue;
                ok = ok && verify_placement(*member);
            }
            return {ok, result.best_effort_failed};
        };

        auto switch_gate = [&](WorkspaceId target,
                               CoordinatorResult& result) {
            result = coordinator.Switch(monitor_a_id, target);
            if (!result.succeeded() &&
                result.transaction.rollback_succeeded &&
                !result.transaction.recovery_required &&
                result.code != CoordinatorResultCode::PlanRejected) {
                // A clean rollback caused by transient unrelated-window
                // lifecycle noise is retried once with a fresh snapshot.
                Field("  transient noise; retrying switch", "");
                result = coordinator.Switch(monitor_a_id, target);
            }
            return result.succeeded() && result.transaction.committed;
        };
        auto wait_quiet = [&]() {
            // Drain the lifecycle stream left behind by presentation restore
            // (placement/Z-order operations emit window-object events) before
            // the next switch, bounded so persistent noise still fails.
            for (int attempt = 0; attempt < 20; ++attempt) {
                const CoordinatorResult result =
                    coordinator.ReconcileDiscovery();
                if (result.succeeded()) return true;
                PumpStaMessages();
                ::Sleep(100);
            }
            return false;
        };
        bool ok = false;
        constexpr int kMaxRoundTripAttempts = 3;
        for (int attempt = 1; attempt <= kMaxRoundTripAttempts && !ok;
             ++attempt) {
            ok = true;
            const CoordinatorResult reconciled =
                coordinator.ReconcileDiscovery();
            Field(std::format("initial reconcile (attempt {}/{})", attempt,
                              kMaxRoundTripAttempts)
                      .c_str(),
                  reconciled.succeeded() ? "PASS" : "FAIL");
            ok = reconciled.succeeded() && control_unchanged();

            const WorkspaceId active_now =
                engine.Monitor(monitor_a_id)->active;
            const WorkspaceId first_target =
                active_now == kA1 ? kA2 : kA1;
            const WorkspaceId second_target = active_now;
            CoordinatorResult forward;
            CoordinatorResult reverse;
            const std::vector<const LogicalWindow*> first_members =
                first_target == kA2
                    ? std::vector<const LogicalWindow*>{&logical_a2}
                    : std::vector<const LogicalWindow*>{&logical_a1_top,
                                                        &logical_a1_bot};
            const std::vector<const LogicalWindow*> second_members =
                second_target == kA2
                    ? std::vector<const LogicalWindow*>{&logical_a2}
                    : std::vector<const LogicalWindow*>{&logical_a1_top,
                                                        &logical_a1_bot};
            if (ok) {
                const bool switched = switch_gate(first_target, forward);
                Field(std::format("switch -> {} (attempt {}/{})",
                                  first_target, attempt,
                                  kMaxRoundTripAttempts)
                          .c_str(),
                      switched ? "PASS" : "FAIL");
                ok = switched &&
                     engine.Monitor(monitor_a_id)->active == first_target &&
                     engine.Monitor(monitor_b_id)->active == kB1 &&
                     control_unchanged();
            }
            if (ok) {
                const auto [restored, foreground_failed] =
                    run_restore(first_target, first_members);
                Field("first placement/Z-order restore",
                      restored ? "PASS" : "FAIL");
                ok = restored;
                WindowDesktopState target_state;
                ok = ok &&
                     ReadWindowDesktopState(documented_manager.Get(),
                                            first_members.front()->identity.hwnd,
                                            target_state) &&
                     WindowStateMatches(target_state, carrier.id, true);
                Field("first workspace remains Carrier after restore",
                      ok ? "PASS" : "FAIL");
                (void)foreground_failed;
                ok = ok && wait_quiet();
            }
            if (ok) {
                const bool switched = switch_gate(second_target, reverse);
                Field(std::format("switch -> {} (attempt {}/{})",
                                  second_target, attempt,
                                  kMaxRoundTripAttempts)
                          .c_str(),
                      switched ? "PASS" : "FAIL");
                ok = switched &&
                     engine.Monitor(monitor_a_id)->active == second_target &&
                     engine.Monitor(monitor_b_id)->active == kB1 &&
                     control_unchanged();
            }
            if (ok) {
                const auto [restored, foreground_failed] =
                    run_restore(second_target, second_members);
                Field("second placement/Z-order restore",
                      restored ? "PASS" : "FAIL");
                ok = restored;
                if (second_target == kA1) {
                    ok = ok && probe_above(logical_a1_top.identity.hwnd,
                                           logical_a1_bot.identity.hwnd);
                    Field("A1 top above A1 bottom after restore",
                          ok ? "PASS" : "FAIL");
                }
                WindowDesktopState second_state;
                ok = ok &&
                     ReadWindowDesktopState(documented_manager.Get(),
                                            second_members.front()->identity.hwnd,
                                            second_state) &&
                     WindowStateMatches(second_state, carrier.id, true);
                Field("second workspace remains Carrier after restore",
                      ok ? "PASS" : "FAIL");
                (void)foreground_failed;
            }
            if (!ok && attempt < kMaxRoundTripAttempts) {
                Field("  transient noise; retrying round-trip", "");
                (void)coordinator.ReconcileDiscovery();
            }
        }
        std::string pending_error;
        const std::optional<SwitchPlan> pending =
            journal.ReadPending(&pending_error);
        ok = ok && !pending && pending_error.empty() &&
             engine.CheckInvariant(&error);
        const bool final_control_unchanged = control_unchanged();
        ok = ok && final_control_unchanged;
        const bool restored_here = restore_and_close();
        restoration_done = true;
        restored_result = restored_here;
        ok = ok && restored_here;
        source.Stop();
        const bool lifecycle_stopped = source.shutdown_ok();
        ok = ok && lifecycle_stopped;
        bool journal_cleaned = false;
        std::error_code remove_error;
        std::error_code exists_error;
        if (!pending && pending_error.empty() && lifecycle_stopped &&
            restored_here) {
            const bool removed =
                std::filesystem::remove(journal_path, remove_error);
            if (removed) {
                journal_cleaned = true;
            } else if (!remove_error) {
                const bool exists =
                    std::filesystem::exists(journal_path, exists_error);
                journal_cleaned = !exists_error && !exists;
            }
            ok = ok && journal_cleaned;
        }
        Field("monitor B unchanged",
              final_control_unchanged ? "PASS" : "FAIL");
        Field("stable journal pending", pending ? "YES" : "no");
        Field("stable journal cleanup",
              journal_cleaned ? "PASS" : pending ? "retained (pending)"
                                                   : "FAILED");
        if (!pending_error.empty()) Field("journal error", pending_error);
        if (remove_error) {
            Field("journal cleanup error", remove_error.message());
        }
        if (exists_error) {
            Field("journal existence error", exists_error.message());
        }
        if (!error.empty()) Field("engine error", error);
        return ok ? 0 : 1;
    }();
    } catch (const std::exception& exception) {
        Field("integration error", std::format("exception: {}", exception.what()));
    } catch (...) {
        Field("integration error", "unknown exception");
    }

    const bool restored =
        restoration_done ? restored_result : restore_and_close();
    const bool blocked = integration_rc == kExitInconclusive && restored;
    const bool passed = integration_rc == 0 && restored;
    Field("probe cleanup/restoration", restored ? "PASS" : "FAIL");
    Field("mutation_started", mutation_started ? "yes" : "no");
    Field("result", passed ? "PASS" : blocked ? "ENVIRONMENT-BLOCKED"
                                              : "FAIL");
    Print("mutation_started={}\n", mutation_started ? "yes" : "no");
    Print("RESULT={}\n", passed ? "PASS" : blocked ? "ENVIRONMENT-BLOCKED"
                                                  : "FAIL");
    return passed ? 0 : (blocked ? kExitInconclusive : 1);
}

// ------------------------------------------------------------ workspace-manager

namespace {

struct ManagerHotkeyContext {
    std::function<bool(UINT modifiers, UINT vk)> handler;
    UINT next_hotkey_id = 1;
    std::vector<std::pair<UINT, WorkspaceHotkey>> registered;
};

LRESULT CALLBACK ManagerHotkeyWindowProc(HWND hwnd, UINT message,
                                         WPARAM wparam, LPARAM lparam) {
    if (message == WM_HOTKEY) {
        ManagerHotkeyContext* context = reinterpret_cast<ManagerHotkeyContext*>(
            ::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (context != nullptr && context->handler) {
            context->handler(LOWORD(lparam), HIWORD(lparam));
        }
        return 0;
    }
    return ::DefWindowProcW(hwnd, message, wparam, lparam);
}

bool EnsureManagerHotkeyClass() {
    static constexpr wchar_t kClassName[] = L"vdprobe.WorkspaceManagerHotkeys";
    static bool registered = false;
    if (registered) return true;
    WNDCLASSEXW klass{};
    klass.cbSize = sizeof(klass);
    klass.hInstance = ::GetModuleHandleW(nullptr);
    klass.lpfnWndProc = &ManagerHotkeyWindowProc;
    klass.lpszClassName = kClassName;
    if (::RegisterClassExW(&klass) == 0 &&
        ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }
    registered = true;
    return true;
}

}  // namespace

int CmdWorkspaceManager(bool confirm_mutate, const char* config_path) {
    Heading("workspace-manager");
    Field("scope", "hotkey-driven probe-owned workspace switches (self-test)");
    Field("discovery", "complete system EnumWindows + capability augmentation");
    Field("global desktop switch", "never called");
    Field("desktop lifecycle", "no create/remove");

    auto environment_blocked = [](const std::string& reason) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", reason);
        Field("mutation_started", "no");
        Print("mutation_started=no\n");
        Print("RESULT=ENVIRONMENT-BLOCKED\n");
        return kExitInconclusive;
    };

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print("\n  Refusing the workspace-manager self-test without "
              "--confirm-mutate.\n\n      vdprobe workspace-manager "
              "--confirm-mutate\n");
        return 1;
    }

    const std::vector<MonitorRec> monitors = EnumerateMonitors();
    if (monitors.size() < 2) {
        return environment_blocked("at least two monitors are required");
    }
    const MonitorRec& monitor_a = monitors[0];
    const MonitorRec& monitor_b = monitors[1];
    const MonitorId monitor_a_id =
        reinterpret_cast<MonitorId>(monitor_a.handle);
    const MonitorId monitor_b_id =
        reinterpret_cast<MonitorId>(monitor_b.handle);
    WorkspaceId kA1 = 1;
    WorkspaceId kA2 = 2;
    WorkspaceId kB1 = 3;
    std::vector<WorkspaceId> monitor_a_workspaces{kA1, kA2};
    std::vector<WorkspaceId> monitor_b_workspaces{kB1};
    Field("monitor A", ToUtf8(monitor_a.device));
    Field("monitor B", ToUtf8(monitor_b.device));

    const std::filesystem::path journal_path =
        std::filesystem::temp_directory_path() /
        "vdprobe-workspace-manager.journal";
    WorkspaceJournal journal(journal_path);
    std::string journal_error;
    const std::optional<SwitchPlan> existing_pending =
        journal.ReadPending(&journal_error);
    if (!journal_error.empty() || existing_pending) {
        Field("journal", journal_path.string());
        return environment_blocked(
            !journal_error.empty()
                ? "stable journal could not be read: " + journal_error
                : "stable journal contains a pending transaction");
    }
    Field("journal", journal_path.string());

    WorkspaceManagerConfig hotkey_config;
    hotkey_config.journal_path = journal_path;
    hotkey_config.tray_icon = true;
    const WorkspaceHotkey* target_hotkey = nullptr;
    const WorkspaceHotkey* active_hotkey = nullptr;
    if (config_path != nullptr && *config_path != '\0') {
        std::string config_error;
        if (!LoadManagerConfig(std::filesystem::path(config_path),
                               hotkey_config, &config_error)) {
            Field("result", "ERROR");
            Field("reason", "config load failed: " + config_error);
            Field("mutation_started", "no");
            return 1;
        }
        Field("config", config_path);
        std::vector<HMONITOR> real_monitors;
        for (const MonitorRec& monitor : monitors) {
            real_monitors.push_back(monitor.handle);
        }
        ManagerRuntimeTopology topology;
        if (!DeriveManagerRuntimeTopology(hotkey_config, real_monitors,
                                          topology, &config_error)) {
            Field("result", "ERROR");
            Field("reason", "config topology failed: " + config_error);
            Field("mutation_started", "no");
            return 1;
        }
        if (topology.monitors.size() < 2 ||
            topology.monitors[0].workspace_count < 2) {
            Field("result", "ERROR");
            Field("reason", "config must define at least two monitors and two "
                            "workspaces on monitor 1");
            Field("mutation_started", "no");
            return 1;
        }
        kA1 = topology.monitors[0].active;
        kB1 = topology.monitors[1].active;
        monitor_a_workspaces = topology.monitors[0].workspace_ids;
        monitor_b_workspaces = topology.monitors[1].workspace_ids;
        kA2 = monitor_a_workspaces.size() > 1 ? monitor_a_workspaces[1] : kA1;
        hotkey_config.bindings = topology.bindings;
        for (const WorkspaceHotkeyBinding& binding : hotkey_config.bindings) {
            if (binding.monitor != monitor_a_id) continue;
            if (binding.workspace == kA2) target_hotkey = &binding.hotkey;
            if (binding.workspace == kA1) active_hotkey = &binding.hotkey;
        }
        if (target_hotkey == nullptr || active_hotkey == nullptr) {
            Field("result", "ERROR");
            Field("reason", "config must bind hotkeys to monitor 1's target "
                            "workspace and active workspace");
            Field("mutation_started", "no");
            return 1;
        }
        Field("config bindings",
              std::format("{}", hotkey_config.bindings.size()));
    } else {
        hotkey_config.bindings = {
            {{MOD_CONTROL | MOD_ALT, VK_F9}, monitor_a_id, 2},
            {{MOD_CONTROL | MOD_ALT, VK_F10}, monitor_a_id, 1},
        };
        target_hotkey = &hotkey_config.bindings[0].hotkey;
        active_hotkey = &hotkey_config.bindings[1].hotkey;
        Field("hotkey Ctrl+Alt+F9", "monitor A -> A2");
        Field("hotkey Ctrl+Alt+F10", "monitor A -> A1");
    }

    Com<IServiceProvider> sp;
    const HRESULT shell_hr = GetImmersiveShell(sp);
    if (FAILED(shell_hr) || !sp) {
        const std::string reason = std::format("ImmersiveShell unavailable ({})",
                                               HrToString(shell_hr));
        if (shell_hr == E_ACCESSDENIED) return environment_blocked(reason);
        Field("result", "ERROR");
        Field("reason", reason);
        Field("mutation_started", "no");
        return 1;
    }

    ManagerInternal manager = AcquireManagerInternal(sp.Get());
    if (!manager.obj || manager.layout == nullptr) {
        if (manager.access_denied_seen) {
            return environment_blocked(
                "usable IVirtualDesktopManagerInternal unavailable");
        }
        Field("result", "ERROR");
        Field("reason", "usable IVirtualDesktopManagerInternal unavailable");
        Field("mutation_started", "no");
        return 1;
    }
    DesktopSnapshot carrier;
    HRESULT current_hr = E_ABORT;
    if (!ReadCurrentDesktop(manager, carrier, &current_hr)) {
        if (current_hr == E_ACCESSDENIED) {
            return environment_blocked("current Carrier unavailable");
        }
        Field("result", "ERROR");
        Field("reason", "current Carrier unavailable");
        Field("mutation_started", "no");
        return 1;
    }
    std::vector<DesktopSnapshot> desktops;
    HRESULT desktops_hr = E_ABORT;
    if (!ReadDesktopList(manager, desktops, &desktops_hr)) {
        if (desktops_hr == E_ACCESSDENIED) {
            return environment_blocked("existing desktop enumeration failed");
        }
        Field("result", "ERROR");
        Field("reason", "existing desktop enumeration failed");
        Field("mutation_started", "no");
        return 1;
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.id_ok || !parking.object) {
        return environment_blocked("no existing inactive Parking desktop");
    }

    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    const MethodEntry* get_view =
        views.layout == nullptr ? nullptr
                                : FindMethod(*views.layout, "GetViewForHwnd");
    const MethodEntry* can_move =
        FindMethod(*manager.layout, "CanViewMoveDesktops");
    if (!views.object || get_view == nullptr || can_move == nullptr) {
        if (views.access_denied_seen) {
            return environment_blocked(
                "application-view capability APIs unavailable");
        }
        Field("result", "ERROR");
        Field("reason", "application-view capability APIs unavailable");
        Field("mutation_started", "no");
        return 1;
    }

    Com<IVirtualDesktopManager> documented_manager;
    const HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER,
        IID_IVirtualDesktopManager, documented_manager.PutVoid());
    if (FAILED(documented_hr) || !documented_manager) {
        const std::string reason = std::format(
            "IVirtualDesktopManager unavailable ({})", HrToString(documented_hr));
        if (documented_hr == E_ACCESSDENIED) return environment_blocked(reason);
        Field("result", "ERROR");
        Field("reason", reason);
        Field("mutation_started", "no");
        return 1;
    }

    struct PendingDispatch {
        MonitorId monitor = 0;
        WorkspaceId workspace = 0;
    };
    std::vector<PendingDispatch> hotkey_requests;
    ManagerHotkeyContext hotkey_context;
    HWND hotkey_window = nullptr;
    NOTIFYICONDATAW tray_data{};
    bool tray_added = false;
    auto cleanup_hotkeys = [&]() {
        for (const auto& entry : hotkey_context.registered) {
            ::UnregisterHotKey(hotkey_window, entry.first);
        }
        hotkey_context.registered.clear();
        if (tray_added) {
            ::Shell_NotifyIconW(NIM_DELETE, &tray_data);
            tray_added = false;
        }
        if (hotkey_window != nullptr) {
            ::DestroyWindow(hotkey_window);
            hotkey_window = nullptr;
        }
    };
    if (!EnsureManagerHotkeyClass()) {
        Field("result", "ERROR");
        Field("reason", "hotkey window class unavailable");
        Field("mutation_started", "no");
        return 1;
    }
    hotkey_window = ::CreateWindowExW(
        0, L"vdprobe.WorkspaceManagerHotkeys", L"vdprobe-manager", 0, 0, 0, 0,
        0, HWND_MESSAGE, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    if (hotkey_window == nullptr) {
        Field("result", "ERROR");
        Field("reason", "hotkey message window unavailable");
        Field("mutation_started", "no");
        return 1;
    }
    ::SetWindowLongPtrW(hotkey_window, GWLP_USERDATA,
                        reinterpret_cast<LONG_PTR>(&hotkey_context));
    hotkey_context.handler = [&](UINT modifiers, UINT vk) {
        MonitorId monitor = 0;
        WorkspaceId workspace = 0;
        if (ResolveWorkspaceHotkey(hotkey_config, modifiers, vk, monitor,
                                   workspace)) {
            hotkey_requests.push_back({monitor, workspace});
        }
        return true;
    };
    for (const WorkspaceHotkeyBinding& binding : hotkey_config.bindings) {
        const UINT id = hotkey_context.next_hotkey_id++;
        if (!::RegisterHotKey(hotkey_window, id,
                              binding.hotkey.modifiers | MOD_NOREPEAT,
                              binding.hotkey.vk)) {
            cleanup_hotkeys();
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "hotkey registration failed (already bound?)");
            Field("mutation_started", "no");
            Print("mutation_started=no\n");
            Print("RESULT=ENVIRONMENT-BLOCKED\n");
            return kExitInconclusive;
        }
        hotkey_context.registered.emplace_back(id, binding.hotkey);
    }
    if (hotkey_config.tray_icon) {
        tray_data = {};
        tray_data.cbSize = sizeof(tray_data);
        tray_data.hWnd = hotkey_window;
        tray_data.uID = 1;
        tray_data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        tray_data.uCallbackMessage = WM_APP + 1;
        tray_data.hIcon = ::LoadIconW(nullptr, IDI_APPLICATION);
        wcscpy_s(tray_data.szTip, L"vdprobe workspace manager");
        tray_added = ::Shell_NotifyIconW(NIM_ADD, &tray_data) != FALSE;
    }
    Field("tray icon", tray_added ? "added" : "unavailable (recorded)");

    auto acquire_view = [&](HWND hwnd, RawObject& out,
                            std::string* error = nullptr) -> bool {
        const ULONGLONG deadline = ::GetTickCount64() + 2000;
        HRESULT last_hr = E_ABORT;
        Gate last_gate = Gate::Ok;
        do {
            PumpStaMessages();
            last_gate = Gate::Ok;
            last_hr = InvokeSlot(views.object.Get(), *views.layout, *get_view,
                                 last_gate, false, hwnd, out.PutVoid());
            if (last_gate == Gate::Ok && SUCCEEDED(last_hr) && out) return true;
            ::Sleep(25);
        } while (::GetTickCount64() < deadline);
        if (error != nullptr) {
            *error = std::format("GetViewForHwnd 0x{:X} failed: gate={} hr={}",
                                 reinterpret_cast<std::uintptr_t>(hwnd),
                                 GateText(last_gate), HrToString(last_hr));
        }
        return false;
    };
    auto view_can_move = [&](IUnknown* view, std::string* error = nullptr) {
        Gate gate = Gate::Ok;
        BOOL value = FALSE;
        const HRESULT hr = InvokeSlot(manager.obj.Get(), *manager.layout,
                                      *can_move, gate, false, view, &value);
        if (gate == Gate::Ok && SUCCEEDED(hr) && value != FALSE) return true;
        if (error != nullptr) {
            *error = std::format("CanViewMoveDesktops failed: gate={} hr={}",
                                 GateText(gate), HrToString(hr));
        }
        return false;
    };

    SpawnedProbeWindow a1;
    SpawnedProbeWindow a2;
    SpawnedProbeWindow b1;
    auto close_probes = [&]() {
        const bool b1_closed = CloseThrowawayProbeWindow(b1);
        const bool a2_closed = CloseThrowawayProbeWindow(a2);
        const bool a1_closed = CloseThrowawayProbeWindow(a1);
        const bool closed = b1_closed && a2_closed && a1_closed;
        Field("probe window close", closed ? "PASS" : "FAIL");
        return closed;
    };
    if (!SpawnThrowawayProbeWindow(a1) || !SpawnThrowawayProbeWindow(a2) ||
        !SpawnThrowawayProbeWindow(b1) ||
        !PlaceProbeWindowOnMonitor(a1.hwnd, monitor_a, 0) ||
        !PlaceProbeWindowOnMonitor(a2.hwnd, monitor_a, 1) ||
        !PlaceProbeWindowOnMonitor(b1.hwnd, monitor_b, 0)) {
        cleanup_hotkeys();
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not create and place three probe windows");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "no");
        return 1;
    }

    LogicalWindow logical_a1;
    LogicalWindow logical_a2;
    LogicalWindow logical_b1;
    if (!CaptureLogicalWindow(documented_manager.Get(), a1.hwnd,
                              monitor_a.handle, kA1, logical_a1) ||
        !CaptureLogicalWindow(documented_manager.Get(), a2.hwnd,
                              monitor_a.handle, kA2, logical_a2) ||
        !CaptureLogicalWindow(documented_manager.Get(), b1.hwnd,
                              monitor_b.handle, kB1, logical_b1)) {
        cleanup_hotkeys();
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not capture exact probe identities");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "no");
        return 1;
    }
    WindowDesktopState b1_baseline_state;
    if (!ReadWindowDesktopState(documented_manager.Get(), b1.hwnd,
                                b1_baseline_state) ||
        !WindowStateMatches(b1_baseline_state, carrier.id, true)) {
        cleanup_hotkeys();
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "control probe baseline is not on Carrier");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "no");
        return 1;
    }

    const LogicalWindow* all_windows[] = {&logical_a1, &logical_a2,
                                          &logical_b1};
    auto owned_logical = [&](const WindowIdentity& identity) {
        for (const LogicalWindow* logical : all_windows) {
            if (logical != nullptr && logical->identity == identity) {
                return logical;
            }
        }
        return static_cast<const LogicalWindow*>(nullptr);
    };
    auto observe_role = [&](const WindowRecord& record) {
        const LogicalWindow* logical = owned_logical(record.identity);
        WindowIdentity current;
        if (logical == nullptr ||
            !ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity) {
            return NativeDesktopRole::Unknown;
        }
        WindowDesktopState state;
        if (!ReadWindowDesktopState(documented_manager.Get(),
                                    record.identity.hwnd, state)) {
            return NativeDesktopRole::Unknown;
        }
        if (::IsEqualGUID(state.desktop, carrier.id) && state.on_current) {
            return NativeDesktopRole::Carrier;
        }
        if (::IsEqualGUID(state.desktop, parking.id) && !state.on_current) {
            return NativeDesktopRole::Parking;
        }
        return NativeDesktopRole::Unknown;
    };
    auto move_to_role = [&](const WindowRecord& record,
                            NativeDesktopRole target) -> bool {
        const LogicalWindow* logical = owned_logical(record.identity);
        WindowIdentity current;
        if (logical == nullptr ||
            !ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity ||
            ::MonitorFromWindow(record.identity.hwnd,
                                MONITOR_DEFAULTTONULL) != logical->monitor) {
            return false;
        }
        RawObject view;
        std::string error;
        if (!acquire_view(record.identity.hwnd, view, &error) ||
            !view_can_move(view.Get(), &error)) {
            if (!error.empty()) Field("native move error", error);
            return false;
        }
        IUnknown* target_object =
            target == NativeDesktopRole::Carrier ? carrier.object.Get()
            : target == NativeDesktopRole::Parking ? parking.object.Get()
                                                    : nullptr;
        const GUID* target_id =
            target == NativeDesktopRole::Carrier ? &carrier.id
            : target == NativeDesktopRole::Parking ? &parking.id : nullptr;
        if (target_object == nullptr || target_id == nullptr) return false;
        Gate gate = Gate::Ok;
        HRESULT hr = E_ABORT;
        const bool moved = MoveViewToDesktopAndWait(
            manager, view.Get(), target_object, record.identity.hwnd,
            documented_manager.Get(), *target_id, carrier.id, confirm_mutate,
            gate, hr);
        Field(std::format("move 0x{:X} -> {}",
                          reinterpret_cast<std::uintptr_t>(record.identity.hwnd),
                          NativeDesktopRoleText(target)),
              moved ? "verified" : "FAILED");
        return moved;
    };

    bool mutation_started = false;
    WindowRecord setup_a2{};
    setup_a2.identity = logical_a2.identity;
    setup_a2.monitor = monitor_a_id;
    setup_a2.workspace = kA2;
    setup_a2.native_role = NativeDesktopRole::Carrier;
    setup_a2.capabilities = {true, true, true, true, true};
    mutation_started = true;
    if (!move_to_role(setup_a2, NativeDesktopRole::Parking)) {
        const bool setup_restored =
            observe_role(setup_a2) == NativeDesktopRole::Carrier ||
            move_to_role(setup_a2, NativeDesktopRole::Carrier);
        cleanup_hotkeys();
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not establish A2 on Parking");
        Field("setup restoration",
              setup_restored ? "PASS" : "FAILED (probe destroyed)");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "yes");
        return 1;
    }

    auto restore_and_close = [&]() {
        bool restored = true;
        for (const LogicalWindow* logical : all_windows) {
            if (logical == nullptr) continue;
            WindowRecord record{};
            record.identity = logical->identity;
            record.monitor = reinterpret_cast<MonitorId>(logical->monitor);
            record.workspace = logical->workspace;
            record.capabilities = {true, true, true, true, true};
            const NativeDesktopRole role = observe_role(record);
            if (role != NativeDesktopRole::Carrier &&
                !move_to_role(record, NativeDesktopRole::Carrier)) {
                restored = false;
            }
        }
        return restored && close_probes();
    };

    bool restoration_done = false;
    bool restored_result = true;
    int integration_rc = 1;
    try {
    integration_rc = [&]() -> int {
        bool capability_access_denied = false;
        Win32WindowDiscoveryOptions options;
        options.carrier = carrier.id;
        options.parking = parking.id;
        options.augment_capabilities =
            [&](HWND hwnd, const WindowDiscoveryObservation& observation,
                WindowCapabilities& capabilities, std::string* error) {
                const LogicalWindow* logical = owned_logical(observation.identity);
                if (logical == nullptr) return true;
                if (hwnd != logical->identity.hwnd ||
                    ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL) !=
                        logical->monitor) {
                    if (error != nullptr) {
                        *error = "owned probe identity or monitor changed";
                    }
                    return false;
                }
                RawObject view;
                if (!acquire_view(hwnd, view, error)) return false;
                capabilities.has_application_view = true;
                Gate gate = Gate::Ok;
                BOOL value = FALSE;
                const HRESULT hr = InvokeSlot(
                    manager.obj.Get(), *manager.layout, *can_move, gate, false,
                    view.Get(), &value);
                if (hr == E_ACCESSDENIED) capability_access_denied = true;
                if (gate != Gate::Ok || FAILED(hr)) {
                    if (error != nullptr) {
                        *error = std::format(
                            "CanViewMoveDesktops failed: gate={} hr={}",
                            GateText(gate), HrToString(hr));
                    }
                    return false;
                }
                capabilities.can_move_desktops = value != FALSE;
                return true;
            };

        std::string error;
        HRESULT backend_hr = S_OK;
        auto backend = CreateSystemWindowDiscoveryBackend(
            std::move(options), &error, &backend_hr);
        if (!backend) {
            Field("integration error", error);
            return backend_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
        }
        WindowDiscovery discovery(std::move(*backend));

        WorkspaceEngine engine(carrier.id, parking.id);
        if (!engine.AddMonitor(monitor_a_id, kA1, monitor_a_workspaces,
                               &error) ||
            !engine.AddMonitor(monitor_b_id, kB1, monitor_b_workspaces,
                               &error)) {
            Field("integration error", error);
            return 1;
        }
        WorkspaceAssignmentAdapter assignment(engine);
        if (!assignment.ConfigureMonitor(monitor_a_id, kA1,
                                         monitor_a_workspaces,
                                         &error) ||
            !assignment.ConfigureMonitor(monitor_b_id, kB1,
                                         monitor_b_workspaces, &error)) {
            Field("assignment error", error);
            return 1;
        }

        std::vector<DiscoveredWindow> initial;
        if (!discovery.Discover(initial, &error)) {
            Field("discovery error", error);
            return capability_access_denied ? kExitInconclusive : 1;
        }
        const struct {
            const LogicalWindow* logical;
            NativeDesktopRole expected;
        } expectations[] = {
            {&logical_a1, NativeDesktopRole::Carrier},
            {&logical_a2, NativeDesktopRole::Parking},
            {&logical_b1, NativeDesktopRole::Carrier},
        };
        for (const auto& expectation : expectations) {
            const auto found = std::find_if(
                initial.begin(), initial.end(),
                [&](const DiscoveredWindow& item) {
                    return item.identity == expectation.logical->identity;
                });
            if (found == initial.end() ||
                found->disposition != WindowDisposition::Managed ||
                found->native_role != expectation.expected ||
                !found->capabilities.Manageable()) {
                Field("integration error",
                      "system discovery did not prove all owned probes");
                return 1;
            }
            WindowRecord record{};
            record.identity = found->identity;
            record.monitor = reinterpret_cast<MonitorId>(found->monitor);
            record.workspace = expectation.logical->workspace;
            record.native_role = found->native_role;
            record.capabilities = found->capabilities;
            record.presentation = found->presentation;
            record.disposition = WindowDisposition::Managed;
            record.present = true;
            if (engine.UpsertWindow(std::move(record), &error) !=
                UpsertResult::Added) {
                Field("assignment error", error);
                return 1;
            }
        }
        if (!engine.CheckInvariant(&error)) {
            Field("integration error", error);
            return 1;
        }

        auto discover_assigned = [&](std::vector<WindowRecord>& records,
                                     std::string* local_error) {
            std::vector<DiscoveredWindow> complete;
            if (!discovery.Discover(complete, local_error) ||
                !assignment.ConvertCompleteSnapshot(complete, records,
                                                    local_error)) {
                return false;
            }
            if (records.size() != std::size(all_windows) ||
                std::any_of(records.begin(), records.end(),
                            [&](const WindowRecord& record) {
                                return owned_logical(record.identity) == nullptr;
                            })) {
                if (local_error != nullptr) {
                    *local_error =
                        "assigned snapshot escaped the probe ownership boundary";
                }
                return false;
            }
            return true;
        };
        auto observe_owned = [&](HWND hwnd) -> std::optional<WindowRecord> {
            std::vector<WindowRecord> records;
            std::string local_error;
            if (!discover_assigned(records, &local_error)) return std::nullopt;
            const auto found = std::find_if(
                records.begin(), records.end(),
                [hwnd](const WindowRecord& record) {
                    return record.identity.hwnd == hwnd;
                });
            return found == records.end() ? std::nullopt
                                          : std::optional<WindowRecord>(*found);
        };

        WindowLifecycleAdapter lifecycle(engine, observe_owned);
        WinEventLifecycleSource source;
        if (!source.Start(&error)) {
            Field("lifecycle error", error);
            return 1;
        }
        auto coordinator_discovery = [&](std::vector<WindowRecord>& records,
                                         std::string* local_error) {
            if (!source.PumpOwnerThreadMessages(local_error)) return false;
            return discover_assigned(records, local_error);
        };
        WorkspaceCoordinator coordinator(
            engine, lifecycle, source, coordinator_discovery, move_to_role,
            observe_role, &journal, 10, 5);

        auto control_unchanged = [&]() {
            WindowIdentity identity;
            WindowDesktopState state;
            RECT rect{};
            GUID current{};
            return ReadWindowIdentity(logical_b1.identity.hwnd, identity) &&
                   identity == logical_b1.identity &&
                   ::MonitorFromWindow(logical_b1.identity.hwnd,
                                       MONITOR_DEFAULTTONULL) ==
                       monitor_b.handle &&
                   ::GetWindowRect(logical_b1.identity.hwnd, &rect) &&
                   SameRect(rect, logical_b1.rect) &&
                   ReadWindowDesktopState(documented_manager.Get(),
                                          logical_b1.identity.hwnd, state) &&
                   WindowStateMatches(state, carrier.id, true) &&
                   state.visible == b1_baseline_state.visible &&
                   state.cloaked == b1_baseline_state.cloaked &&
                   ReadCurrentDesktopId(manager, current) &&
                   ::IsEqualGUID(current, carrier.id);
        };
        auto dispatch_hotkey = [&](const WorkspaceHotkey& hotkey,
                                   CoordinatorResult& out) {
            hotkey_requests.clear();
            const auto found = std::find_if(
                hotkey_context.registered.begin(),
                hotkey_context.registered.end(),
                [&](const std::pair<UINT, WorkspaceHotkey>& entry) {
                    return entry.second == hotkey;
                });
            if (found == hotkey_context.registered.end()) return false;
            ::PostMessageW(hotkey_window, WM_HOTKEY, found->first,
                           MAKELPARAM(hotkey.modifiers, hotkey.vk));
            PumpStaMessages();
            if (hotkey_requests.size() != 1) return false;
            const PendingDispatch& request = hotkey_requests.front();
            out = coordinator.Switch(request.monitor, request.workspace);
            return true;
        };

        bool ok = true;
        const CoordinatorResult reconciled = coordinator.ReconcileDiscovery();
        Field("initial authoritative reconcile",
              reconciled.succeeded() ? "PASS" : "FAIL");
        ok = reconciled.succeeded() && control_unchanged();

        CoordinatorResult forward;
        CoordinatorResult reverse;
        if (ok) {
            const bool dispatched = dispatch_hotkey(*target_hotkey, forward);
            Field("WM_HOTKEY target-workspace dispatched",
                  dispatched ? "PASS" : "FAIL");
            Field("A1 -> A2 switch", forward.succeeded() ? "PASS" : "FAIL");
            ok = dispatched && forward.succeeded() &&
                 forward.transaction.committed &&
                 engine.Monitor(monitor_a_id)->active == kA2 &&
                 engine.Monitor(monitor_b_id)->active == kB1 &&
                 control_unchanged();
        }
        if (ok) {
            const bool dispatched = dispatch_hotkey(*active_hotkey, reverse);
            Field("WM_HOTKEY active-workspace dispatched",
                  dispatched ? "PASS" : "FAIL");
            Field("A2 -> A1 switch", reverse.succeeded() ? "PASS" : "FAIL");
            ok = dispatched && reverse.succeeded() &&
                 reverse.transaction.committed &&
                 engine.Monitor(monitor_a_id)->active == kA1 &&
                 engine.Monitor(monitor_b_id)->active == kB1 &&
                 control_unchanged();
        }
        std::string pending_error;
        const std::optional<SwitchPlan> pending =
            journal.ReadPending(&pending_error);
        ok = ok && !pending && pending_error.empty() &&
             engine.CheckInvariant(&error);
        const bool final_control_unchanged = control_unchanged();
        ok = ok && final_control_unchanged;
        const bool restored_here = restore_and_close();
        restoration_done = true;
        restored_result = restored_here;
        ok = ok && restored_here;
        source.Stop();
        const bool lifecycle_stopped = source.shutdown_ok();
        ok = ok && lifecycle_stopped;
        bool journal_cleaned = false;
        std::error_code remove_error;
        std::error_code exists_error;
        if (!pending && pending_error.empty() && lifecycle_stopped &&
            restored_here) {
            const bool removed =
                std::filesystem::remove(journal_path, remove_error);
            if (removed) {
                journal_cleaned = true;
            } else if (!remove_error) {
                const bool exists =
                    std::filesystem::exists(journal_path, exists_error);
                journal_cleaned = !exists_error && !exists;
            }
            ok = ok && journal_cleaned;
        }
        Field("monitor B unchanged",
              final_control_unchanged ? "PASS" : "FAIL");
        Field("stable journal pending", pending ? "YES" : "no");
        Field("stable journal cleanup",
              journal_cleaned ? "PASS" : pending ? "retained (pending)"
                                                   : "FAILED");
        if (!pending_error.empty()) Field("journal error", pending_error);
        if (remove_error) {
            Field("journal cleanup error", remove_error.message());
        }
        if (exists_error) {
            Field("journal existence error", exists_error.message());
        }
        if (!error.empty()) Field("engine error", error);
        cleanup_hotkeys();
        return ok ? 0 : 1;
    }();
    } catch (const std::exception& exception) {
        Field("integration error", std::format("exception: {}", exception.what()));
    } catch (...) {
        Field("integration error", "unknown exception");
    }

    cleanup_hotkeys();
    const bool restored =
        restoration_done ? restored_result : restore_and_close();
    const bool blocked = integration_rc == kExitInconclusive && restored;
    const bool passed = integration_rc == 0 && restored;
    Field("probe cleanup/restoration", restored ? "PASS" : "FAIL");
    Field("mutation_started", mutation_started ? "yes" : "no");
    Field("result", passed ? "PASS" : blocked ? "ENVIRONMENT-BLOCKED"
                                              : "FAIL");
    Print("mutation_started={}\n", mutation_started ? "yes" : "no");
    Print("RESULT={}\n", passed ? "PASS" : blocked ? "ENVIRONMENT-BLOCKED"
                                                  : "FAIL");
    return passed ? 0 : (blocked ? kExitInconclusive : 1);
}

// -------------------------------------------------- workspace-manager --run

namespace {

constexpr wchar_t kManagerMainClassName[] = L"vdprobe.WorkspaceManagerMain";
constexpr wchar_t kManagerMutexName[] = L"Local\vdprobe-workspace-manager";
constexpr UINT kManagerTrayMessage = WM_APP + 1;
constexpr UINT_PTR kManagerReconcileTimerId = 1;
constexpr UINT_PTR kManagerShutdownTimerId = 2;
constexpr std::uint32_t kManagerReconcileIntervalMs = 3000;

struct ManagerMainContext {
    std::function<bool(UINT modifiers, UINT vk)> hotkey_handler;
    std::function<void()> reconcile_handler;
    std::function<void(int command)> tray_command_handler;
    std::function<void(HMENU menu)> menu_builder;
    std::function<void()> display_change_handler;
    std::function<void()> resume_handler;
    std::function<void()> reload_handler;
    std::function<std::string()> status_text;
    bool exit_requested = false;
};

LRESULT CALLBACK ManagerMainWindowProc(HWND hwnd, UINT message,
                                       WPARAM wparam, LPARAM lparam) {
    ManagerMainContext* context = reinterpret_cast<ManagerMainContext*>(
        ::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_HOTKEY && context != nullptr &&
        context->hotkey_handler) {
        context->hotkey_handler(LOWORD(lparam), HIWORD(lparam));
        return 0;
    }
    if (message == WM_TIMER && context != nullptr) {
        if (wparam == kManagerReconcileTimerId &&
            context->reconcile_handler) {
            context->reconcile_handler();
        } else if (wparam == kManagerShutdownTimerId) {
            context->exit_requested = true;
            ::PostMessageW(hwnd, WM_CLOSE, 0, 0);
        }
        return 0;
    }
    if (message == kManagerTrayMessage && context != nullptr) {
        if (lparam == WM_RBUTTONUP || lparam == WM_LBUTTONUP) {
            HMENU menu = ::CreatePopupMenu();
            if (context->menu_builder) {
                context->menu_builder(menu);
            } else {
                ::AppendMenuW(menu, MF_STRING, 1,
                              L"Switch monitor A -> A2");
                ::AppendMenuW(menu, MF_STRING, 2,
                              L"Switch monitor A -> A1");
                ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
                ::AppendMenuW(menu, MF_STRING, 3, L"Status");
                ::AppendMenuW(menu, MF_STRING, 4, L"Diagnostics");
                ::AppendMenuW(menu, MF_STRING, 5,
                              L"Reload configuration");
                ::AppendMenuW(menu, MF_STRING, 6, L"Exit");
            }
            POINT point{};
            ::GetCursorPos(&point);
            const int command = ::TrackPopupMenu(
                menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
                point.x, point.y, 0, hwnd, nullptr);
            ::DestroyMenu(menu);
            if (command != 0 && context->tray_command_handler) {
                context->tray_command_handler(command);
            }
        }
        return 0;
    }
    if (message == WM_APP + 2 && context != nullptr) {
        if (context->reload_handler) {
            context->reload_handler();
        }
        return 0;
    }
    if (message == WM_DISPLAYCHANGE && context != nullptr) {
        if (context->display_change_handler) {
            context->display_change_handler();
        }
        return 0;
    }
    if (message == WM_POWERBROADCAST && context != nullptr) {
        if (wparam == PBT_APMRESUMESUSPEND && context->resume_handler) {
            context->resume_handler();
        }
        return TRUE;
    }
    if (message == WM_QUERYENDSESSION) {
        if (context != nullptr) context->exit_requested = true;
        return TRUE;
    }
    if (message == WM_CLOSE && context != nullptr) {
        context->exit_requested = true;
        ::DestroyWindow(hwnd);
        return 0;
    }
    return ::DefWindowProcW(hwnd, message, wparam, lparam);
}

bool EnsureManagerMainClass() {
    static bool registered = false;
    if (registered) return true;
    WNDCLASSEXW klass{};
    klass.cbSize = sizeof(klass);
    klass.hInstance = ::GetModuleHandleW(nullptr);
    klass.lpfnWndProc = &ManagerMainWindowProc;
    klass.lpszClassName = kManagerMainClassName;
    if (::RegisterClassExW(&klass) == 0 &&
        ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return false;
    }
    registered = true;
    return true;
}

}  // namespace

int CmdWorkspaceManagerRunProbeGate(const char* config_path, int seconds,
                                    bool self_resilience,
                                    bool confirm_mutate) {
    Heading("workspace-manager --run");
    Field("scope", "long-running host: hotkeys, tray, periodic reconciliation");
    Field("managed scope", "probe-owned windows (live gate)");
    Field("global desktop switch", "never called");
    Field("desktop lifecycle", "no create/remove");

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print("\n  Refusing the probe gate without --confirm-mutate.\n");
        return 1;
    }

    HANDLE mutex = ::CreateMutexW(nullptr, FALSE, kManagerMutexName);
    if (mutex == nullptr) {
        Field("result", "ERROR");
        Field("reason", "single-instance mutex unavailable");
        return 1;
    }
    if (::GetLastError() == ERROR_ALREADY_EXISTS) {
        Print("another workspace-manager instance is already running\n");
        ::CloseHandle(mutex);
        return 0;
    }
    auto release_mutex = [&]() { ::CloseHandle(mutex); };

    const std::vector<MonitorRec> monitors = EnumerateMonitors();
    if (monitors.size() < 2) {
        Field("result", "ERROR");
        Field("reason", "at least two monitors are required");
        release_mutex();
        return 1;
    }
    const MonitorRec& monitor_a = monitors[0];
    const MonitorRec& monitor_b = monitors[1];
    const MonitorId monitor_a_id =
        reinterpret_cast<MonitorId>(monitor_a.handle);
    const MonitorId monitor_b_id =
        reinterpret_cast<MonitorId>(monitor_b.handle);
    WorkspaceId kA1 = 1;
    WorkspaceId kA2 = 2;
    WorkspaceId kB1 = 3;
    std::vector<WorkspaceId> monitor_a_workspaces{kA1, kA2};
    std::vector<WorkspaceId> monitor_b_workspaces{kB1};
    Field("monitor A", ToUtf8(monitor_a.device));
    Field("monitor B", ToUtf8(monitor_b.device));

    const std::filesystem::path journal_path =
        std::filesystem::temp_directory_path() /
        "vdprobe-workspace-manager.journal";
    WorkspaceJournal journal(journal_path);
    std::string journal_error;
    const std::optional<SwitchPlan> existing_pending =
        journal.ReadPending(&journal_error);
    if (!journal_error.empty() || existing_pending) {
        Field("journal", journal_path.string());
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", !journal_error.empty()
                            ? "stable journal could not be read: " +
                                  journal_error
                            : "stable journal contains a pending transaction");
        Field("mutation_started", "no");
        release_mutex();
        return kExitInconclusive;
    }
    Field("journal", journal_path.string());

    WorkspaceManagerConfig hotkey_config;
    hotkey_config.journal_path = journal_path;
    hotkey_config.tray_icon = true;
    if (config_path != nullptr && *config_path != '\0') {
        std::string config_error;
        if (!LoadManagerConfig(std::filesystem::path(config_path),
                               hotkey_config, &config_error)) {
            Field("result", "ERROR");
            Field("reason", "config load failed: " + config_error);
            release_mutex();
            return 1;
        }
        Field("config", config_path);
        std::vector<HMONITOR> real_monitors;
        for (const MonitorRec& monitor : monitors) {
            real_monitors.push_back(monitor.handle);
        }
        ManagerRuntimeTopology topology;
        if (!DeriveManagerRuntimeTopology(hotkey_config, real_monitors,
                                          topology, &config_error)) {
            Field("result", "ERROR");
            Field("reason", "config topology failed: " + config_error);
            release_mutex();
            return 1;
        }
        if (topology.monitors.size() < 2) {
            Field("result", "ERROR");
            Field("reason", "config must define at least two monitors");
            release_mutex();
            return 1;
        }
        kA1 = topology.monitors[0].active;
        kB1 = topology.monitors[1].active;
        monitor_a_workspaces = topology.monitors[0].workspace_ids;
        monitor_b_workspaces = topology.monitors[1].workspace_ids;
        kA2 = monitor_a_workspaces.size() > 1 ? monitor_a_workspaces[1] : kA1;
        hotkey_config.bindings = topology.bindings;
        Field("config bindings",
              std::format("{}", hotkey_config.bindings.size()));
    } else {
        hotkey_config.bindings = {
            {{MOD_CONTROL | MOD_ALT, VK_F9}, monitor_a_id, kA2},
            {{MOD_CONTROL | MOD_ALT, VK_F10}, monitor_a_id, kA1},
        };
    }

    Com<IServiceProvider> sp;
    const HRESULT shell_hr = GetImmersiveShell(sp);
    if (FAILED(shell_hr) || !sp) {
        const std::string reason = std::format("ImmersiveShell unavailable ({})",
                                               HrToString(shell_hr));
        Field("result", shell_hr == E_ACCESSDENIED ? "ENVIRONMENT-BLOCKED"
                                                   : "ERROR");
        Field("reason", reason);
        Field("mutation_started", "no");
        release_mutex();
        return shell_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
    }
    ManagerInternal manager = AcquireManagerInternal(sp.Get());
    if (!manager.obj || manager.layout == nullptr) {
        Field("result", manager.access_denied_seen ? "ENVIRONMENT-BLOCKED"
                                                   : "ERROR");
        Field("reason", "usable IVirtualDesktopManagerInternal unavailable");
        Field("mutation_started", "no");
        release_mutex();
        return manager.access_denied_seen ? kExitInconclusive : 1;
    }
    DesktopSnapshot carrier;
    HRESULT current_hr = E_ABORT;
    if (!ReadCurrentDesktop(manager, carrier, &current_hr)) {
        Field("result", current_hr == E_ACCESSDENIED ? "ENVIRONMENT-BLOCKED"
                                                     : "ERROR");
        Field("reason", "current Carrier unavailable");
        Field("mutation_started", "no");
        release_mutex();
        return current_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
    }
    std::vector<DesktopSnapshot> desktops;
    HRESULT desktops_hr = E_ABORT;
    if (!ReadDesktopList(manager, desktops, &desktops_hr)) {
        Field("result", desktops_hr == E_ACCESSDENIED ? "ENVIRONMENT-BLOCKED"
                                                      : "ERROR");
        Field("reason", "existing desktop enumeration failed");
        Field("mutation_started", "no");
        release_mutex();
        return desktops_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.id_ok || !parking.object) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "no existing inactive Parking desktop");
        release_mutex();
        return kExitInconclusive;
    }
    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    const MethodEntry* get_view =
        views.layout == nullptr ? nullptr
                                : FindMethod(*views.layout, "GetViewForHwnd");
    const MethodEntry* can_move =
        FindMethod(*manager.layout, "CanViewMoveDesktops");
    if (!views.object || get_view == nullptr || can_move == nullptr) {
        Field("result", views.access_denied_seen ? "ENVIRONMENT-BLOCKED"
                                                 : "ERROR");
        Field("reason", "application-view capability APIs unavailable");
        release_mutex();
        return views.access_denied_seen ? kExitInconclusive : 1;
    }
    Com<IVirtualDesktopManager> documented_manager;
    const HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER,
        IID_IVirtualDesktopManager, documented_manager.PutVoid());
    if (FAILED(documented_hr) || !documented_manager) {
        Field("result", documented_hr == E_ACCESSDENIED ? "ENVIRONMENT-BLOCKED"
                                                        : "ERROR");
        Field("reason", std::format("IVirtualDesktopManager unavailable ({})",
                                    HrToString(documented_hr)));
        release_mutex();
        return documented_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
    }

    auto acquire_view = [&](HWND hwnd, RawObject& out,
                            std::string* error = nullptr) -> bool {
        const ULONGLONG deadline = ::GetTickCount64() + 2000;
        HRESULT last_hr = E_ABORT;
        Gate last_gate = Gate::Ok;
        do {
            PumpStaMessages();
            last_gate = Gate::Ok;
            last_hr = InvokeSlot(views.object.Get(), *views.layout, *get_view,
                                 last_gate, false, hwnd, out.PutVoid());
            if (last_gate == Gate::Ok && SUCCEEDED(last_hr) && out) return true;
            ::Sleep(25);
        } while (::GetTickCount64() < deadline);
        if (error != nullptr) {
            *error = std::format("GetViewForHwnd 0x{:X} failed: gate={} hr={}",
                                 reinterpret_cast<std::uintptr_t>(hwnd),
                                 GateText(last_gate), HrToString(last_hr));
        }
        return false;
    };
    auto view_can_move = [&](IUnknown* view, std::string* error = nullptr) {
        Gate gate = Gate::Ok;
        BOOL value = FALSE;
        const HRESULT hr = InvokeSlot(manager.obj.Get(), *manager.layout,
                                      *can_move, gate, false, view, &value);
        if (gate == Gate::Ok && SUCCEEDED(hr) && value != FALSE) return true;
        if (error != nullptr) {
            *error = std::format("CanViewMoveDesktops failed: gate={} hr={}",
                                 GateText(gate), HrToString(hr));
        }
        return false;
    };

    SpawnedProbeWindow a1;
    SpawnedProbeWindow a2;
    SpawnedProbeWindow b1;
    auto close_probes = [&]() {
        const bool b1_closed = CloseThrowawayProbeWindow(b1);
        const bool a2_closed = CloseThrowawayProbeWindow(a2);
        const bool a1_closed = CloseThrowawayProbeWindow(a1);
        const bool closed = b1_closed && a2_closed && a1_closed;
        Field("probe window close", closed ? "PASS" : "FAIL");
        return closed;
    };
    if (!SpawnThrowawayProbeWindow(a1) || !SpawnThrowawayProbeWindow(a2) ||
        !SpawnThrowawayProbeWindow(b1) ||
        !PlaceProbeWindowOnMonitor(a1.hwnd, monitor_a, 0) ||
        !PlaceProbeWindowOnMonitor(a2.hwnd, monitor_a, 1) ||
        !PlaceProbeWindowOnMonitor(b1.hwnd, monitor_b, 0)) {
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not create and place three probe windows");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        release_mutex();
        return 1;
    }
    LogicalWindow logical_a1;
    LogicalWindow logical_a2;
    LogicalWindow logical_b1;
    if (!CaptureLogicalWindow(documented_manager.Get(), a1.hwnd,
                              monitor_a.handle, kA1, logical_a1) ||
        !CaptureLogicalWindow(documented_manager.Get(), a2.hwnd,
                              monitor_a.handle, kA2, logical_a2) ||
        !CaptureLogicalWindow(documented_manager.Get(), b1.hwnd,
                              monitor_b.handle, kB1, logical_b1)) {
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not capture exact probe identities");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        release_mutex();
        return 1;
    }
    WindowDesktopState b1_baseline_state;
    if (!ReadWindowDesktopState(documented_manager.Get(), b1.hwnd,
                                b1_baseline_state) ||
        !WindowStateMatches(b1_baseline_state, carrier.id, true)) {
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "control probe baseline is not on Carrier");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        release_mutex();
        return 1;
    }
    const LogicalWindow* all_windows[] = {&logical_a1, &logical_a2,
                                          &logical_b1};
    auto owned_logical = [&](const WindowIdentity& identity) {
        for (const LogicalWindow* logical : all_windows) {
            if (logical != nullptr && logical->identity == identity) {
                return logical;
            }
        }
        return static_cast<const LogicalWindow*>(nullptr);
    };
    auto observe_role = [&](const WindowRecord& record) {
        const LogicalWindow* logical = owned_logical(record.identity);
        WindowIdentity current;
        if (logical == nullptr ||
            !ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity) {
            return NativeDesktopRole::Unknown;
        }
        WindowDesktopState state;
        if (!ReadWindowDesktopState(documented_manager.Get(),
                                    record.identity.hwnd, state)) {
            return NativeDesktopRole::Unknown;
        }
        if (::IsEqualGUID(state.desktop, carrier.id) && state.on_current) {
            return NativeDesktopRole::Carrier;
        }
        if (::IsEqualGUID(state.desktop, parking.id) && !state.on_current) {
            return NativeDesktopRole::Parking;
        }
        return NativeDesktopRole::Unknown;
    };
    auto move_to_role = [&](const WindowRecord& record,
                            NativeDesktopRole target) -> bool {
        const LogicalWindow* logical = owned_logical(record.identity);
        WindowIdentity current;
        if (logical == nullptr ||
            !ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity ||
            ::MonitorFromWindow(record.identity.hwnd,
                                MONITOR_DEFAULTTONULL) != logical->monitor) {
            return false;
        }
        RawObject view;
        std::string error;
        if (!acquire_view(record.identity.hwnd, view, &error) ||
            !view_can_move(view.Get(), &error)) {
            if (!error.empty()) Field("native move error", error);
            return false;
        }
        IUnknown* target_object =
            target == NativeDesktopRole::Carrier ? carrier.object.Get()
            : target == NativeDesktopRole::Parking ? parking.object.Get()
                                                    : nullptr;
        const GUID* target_id =
            target == NativeDesktopRole::Carrier ? &carrier.id
            : target == NativeDesktopRole::Parking ? &parking.id : nullptr;
        if (target_object == nullptr || target_id == nullptr) return false;
        Gate gate = Gate::Ok;
        HRESULT hr = E_ABORT;
        return MoveViewToDesktopAndWait(
            manager, view.Get(), target_object, record.identity.hwnd,
            documented_manager.Get(), *target_id, carrier.id, true, gate, hr);
    };

    bool mutation_started = false;
    WindowRecord setup_a2{};
    setup_a2.identity = logical_a2.identity;
    setup_a2.monitor = monitor_a_id;
    setup_a2.workspace = kA2;
    setup_a2.native_role = NativeDesktopRole::Carrier;
    setup_a2.capabilities = {true, true, true, true, true};
    mutation_started = true;
    if (!move_to_role(setup_a2, NativeDesktopRole::Parking)) {
        const bool setup_restored =
            observe_role(setup_a2) == NativeDesktopRole::Carrier ||
            move_to_role(setup_a2, NativeDesktopRole::Carrier);
        const bool closed = close_probes();
        Field("result", "ERROR");
        Field("reason", "could not establish A2 on Parking");
        Field("setup restoration",
              setup_restored ? "PASS" : "FAILED (probe destroyed)");
        Field("probe cleanup", closed ? "PASS" : "FAIL");
        Field("mutation_started", "yes");
        release_mutex();
        return 1;
    }

    auto restore_and_close = [&]() {
        bool restored = true;
        for (const LogicalWindow* logical : all_windows) {
            if (logical == nullptr) continue;
            WindowRecord record{};
            record.identity = logical->identity;
            record.monitor = reinterpret_cast<MonitorId>(logical->monitor);
            record.workspace = logical->workspace;
            record.capabilities = {true, true, true, true, true};
            const NativeDesktopRole role = observe_role(record);
            if (role != NativeDesktopRole::Carrier &&
                !move_to_role(record, NativeDesktopRole::Carrier)) {
                restored = false;
            }
        }
        return restored && close_probes();
    };

    bool restoration_done = false;
    bool restored_result = true;
    int integration_rc = 1;
    try {
    integration_rc = [&]() -> int {
        bool capability_access_denied = false;
        Win32WindowDiscoveryOptions options;
        options.carrier = carrier.id;
        options.parking = parking.id;
        options.augment_capabilities =
            [&](HWND hwnd, const WindowDiscoveryObservation& observation,
                WindowCapabilities& capabilities, std::string* error) {
                const LogicalWindow* logical =
                    owned_logical(observation.identity);
                if (logical == nullptr) return true;
                if (hwnd != logical->identity.hwnd ||
                    ::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONULL) !=
                        logical->monitor) {
                    if (error != nullptr) {
                        *error = "owned probe identity or monitor changed";
                    }
                    return false;
                }
                RawObject view;
                if (!acquire_view(hwnd, view, error)) return false;
                capabilities.has_application_view = true;
                Gate gate = Gate::Ok;
                BOOL value = FALSE;
                const HRESULT hr = InvokeSlot(
                    manager.obj.Get(), *manager.layout, *can_move, gate, false,
                    view.Get(), &value);
                if (hr == E_ACCESSDENIED) capability_access_denied = true;
                if (gate != Gate::Ok || FAILED(hr)) {
                    if (error != nullptr) {
                        *error = std::format(
                            "CanViewMoveDesktops failed: gate={} hr={}",
                            GateText(gate), HrToString(hr));
                    }
                    return false;
                }
                capabilities.can_move_desktops = value != FALSE;
                return true;
            };

        std::string error;
        HRESULT backend_hr = S_OK;
        auto backend = CreateSystemWindowDiscoveryBackend(
            std::move(options), &error, &backend_hr);
        if (!backend) {
            Field("integration error", error);
            return backend_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
        }
        WindowDiscovery discovery(std::move(*backend));

        WorkspaceEngine engine(carrier.id, parking.id);
        if (!engine.AddMonitor(monitor_a_id, kA1, monitor_a_workspaces,
                               &error) ||
            !engine.AddMonitor(monitor_b_id, kB1, monitor_b_workspaces,
                               &error)) {
            Field("integration error", error);
            return 1;
        }
        engine.SetAutoQuarantine(hotkey_config.quarantine_enabled);
        WorkspaceAssignmentAdapter assignment(engine);
        if (!assignment.ConfigureMonitor(monitor_a_id, kA1,
                                         monitor_a_workspaces, &error) ||
            !assignment.ConfigureMonitor(monitor_b_id, kB1,
                                         monitor_b_workspaces, &error)) {
            Field("assignment error", error);
            return 1;
        }
        std::vector<DiscoveredWindow> initial;
        if (!discovery.Discover(initial, &error)) {
            Field("discovery error", error);
            return capability_access_denied ? kExitInconclusive : 1;
        }
        const struct {
            const LogicalWindow* logical;
            NativeDesktopRole expected;
        } expectations[] = {
            {&logical_a1, NativeDesktopRole::Carrier},
            {&logical_a2, NativeDesktopRole::Parking},
            {&logical_b1, NativeDesktopRole::Carrier},
        };
        for (const auto& expectation : expectations) {
            const auto found = std::find_if(
                initial.begin(), initial.end(),
                [&](const DiscoveredWindow& item) {
                    return item.identity == expectation.logical->identity;
                });
            if (found == initial.end() ||
                found->disposition != WindowDisposition::Managed ||
                found->native_role != expectation.expected ||
                !found->capabilities.Manageable()) {
                Field("integration error",
                      "system discovery did not prove all owned probes");
                return 1;
            }
            WindowRecord record{};
            record.identity = found->identity;
            record.monitor = reinterpret_cast<MonitorId>(found->monitor);
            record.workspace = expectation.logical->workspace;
            record.native_role = found->native_role;
            record.capabilities = found->capabilities;
            record.presentation = found->presentation;
            record.disposition = WindowDisposition::Managed;
            record.present = true;
            if (engine.UpsertWindow(std::move(record), &error) !=
                UpsertResult::Added) {
                Field("assignment error", error);
                return 1;
            }
        }
        if (!engine.CheckInvariant(&error)) {
            Field("integration error", error);
            return 1;
        }
        auto discover_assigned = [&](std::vector<WindowRecord>& records,
                                     std::string* local_error) {
            std::vector<DiscoveredWindow> complete;
            if (!discovery.Discover(complete, local_error) ||
                !assignment.ConvertCompleteSnapshot(complete, records,
                                                    local_error)) {
                return false;
            }
            if (records.size() != std::size(all_windows) ||
                std::any_of(records.begin(), records.end(),
                            [&](const WindowRecord& record) {
                                return owned_logical(record.identity) == nullptr;
                            })) {
                if (local_error != nullptr) {
                    *local_error =
                        "assigned snapshot escaped the probe ownership boundary";
                }
                return false;
            }
            return true;
        };
        auto observe_owned = [&](HWND hwnd) -> std::optional<WindowRecord> {
            std::vector<WindowRecord> records;
            std::string local_error;
            if (!discover_assigned(records, &local_error)) return std::nullopt;
            const auto found = std::find_if(
                records.begin(), records.end(),
                [hwnd](const WindowRecord& record) {
                    return record.identity.hwnd == hwnd;
                });
            return found == records.end() ? std::nullopt
                                          : std::optional<WindowRecord>(*found);
        };
        WindowLifecycleAdapter lifecycle(engine, observe_owned);
        WinEventLifecycleSource source;
        if (!source.Start(&error)) {
            Field("lifecycle error", error);
            return 1;
        }
        auto coordinator_discovery = [&](std::vector<WindowRecord>& records,
                                         std::string* local_error) {
            if (!source.PumpOwnerThreadMessages(local_error)) return false;
            return discover_assigned(records, local_error);
        };
        WorkspaceCoordinator coordinator(
            engine, lifecycle, source, coordinator_discovery, move_to_role,
            observe_role, &journal, 10, 5);

        std::size_t hotkey_dispatches = 0;
        std::size_t switches_committed = 0;
        HWND hotkey_window = nullptr;
        MonitorTopologyMapper topology_mapper;
        std::vector<MonitorTopologyMapper::BoundMonitor> bound_monitors;
        std::vector<std::size_t> missing_monitors;
        HostResilienceState resilience;
        std::size_t host_expected_monitors = 0;
        auto refresh_topology = [&]() {
            const std::vector<MonitorRec> current = EnumerateMonitors();
            std::vector<std::pair<MonitorId, std::string>> real;
            for (const MonitorRec& monitor : current) {
                real.push_back({reinterpret_cast<MonitorId>(monitor.handle),
                                ToUtf8(monitor.device)});
            }
            topology_mapper.Update(real, bound_monitors, missing_monitors,
                                   host_expected_monitors);
            const std::size_t presence_size =
                bound_monitors.empty()
                    ? 0
                    : bound_monitors.back().config_index + 1;
            std::vector<bool> present(presence_size, false);
            for (const auto& entry : bound_monitors) {
                if (entry.config_index < present.size()) {
                    present[entry.config_index] = true;
                }
            }
            resilience.monitor_present = std::move(present);
            resilience.degraded =
                resilience.degraded || !missing_monitors.empty();
        };
        {
            const std::vector<MonitorRec> current = EnumerateMonitors();
            for (std::size_t i = 0; i < current.size(); ++i) {
                bound_monitors.push_back(
                    {i, reinterpret_cast<MonitorId>(current[i].handle),
                     ToUtf8(current[i].device)});
            }
            host_expected_monitors = bound_monitors.size();
            resilience.monitor_present.assign(host_expected_monitors, true);
        }
        auto do_switch = [&](WorkspaceId target) {
            if (resilience.monitor_present.empty() ||
                !resilience.monitor_present[0]) {
                Field("switch skipped", "monitor A suspended");
                return CoordinatorResult{};
            }
            const CoordinatorResult result =
                coordinator.Switch(monitor_a_id, target);
            if (result.succeeded() && result.transaction.committed) {
                ++switches_committed;
                Field("switch -> " + std::to_string(target), "PASS");
            } else {
                Field("switch -> " + std::to_string(target), "FAIL");
                if (!result.error.empty()) {
                    Field("  switch error", result.error);
                }
            }
            return result;
        };

        ManagerMainContext main_context;
        main_context.hotkey_handler = [&](UINT modifiers, UINT vk) {
            MonitorId monitor = 0;
            WorkspaceId workspace = 0;
            if (!ResolveWorkspaceHotkey(hotkey_config, modifiers, vk, monitor,
                                        workspace)) {
                return true;
            }
            ++hotkey_dispatches;
            if (monitor == monitor_a_id) {
                do_switch(workspace);
            }
            return true;
        };
        std::size_t reconcile_count = 0;
        main_context.reconcile_handler = [&]() {
            ++reconcile_count;
            const CoordinatorResult result = coordinator.ReconcileDiscovery();
            if (!result.succeeded() && !result.error.empty()) {
                Field("periodic reconcile error", result.error);
            }
        };
        main_context.tray_command_handler = [&](int command) {
            if (command == 1) {
                do_switch(kA2);
            } else if (command == 2) {
                do_switch(kA1);
            } else if (command == 3) {
                if (main_context.status_text) {
                    Print("status: {}\n", main_context.status_text());
                }
            } else if (command == 4) {
                const MonitorWorkspaceState* monitor_a_state =
                    engine.Monitor(monitor_a_id);
                const MonitorWorkspaceState* monitor_b_state =
                    engine.Monitor(monitor_b_id);
                Print("diagnostics: monitor A active={} monitor B active={} "
                      "reconciles={} switches={} hotkeys={} quarantine={}\n",
                      monitor_a_state ? monitor_a_state->active : 0,
                      monitor_b_state ? monitor_b_state->active : 0,
                      reconcile_count, switches_committed, hotkey_dispatches,
                      engine.QuarantineLog().size());
            } else if (command == 5) {
                if (main_context.reload_handler) {
                    main_context.reload_handler();
                }
            } else if (command == 6) {
                main_context.exit_requested = true;
                ::PostMessageW(hotkey_window, WM_CLOSE, 0, 0);
            }
        };
        main_context.status_text = [&]() {
            const MonitorWorkspaceState* monitor_a_state =
                engine.Monitor(monitor_a_id);
            const MonitorWorkspaceState* monitor_b_state =
                engine.Monitor(monitor_b_id);
            return std::format(
                "monitor A active={} monitor B active={} reconciles={} "
                "switches={} quarantine={}",
                monitor_a_state ? monitor_a_state->active : 0,
                monitor_b_state ? monitor_b_state->active : 0,
                reconcile_count, switches_committed,
                engine.QuarantineLog().size());
        };
        main_context.reload_handler = [&]() {
            if (config_path == nullptr || *config_path == '\0') {
                Print("config reload: no config file; kept running\n");
                return;
            }
            WorkspaceManagerConfig reloaded;
            std::string reload_error;
            if (!LoadManagerConfig(std::filesystem::path(config_path),
                                   reloaded, &reload_error)) {
                Print("config reload REJECTED (kept previous): {}\n",
                      reload_error);
                return;
            }
            std::vector<HMONITOR> real_monitors;
            for (const MonitorRec& monitor : monitors) {
                real_monitors.push_back(monitor.handle);
            }
            ManagerRuntimeTopology topology;
            if (!DeriveManagerRuntimeTopology(reloaded, real_monitors,
                                              topology, &reload_error)) {
                Print("config reload REJECTED (kept previous): {}\n",
                      reload_error);
                return;
            }
            for (const WorkspaceHotkeyBinding& binding : hotkey_config.bindings) {
                const UINT id =
                    100 + static_cast<UINT>(&binding -
                                            hotkey_config.bindings.data());
                ::UnregisterHotKey(hotkey_window, id);
            }
            hotkey_config = reloaded;
            hotkey_config.bindings = topology.bindings;
            for (const WorkspaceHotkeyBinding& binding : hotkey_config.bindings) {
                const UINT id =
                    100 + static_cast<UINT>(&binding -
                                            hotkey_config.bindings.data());
                if (!::RegisterHotKey(hotkey_window, id,
                                      binding.hotkey.modifiers | MOD_NOREPEAT,
                                      binding.hotkey.vk)) {
                    Print("config reload: hotkey registration failed for a "
                          "binding (kept running)\n");
                }
            }
            engine.SetAutoQuarantine(hotkey_config.quarantine_enabled);
            Print("config reload accepted ({} hotkeys, quarantine={})\n",
                  hotkey_config.bindings.size(),
                  hotkey_config.quarantine_enabled ? "on" : "off");
        };
        main_context.display_change_handler = [&]() {
            ++resilience.display_changes_handled;
            refresh_topology();
        };
        main_context.resume_handler = [&]() {
            ++resilience.resume_events_handled;
            refresh_topology();
            GUID current{};
            if (!ReadCurrentDesktopId(manager, current)) {
                resilience.shell_lost = true;
                resilience.degraded = true;
                ++resilience.shell_reacquire_attempts;
                Com<IServiceProvider> fresh_sp;
                if (SUCCEEDED(GetImmersiveShell(fresh_sp)) && fresh_sp) {
                    ManagerInternal fresh_manager =
                        AcquireManagerInternal(fresh_sp.Get());
                    DesktopSnapshot fresh_carrier;
                    HRESULT fresh_hr = E_ABORT;
                    if (fresh_manager.obj && fresh_manager.layout &&
                        ReadCurrentDesktop(fresh_manager, fresh_carrier,
                                           &fresh_hr) &&
                        ::IsEqualGUID(fresh_carrier.id, carrier.id)) {
                        resilience.shell_lost = false;
                        sp = std::move(fresh_sp);
                        manager = std::move(fresh_manager);
                    }
                }
            }
        };

        if (!EnsureManagerMainClass()) {
            Field("result", "ERROR");
            Field("reason", "manager main window class unavailable");
            return 1;
        }
        hotkey_window = ::CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, kManagerMainClassName,
            L"vdprobe-workspace-manager", WS_OVERLAPPED, 0, 0, 0, 0, nullptr,
            nullptr, ::GetModuleHandleW(nullptr), nullptr);
        if (hotkey_window == nullptr) {
            Field("result", "ERROR");
            Field("reason", "manager main window unavailable");
            return 1;
        }
        ::SetWindowLongPtrW(hotkey_window, GWLP_USERDATA,
                            reinterpret_cast<LONG_PTR>(&main_context));
        for (const WorkspaceHotkeyBinding& binding : hotkey_config.bindings) {
            const UINT id = 100 + static_cast<UINT>(&binding -
                                                    hotkey_config.bindings.data());
            if (!::RegisterHotKey(hotkey_window, id,
                                  binding.hotkey.modifiers | MOD_NOREPEAT,
                                  binding.hotkey.vk)) {
                Field("result", "ENVIRONMENT-BLOCKED");
                Field("reason", "hotkey registration failed (already bound?)");
                return kExitInconclusive;
            }
        }
        NOTIFYICONDATAW tray_data{};
        tray_data.cbSize = sizeof(tray_data);
        tray_data.hWnd = hotkey_window;
        tray_data.uID = 1;
        tray_data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        tray_data.uCallbackMessage = kManagerTrayMessage;
        tray_data.hIcon = ::LoadIconW(nullptr, IDI_APPLICATION);
        wcscpy_s(tray_data.szTip, L"vdprobe workspace manager");
        const bool tray_added =
            ::Shell_NotifyIconW(NIM_ADD, &tray_data) != FALSE;
        Field("tray icon", tray_added ? "added" : "unavailable (recorded)");
        ::SetTimer(hotkey_window, kManagerReconcileTimerId,
                   kManagerReconcileIntervalMs, nullptr);
        if (seconds > 0) {
            ::SetTimer(hotkey_window, kManagerShutdownTimerId,
                       static_cast<UINT>(seconds) * 1000U, nullptr);
        }
        Field("run mode", seconds > 0
                              ? std::format("bounded {}s", seconds)
                              : "unbounded (stop via --stop or tray Exit)");
        if (self_resilience) {
            // Post the resilience events to our own window: identical message
            // path to external display-change / resume delivery.
            ::PostMessageW(hotkey_window, WM_DISPLAYCHANGE, 0, 0);
            ::PostMessageW(hotkey_window, WM_POWERBROADCAST,
                           static_cast<WPARAM>(PBT_APMRESUMESUSPEND), 0);
        }

        MSG message{};
        bool loop_error = false;
        while (!main_context.exit_requested) {
            const int result = ::GetMessageW(&message, nullptr, 0, 0);
            if (result < 0) {
                loop_error = true;
                break;
            }
            if (result == 0) break;
            ::TranslateMessage(&message);
            ::DispatchMessageW(&message);
        }
        ::KillTimer(hotkey_window, kManagerReconcileTimerId);
        ::KillTimer(hotkey_window, kManagerShutdownTimerId);
        for (const WorkspaceHotkeyBinding& binding : hotkey_config.bindings) {
            const UINT id = 100 + static_cast<UINT>(&binding -
                                                    hotkey_config.bindings.data());
            ::UnregisterHotKey(hotkey_window, id);
        }
        if (tray_added) {
            ::Shell_NotifyIconW(NIM_DELETE, &tray_data);
        }
        ::DestroyWindow(hotkey_window);

        Field("uptime reconciliations", std::format("{}", reconcile_count));
        Field("hotkey dispatches", std::format("{}", hotkey_dispatches));
        Field("switches committed", std::format("{}", switches_committed));
        Field("quarantine entries",
              std::format("{}", engine.QuarantineLog().size()));
        Field("display changes handled",
              std::format("{}", resilience.display_changes_handled));
        Field("resume events handled",
              std::format("{}", resilience.resume_events_handled));
        Field("shell reacquire attempts",
              std::format("{}", resilience.shell_reacquire_attempts));
        Field("host degraded", resilience.degraded ? "yes" : "no");
        std::string pending_error;
        const std::optional<SwitchPlan> pending =
            journal.ReadPending(&pending_error);
        bool ok = !loop_error && !pending && pending_error.empty() &&
                  engine.CheckInvariant(&error);
        const bool restored_here = restore_and_close();
        restoration_done = true;
        restored_result = restored_here;
        ok = ok && restored_here;
        source.Stop();
        ok = ok && source.shutdown_ok();
        Field("probe cleanup/restoration", restored_here ? "PASS" : "FAIL");
        Field("stable journal pending", pending ? "YES" : "no");
        if (!ok && !error.empty()) {
            Field("failure reason", error);
        }
        return ok ? 0 : 1;
    }();
    } catch (const std::exception& exception) {
        Field("integration error", std::format("exception: {}", exception.what()));
    } catch (...) {
        Field("integration error", "unknown exception");
    }

    const bool restored =
        restoration_done ? restored_result : restore_and_close();
    const bool passed = integration_rc == 0 && restored;
    Field("mutation_started", mutation_started ? "yes" : "no");
    Field("result", passed ? "PASS" : "FAIL");
    Print("mutation_started={}\n", mutation_started ? "yes" : "no");
    Print("RESULT={}\n", passed ? "PASS" : "FAIL");
    release_mutex();
    return passed ? 0 : 1;
}

int CmdWorkspaceManagerStop() {
    HWND hwnd = ::FindWindowW(kManagerMainClassName, nullptr);
    if (hwnd == nullptr) {
        Print("no workspace-manager window found\n");
        return 1;
    }
    if (!::PostMessageW(hwnd, WM_CLOSE, 0, 0)) {
        Print("failed to post shutdown to workspace-manager\n");
        return 1;
    }
    Print("shutdown requested\n");
    return 0;
}

int CmdWorkspaceManagerReload() {
    HWND hwnd = ::FindWindowW(kManagerMainClassName, nullptr);
    if (hwnd == nullptr) {
        Print("no workspace-manager window found\n");
        return 1;
    }
    if (!::PostMessageW(hwnd, WM_APP + 2, 0, 0)) {
        Print("failed to post reload to workspace-manager\n");
        return 1;
    }
    Print("reload requested\n");
    return 0;
}

int CmdWorkspaceManagerInstallStartup(bool remove,
                                      const char* config_path) {
    constexpr wchar_t kRunKey[] =
        L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    constexpr wchar_t kValueName[] = L"VdprobeWorkspaceManager";
    HKEY key = nullptr;
    const LONG open_result = ::RegOpenKeyExW(
        HKEY_CURRENT_USER, kRunKey, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &key);
    if (open_result != ERROR_SUCCESS) {
        Field("result", "ERROR");
        Field("reason", std::format("cannot open HKCU Run key (Win32 {})",
                                    open_result));
        return 1;
    }
    if (remove) {
        const LONG delete_result = ::RegDeleteValueW(key, kValueName);
        ::RegCloseKey(key);
        const bool ok = delete_result == ERROR_SUCCESS ||
                        delete_result == ERROR_FILE_NOT_FOUND;
        Field("startup entry", ok ? "removed" : "REMOVE FAILED");
        Field("result", ok ? "PASS" : "FAIL");
        return ok ? 0 : 1;
    }
    wchar_t module[MAX_PATH] = {};
    const DWORD module_size = ::GetModuleFileNameW(nullptr, module, MAX_PATH);
    if (module_size == 0 || module_size >= MAX_PATH) {
        ::RegCloseKey(key);
        Field("result", "ERROR");
        Field("reason", "cannot resolve executable path");
        return 1;
    }
    std::wstring command = L"\"" + std::wstring(module) +
                           L"\" workspace-manager --run";
    if (config_path != nullptr && *config_path != '\0') {
        command += L" --config \"" + ToWide(config_path) + L"\"";
    }
    const LONG set_result = ::RegSetValueExW(
        key, kValueName, 0, REG_SZ,
        reinterpret_cast<const BYTE*>(command.c_str()),
        static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
    ::RegCloseKey(key);
    if (set_result != ERROR_SUCCESS) {
        Field("result", "ERROR");
        Field("reason", std::format("cannot write HKCU Run value (Win32 {})",
                                    set_result));
        return 1;
    }
    Field("startup entry", "installed (HKCU Run)");
    Field("command", ToUtf8(command));
    Field("result", "PASS");
    return 0;
}

int CmdWorkspaceManagerDiagnostics(const char* config_path) {
    Heading("workspace-manager diagnostics");
    Print("version: vdprobe 0.1.0 (per-monitor workspace manager)\n");

    using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOW*);
    const auto rtl_get_version = []() -> RtlGetVersionFn {
        HMODULE module = ::GetModuleHandleW(L"ntdll.dll");
        return module == nullptr
                   ? nullptr
                   : reinterpret_cast<RtlGetVersionFn>(
                         ::GetProcAddress(module, "RtlGetVersion"));
    }();
    if (rtl_get_version != nullptr) {
        OSVERSIONINFOW info{};
        info.dwOSVersionInfoSize = sizeof(info);
        if (rtl_get_version(&info) == 0) {
            Print("windows build: {}.{}.{}\n", info.dwMajorVersion,
                  info.dwMinorVersion, info.dwBuildNumber);
        }
    }

    const std::vector<MonitorRec> monitors = EnumerateMonitors();
    Print("monitors: {}\n", monitors.size());
    for (const MonitorRec& monitor : monitors) {
        Print("  {} work=({},{})-({},{})\n", ToUtf8(monitor.device),
              monitor.work.left, monitor.work.top, monitor.work.right,
              monitor.work.bottom);
    }

    if (config_path != nullptr && *config_path != '\0') {
        WorkspaceManagerConfig config;
        std::string error;
        if (LoadManagerConfig(std::filesystem::path(config_path), config,
                              &error)) {
            Print("config: {} (monitors={}, hotkeys={}, migration={}, "
                  "quarantine={}, log-level={})\n",
                  config_path, config.monitors.size(), config.bindings.size(),
                  config.migration_policy ==
                          MonitorMigrationPolicy::ReassignToDestinationActive
                      ? "reassign"
                      : "fail-closed",
                  config.quarantine_enabled ? "on" : "off",
                  config.log_level == ManagerLogLevel::Debug
                      ? "debug"
                      : config.log_level == ManagerLogLevel::Info
                            ? "info"
                            : config.log_level == ManagerLogLevel::Warn
                                  ? "warn"
                                  : "error");
        } else {
            Print("config: {} (INVALID: {})\n", config_path, error);
        }
    } else {
        Print("config: none (built-in defaults)\n");
    }

    const std::filesystem::path journal_path =
        std::filesystem::temp_directory_path() /
        "vdprobe-workspace-manager.journal";
    WorkspaceJournal journal(journal_path);
    std::string journal_error;
    const std::optional<SwitchPlan> pending =
        journal.ReadPending(&journal_error);
    Print("journal: {} (pending={}, error={})\n", journal_path.string(),
          pending ? "yes" : "no",
          journal_error.empty() ? "none" : journal_error);
    Field("result", "OK");
    return 0;
}

// ------------------------------------------- production host (real windows)

int CmdWorkspaceManagerRun(const char* config_path, int seconds,
                           bool self_resilience, bool confirm_mutate,
                           bool probe_gate) {
    if (probe_gate) {
        return CmdWorkspaceManagerRunProbeGate(config_path, seconds,
                                               self_resilience, confirm_mutate);
    }

    Heading("workspace-manager --run");
    Field("mode", "production: real top-level windows");
    Field("global desktop switch", "never called");
    Field("desktop lifecycle", "no create/remove");

    if (!confirm_mutate) {
        Field("gate", GateText(Gate::Mutating));
        Print("\n  Refusing the production manager without --confirm-mutate.\n"
              "\n      vdprobe workspace-manager --run --confirm-mutate "
              "[--config PATH]\n");
        return 1;
    }

    HANDLE mutex = ::CreateMutexW(nullptr, FALSE, kManagerMutexName);
    if (mutex == nullptr) {
        Field("result", "ERROR");
        Field("reason", "single-instance mutex unavailable");
        return 1;
    }
    if (::GetLastError() == ERROR_ALREADY_EXISTS) {
        Print("another workspace-manager instance is already running\n");
        ::CloseHandle(mutex);
        return 0;
    }
    auto release_mutex = [&]() { ::CloseHandle(mutex); };

    const std::vector<MonitorRec> monitors = EnumerateMonitors();
    if (monitors.size() < 2) {
        Field("result", "ERROR");
        Field("reason", "at least two monitors are required");
        release_mutex();
        return 1;
    }
    for (const MonitorRec& monitor : monitors) {
        Field("monitor", ToUtf8(monitor.device));
    }

    WorkspaceManagerConfig config;
    std::filesystem::path config_file;
    if (config_path != nullptr && *config_path != '\0') {
        config_file = config_path;
        std::string load_error;
        if (!LoadManagerConfig(config_file, config, &load_error)) {
            Field("result", "ERROR");
            Field("reason", "config load failed: " + load_error);
            release_mutex();
            return 1;
        }
    } else {
        config_file = DefaultManagerConfigPath();
        if (std::filesystem::exists(config_file)) {
            std::string load_error;
            if (!LoadManagerConfig(config_file, config, &load_error)) {
                Field("result", "ERROR");
                Field("reason", "default config load failed: " + load_error);
                release_mutex();
                return 1;
            }
        } else {
            config.schema_version = 1;
            config.monitors = {
                {static_cast<MonitorId>(1), {"A1", "A2"}, "A1"},
                {static_cast<MonitorId>(2), {"B1"}, "B1"},
            };
            config.bindings = {
                {{MOD_CONTROL | MOD_ALT, VK_F9},
                 static_cast<MonitorId>(1), 2},
                {{MOD_CONTROL | MOD_ALT, VK_F10},
                 static_cast<MonitorId>(1), 1},
            };
            config.migration_policy =
                MonitorMigrationPolicy::ReassignToDestinationActive;
            config.log_level = ManagerLogLevel::Info;
            config.quarantine_enabled = true;
            config.tray_icon = true;
            config.journal_path =
                std::filesystem::temp_directory_path() /
                "vdprobe-workspace-manager.journal";
            std::error_code mkdir_error;
            std::filesystem::create_directories(config_file.parent_path(),
                                                mkdir_error);
            std::string save_error;
            if (!SaveManagerConfig(config, config_file, &save_error)) {
                Print("warning: could not write default config {}: {}\n",
                      config_file.string(), save_error);
            }
        }
    }
    Field("config", config_file.string());

    std::vector<HMONITOR> real_monitors;
    for (const MonitorRec& monitor : monitors) {
        real_monitors.push_back(monitor.handle);
    }
    ManagerRuntimeTopology topology;
    std::string topology_error;
    if (!DeriveManagerRuntimeTopology(config, real_monitors, topology,
                                      &topology_error)) {
        Field("result", "ERROR");
        Field("reason", "config topology failed: " + topology_error);
        release_mutex();
        return 1;
    }
    if (topology.monitors.size() < 2) {
        Field("result", "ERROR");
        Field("reason", "config must define at least two monitors");
        release_mutex();
        return 1;
    }
    Field("configured monitors", std::format("{}", topology.monitors.size()));
    Field("hotkey bindings", std::format("{}", topology.bindings.size()));

    const std::filesystem::path journal_path =
        config.journal_path.empty()
            ? std::filesystem::temp_directory_path() /
                  "vdprobe-workspace-manager.journal"
            : config.journal_path;
    WorkspaceJournal journal(journal_path);
    std::string journal_error;
    const std::optional<SwitchPlan> existing_pending =
        journal.ReadPending(&journal_error);
    if (!journal_error.empty() || existing_pending) {
        Field("journal", journal_path.string());
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason",
              !journal_error.empty()
                  ? "stable journal could not be read: " + journal_error
                  : "stable journal contains a pending transaction; startup "
                    "recovery is wired in the next milestone");
        release_mutex();
        return kExitInconclusive;
    }
    Field("journal", journal_path.string());

    Com<IServiceProvider> sp;
    const HRESULT shell_hr = GetImmersiveShell(sp);
    if (FAILED(shell_hr) || !sp) {
        Field("result", shell_hr == E_ACCESSDENIED ? "ENVIRONMENT-BLOCKED"
                                                   : "ERROR");
        Field("reason", std::format("ImmersiveShell unavailable ({})",
                                    HrToString(shell_hr)));
        release_mutex();
        return shell_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
    }
    ManagerInternal manager = AcquireManagerInternal(sp.Get());
    if (!manager.obj || manager.layout == nullptr) {
        Field("result", manager.access_denied_seen ? "ENVIRONMENT-BLOCKED"
                                                   : "ERROR");
        Field("reason", "usable IVirtualDesktopManagerInternal unavailable");
        release_mutex();
        return manager.access_denied_seen ? kExitInconclusive : 1;
    }
    DesktopSnapshot carrier;
    HRESULT current_hr = E_ABORT;
    if (!ReadCurrentDesktop(manager, carrier, &current_hr)) {
        Field("result", current_hr == E_ACCESSDENIED ? "ENVIRONMENT-BLOCKED"
                                                     : "ERROR");
        Field("reason", "current Carrier unavailable");
        release_mutex();
        return current_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
    }
    std::vector<DesktopSnapshot> desktops;
    HRESULT desktops_hr = E_ABORT;
    if (!ReadDesktopList(manager, desktops, &desktops_hr)) {
        Field("result", desktops_hr == E_ACCESSDENIED ? "ENVIRONMENT-BLOCKED"
                                                      : "ERROR");
        Field("reason", "existing desktop enumeration failed");
        release_mutex();
        return desktops_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
    }
    DesktopSnapshot parking;
    for (DesktopSnapshot& desktop : desktops) {
        if (desktop.id_ok && !::IsEqualGUID(desktop.id, carrier.id)) {
            parking = std::move(desktop);
            break;
        }
    }
    if (!parking.id_ok || !parking.object) {
        Field("result", "ENVIRONMENT-BLOCKED");
        Field("reason", "no existing inactive Parking desktop");
        release_mutex();
        return kExitInconclusive;
    }
    ApplicationViewCollectionBinding views =
        AcquireApplicationViewCollection(sp.Get());
    const MethodEntry* get_view =
        views.layout == nullptr ? nullptr
                                : FindMethod(*views.layout, "GetViewForHwnd");
    const MethodEntry* can_move =
        FindMethod(*manager.layout, "CanViewMoveDesktops");
    if (!views.object || get_view == nullptr || can_move == nullptr) {
        Field("result", views.access_denied_seen ? "ENVIRONMENT-BLOCKED"
                                                 : "ERROR");
        Field("reason", "application-view capability APIs unavailable");
        release_mutex();
        return views.access_denied_seen ? kExitInconclusive : 1;
    }
    Com<IVirtualDesktopManager> documented_manager;
    const HRESULT documented_hr = ::CoCreateInstance(
        CLSID_VirtualDesktopManager, nullptr,
        CLSCTX_LOCAL_SERVER | CLSCTX_INPROC_SERVER,
        IID_IVirtualDesktopManager, documented_manager.PutVoid());
    if (FAILED(documented_hr) || !documented_manager) {
        Field("result", documented_hr == E_ACCESSDENIED ? "ENVIRONMENT-BLOCKED"
                                                        : "ERROR");
        Field("reason", std::format("IVirtualDesktopManager unavailable ({})",
                                    HrToString(documented_hr)));
        release_mutex();
        return documented_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
    }

    auto acquire_view = [&](HWND hwnd, RawObject& out,
                            std::string* error = nullptr) -> bool {
        PumpStaMessages();
        Gate last_gate = Gate::Ok;
        HRESULT last_hr = InvokeSlot(
            views.object.Get(), *views.layout, *get_view, last_gate, false,
            hwnd, out.PutVoid());
        if (last_gate == Gate::Ok && SUCCEEDED(last_hr) && out) return true;
        if (error != nullptr) {
            *error = std::format("GetViewForHwnd 0x{:X} failed: gate={} hr={}",
                                 reinterpret_cast<std::uintptr_t>(hwnd),
                                 GateText(last_gate), HrToString(last_hr));
        }
        return false;
    };
    auto view_can_move = [&](IUnknown* view, std::string* error = nullptr) {
        Gate gate = Gate::Ok;
        BOOL value = FALSE;
        const HRESULT hr = InvokeSlot(manager.obj.Get(), *manager.layout,
                                      *can_move, gate, false, view, &value);
        if (gate == Gate::Ok && SUCCEEDED(hr) && value != FALSE) return true;
        if (error != nullptr) {
            *error = std::format("CanViewMoveDesktops failed: gate={} hr={}",
                                 GateText(gate), HrToString(hr));
        }
        return false;
    };

    auto observe_role = [&](const WindowRecord& record) {
        WindowIdentity current;
        if (!ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity) {
            return NativeDesktopRole::Unknown;
        }
        WindowDesktopState state;
        if (!ReadWindowDesktopState(documented_manager.Get(),
                                    record.identity.hwnd, state)) {
            return NativeDesktopRole::Unknown;
        }
        if (::IsEqualGUID(state.desktop, carrier.id) && state.on_current) {
            return NativeDesktopRole::Carrier;
        }
        if (::IsEqualGUID(state.desktop, parking.id) && !state.on_current) {
            return NativeDesktopRole::Parking;
        }
        return NativeDesktopRole::Unknown;
    };
    auto move_to_role = [&](const WindowRecord& record,
                            NativeDesktopRole target) -> bool {
        WindowIdentity current;
        if (!ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity) {
            return false;
        }
        RawObject view;
        std::string error;
        if (!acquire_view(record.identity.hwnd, view, &error) ||
            !view_can_move(view.Get(), &error)) {
            return false;
        }
        IUnknown* target_object =
            target == NativeDesktopRole::Carrier ? carrier.object.Get()
            : target == NativeDesktopRole::Parking ? parking.object.Get()
                                                    : nullptr;
        const GUID* target_id =
            target == NativeDesktopRole::Carrier ? &carrier.id
            : target == NativeDesktopRole::Parking ? &parking.id : nullptr;
        if (target_object == nullptr || target_id == nullptr) return false;
        Gate gate = Gate::Ok;
        HRESULT hr = E_ABORT;
        return MoveViewToDesktopAndWait(
            manager, view.Get(), target_object, record.identity.hwnd,
            documented_manager.Get(), *target_id, carrier.id, confirm_mutate,
            gate, hr);
    };

    std::string error;
    WorkspaceEngine engine(carrier.id, parking.id);
    for (const ManagerRuntimeTopology::MonitorBinding& binding :
         topology.monitors) {
        if (!engine.AddMonitor(binding.real_monitor, binding.active,
                               binding.workspace_ids, &error)) {
            Field("result", "ERROR");
            Field("reason", "engine monitor setup failed: " + error);
            release_mutex();
            return 1;
        }
    }
    engine.SetAutoQuarantine(config.quarantine_enabled);
    WorkspaceAssignmentAdapter assignment(engine);
    assignment.SetMonitorMigrationPolicy(config.migration_policy);
    for (const ManagerRuntimeTopology::MonitorBinding& binding :
         topology.monitors) {
        if (!assignment.ConfigureMonitor(binding.real_monitor, binding.active,
                                         binding.workspace_ids, &error)) {
            Field("result", "ERROR");
            Field("reason", "assignment setup failed: " + error);
            release_mutex();
            return 1;
        }
    }

    bool capability_access_denied = false;
    Win32WindowDiscoveryOptions options;
    options.carrier = carrier.id;
    options.parking = parking.id;
    options.augment_capabilities =
        [&](HWND hwnd, const WindowDiscoveryObservation& observation,
            WindowCapabilities& capabilities, std::string* aug_error) {
            (void)observation;
            RawObject view;
            if (!acquire_view(hwnd, view, aug_error)) {
                // Windows without a usable IApplicationView are Unsupported,
                // not discovery failures.
                return true;
            }
            capabilities.has_application_view = true;
            Gate gate = Gate::Ok;
            BOOL value = FALSE;
            const HRESULT hr = InvokeSlot(
                manager.obj.Get(), *manager.layout, *can_move, gate, false,
                view.Get(), &value);
            if (hr == E_ACCESSDENIED) capability_access_denied = true;
            if (gate != Gate::Ok || FAILED(hr)) {
                capabilities.can_move_desktops = false;
                return true;
            }
            capabilities.can_move_desktops = value != FALSE;
            return true;
        };
    HRESULT backend_hr = S_OK;
    auto backend = CreateSystemWindowDiscoveryBackend(
        std::move(options), &error, &backend_hr);
    if (!backend) {
        Field("result", backend_hr == E_ACCESSDENIED ? "ENVIRONMENT-BLOCKED"
                                                     : "ERROR");
        Field("reason", error);
        release_mutex();
        return backend_hr == E_ACCESSDENIED ? kExitInconclusive : 1;
    }
    WindowDiscovery discovery(std::move(*backend));

    auto discover_assigned = [&](std::vector<WindowRecord>& records,
                                 std::string* local_error) {
        std::vector<DiscoveredWindow> complete;
        if (!discovery.Discover(complete, local_error) ||
            !assignment.ConvertCompleteSnapshot(complete, records,
                                                local_error)) {
            return false;
        }
        return true;
    };
    auto observe_owned = [&](HWND hwnd) -> std::optional<WindowRecord> {
        std::vector<WindowRecord> records;
        std::string local_error;
        if (!discover_assigned(records, &local_error)) return std::nullopt;
        const auto found = std::find_if(
            records.begin(), records.end(),
            [hwnd](const WindowRecord& record) {
                return record.identity.hwnd == hwnd;
            });
        return found == records.end() ? std::nullopt
                                      : std::optional<WindowRecord>(*found);
    };

    WindowLifecycleAdapter lifecycle(engine, observe_owned);
    WinEventLifecycleSource source;
    if (!source.Start(&error)) {
        Field("result", "ERROR");
        Field("reason", "lifecycle source failed: " + error);
        release_mutex();
        return 1;
    }
    auto coordinator_discovery = [&](std::vector<WindowRecord>& records,
                                     std::string* local_error) {
        if (!source.PumpOwnerThreadMessages(local_error)) return false;
        return discover_assigned(records, local_error);
    };
    WorkspaceCoordinator coordinator(
        engine, lifecycle, source, coordinator_discovery, move_to_role,
        observe_role, &journal, 10, 5);

    const CoordinatorResult initial = coordinator.ReconcileDiscovery();
    if (!initial.succeeded()) {
        Field("result", capability_access_denied ? "ENVIRONMENT-BLOCKED"
                                                 : "ERROR");
        Field("reason", "initial reconcile failed: " + initial.error);
        source.Stop();
        release_mutex();
        return capability_access_denied ? kExitInconclusive : 1;
    }
    if (!engine.CheckInvariant(&error)) {
        Field("result", "ERROR");
        Field("reason", "initial invariant failed: " + error);
        source.Stop();
        release_mutex();
        return 1;
    }
    std::size_t managed_count = 0;
    for (const WindowRecord* window : engine.Windows()) {
        if (window->disposition == WindowDisposition::Managed) {
            ++managed_count;
        }
    }
    Field("managed windows (initial)", std::format("{}", managed_count));

    MonitorTopologyMapper topology_mapper;
    std::vector<MonitorTopologyMapper::BoundMonitor> bound_monitors;
    std::vector<std::size_t> missing_monitors;
    HostResilienceState resilience;
    resilience.monitor_present.assign(topology.monitors.size(), true);
    bool degraded = false;
    auto refresh_topology = [&]() {
        const std::vector<MonitorRec> current = EnumerateMonitors();
        std::vector<std::pair<MonitorId, std::string>> real;
        for (const MonitorRec& monitor : current) {
            real.push_back({reinterpret_cast<MonitorId>(monitor.handle),
                            ToUtf8(monitor.device)});
        }
        topology_mapper.Update(real, bound_monitors, missing_monitors,
                               topology.monitors.size());
        std::vector<bool> present(topology.monitors.size(), false);
        for (const auto& entry : bound_monitors) {
            if (entry.config_index < present.size()) {
                present[entry.config_index] = true;
            }
        }
        resilience.monitor_present = std::move(present);
        degraded = degraded || !missing_monitors.empty();
    };
    {
        const std::vector<MonitorRec> current = EnumerateMonitors();
        std::vector<std::pair<MonitorId, std::string>> real;
        for (const MonitorRec& monitor : current) {
            real.push_back({reinterpret_cast<MonitorId>(monitor.handle),
                            ToUtf8(monitor.device)});
        }
        topology_mapper.Update(real, bound_monitors, missing_monitors,
                               topology.monitors.size());
        degraded = !missing_monitors.empty();
    }

    std::size_t reconcile_count = 0;
    std::size_t hotkey_dispatches = 0;
    std::size_t switches_committed = 0;
    HWND hotkey_window = nullptr;
    auto native_invariant_ok = [&]() {
        GUID current{};
        return ReadCurrentDesktopId(manager, current) &&
               ::IsEqualGUID(current, carrier.id);
    };
    auto refresh_focus_snapshots = [&]() {
        for (const ManagerRuntimeTopology::MonitorBinding& binding :
             topology.monitors) {
            const MonitorWorkspaceState* state =
                engine.Monitor(binding.real_monitor);
            if (state == nullptr) continue;
            for (WorkspaceId workspace : state->workspaces) {
                const WorkspaceDefinition* definition =
                    engine.Workspace(workspace);
                if (definition == nullptr) continue;
                std::vector<std::pair<std::int64_t, WindowIdentity>> ordered;
                for (const WindowIdentity& identity : definition->windows) {
                    const WindowRecord* record = engine.FindWindow(identity);
                    if (record != nullptr &&
                        record->disposition == WindowDisposition::Managed &&
                        record->capabilities.Manageable() &&
                        record->presentation.placement_valid) {
                        ordered.push_back(
                            {record->presentation.z_order, identity});
                    }
                }
                std::stable_sort(
                    ordered.begin(), ordered.end(),
                    [](const auto& left, const auto& right) {
                        return left.first < right.first;
                    });
                if (ordered.empty()) continue;
                std::vector<WindowIdentity> members;
                for (const auto& entry : ordered) {
                    members.push_back(entry.second);
                }
                std::string local_error;
                if (!engine.SetZOrder(binding.real_monitor, workspace,
                                      members, &local_error)) {
                    Print("focus snapshot error: {}\n", local_error);
                    continue;
                }
                for (const auto& entry : ordered) {
                    const WindowRecord* record =
                        engine.FindWindow(entry.second);
                    if (record != nullptr &&
                        record->presentation.foreground) {
                        (void)engine.SetLastForeground(
                            binding.real_monitor, workspace, entry.second,
                            &local_error);
                        break;
                    }
                }
            }
        }
    };
    auto apply_production_presentation =
        [&](const WindowRecord& record,
            const PresentationOperation& operation) -> bool {
        WindowIdentity current;
        if (!ReadWindowIdentity(record.identity.hwnd, current) ||
            current != record.identity ||
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
                return ::SetWindowPos(
                           record.identity.hwnd, HWND_TOP, 0, 0, 0, 0,
                           SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE |
                               SWP_NOOWNERZORDER) != FALSE;
            case PresentationOperationKind::RestoreForeground:
                return ::SetForegroundWindow(record.identity.hwnd) != FALSE;
        }
        return false;
    };
    auto restore_presentation = [&](MonitorId monitor, WorkspaceId workspace) {
        std::string restore_error;
        const std::optional<PresentationPlan> plan =
            engine.PreparePresentationRestore(monitor, workspace,
                                              &restore_error);
        if (!plan) return;
        const PresentationResult result = engine.ExecutePresentationRestore(
            *plan,
            [&](const WindowRecord& record) {
                WindowIdentity current;
                return record.disposition == WindowDisposition::Managed &&
                       record.capabilities.Manageable() &&
                       ReadWindowIdentity(record.identity.hwnd, current) &&
                       current == record.identity;
            },
            apply_production_presentation);
        if (!result.completed && !result.error.empty()) {
            Print("presentation restore error: {}\n", result.error);
        }
    };
    auto do_switch = [&](MonitorId monitor, WorkspaceId target) {
        if (degraded) {
            Field("switch blocked", "host degraded");
            return;
        }
        if (!native_invariant_ok()) {
            Field("switch blocked",
                  "global current desktop != Carrier (degraded)");
            degraded = true;
            return;
        }
        std::size_t config_index = topology.monitors.size();
        for (std::size_t i = 0; i < topology.monitors.size(); ++i) {
            if (topology.monitors[i].real_monitor == monitor) {
                config_index = i;
                break;
            }
        }
        if (config_index >= resilience.monitor_present.size() ||
            !resilience.monitor_present[config_index]) {
            Field("switch blocked", "monitor suspended");
            return;
        }
        CoordinatorResult result = coordinator.Switch(monitor, target);
        if (!result.succeeded() && result.transaction.rollback_succeeded &&
            !result.transaction.recovery_required &&
            result.code != CoordinatorResultCode::PlanRejected) {
            result = coordinator.Switch(monitor, target);
        }
        if (result.succeeded() && result.transaction.committed) {
            ++switches_committed;
            refresh_focus_snapshots();
            restore_presentation(monitor, target);
        } else if (!result.error.empty()) {
            Print("switch error: {}\n", result.error);
        }
    };

    std::vector<std::pair<int, std::pair<MonitorId, WorkspaceId>>>
        tray_commands;
    int next_tray_command = 10;
    for (const ManagerRuntimeTopology::MonitorBinding& binding :
         topology.monitors) {
        for (WorkspaceId workspace : binding.workspace_ids) {
            tray_commands.push_back(
                {next_tray_command++, {binding.real_monitor, workspace}});
        }
    }

    ManagerMainContext main_context;
    main_context.hotkey_handler = [&](UINT modifiers, UINT vk) {
        MonitorId monitor = 0;
        WorkspaceId workspace = 0;
        if (!ResolveWorkspaceHotkey(config, modifiers, vk, monitor,
                                    workspace)) {
            return true;
        }
        ++hotkey_dispatches;
        do_switch(monitor, workspace);
        return true;
    };
    main_context.reconcile_handler = [&]() {
        ++reconcile_count;
        if (!native_invariant_ok()) {
            degraded = true;
            return;
        }
        const CoordinatorResult result = coordinator.ReconcileDiscovery();
        if (!result.succeeded() && !result.error.empty()) {
            Print("periodic reconcile error: {}\n", result.error);
            degraded = true;
        }
    };
    main_context.status_text = [&]() {
        std::string text = "active:";
        for (const ManagerRuntimeTopology::MonitorBinding& binding :
             topology.monitors) {
            const MonitorWorkspaceState* state =
                engine.Monitor(binding.real_monitor);
            text += " " + std::to_string(state ? state->active : 0);
        }
        return text + std::format(" reconciles={} switches={} quarantine={}",
                                  reconcile_count, switches_committed,
                                  engine.QuarantineLog().size());
    };
    main_context.menu_builder = [&](HMENU menu) {
        for (const auto& entry : tray_commands) {
            const std::wstring label =
                L"Switch monitor " +
                std::to_wstring(static_cast<std::uint64_t>(
                    entry.second.first)) +
                L" -> workspace " +
                std::to_wstring(entry.second.second);
            ::AppendMenuW(menu, MF_STRING, entry.first, label.c_str());
        }
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, 1001, L"Status");
        ::AppendMenuW(menu, MF_STRING, 1002, L"Diagnostics");
        ::AppendMenuW(menu, MF_STRING, 1003, L"Reload configuration");
        ::AppendMenuW(menu, MF_STRING, 1004, L"Exit");
    };
    main_context.tray_command_handler = [&](int command) {
        if (command >= 10 && command < 1000) {
            for (const auto& entry : tray_commands) {
                if (entry.first == command) {
                    do_switch(entry.second.first, entry.second.second);
                    break;
                }
            }
        } else if (command == 1001) {
            if (main_context.status_text) {
                Print("status: {}\n", main_context.status_text());
            }
        } else if (command == 1002) {
            if (main_context.status_text) {
                Print("diagnostics: {}\n", main_context.status_text());
            }
        } else if (command == 1003) {
            if (main_context.reload_handler) {
                main_context.reload_handler();
            }
        } else if (command == 1004) {
            main_context.exit_requested = true;
            ::PostMessageW(hotkey_window, WM_CLOSE, 0, 0);
        }
    };
    main_context.reload_handler = [&]() {
        WorkspaceManagerConfig reloaded;
        std::string reload_error;
        if (!LoadManagerConfig(config_file, reloaded, &reload_error)) {
            Print("config reload REJECTED (kept previous): {}\n",
                  reload_error);
            return;
        }
        ManagerRuntimeTopology new_topology;
        if (!DeriveManagerRuntimeTopology(reloaded, real_monitors,
                                          new_topology, &reload_error)) {
            Print("config reload REJECTED (kept previous): {}\n",
                  reload_error);
            return;
        }
        if (new_topology.monitors.size() != topology.monitors.size()) {
            Print("config reload REJECTED (kept previous): monitor topology "
                  "changes require a restart\n");
            return;
        }
        WorkspaceManagerConfig staged = reloaded;
        staged.bindings = new_topology.bindings;
        std::vector<std::pair<UINT, WorkspaceHotkey>> staged_registered;
        UINT id = 100;
        bool all_registered = true;
        for (const WorkspaceHotkeyBinding& binding : staged.bindings) {
            if (!::RegisterHotKey(hotkey_window, id,
                                  binding.hotkey.modifiers | MOD_NOREPEAT,
                                  binding.hotkey.vk)) {
                all_registered = false;
                break;
            }
            staged_registered.push_back({id, binding.hotkey});
            ++id;
        }
        if (!all_registered) {
            for (const auto& entry : staged_registered) {
                ::UnregisterHotKey(hotkey_window, entry.first);
            }
            Print("config reload REJECTED (kept previous): hotkey conflict\n");
            return;
        }
        for (const WorkspaceHotkeyBinding& binding : config.bindings) {
            const UINT old_id =
                100 + static_cast<UINT>(&binding - config.bindings.data());
            ::UnregisterHotKey(hotkey_window, old_id);
        }
        config = staged;
        topology = new_topology;
        engine.SetAutoQuarantine(config.quarantine_enabled);
        assignment.SetMonitorMigrationPolicy(config.migration_policy);
        Print("config reload accepted ({} hotkeys, quarantine={})\n",
              config.bindings.size(),
              config.quarantine_enabled ? "on" : "off");
    };
    main_context.display_change_handler = [&]() {
        ++resilience.display_changes_handled;
        refresh_topology();
    };
    main_context.resume_handler = [&]() {
        ++resilience.resume_events_handled;
        refresh_topology();
        if (!native_invariant_ok()) {
            degraded = true;
            ++resilience.shell_reacquire_attempts;
        }
    };

    if (!EnsureManagerMainClass()) {
        Field("result", "ERROR");
        Field("reason", "manager main window class unavailable");
        source.Stop();
        release_mutex();
        return 1;
    }
    hotkey_window = ::CreateWindowExW(
        WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE, kManagerMainClassName,
        L"vdprobe-workspace-manager", WS_OVERLAPPED, 0, 0, 0, 0, nullptr,
        nullptr, ::GetModuleHandleW(nullptr), nullptr);
    if (hotkey_window == nullptr) {
        Field("result", "ERROR");
        Field("reason", "manager main window unavailable");
        source.Stop();
        release_mutex();
        return 1;
    }
    ::SetWindowLongPtrW(hotkey_window, GWLP_USERDATA,
                        reinterpret_cast<LONG_PTR>(&main_context));
    UINT hotkey_id = 100;
    for (const WorkspaceHotkeyBinding& binding : config.bindings) {
        if (!::RegisterHotKey(hotkey_window, hotkey_id,
                              binding.hotkey.modifiers | MOD_NOREPEAT,
                              binding.hotkey.vk)) {
            Field("result", "ENVIRONMENT-BLOCKED");
            Field("reason", "hotkey registration failed (already bound?)");
            source.Stop();
            release_mutex();
            return kExitInconclusive;
        }
        ++hotkey_id;
    }
    NOTIFYICONDATAW tray_data{};
    bool tray_added = false;
    if (config.tray_icon) {
        tray_data.cbSize = sizeof(tray_data);
        tray_data.hWnd = hotkey_window;
        tray_data.uID = 1;
        tray_data.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
        tray_data.uCallbackMessage = kManagerTrayMessage;
        tray_data.hIcon = ::LoadIconW(nullptr, IDI_APPLICATION);
        wcscpy_s(tray_data.szTip, L"vdprobe workspace manager");
        tray_added = ::Shell_NotifyIconW(NIM_ADD, &tray_data) != FALSE;
    }
    Field("tray icon", config.tray_icon
                           ? (tray_added ? "added" : "unavailable (recorded)")
                           : "disabled by config");
    ::SetTimer(hotkey_window, kManagerReconcileTimerId,
               kManagerReconcileIntervalMs, nullptr);
    if (seconds > 0) {
        ::SetTimer(hotkey_window, kManagerShutdownTimerId,
                   static_cast<UINT>(seconds) * 1000U, nullptr);
    }
    Field("run mode", seconds > 0
                          ? std::format("bounded {}s", seconds)
                          : "unbounded (stop via --stop or tray Exit)");
    if (self_resilience) {
        ::PostMessageW(hotkey_window, WM_DISPLAYCHANGE, 0, 0);
        ::PostMessageW(hotkey_window, WM_POWERBROADCAST,
                       static_cast<WPARAM>(PBT_APMRESUMESUSPEND), 0);
    }

    MSG message{};
    bool loop_error = false;
    while (!main_context.exit_requested) {
        const int result = ::GetMessageW(&message, nullptr, 0, 0);
        if (result < 0) {
            loop_error = true;
            break;
        }
        if (result == 0) break;
        ::TranslateMessage(&message);
        ::DispatchMessageW(&message);
    }
    ::KillTimer(hotkey_window, kManagerReconcileTimerId);
    ::KillTimer(hotkey_window, kManagerShutdownTimerId);
    UINT unregister_id = 100;
    for (const WorkspaceHotkeyBinding& binding : config.bindings) {
        (void)binding;
        ::UnregisterHotKey(hotkey_window, unregister_id);
        ++unregister_id;
    }
    if (tray_added) {
        ::Shell_NotifyIconW(NIM_DELETE, &tray_data);
    }
    ::DestroyWindow(hotkey_window);

    Field("uptime reconciliations", std::format("{}", reconcile_count));
    Field("hotkey dispatches", std::format("{}", hotkey_dispatches));
    Field("switches committed", std::format("{}", switches_committed));
    Field("quarantine entries",
          std::format("{}", engine.QuarantineLog().size()));
    Field("display changes handled",
          std::format("{}", resilience.display_changes_handled));
    Field("resume events handled",
          std::format("{}", resilience.resume_events_handled));
    Field("shell reacquire attempts",
          std::format("{}", resilience.shell_reacquire_attempts));
    Field("host degraded", degraded ? "yes" : "no");
    std::string pending_error;
    const std::optional<SwitchPlan> pending =
        journal.ReadPending(&pending_error);
    bool ok = !loop_error && !pending && pending_error.empty() &&
              engine.CheckInvariant(&error);
    source.Stop();
    ok = ok && source.shutdown_ok();
    Field("stable journal pending", pending ? "YES" : "no");
    if (!ok && !error.empty()) {
        Field("failure reason", error);
    }
    Field("result", ok ? "PASS" : "FAIL");
    Print("RESULT={}\n", ok ? "PASS" : "FAIL");
    release_mutex();
    return ok ? 0 : 1;
}

// ---------------------------------------------------- logical-workspace-test

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
                move_to_role, observe_role, &journal, 10, 5);

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
                Field("    foreground best-effort failures",
                      std::format("{}", presentation.best_effort_failed));
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
            WaitForNoProbeChromiumWindows(executable, profile);
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
