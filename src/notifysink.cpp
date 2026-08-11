#include "notifysink.h"

#include <objectarray.h>

#include "util.h"
#include "vdids.h"
#include "vdlayout.h"

namespace vd {

// ---------------------------------------------------------------------------
// IVirtualDesktopNotification, declared to match the VERIFIED layout in
// src/vdlayout.cpp exactly (slots 3..13, one IVirtualDesktop-shaped IUnknown
// per desktop argument).  This is a C++ interface we IMPLEMENT, so declaring
// it is the correct and necessary thing to do -- the project's "never declare
// a speculative interface and call through it" rule is about calling INTO the
// shell's objects with a guessed shape, not about defining our own server-side
// contract, which every COM server must do.
//
// Kept file-local: nothing outside notifysink.cpp needs to name these types.
// ---------------------------------------------------------------------------

enum class VirtualDesktopSwitchTypeRaw : int {};  // opaque; not interpreted

struct IVirtualDesktopNotificationVtbl {
    // IUnknown
    HRESULT(__stdcall* QueryInterface)(IUnknown* self, REFIID riid, void** out);
    ULONG(__stdcall* AddRef)(IUnknown* self);
    ULONG(__stdcall* Release)(IUnknown* self);
    // IVirtualDesktopNotification (slots 3..13, verified)
    HRESULT(__stdcall* VirtualDesktopCreated)(IUnknown* self, IUnknown* desktop);
    HRESULT(__stdcall* VirtualDesktopDestroyBegin)(IUnknown* self, IUnknown* destroyed,
                                                   IUnknown* fallback);
    HRESULT(__stdcall* VirtualDesktopDestroyFailed)(IUnknown* self, IUnknown* destroyed,
                                                     IUnknown* fallback);
    HRESULT(__stdcall* VirtualDesktopDestroyed)(IUnknown* self, IUnknown* destroyed,
                                                IUnknown* fallback);
    HRESULT(__stdcall* VirtualDesktopMoved)(IUnknown* self, IUnknown* desktop,
                                            UINT old_index, UINT new_index);
    HRESULT(__stdcall* VirtualDesktopNameChanged)(IUnknown* self, IUnknown* desktop,
                                                  void* hstring_name);
    HRESULT(__stdcall* ViewVirtualDesktopChanged)(IUnknown* self, IUnknown* view);
    HRESULT(__stdcall* CurrentVirtualDesktopChanged)(IUnknown* self, IUnknown* old_desktop,
                                                      IUnknown* new_desktop);
    HRESULT(__stdcall* VirtualDesktopWallpaperChanged)(IUnknown* self, IUnknown* desktop,
                                                        void* hstring_path);
    HRESULT(__stdcall* VirtualDesktopSwitched)(IUnknown* self, IUnknown* desktop,
                                               VirtualDesktopSwitchTypeRaw type);
    HRESULT(__stdcall* RemoteVirtualDesktopConnected)(IUnknown* self, IUnknown* desktop);
};

static_assert(sizeof(IVirtualDesktopNotificationVtbl) == 14 * sizeof(void*),
             "IVirtualDesktopNotificationVtbl must have exactly 14 slots (3 IUnknown "
             "+ 11 verified notification methods, slots 3..13) to match the layout "
             "dumped from twinui.pcshell.dll for this build");

namespace {

// Reads a desktop GUID off a raw IVirtualDesktop-shaped IUnknown using the same
// verified GetId slot the rest of phase2.cpp uses, without pulling in the
// heavier DesktopInfo machinery (that lives in phase2.cpp, this file must not
// depend on it to avoid a link-order cycle).
bool TryGetDesktopId(IUnknown* raw, GUID& out_id) {
    if (raw == nullptr) return false;
    for (const IidCandidate& c : IidCandidatesFor("IVirtualDesktop")) {
        RawObject probe;
        if (FAILED(raw->QueryInterface(*c.iid, probe.PutVoid()))) continue;
        const LayoutTable* t = LayoutForIid(*c.iid);
        if (t == nullptr) return false;
        const MethodEntry* m = FindMethod(*t, "GetId");
        if (m == nullptr) return false;
        Gate g = Gate::Ok;
        GUID id{};
        HRESULT hr = InvokeSlot(probe.Get(), *t, *m, g, false, &id);
        if (g == Gate::Ok && SUCCEEDED(hr)) {
            out_id = id;
            return true;
        }
        return false;
    }
    return false;
}

HWND TryGetViewHwnd(IUnknown* raw) {
    if (raw == nullptr) return nullptr;
    const LayoutTable* t = LayoutForIid(IID_IApplicationView);
    if (t == nullptr) return nullptr;
    const MethodEntry* m = FindMethod(*t, "GetThumbnailWindow");
    if (m == nullptr) return nullptr;
    Gate g = Gate::Ok;
    HWND hwnd = nullptr;
    HRESULT hr = InvokeSlot(raw, *t, *m, g, false, &hwnd);
    return (g == Gate::Ok && SUCCEEDED(hr)) ? hwnd : nullptr;
}

NotifySink* SelfOf(IUnknown* self) { return reinterpret_cast<NotifySink*>(self); }

HRESULT __stdcall Thunk_QueryInterface(IUnknown* self, REFIID riid, void** out) {
    return SelfOf(self)->QueryInterface(riid, out);
}
ULONG __stdcall Thunk_AddRef(IUnknown* self) { return SelfOf(self)->AddRef(); }
ULONG __stdcall Thunk_Release(IUnknown* self) { return SelfOf(self)->Release(); }

NotifyEvent MakeEvent(NotifyEventKind kind) {
    NotifyEvent ev;
    ev.kind = kind;
    ev.callback_thread_id = ::GetCurrentThreadId();
    LARGE_INTEGER qpc{};
    ::QueryPerformanceCounter(&qpc);
    ev.timestamp_qpc = static_cast<ULONGLONG>(qpc.QuadPart);
    return ev;
}

HRESULT __stdcall Thunk_VirtualDesktopCreated(IUnknown* self, IUnknown* desktop) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::VirtualDesktopCreated);
    ev.desktop_a_ok = TryGetDesktopId(desktop, ev.desktop_a);
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}
HRESULT __stdcall Thunk_VirtualDesktopDestroyBegin(IUnknown* self, IUnknown* destroyed,
                                                    IUnknown* fallback) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::VirtualDesktopDestroyBegin);
    ev.desktop_a_ok = TryGetDesktopId(destroyed, ev.desktop_a);
    ev.desktop_b_ok = TryGetDesktopId(fallback, ev.desktop_b);
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}
HRESULT __stdcall Thunk_VirtualDesktopDestroyFailed(IUnknown* self, IUnknown* destroyed,
                                                     IUnknown* fallback) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::VirtualDesktopDestroyFailed);
    ev.desktop_a_ok = TryGetDesktopId(destroyed, ev.desktop_a);
    ev.desktop_b_ok = TryGetDesktopId(fallback, ev.desktop_b);
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}
HRESULT __stdcall Thunk_VirtualDesktopDestroyed(IUnknown* self, IUnknown* destroyed,
                                                IUnknown* fallback) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::VirtualDesktopDestroyed);
    ev.desktop_a_ok = TryGetDesktopId(destroyed, ev.desktop_a);
    ev.desktop_b_ok = TryGetDesktopId(fallback, ev.desktop_b);
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}
HRESULT __stdcall Thunk_VirtualDesktopMoved(IUnknown* self, IUnknown* desktop,
                                            UINT old_index, UINT new_index) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::VirtualDesktopMoved);
    ev.desktop_a_ok = TryGetDesktopId(desktop, ev.desktop_a);
    ev.detail = std::format("{} -> {}", old_index, new_index);
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}
HRESULT __stdcall Thunk_VirtualDesktopNameChanged(IUnknown* self, IUnknown* desktop,
                                                   void* /*hstring_name*/) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::VirtualDesktopNameChanged);
    ev.desktop_a_ok = TryGetDesktopId(desktop, ev.desktop_a);
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}
HRESULT __stdcall Thunk_ViewVirtualDesktopChanged(IUnknown* self, IUnknown* view) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::ViewVirtualDesktopChanged);
    ev.hwnd = TryGetViewHwnd(view);
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}
HRESULT __stdcall Thunk_CurrentVirtualDesktopChanged(IUnknown* self, IUnknown* old_desktop,
                                                      IUnknown* new_desktop) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::CurrentVirtualDesktopChanged);
    ev.desktop_a_ok = TryGetDesktopId(old_desktop, ev.desktop_a);
    ev.desktop_b_ok = TryGetDesktopId(new_desktop, ev.desktop_b);
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}
HRESULT __stdcall Thunk_VirtualDesktopWallpaperChanged(IUnknown* self, IUnknown* desktop,
                                                        void* /*hstring_path*/) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::VirtualDesktopWallpaperChanged);
    ev.desktop_a_ok = TryGetDesktopId(desktop, ev.desktop_a);
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}
HRESULT __stdcall Thunk_VirtualDesktopSwitched(IUnknown* self, IUnknown* desktop,
                                               VirtualDesktopSwitchTypeRaw type) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::VirtualDesktopSwitched);
    ev.desktop_a_ok = TryGetDesktopId(desktop, ev.desktop_a);
    ev.detail = std::format("switch_type_raw={}", static_cast<int>(type));
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}
HRESULT __stdcall Thunk_RemoteVirtualDesktopConnected(IUnknown* self, IUnknown* desktop) {
    NotifyEvent ev = MakeEvent(NotifyEventKind::RemoteVirtualDesktopConnected);
    ev.desktop_a_ok = TryGetDesktopId(desktop, ev.desktop_a);
    SelfOf(self)->PushEvent(std::move(ev));
    return S_OK;
}

// Exactly one instance; laid out at namespace scope so its address is a stable,
// static, read-only vtable -- the same shape every NotifySink instance shares,
// which is the normal COM pattern and avoids per-instance vtable allocation.
constexpr IVirtualDesktopNotificationVtbl kSinkVtbl = {
    &Thunk_QueryInterface,
    &Thunk_AddRef,
    &Thunk_Release,
    &Thunk_VirtualDesktopCreated,
    &Thunk_VirtualDesktopDestroyBegin,
    &Thunk_VirtualDesktopDestroyFailed,
    &Thunk_VirtualDesktopDestroyed,
    &Thunk_VirtualDesktopMoved,
    &Thunk_VirtualDesktopNameChanged,
    &Thunk_ViewVirtualDesktopChanged,
    &Thunk_CurrentVirtualDesktopChanged,
    &Thunk_VirtualDesktopWallpaperChanged,
    &Thunk_VirtualDesktopSwitched,
    &Thunk_RemoteVirtualDesktopConnected,
};

}  // namespace

const char* NotifyEventKindText(NotifyEventKind k) {
    switch (k) {
        case NotifyEventKind::VirtualDesktopCreated:        return "VirtualDesktopCreated";
        case NotifyEventKind::VirtualDesktopDestroyBegin:   return "VirtualDesktopDestroyBegin";
        case NotifyEventKind::VirtualDesktopDestroyFailed:  return "VirtualDesktopDestroyFailed";
        case NotifyEventKind::VirtualDesktopDestroyed:      return "VirtualDesktopDestroyed";
        case NotifyEventKind::VirtualDesktopMoved:          return "VirtualDesktopMoved";
        case NotifyEventKind::VirtualDesktopNameChanged:    return "VirtualDesktopNameChanged";
        case NotifyEventKind::ViewVirtualDesktopChanged:    return "ViewVirtualDesktopChanged";
        case NotifyEventKind::CurrentVirtualDesktopChanged: return "CurrentVirtualDesktopChanged";
        case NotifyEventKind::VirtualDesktopWallpaperChanged: return "VirtualDesktopWallpaperChanged";
        case NotifyEventKind::VirtualDesktopSwitched:       return "VirtualDesktopSwitched";
        case NotifyEventKind::RemoteVirtualDesktopConnected: return "RemoteVirtualDesktopConnected";
    }
    return "?";
}

// The vtable pointer every NotifySink presents to COM is &kSinkVtbl, assigned
// directly to the private vtbl_ member (this constructor is a member of
// NotifySink, so it has access; no friend declaration or reinterpret trick is
// needed beyond the initial write).
//
// The runtime check below stands in for a static_assert(offsetof(...)==0) that
// cannot be written here (offsetof requires access to the private member from
// outside the class).  A COM object whose vtable pointer is not its first byte
// would corrupt every call the shell makes into it, so this is checked before
// the object could possibly be registered with the shell, not left as an
// assumption.
NotifySink::NotifySink() : vtbl_(&kSinkVtbl) {
    if (reinterpret_cast<const void*>(this) != reinterpret_cast<const void*>(&vtbl_)) {
        ::RaiseFailFastException(nullptr, nullptr, 0);
    }
}

HRESULT NotifySink::QueryInterface(REFIID riid, void** out) {
    if (out == nullptr) return E_POINTER;
    if (::IsEqualGUID(riid, IID_IUnknown) ||
        ::IsEqualGUID(riid, IID_IVirtualDesktopNotification)) {
        AddRef();
        *out = this;
        return S_OK;
    }
    *out = nullptr;
    return E_NOINTERFACE;
}

ULONG NotifySink::AddRef() { return ++ref_count_; }

ULONG NotifySink::Release() {
    ULONG n = --ref_count_;
    if (n == 0) delete this;
    return n;
}

void NotifySink::PushEvent(NotifyEvent ev) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back(std::move(ev));
    ++total_count_;
}

std::deque<NotifyEvent> NotifySink::DrainEvents() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::deque<NotifyEvent> out;
    out.swap(events_);
    return out;
}

}  // namespace vd
