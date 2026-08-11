// notifysink.h - vdprobe's own COM object implementing IVirtualDesktopNotification.
//
// This is the one place in vdprobe where WE are the COM server rather than the
// client.  The vtable layout is not something we call through the gate; it is
// something the shell calls INTO, so the ordinary "never guess a slot" rule
// takes a different, stricter form here: the vtable shape (method count,
// calling convention, parameter types) must match this build's verified layout
// in src/vdlayout.cpp exactly, because a mismatch corrupts the shell's call
// into our object, not merely our own state.
//
// The vtable below was hand-verified against the IVirtualDesktopNotification
// row in the layout registry (source: CVirtualDesktopNotificationsDerived's
// pure-interface vtable slice in twinui.pcshell.dll 6.2.26100.8875).
#pragma once

#include <windows.h>

#include <atomic>
#include <cstddef>
#include <deque>
#include <mutex>
#include <string>

#include "comraw.h"

namespace vd {

enum class NotifyEventKind {
    VirtualDesktopCreated,
    VirtualDesktopDestroyBegin,
    VirtualDesktopDestroyFailed,
    VirtualDesktopDestroyed,
    VirtualDesktopMoved,
    VirtualDesktopNameChanged,
    ViewVirtualDesktopChanged,
    CurrentVirtualDesktopChanged,
    VirtualDesktopWallpaperChanged,
    VirtualDesktopSwitched,
    RemoteVirtualDesktopConnected,
};

struct NotifyEvent {
    NotifyEventKind kind;
    ULONGLONG timestamp_qpc = 0;
    DWORD callback_thread_id = 0;
    // Best-effort GUIDs of the IVirtualDesktop arguments, read via the same
    // verified IVirtualDesktop::GetId slot everything else in phase2.cpp uses.
    // Empty/zero when the argument was null or GetId failed.
    GUID desktop_a{};
    bool desktop_a_ok = false;
    GUID desktop_b{};
    bool desktop_b_ok = false;
    // For ViewVirtualDesktopChanged: the HWND behind the IApplicationView, when
    // resolvable.
    HWND hwnd = nullptr;
    std::string detail;  // free-form extra text (index, name, switch type...)
};

const char* NotifyEventKindText(NotifyEventKind k);

// Thread-safe append-only event log.
//
// Deliberately NOT a C++ class with virtual functions and NOT derived from
// IUnknown.  If it inherited from IUnknown, the compiler would synthesize its
// own 3-slot vtable and place a pointer to it at offset 0; this object needs
// offset 0 to hold a pointer to the hand-written 14-slot kSinkVtbl instead
// (declared in notifysink.cpp), because that is the vtable the shell will
// actually call through once it holds this object as an
// IVirtualDesktopNotification*.  Mixing "inherit from IUnknown" with "manually
// overwrite the vtable pointer" would leave two incompatible ideas of what is
// at offset 0 and is exactly the kind of mistake this project's safety model
// exists to avoid -- so there is only one idea of offset 0, ever: the pointer
// this class sets in its constructor and never touches again.
//
// QueryInterface/AddRef/Release are ordinary (non-virtual) member functions;
// the free-function thunks in notifysink.cpp forward to them.
class NotifySink {
   public:
    NotifySink();
    NotifySink(const NotifySink&) = delete;
    NotifySink& operator=(const NotifySink&) = delete;

    HRESULT QueryInterface(REFIID riid, void** out);
    ULONG AddRef();
    ULONG Release();

    // Drains and returns all events observed since the last call.
    std::deque<NotifyEvent> DrainEvents();

    size_t TotalEventCount() const { return total_count_.load(); }

    // Raw IUnknown* suitable for passing to Register().  Does not add a
    // reference; the caller must keep the NotifySink alive for the lifetime of
    // the registration.
    IUnknown* AsUnknown() { return reinterpret_cast<IUnknown*>(this); }

    // Called by the file-local vtable thunks in notifysink.cpp when the shell
    // invokes a notification method.  Public because the thunks are free
    // functions, not members; it is not part of the class's COM-facing
    // contract.
    void PushEvent(NotifyEvent ev);

   private:
    // MUST be the first member: this is the object's vtable pointer as COM
    // sees it.  Set once in the constructor to &kSinkVtbl (notifysink.cpp) and
    // never reassigned.  The constructor verifies at runtime (via assert) that
    // this member really is the object's first byte, since offsetof cannot be
    // used on a private member from outside the class and this check matters
    // more than the inconvenience of doing it at runtime once per instance.
    const void* vtbl_;

    std::atomic<ULONG> ref_count_{1};
    std::atomic<size_t> total_count_{0};
    std::mutex mutex_;
    std::deque<NotifyEvent> events_;
};

}  // namespace vd
