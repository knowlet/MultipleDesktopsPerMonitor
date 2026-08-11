// comraw.h - minimal COM smart pointer plus a *gated* raw vtable dispatcher.
//
// Design rule for this project: undocumented COM methods are never reached by
// declaring a speculative C++ interface and calling a member function.  Every
// call goes through InvokeSlot(), which takes a MethodEntry from vdlayout.cpp.
// A MethodEntry only exists when the slot index was derived from evidence, and
// InvokeSlot() additionally validates at runtime that the slot really holds a
// code pointer inside a mapped image.  See vdlayout.h for the gate.
#pragma once

#include <windows.h>
#include <objbase.h>
#include <unknwn.h>

#include <cstdint>
#include <string>
#include <utility>

namespace vd {

// ------------------------------------------------------------------ Com<T>

// Deliberately tiny: no ATL/WRL dependency, no operator-> gymnastics.
template <class T>
class Com {
   public:
    Com() = default;
    Com(const Com&) = delete;
    Com& operator=(const Com&) = delete;

    Com(Com&& o) noexcept : p_(o.p_) { o.p_ = nullptr; }
    Com& operator=(Com&& o) noexcept {
        if (this != &o) {
            Reset();
            p_ = o.p_;
            o.p_ = nullptr;
        }
        return *this;
    }
    ~Com() { Reset(); }

    void Reset() {
        if (p_) {
            p_->Release();
            p_ = nullptr;
        }
    }

    T** Put() {
        Reset();
        return &p_;
    }
    void** PutVoid() { return reinterpret_cast<void**>(Put()); }

    T* Get() const { return p_; }
    T* operator->() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }

   private:
    T* p_ = nullptr;
};

// An interface whose layout we have not proven.  Only the three IUnknown slots
// may be touched through this type; everything else must go via InvokeSlot().
struct OpaqueUnknown : public IUnknown {};

// Owns an IUnknown* that we intentionally do not describe with a C++ vtable.
class RawObject {
   public:
    RawObject() = default;
    RawObject(const RawObject&) = delete;
    RawObject& operator=(const RawObject&) = delete;
    RawObject(RawObject&& o) noexcept : p_(o.p_) { o.p_ = nullptr; }
    RawObject& operator=(RawObject&& o) noexcept {
        if (this != &o) {
            Reset();
            p_ = o.p_;
            o.p_ = nullptr;
        }
        return *this;
    }
    ~RawObject() { Reset(); }

    void Reset() {
        if (p_) {
            p_->Release();
            p_ = nullptr;
        }
    }

    IUnknown* Get() const { return p_; }
    void** PutVoid() {
        Reset();
        return reinterpret_cast<void**>(&p_);
    }
    void Attach(IUnknown* p) {
        Reset();
        p_ = p;
    }
    explicit operator bool() const { return p_ != nullptr; }

   private:
    IUnknown* p_ = nullptr;
};

// ------------------------------------------------------- vtable introspection

// True when `addr` lies in a committed, executable page of a mapped image.
bool IsImageCodePointer(const void* addr);

// True when `addr` lies in a committed, readable page.
bool IsReadablePointer(const void* addr, size_t bytes);

// Module file name containing `addr`, or "" when it is not in a loaded module.
std::string ModuleOf(const void* addr);

// Reads the vtable pointer of a COM object after validating readability.
void** VtableOf(IUnknown* obj);

// Number of leading vtable entries that look like image code pointers.  This is
// a *lower bound* on the method count and is used purely as a sanity check --
// it is never used to guess what a slot does.
unsigned ProbeVtableCodeRun(IUnknown* obj, unsigned max_slots);

// MIDL stubless proxies are laid out as CInterfaceProxyVtbl:
//     struct { const IID* piid; void* Vtbl[]; }
// so for an out-of-process proxy, vtbl[-1] points at the IID the proxy was
// generated for.  That gives an independent confirmation of which interface we
// actually received.  Returns false for in-proc objects (no such header).
bool TryReadProxyIid(IUnknown* obj, GUID& out_iid);

// ------------------------------------------------------------- raw dispatch

// Low-level dispatcher.  Callers must not use this directly; go through
// vdlayout.h's InvokeSlot(), which enforces the evidence gate.
template <class Ret, class... Args>
Ret UnsafeCallSlot(IUnknown* obj, unsigned slot, Args... args) {
    using Fn = Ret(__stdcall*)(IUnknown*, Args...);
    void** vt = *reinterpret_cast<void***>(obj);
    return reinterpret_cast<Fn>(vt[slot])(obj, args...);
}

}  // namespace vd
