#include "comraw.h"

#include <psapi.h>

#include <cstring>

#include "util.h"

namespace vd {

bool IsReadablePointer(const void* addr, size_t bytes) {
    if (addr == nullptr) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (::VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT) return false;
    constexpr DWORD kNoRead = PAGE_NOACCESS | PAGE_GUARD;
    if (mbi.Protect & kNoRead) return false;
    // The range must not run off the end of this region.
    const auto start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    const auto want_end = reinterpret_cast<uintptr_t>(addr) + bytes;
    return want_end <= start + mbi.RegionSize;
}

bool IsImageCodePointer(const void* addr) {
    if (addr == nullptr) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (::VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Type != MEM_IMAGE) return false;  // must live in a mapped module
    const DWORD prot = mbi.Protect & 0xFF;
    return prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
           prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY;
}

std::string ModuleOf(const void* addr) {
    HMODULE mod = nullptr;
    if (!::GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCWSTR>(addr), &mod) ||
        mod == nullptr) {
        return {};
    }
    wchar_t path[MAX_PATH]{};
    DWORD n = ::GetModuleFileNameW(mod, path, MAX_PATH);
    if (n == 0) return {};
    std::wstring full(path, n);
    size_t slash = full.find_last_of(L'\\');
    return ToUtf8(slash == std::wstring::npos ? full : full.substr(slash + 1));
}

void** VtableOf(IUnknown* obj) {
    if (!IsReadablePointer(obj, sizeof(void*))) return nullptr;
    void** vt = *reinterpret_cast<void***>(obj);
    if (!IsReadablePointer(vt, sizeof(void*))) return nullptr;
    return vt;
}

unsigned ProbeVtableCodeRun(IUnknown* obj, unsigned max_slots) {
    void** vt = VtableOf(obj);
    if (vt == nullptr) return 0;
    unsigned n = 0;
    for (; n < max_slots; ++n) {
        if (!IsReadablePointer(&vt[n], sizeof(void*))) break;
        if (!IsImageCodePointer(vt[n])) break;
    }
    return n;
}

bool TryReadProxyIid(IUnknown* obj, GUID& out_iid) {
    void** vt = VtableOf(obj);
    if (vt == nullptr) return false;
    // CInterfaceProxyVtbl places `const IID* piid` immediately before Vtbl[0].
    void** slot = vt - 1;
    if (!IsReadablePointer(slot, sizeof(void*))) return false;
    const void* piid = *slot;
    if (!IsReadablePointer(piid, sizeof(GUID))) return false;
    // Require the IID to live in a mapped image (proxy .rdata), which rules out
    // heap data that happens to be readable.
    MEMORY_BASIC_INFORMATION mbi{};
    if (::VirtualQuery(piid, &mbi, sizeof(mbi)) != sizeof(mbi)) return false;
    if (mbi.Type != MEM_IMAGE) return false;
    GUID candidate{};
    std::memcpy(&candidate, piid, sizeof(GUID));
    // A GUID of all zeroes is a sure sign we read something else.
    static const GUID kZero{};
    if (::IsEqualGUID(candidate, kZero)) return false;
    out_iid = candidate;
    return true;
}

}  // namespace vd
