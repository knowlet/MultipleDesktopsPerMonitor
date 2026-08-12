#include "window_lifecycle.h"

#include <algorithm>
#include <exception>
#include <system_error>
#include <unordered_map>

namespace vd {
namespace {

std::mutex g_sources_mutex;
std::unordered_map<HWINEVENTHOOK, WinEventLifecycleSource*> g_sources;

std::string Win32Error(const char* action) {
    return std::string(action) + ": " +
           std::system_category().message(static_cast<int>(GetLastError()));
}

bool RemoveHookNoexcept(const WinEventLifecycleSource::RemoveHook& remove,
                        HWINEVENTHOOK hook) noexcept {
    try {
        return remove && remove(hook);
    } catch (...) {
        return false;
    }
}

bool IsWellFormedHint(const WindowLifecycleEvent& event) noexcept {
    if (event.hwnd == nullptr) return false;
    if (event.kind != WindowLifecycleEventKind::Appeared &&
        event.kind != WindowLifecycleEventKind::Closed) {
        return false;
    }
    return !event.identity ||
           (event.identity->IsValid() && event.identity->hwnd == event.hwnd);
}

}  // namespace

WindowLifecycleAdapter::WindowLifecycleAdapter(WorkspaceEngine& engine,
                                               ObserveWindow observe)
    : engine_(engine), observe_(std::move(observe)) {}

LifecycleApplyResult WindowLifecycleAdapter::RequireReconcile(
    const char* message, std::string* error) {
    reconciliation_required_ = true;
    if (error) *error = message;
    return LifecycleApplyResult::NeedsReconcile;
}

LifecycleApplyResult WindowLifecycleAdapter::Apply(
    const WindowLifecycleEvent& event, std::string* error) {
    if (error) error->clear();
    // Hints are never authoritative.  In particular, a malformed hint must
    // not force a snapshot or cause the observer to mutate model state.
    if (!IsWellFormedHint(event)) return LifecycleApplyResult::Ignored;
    if (reconciliation_required_) {
        return RequireReconcile(
            "authoritative full snapshot required before incremental events",
            error);
    }

    if (event.kind == WindowLifecycleEventKind::Closed) {
        // Destroy notifications are hints, not authority. Even a supplied
        // HWND/PID/process-time tuple cannot distinguish same-process HWND
        // reuse after an out-of-context callback has been delayed. Only a
        // complete authoritative snapshot may close tracked records.
        return RequireReconcile(
            "close hint requires an authoritative full snapshot", error);
    }

    const WindowRecord* tracked = engine_.FindWindowByHwnd(event.hwnd);
    if (!observe_) {
        return RequireReconcile("window observation callback is unavailable",
                                error);
    }
    std::optional<WindowRecord> observed;
    try {
        observed = observe_(event.hwnd);
    } catch (const std::exception& exception) {
        return RequireReconcile(
            (std::string("window observation callback threw: ") +
             exception.what())
                .c_str(),
            error);
    } catch (...) {
        return RequireReconcile("window observation callback threw", error);
    }
    if (!observed) {
        // Creation/show notifications are hints. An untracked window may have
        // vanished before dispatch; losing a tracked observation is unsafe.
        if (tracked == nullptr) return LifecycleApplyResult::Ignored;
        return RequireReconcile("tracked window could not be observed", error);
    }
    if (observed->identity.hwnd != event.hwnd) {
        return RequireReconcile("observer returned a different HWND", error);
    }
    if (event.identity && event.identity->IsValid() &&
        observed->identity != *event.identity) {
        // Event belonged to a previous generation; do not let it overwrite the
        // current observation or force a false close.
        return LifecycleApplyResult::Ignored;
    }

    const UpsertResult result = engine_.UpsertWindow(std::move(*observed), error);
    switch (result) {
        case UpsertResult::Added:
            return LifecycleApplyResult::Added;
        case UpsertResult::Updated:
            return LifecycleApplyResult::Updated;
        case UpsertResult::Recreated:
            return LifecycleApplyResult::Recreated;
        case UpsertResult::Rejected:
            return RequireReconcile("observed window was rejected", error);
        default:
            return RequireReconcile("unknown lifecycle upsert result", error);
    }
}

bool WindowLifecycleAdapter::ReconcileCompleteSnapshot(
    const std::vector<WindowLifecycleEvent>& events,
    std::vector<WindowRecord> complete_observation,
    LifecycleReconcileResult* result, std::string* error) {
    if (error) error->clear();
    LifecycleReconcileResult next;
    next.events = events.size();
    if (result) *result = {};

    struct EventKey {
        WindowLifecycleEventKind kind;
        HWND hwnd;
        std::optional<WindowIdentity> identity;
    };
    std::vector<EventKey> unique;
    unique.reserve(events.size());
    for (const WindowLifecycleEvent& event : events) {
        if (!IsWellFormedHint(event)) {
            ++next.invalid_events;
            continue;
        }
        const bool duplicate = std::any_of(
            unique.begin(), unique.end(), [&](const EventKey& existing) {
                return existing.kind == event.kind &&
                       existing.hwnd == event.hwnd &&
                       existing.identity == event.identity;
            });
        if (duplicate) {
            ++next.duplicates;
        } else {
            unique.push_back({event.kind, event.hwnd, event.identity});
        }
    }

    for (const EventKey& event : unique) {
        if (!event.identity) continue;
        const auto observed = std::find_if(
            complete_observation.begin(), complete_observation.end(),
            [&](const WindowRecord& record) {
                return record.identity.hwnd == event.hwnd;
            });
        if (observed != complete_observation.end() &&
            observed->identity != *event.identity) {
            ++next.stale_generations;
        }
    }

    if (!engine_.ReconcileDiscoverySnapshot(std::move(complete_observation),
                                            &next.discovery, error)) {
        reconciliation_required_ = true;
        return false;
    }
    reconciliation_required_ = false;
    if (result) *result = next;
    return true;
}

WinEventLifecycleSource::WinEventLifecycleSource(InstallHook install,
                                                 RemoveHook remove)
    : install_(std::move(install)), remove_(std::move(remove)) {
    if (!install_) {
        install_ = [](DWORD event_min, DWORD event_max,
                      WINEVENTPROC callback) {
            return SetWinEventHook(event_min, event_max, nullptr, callback, 0,
                                   0, WINEVENT_OUTOFCONTEXT);
        };
    }
    if (!remove_) {
        remove_ = [](HWINEVENTHOOK hook) {
            return UnhookWinEvent(hook) != FALSE;
        };
    }
}

WinEventLifecycleSource::~WinEventLifecycleSource() { Stop(); }

bool WinEventLifecycleSource::Start(std::string* error) {
    const DWORD current_thread = GetCurrentThreadId();
    if (owner_thread_id_ != 0 && owner_thread_id_ != current_thread) {
        if (error) {
            *error = "WinEvent source must be restarted on its owner thread";
        }
        shutdown_ok_ = false;
        return false;
    }
    if (running()) return true;
    if (!hooks_.empty()) {
        if (error) {
            *error = "WinEvent source has a hook pending failed shutdown";
        }
        shutdown_ok_ = false;
        return false;
    }
    owner_thread_id_ = current_thread;

    HWINEVENTHOOK hook = nullptr;
    bool duplicate_hook = false;
    try {
        hooks_.reserve(1);
        // CREATE, DESTROY, and SHOW are contiguous EVENT_OBJECT values. One
        // hook keeps their delivery in a single ordered source.
        hook = install_(EVENT_OBJECT_CREATE, EVENT_OBJECT_SHOW, Callback);
        if (hook == nullptr) {
            if (error) *error = Win32Error("SetWinEventHook failed");
            shutdown_ok_ = true;
            return false;
        }
        hooks_.push_back(hook);
        {
            std::lock_guard lock(g_sources_mutex);
            const auto [it, inserted] = g_sources.emplace(hook, this);
            (void)it;
            duplicate_hook = !inserted;
        }
        if (duplicate_hook) {
            const bool removed = RemoveHookNoexcept(remove_, hook);
            if (removed) hooks_.pop_back();
            shutdown_ok_ = removed;
            if (error) {
                *error = removed ? "SetWinEventHook returned a duplicate hook"
                                 : "SetWinEventHook returned a duplicate hook "
                                   "and cleanup failed";
            }
            return false;
        }
        running_ = true;
        shutdown_ok_ = true;
        queue_overflowed_.store(false, std::memory_order_release);
        return true;
    } catch (...) {
        // reserve() completes before a native hook is installed, so an
        // installed hook always has a no-allocation slot in hooks_.  Remove it
        // directly rather than calling Stop(), whose public semantics retain
        // failed unhooks for an explicit retry.
        const bool removed =
            hook != nullptr && !hooks_.empty() && hooks_.back() == hook &&
            RemoveHookNoexcept(remove_, hook);
        if (removed) hooks_.pop_back();
        shutdown_ok_ = hook == nullptr || removed;
        if (error) {
            *error = shutdown_ok_ ? "SetWinEventHook installation threw"
                                  : "SetWinEventHook installation threw and "
                                    "hook cleanup failed";
        }
        return false;
    }
}

bool WinEventLifecycleSource::PumpOwnerThreadMessages(std::string* error) {
    if (error) error->clear();
    if (owner_thread_id_ == 0 || owner_thread_id_ != GetCurrentThreadId()) {
        if (error) {
            *error = "WinEvent message pump must run on the source owner thread";
        }
        return false;
    }

    MSG message{};
    while (::PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
        if (message.message == WM_QUIT) {
            // Preserve process shutdown semantics for the owning application.
            ::PostQuitMessage(static_cast<int>(message.wParam));
            break;
        }
        ::TranslateMessage(&message);
        ::DispatchMessageW(&message);
    }
    return true;
}

void WinEventLifecycleSource::Stop() noexcept {
    if (hooks_.empty()) {
        running_ = false;
        return;
    }
    if (owner_thread_id_ != GetCurrentThreadId()) {
        // The WinEvent API requires unhooking on the installing thread. Do
        // remove registry ownership here so a cross-thread destructor cannot
        // leave callbacks dereferencing a destroyed source. The native hooks
        // remain installed until their owner thread can unhook them.
        try {
            std::lock_guard lock(g_sources_mutex);
            for (HWINEVENTHOOK hook : hooks_) g_sources.erase(hook);
        } catch (...) {
            // There is no safe way to unhook while a callback may still hold
            // this source's registry entry. Keep the failure observable.
        }
        running_ = false;
        shutdown_ok_ = false;
        return;
    }
    std::size_t index = 0;
    bool all_removed = true;
    while (index < hooks_.size()) {
        const HWINEVENTHOOK hook = hooks_[index];
        try {
            std::lock_guard lock(g_sources_mutex);
            g_sources.erase(hook);
        } catch (...) {
            // Do not call the native unhook while callbacks can still reach
            // the source through an entry that could not be removed.
            all_removed = false;
            ++index;
            continue;
        }
        if (RemoveHookNoexcept(remove_, hook)) {
            hooks_[index] = hooks_.back();
            hooks_.pop_back();
        } else {
            all_removed = false;
            ++index;
        }
    }
    running_ = false;
    shutdown_ok_ = all_removed && hooks_.empty();
}

std::vector<WindowLifecycleEvent> WinEventLifecycleSource::Drain() {
    return DrainBatch().events;
}

WindowLifecycleBatch WinEventLifecycleSource::DrainBatch() {
    std::lock_guard lock(queue_mutex_);
    WindowLifecycleBatch result;
    // Allocate before consuming the sticky bit.  If reserve throws, both the
    // queued hints and the evidence that hints were lost remain available to
    // the next successful drain.
    result.events.reserve(queue_.size());
    result.overflowed =
        queue_overflowed_.exchange(false, std::memory_order_acq_rel);
    result.event_epoch = event_epoch_.load(std::memory_order_acquire);
    while (!queue_.empty()) {
        result.events.push_back(std::move(queue_.front()));
        queue_.pop_front();
    }
    return result;
}

void WinEventLifecycleSource::Collect(WindowLifecycleEvent event) {
    Enqueue(std::move(event));
}

void WinEventLifecycleSource::Enqueue(WindowLifecycleEvent event) {
    std::lock_guard lock(queue_mutex_);
    event_epoch_.fetch_add(1, std::memory_order_acq_rel);
    constexpr std::size_t kMaxQueuedEvents = 4096;
    if (queue_.size() >= kMaxQueuedEvents) {
        queue_overflowed_.store(true, std::memory_order_release);
        return;
    }
    queue_.push_back(std::move(event));
}

void CALLBACK WinEventLifecycleSource::Callback(
    HWINEVENTHOOK hook, DWORD event, HWND hwnd, LONG object_id, LONG child_id,
    DWORD /*event_thread*/, DWORD /*event_time*/) {
    // No exception may cross a WinEvent callback boundary. If queueing itself
    // fails (for example, allocation failure), preserve correctness by
    // forcing the owner to obtain an authoritative snapshot on its next drain.
    try {
        if (hwnd == nullptr || object_id != OBJID_WINDOW ||
            child_id != CHILDID_SELF) {
            return;
        }
        WindowLifecycleEventKind kind;
        if (event == EVENT_OBJECT_DESTROY) {
            kind = WindowLifecycleEventKind::Closed;
        } else if (event == EVENT_OBJECT_CREATE || event == EVENT_OBJECT_SHOW) {
            kind = WindowLifecycleEventKind::Appeared;
        } else {
            return;
        }

        // Native out-of-context callbacks are hints only. Identity is resolved
        // later by the observer/full-snapshot boundary; destroy dispatch is too
        // late to provide a trustworthy event-time generation.
        WindowLifecycleEvent observation{kind, hwnd, std::nullopt};
        std::lock_guard lock(g_sources_mutex);
        const auto it = g_sources.find(hook);
        if (it == g_sources.end()) return;
        try {
            it->second->Enqueue(std::move(observation));
        } catch (...) {
            it->second->queue_overflowed_.store(true,
                                                 std::memory_order_release);
        }
    } catch (...) {
        // The source may be unavailable (for example if acquiring the global
        // registry lock failed). There is no safe target to mark in that case.
    }
}

const char* LifecycleApplyResultText(LifecycleApplyResult result) noexcept {
    switch (result) {
        case LifecycleApplyResult::Added:
            return "added";
        case LifecycleApplyResult::Updated:
            return "updated";
        case LifecycleApplyResult::Recreated:
            return "recreated";
        case LifecycleApplyResult::Ignored:
            return "ignored";
        case LifecycleApplyResult::NeedsReconcile:
            return "needs-reconcile";
        default:
            return "unknown";
    }
}

}  // namespace vd
