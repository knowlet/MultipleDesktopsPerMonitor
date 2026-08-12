#include "window_lifecycle.h"

#include <algorithm>
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
    if (reconciliation_required_) {
        return RequireReconcile(
            "authoritative full snapshot required before incremental events",
            error);
    }
    if (event.hwnd == nullptr) {
        return RequireReconcile("lifecycle event has no HWND", error);
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
    std::optional<WindowRecord> observed = observe_(event.hwnd);
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
        if (event.hwnd == nullptr ||
            (event.identity &&
             (!event.identity->IsValid() ||
              event.identity->hwnd != event.hwnd))) {
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
    owner_thread_id_ = current_thread;
    try {
        hooks_.reserve(1);
        // CREATE, DESTROY, and SHOW are contiguous EVENT_OBJECT values. One
        // hook keeps their delivery in a single ordered source.
        HWINEVENTHOOK hook =
            install_(EVENT_OBJECT_CREATE, EVENT_OBJECT_SHOW, Callback);
        if (hook == nullptr) {
            if (error) *error = Win32Error("SetWinEventHook failed");
            Stop();
            return false;
        }
        hooks_.push_back(hook);
        {
            std::lock_guard lock(g_sources_mutex);
            g_sources.emplace(hook, this);
        }
        shutdown_ok_ = true;
        queue_overflowed_.store(false, std::memory_order_release);
        return true;
    } catch (...) {
        if (error) *error = "SetWinEventHook installation threw";
        Stop();
        return false;
    }
}

void WinEventLifecycleSource::Stop() noexcept {
    if (hooks_.empty()) return;
    if (owner_thread_id_ != GetCurrentThreadId()) {
        // The WinEvent API requires unhooking on the installing thread. Do
        // remove registry ownership here so a cross-thread destructor cannot
        // leave callbacks dereferencing a destroyed source. The native hooks
        // remain installed until their owner thread can unhook them.
        {
            std::lock_guard lock(g_sources_mutex);
            for (HWINEVENTHOOK hook : hooks_) g_sources.erase(hook);
        }
        shutdown_ok_ = false;
        return;
    }
    std::vector<HWINEVENTHOOK> remaining;
    remaining.reserve(hooks_.size());
    for (HWINEVENTHOOK hook : hooks_) {
        {
            std::lock_guard lock(g_sources_mutex);
            g_sources.erase(hook);
        }
        bool removed = false;
        try {
            removed = remove_(hook);
        } catch (...) {
            removed = false;
        }
        if (!removed) remaining.push_back(hook);
    }
    hooks_.swap(remaining);
    shutdown_ok_ = hooks_.empty();
}

std::vector<WindowLifecycleEvent> WinEventLifecycleSource::Drain() {
    return DrainBatch().events;
}

WindowLifecycleBatch WinEventLifecycleSource::DrainBatch() {
    std::lock_guard lock(queue_mutex_);
    WindowLifecycleBatch result;
    result.overflowed =
        queue_overflowed_.exchange(false, std::memory_order_acq_rel);
    result.events.reserve(queue_.size());
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
    if (it != g_sources.end()) it->second->Enqueue(std::move(observation));
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
