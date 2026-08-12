// Non-mutating WinEvent collection and deterministic workspace-model adapter.
#pragma once

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "workspace_engine.h"

namespace vd {

enum class WindowLifecycleEventKind {
    Appeared,
    Closed,
};

// Identity is an optional hint for create/show observations. Destroy hints are
// intentionally identity-less; only an authoritative complete snapshot may
// remove a tracked record.
struct WindowLifecycleEvent {
    WindowLifecycleEventKind kind = WindowLifecycleEventKind::Appeared;
    HWND hwnd = nullptr;
    std::optional<WindowIdentity> identity;
};

struct LifecycleReconcileResult {
    std::size_t events = 0;
    std::size_t duplicates = 0;
    std::size_t invalid_events = 0;
    std::size_t stale_generations = 0;
    DiscoveryReconcileResult discovery{};
};

struct WindowLifecycleBatch {
    std::vector<WindowLifecycleEvent> events;
    bool overflowed = false;
    std::uint64_t event_epoch = 0;
};

enum class LifecycleApplyResult {
    Added,
    Updated,
    Recreated,
    Ignored,
    NeedsReconcile,
};

// Resolves all capability, ownership, monitor/workspace and native-role state
// outside the lifecycle layer. This keeps the adapter application-neutral and
// lets the same logic consume native hooks or deterministic observations.
class WindowLifecycleAdapter {
   public:
    using ObserveWindow =
        std::function<std::optional<WindowRecord>(HWND hwnd)>;

    WindowLifecycleAdapter(WorkspaceEngine& engine, ObserveWindow observe);

    LifecycleApplyResult Apply(const WindowLifecycleEvent& event,
                               std::string* error = nullptr);
    // Applies an authoritative observation of the complete set of windows in
    // this engine's configured scope. Lifecycle events are hints only: they
    // are deduplicated and generation-checked, but never mutate model state on
    // their own. Thus delayed/out-of-order events cannot close a newer HWND
    // generation. The snapshot is the sole input to model reconciliation.
    bool ReconcileCompleteSnapshot(
        const std::vector<WindowLifecycleEvent>& events,
        std::vector<WindowRecord> complete_observation,
        LifecycleReconcileResult* result = nullptr,
        std::string* error = nullptr);
    bool reconciliation_required() const noexcept {
        return reconciliation_required_;
    }

   private:
    LifecycleApplyResult RequireReconcile(const char* message,
                                          std::string* error);

    WorkspaceEngine& engine_;
    ObserveWindow observe_;
    bool reconciliation_required_ = false;
};

// Read-only source for window-object lifecycle hints. Start and Stop must be
// called on the same thread, and that thread must pump its message queue for
// out-of-context callbacks to be delivered. Callbacks never inspect COM or
// mutate windows/model state; the owner thread drains events and feeds them
// through WindowLifecycleAdapter.
class WinEventLifecycleSource {
   public:
    using InstallHook =
        std::function<HWINEVENTHOOK(DWORD event_min, DWORD event_max,
                                   WINEVENTPROC callback)>;
    using RemoveHook = std::function<bool(HWINEVENTHOOK hook)>;

    WinEventLifecycleSource(InstallHook install = {}, RemoveHook remove = {});
    ~WinEventLifecycleSource();
    WinEventLifecycleSource(const WinEventLifecycleSource&) = delete;
    WinEventLifecycleSource& operator=(const WinEventLifecycleSource&) = delete;

    bool Start(std::string* error = nullptr);
    void Stop() noexcept;
    bool running() const noexcept { return running_; }
    bool shutdown_ok() const noexcept { return shutdown_ok_; }
    bool healthy() const noexcept { return running_ && shutdown_ok_; }
    // Pump the installing thread's queue so OUTOFCONTEXT callbacks can be
    // delivered. Must be called on the owner thread.
    bool PumpOwnerThreadMessages(std::string* error = nullptr);
    std::uint64_t event_epoch() const noexcept {
        return event_epoch_.load(std::memory_order_acquire);
    }
    bool queue_overflowed() const noexcept {
        return queue_overflowed_.load(std::memory_order_acquire);
    }
    std::vector<WindowLifecycleEvent> Drain();
    // Atomically drains queued hints and consumes the sticky overflow flag.
    // Coordinators should prefer this over separately reading queue_overflowed()
    // and Drain(), which cannot form one observation boundary.
    WindowLifecycleBatch DrainBatch();

    // Accepts an already-normalized hint. Useful to join other read-only
    // discovery sources to the same owner-thread drain boundary.
    void Collect(WindowLifecycleEvent event);

   private:
    static void CALLBACK Callback(HWINEVENTHOOK hook, DWORD event, HWND hwnd,
                                  LONG object_id, LONG child_id,
                                  DWORD event_thread, DWORD event_time);
    void Enqueue(WindowLifecycleEvent event);

    std::vector<HWINEVENTHOOK> hooks_;
    InstallHook install_;
    RemoveHook remove_;
    DWORD owner_thread_id_ = 0;
    // A hook that could not be removed is retained for a later Stop() retry,
    // but is no longer considered a running event source once it has been
    // removed from the callback registry.
    bool running_ = false;
    bool shutdown_ok_ = true;
    // Monotonically changes whenever a valid hint reaches this source,
    // including a hint that cannot be queued. Transactions can use this as a
    // non-destructive pre-commit lifecycle boundary.
    std::atomic<std::uint64_t> event_epoch_{0};
    std::atomic_bool queue_overflowed_{false};
    std::mutex queue_mutex_;
    std::deque<WindowLifecycleEvent> queue_;
};

const char* LifecycleApplyResultText(LifecycleApplyResult result) noexcept;

}  // namespace vd
