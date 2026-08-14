#include "workspace_host_resilience.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "util.h"

namespace vd {

void MonitorTopologyMapper::Update(
    const std::vector<std::pair<MonitorId, std::string>>& real,
    std::vector<BoundMonitor>& bound,
    std::vector<std::size_t>& missing,
    std::size_t expected_count) const {
    std::vector<BoundMonitor> next;
    missing.clear();
    std::vector<bool> real_used(real.size(), false);

    // Pass 1: preserve existing bindings by device identity.
    for (const BoundMonitor& previous : bound) {
        const auto found = std::find_if(
            real.begin(), real.end(),
            [&](const std::pair<MonitorId, std::string>& candidate) {
                return candidate.second == previous.device;
            });
        if (found != real.end()) {
            const std::size_t index =
                static_cast<std::size_t>(found - real.begin());
            real_used[index] = true;
            next.push_back(
                {previous.config_index, found->first, found->second});
        }
    }

    // Pass 2: bind config indices in order to remaining real monitors
    // (order fallback) so a fresh start and newly added monitors are covered.
    std::size_t real_index = 0;
    while (real_index < real.size() && next.size() < expected_count) {
        if (real_used[real_index]) {
            ++real_index;
            continue;
        }
        // A new monitor takes the lowest missing config index, never
        // next.size(): pass 1 may have preserved a higher-numbered binding
        // (e.g. only config 1 survived a suspend), and next.size() would
        // collide with it and leave the lower index permanently missing.
        std::size_t config_index = 0;
        while (config_index < expected_count &&
               std::any_of(next.begin(), next.end(),
                           [config_index](const BoundMonitor& monitor) {
                               return monitor.config_index == config_index;
                           })) {
            ++config_index;
        }
        if (config_index >= expected_count) break;
        next.push_back(
            {config_index, real[real_index].first, real[real_index].second});
        real_used[real_index] = true;
        ++real_index;
    }

    for (std::size_t i = 0; i < expected_count; ++i) {
        const bool present = std::any_of(
            next.begin(), next.end(),
            [i](const BoundMonitor& monitor) {
                return monitor.config_index == i;
            });
        if (!present) missing.push_back(i);
    }

    bound = std::move(next);
}

int CmdWorkspaceHostResilienceTest() {
    Heading("workspace-host-resilience-test");
    Field("scope",
          "deterministic monitor topology suspend/recover and identity");
    Field("native mutation", "none");

    bool ok = true;
    MonitorTopologyMapper mapper;
    std::vector<MonitorTopologyMapper::BoundMonitor> bound;
    std::vector<std::size_t> missing;

    mapper.Update(
        {{static_cast<MonitorId>(0x100ULL), "DISPLAYA"},
         {static_cast<MonitorId>(0x200ULL), "DISPLAYB"}},
        bound, missing, 2);
    const bool initial_ok =
        bound.size() == 2 &&
        bound[0].config_index == 0 && bound[0].device == "DISPLAYA" &&
        bound[1].config_index == 1 && bound[1].device == "DISPLAYB" &&
        missing.empty();
    Field("initial topology binds by order", initial_ok ? "PASS" : "FAIL");
    ok = ok && initial_ok;

    mapper.Update(
        {{static_cast<MonitorId>(0x100ULL), "DISPLAYA"}},
        bound, missing, 2);
    const bool suspend_ok =
        bound.size() == 1 && bound[0].device == "DISPLAYA" &&
        missing.size() == 1 && missing[0] == 1;
    Field("missing monitor suspends workspace", suspend_ok ? "PASS" : "FAIL");
    ok = ok && suspend_ok;

    mapper.Update(
        {{static_cast<MonitorId>(0x100ULL), "DISPLAYA"},
         {static_cast<MonitorId>(0x300ULL), "DISPLAYB"}},
        bound, missing, 2);
    const bool recover_ok =
        bound.size() == 2 && bound[1].device == "DISPLAYB" &&
        bound[1].real_monitor == static_cast<MonitorId>(0x300ULL) &&
        missing.empty();
    Field("returning monitor recovers workspace", recover_ok ? "PASS" : "FAIL");
    ok = ok && recover_ok;

    // Device identity survives enumeration order changes.
    mapper.Update(
        {{static_cast<MonitorId>(0x200ULL), "DISPLAYB"},
         {static_cast<MonitorId>(0x100ULL), "DISPLAYA"}},
        bound, missing, 2);
    const bool identity_ok =
        bound.size() == 2 && bound[0].device == "DISPLAYA" &&
        bound[0].real_monitor == static_cast<MonitorId>(0x100ULL) &&
        bound[1].device == "DISPLAYB" &&
        bound[1].real_monitor == static_cast<MonitorId>(0x200ULL) &&
        missing.empty();
    Field("device identity survives order change", identity_ok ? "PASS" : "FAIL");
    ok = ok && identity_ok;

    // A monitor added while only a higher config index is still bound must
    // take the lowest missing index (config 0), not next.size() (which would
    // collide with the surviving config 1).
    mapper.Update(
        {{static_cast<MonitorId>(0x200ULL), "DISPLAYB"},
         {static_cast<MonitorId>(0x400ULL), "DISPLAYC"}},
        bound, missing, 2);
    const bool lowest_index_ok =
        bound.size() == 2 &&
        std::count_if(bound.begin(), bound.end(),
                      [](const MonitorTopologyMapper::BoundMonitor& monitor) {
                          return monitor.config_index == 1;
                      }) == 1 &&
        std::count_if(bound.begin(), bound.end(),
                      [](const MonitorTopologyMapper::BoundMonitor& monitor) {
                          return monitor.config_index == 0;
                      }) == 1 &&
        bound[1].device == "DISPLAYC" && missing.empty();
    Field("new monitor takes lowest missing config index",
          lowest_index_ok ? "PASS" : "FAIL");
    ok = ok && lowest_index_ok;

    Field("result", ok ? "PASS" : "FAIL");
    Print("RESULT={}\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

}  // namespace vd
