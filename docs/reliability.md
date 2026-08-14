# Reliability gates

The production manager is validated with deterministic stress, live stress,
soak, restart recovery, display-topology, and sleep/resume gates.

## Deterministic stress

`workspace-stress-test` (non-mutating) builds an engine with 60 tracked
windows across two monitors, runs 100 A1 <-> A2 switch round-trips with a
journal, and asserts the Carrier/Parking invariant plus a clean journal after
every step. It then adds 20 transient windows, closes them with an
authoritative snapshot, and verifies HWND reuse creates a new generation
without inheriting ownership.

## Live stress

`workspace-live-manager-test --confirm-mutate --rounds N` runs N complete
A1 -> A2 -> A1 round-trips on the live shell with probe-owned windows; every
switch must commit, keep Monitor B and the session-global Carrier unchanged,
and leave no pending journal. The single-round default is the stable gate;
`--rounds 5` is the live stress gate.

## Soak

`workspace-manager --run --seconds N` is the bounded soak gate: the host
runs its real message loop with tray/hotkeys and periodic reconciliation for
N seconds and reports invariant, journal, and cleanup status on shutdown. A
25-second run performed 8 periodic reconciliations with `RESULT=PASS`.

## Restart recovery

`workspace-startup-test` and the coordinator's fresh-engine recovery tests
cover interrupted-transaction recovery; the live `logical-workspace-test`
hands a journal to a fresh engine/coordinator pair and recovers it against
live state.

## Display topology and sleep/resume

`workspace-host-resilience-test` covers monitor suspend/recover and
device-identity preservation deterministically; the host handles
`WM_DISPLAYCHANGE` and `WM_POWERBROADCAST` (resume) live, re-validating the
shell and re-acquiring Carrier/Parking on demand (see docs/resilience.md).

## Exit criterion

No known invariant corruption under representative sustained use: the
deterministic stress (100 switches, 60 windows), live stress (5 round-trips),
soak (25 s host), restart recovery, display/sleep-resume, and quarantine
gates all pass from a fresh build.
