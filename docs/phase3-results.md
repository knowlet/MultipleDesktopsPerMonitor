# Phase 3 validation results

## Logical workspace round trip

`vdprobe logical-workspace-test --confirm-mutate` completed one deterministic
monitor-local round trip using the two existing native desktops:

```text
Monitor A: A1 active, A2 inactive
Monitor B: B1 control window

A1 -> A2
A2 -> A1
```

The test created three vdprobe-owned disposable Win32 windows.  The current
native desktop remained the Carrier and the other existing desktop remained
shared Parking.  No native desktop was created, removed, or globally
selected.

The result was **GO-LOGICAL-WORKSPACE**:

- only the target monitor's A1/A2 views were moved;
- B1 kept the same HWND, rectangle, monitor, desktop GUID, and visibility;
- the global current desktop GUID never changed;
- `CurrentVirtualDesktopChanged` count was zero;
- only A1/A2 produced `ViewVirtualDesktopChanged` callbacks (four total for
  the two-way round trip);
- notification unregistration returned `S_OK`;
- all probe-owned windows and processes were cleaned up.

The resulting invariant is:

```text
logical workspace identity != native virtual desktop identity

active workspace windows   -> Carrier
inactive workspace windows -> shared Parking
```

This is the first proof of an independent per-monitor logical workspace
switch without a session-global desktop switch.
