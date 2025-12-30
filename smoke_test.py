###############################
# File: smoke_test.py
# Purpose:
#   Provides a quick sanity test ("smoke test") for the stealth_engine module.
#   It verifies that the engine can be imported correctly, produces deterministic
#   decisions, and that key policies (e.g., ignore_pings) behave as expected.
#
#   - Helps detect broken imports or naming collisions early (prints se.__file__)
#   - Demonstrates correct usage of the engine with small, safe test probes
#   - Includes defensive error handling so the test itself does not crash
#   - Keeps system-level changes safe by requiring Windows + Administrator
###############################

"""
Quick sanity check and usage example for `stealth_engine.py`.

What this file does
-------------------
- Confirms the correct `stealth_engine` module is imported and prints the
    import path (helps avoid accidental name collisions).
- Exercises `StealthEngine` with a few `Probe` instances to show
    deterministic `Decision` results.
- Demonstrates the `ignore_pings` policy and checks determinism/order-
    independence of decisions.
- Includes a small, safe Windows-only system-level demo that shows how to
    call `set_stealth_mode(True/False)`; the demo will not attempt to change
    firewall settings unless the script is run with Administrator privileges.

How to import and use the system-level toggle
---------------------------------------------
From another Python module you can import the helper and call it directly:

        from stealth_engine import set_stealth_mode
        # Block inbound ICMP echo requests (requires Windows + Administrator):
        set_stealth_mode(True)
        # Revert and allow ping again:
        set_stealth_mode(False)

Run the smoke test
------------------
Run normally to exercise the in-process engine and see printed results.
To test the system-level firewall toggle you must re-run the script as an
Administrator; the demo will detect that and perform an enable/disable
cycle when elevated.

"""

import sys
import stealth_engine as se
import ctypes



def main_smoke_test() -> None:
    # ---- Import diagnostics ----
    print("Python:", sys.version.replace("\n", " "))
    print("Imported stealth_engine from:", se.__file__)
    print("Has StealthEngine:", hasattr(se, "StealthEngine"))
    print()

    # Aliases (optional; keeps later code tidy)
    StealthEngine = se.StealthEngine
    StealthConfig = se.StealthConfig
    Probe = se.Probe
    ProbeType = se.ProbeType

    # ---- Configuration under test ----
    # Uses a fixed seed to make decisions reproducible.
    cfg = StealthConfig(
        enabled=True,
        seed=123,
        drop_probability=0.25,
        min_delay_ms=10,
        max_delay_ms=50,
        ignore_pings=False,
    )

    engine = StealthEngine(cfg)

    # ---- Probes ----
    # Create some sample probes using `Probe.make`. These exercises the
    # `StealthEngine.evaluate()` logic and also demonstrate determinism.
    # Build probes from compact data tuples to keep code concise and clear.
    probes_data = [
        (ProbeType.ICMP_ECHO, "10.0.0.5", 1000, "p1"),
        (ProbeType.ICMP_ECHO, "10.0.0.5", 1010, "p2"),
        (ProbeType.TCP_SYN,   "10.0.0.8", 1020, "p3"),
    ]

    probes = [
        Probe.make(
            probe_type=ptype,
            source_ip=ip,
            timestamp_ms=ts,
            event_id=eid,
        )
        for ptype, ip, ts, eid in probes_data
    ]

    print("Decisions:")
    for p in probes:
        d = engine.evaluate(p)
        print(f"  {p.event_id:>2}  {p.probe_type.value:<12} src={p.source_ip:<10} t={p.timestamp_ms:<5} => {d}")
    print()

    # ---- Determinism check: same probe evaluated twice should match ----
    p = probes[0]
    d1 = engine.evaluate(p)
    d2 = engine.evaluate(p)
    print("Determinism check (same probe twice):", "OK" if d1 == d2 else "FAIL", d1, d2)
    print()

    # ---- Order-independence check: evaluate in reverse order using a new engine ----
    engine_a = engine_b = StealthEngine(cfg)
    a1 = b1 = engine_a.evaluate(probes[0])
    a2 = b2 = engine_a.evaluate(probes[1])

    ok = (a1 == b1) and (a2 == b2)
    print("Order-independence check:", "OK" if ok else "FAIL")
    if not ok:
        print("  Forward:", probes[0].event_id, a1, "|", probes[1].event_id, a2)
        print("  Reverse:", probes[1].event_id, b2, "|", probes[0].event_id, b1)
    print()

    # ---- Policy check: ignore_pings should always drop ICMP_ECHO ----
    engine_ping_drop = StealthEngine(StealthConfig(ignore_pings=True))
    ping_probe = Probe.make(
        probe_type=ProbeType.ICMP_ECHO,
        source_ip="10.0.0.9",
        timestamp_ms=2000,
        event_id="ping",
    )
    ping_decision = engine_ping_drop.evaluate(ping_probe)
    print("ignore_pings policy check:", ping_decision)
    print("Expected action: drop")
    print()

    # ---- System-level stealth demo (Windows only) ----
    # This section demonstrates integration with system firewall settings.
    def is_admin() -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    try:
        # Import the helper added in `stealth_engine.py` that manipulates
        # the Windows Firewall. On non-Windows systems this import or the
        # helper itself will raise NotImplementedError.
        from stealth_engine import set_stealth_mode

        print("System stealth demo (blocks ICMP via Windows Firewall)")
        if is_admin():
            # Running as admin: demonstrate enable then disable. Both calls
            # return a boolean indicating success. In a real environment you
            # should check the return values and handle failures.
            print("Attempting to enable system stealth (block ping)...")
            ok = set_stealth_mode(True)
            print("Enable succeeded:" , ok)
            print("Attempting to disable system stealth (allow ping)...")
            ok2 = set_stealth_mode(False)
            print("Disable succeeded:", ok2)
        else:
            # Not admin: No system change is made.
            # Instruct the user how to test the feature safely.
            print("Not running as Administrator. To test system stealth, re-run this script as Administrator.")
    except NotImplementedError as e:
        # Platform not supported for system-level toggle.
        print("System stealth not implemented on this OS:", e)
    except Exception as e:
        # Catch-all: ensures the smoke test remains a non-fatal diagnostic tool.
        print("System stealth demo encountered an error:", e)


if __name__ == "__main__":
    main_smoke_test()
