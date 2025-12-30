###############################
# File: stealth_engine.py
# Purpose:
#   Provides a "stealth mode" component in two layers:
#
#   1) In-process simulation layer:
#      - A deterministic decision engine (StealthEngine) that evaluates abstract
#        "Probe" events and returns a "Decision" (allow/drop/delay).
#      - This is safe for testing and demonstrates policy enforcement logic
#        without performing real attacks or packet manipulation.
#
#   2) System-level helper (Windows only):
#      - set_stealth_mode(enable) toggles a Windows Firewall rule to block or
#        allow ICMP echo (ping). It is intentionally narrow in scope.
#
#   - Deterministic behavior via hashing + seeding (reproducible decisions)
#   - Defensive validation of configuration values
#   - Thread-safety (lock) for config updates
#   - Safe platform checks (Windows-only firewall operations)
#   - Logging for traceability and reporting
###############################

"""
Overview
--------
This module provides two related features used by the project:

- `StealthEngine` and supporting dataclasses (`Probe`, `Decision`, `StealthConfig`,
    etc.) — an in-process engine that deterministically decides whether to
    allow/drop/delay simulated network probes based on a configuration. This is
    suitable for unit testing, simulation and policy enforcement inside the
    Python process.

- `set_stealth_mode(enable: bool)` — a small OS-level helper that toggles a
    Windows Firewall rule to block or allow inbound ICMPv4 echo requests
    (ping). This provides a pragmatic "system stealth" option (Windows only).

How the code runs
------------------
- To evaluate probes programmatically, construct a `StealthEngine` and call
    `engine.evaluate(probe)` which returns a `Decision` object describing the
    action (`Action.ALLOW`, `Action.DROP`, `Action.DELAY`) and optional delay.

- Use `build_engine(config_dict)` to create a `StealthEngine` from plain
    configuration values (useful for loading JSON/YAML configs).

- `set_stealth_mode(enable)` executes `netsh` commands on Windows to add or
    remove a firewall rule named `pythongroupproject_Block_ICMP_Echo` that
    blocks inbound `icmpv4`. This function returns `True` on success and
    `False` on failure; it raises `NotImplementedError` on non-Windows systems.

Security & safety notes
-----------------------
- `set_stealth_mode` requires Administrator privileges to modify the
    Windows Firewall. When running without admin privileges the function will
    fail (and return False) — the `smoke_test.py` demo is guarded so it does
    not attempt system changes unless the process has admin rights.
- This module intentionally avoids dangerous functionality such as IP
    spoofing. The system-level toggle only blocks ICMP echo requests.

Examples
--------
Importing and using the functions from another script:

        from stealth_engine import StealthEngine, StealthConfig, Probe, ProbeType, set_stealth_mode

        # In-process engine usage
        cfg = StealthConfig(enabled=True, seed=123)
        engine = StealthEngine(cfg)
        p = Probe.make(probe_type=ProbeType.ICMP_ECHO, source_ip='10.0.0.5', timestamp_ms=1234)
        decision = engine.evaluate(p)

        # System-level toggle (Windows, requires Administrator)
        set_stealth_mode(True)   # block inbound ping
        set_stealth_mode(False)  # remove the block
"""

from __future__ import annotations

import hashlib, logging, random, threading, subprocess, platform
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple

from logging_setup import get_logger
logger = get_logger(__name__, "stealth_engine.log")


class Action(str, Enum):
    # Allowed actions returned by the decision engine.
    ALLOW = "allow"
    DROP = "drop"
    DELAY = "delay"


class ProbeType(str, Enum):
    # Types of probes/events the engine can evaluate.
    ICMP_ECHO = "icmp_echo"
    TCP_SYN = "tcp_syn"
    UDP_PACKET = "udp_packet"
    OS_FINGERPRINT = "os_fingerprint"
    OTHER = "other"


def _freeze_meta(meta: Optional[Mapping[str, Any]]) -> Tuple[Tuple[str, Any], ...]:
    # Convert metadata into a stable, hashable tuple.
    return () if not meta else tuple(sorted(meta.items(), key=lambda kv: kv[0]))


@dataclass(frozen=True)
# Immutable representation of a network-related event ("probe") to be evaluated.
class Probe:
    probe_type: ProbeType
    source_ip: str
    timestamp_ms: int
    payload_size: int = 0
    event_id: Optional[str] = None
    metadata: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def make(
        cls,
        probe_type: ProbeType,
        source_ip: str,
        timestamp_ms: int,
        payload_size: int = 0,
        event_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "Probe":
        # Convenience constructor that normalizes metadata into a stable structure.
        return cls(probe_type, source_ip, timestamp_ms, payload_size, event_id, _freeze_meta(metadata))


@dataclass(frozen=True)
class Decision:
    # Output of StealthEngine.evaluate().
    action: Action
    delay_ms: int = 0
    reason: str = "default"

    def __post_init__(self) -> None:
        # Defensive validation prevents incorrect Decision objects from being created.
        if self.action == Action.DELAY:
            if self.delay_ms <= 0:
                raise ValueError("delay_ms must be > 0 when action == DELAY")
        elif self.delay_ms != 0:
            object.__setattr__(self, "delay_ms", 0)

    def __str__(self) -> str:
        # Output is useful for logs and demos.
        return (f"DECISION: {self.action.value} ({self.delay_ms}ms) [{self.reason}]"
                if self.action == Action.DELAY
                else f"DECISION: {self.action.value} [{self.reason}]")


@dataclass(frozen=True)
class StealthConfig:
    # Configuration for the stealth decision engine.
    enabled: bool = True
    seed: Optional[int] = None
    drop_probability: float = 0.0
    min_delay_ms: int = 0
    max_delay_ms: int = 0
    ignore_pings: bool = False

    def validate(self) -> None:
        # Probability must be between 0 and 1.
        if not (0.0 <= self.drop_probability <= 1.0):
            raise ValueError("drop_probability must be between 0.0 and 1.0")
        # Delays must not be negative.
        if self.min_delay_ms < 0 or self.max_delay_ms < 0:
            raise ValueError("min_delay_ms/max_delay_ms must be >= 0")
        if self.min_delay_ms > self.max_delay_ms:
            raise ValueError("min_delay_ms cannot be greater than max_delay_ms")


def _seed_int(seed: Optional[int], purpose: str, p: Probe) -> int:
    # Derive a deterministic integer seed.
    s = str(0 if seed is None else seed)
    blob = "|".join([s, purpose, p.probe_type.value, p.source_ip or "",
                     str(p.timestamp_ms), str(p.payload_size), p.event_id or ""]).encode()
    return int.from_bytes(hashlib.blake2b(blob, digest_size=8).digest(), "big")


class StealthEngine:
    #  Deterministic decision engine that evaluates Probe events according to StealthConfig.
    def __init__(self, config: StealthConfig, logger_override: Optional[logging.Logger] = None) -> None:
        config.validate()
        self._config = config
        self._lock = threading.RLock()
        self._log = logger_override or logger

        # Minimal startup log to confirm initialization and support debugging.
        self._log.info("StealthEngine initialized.")

    @property
    def config(self) -> StealthConfig:
        return self._config

    def update_config(self, new_config: StealthConfig) -> None:
        # Replace configuration.
        new_config.validate()
        with self._lock:
            self._config = new_config
        self._log.info("StealthEngine configuration updated.")

    def evaluate(self, probe: Probe) -> Decision:
        # Evaluate a probe and return a Decision.
        cfg = self._config  # snapshot; avoids lock overhead for read-only evaluation

        if not cfg.enabled:
            return Decision(Action.ALLOW, reason="disabled")

        if cfg.ignore_pings and probe.probe_type == ProbeType.ICMP_ECHO:
            # Logging makes policy enforcement visible in reports.
            self._log.info("Dropped ICMP echo probe (ignore_pings enabled).")
            return Decision(Action.DROP, reason="icmp_drop")

        if cfg.drop_probability > 0.0:
            if random.Random(_seed_int(cfg.seed, "drop", probe)).random() < cfg.drop_probability:
                self._log.warning("Dropped probe due to drop_probability.")
                return Decision(Action.DROP, reason="prob_drop")

        if cfg.max_delay_ms > 0:
            delay = random.Random(_seed_int(cfg.seed, "delay", probe)).randint(cfg.min_delay_ms, cfg.max_delay_ms)
            if delay > 0:
                self._log.info(f"Delayed probe by {delay} ms.")
                return Decision(Action.DELAY, delay_ms=delay, reason="jitter")

        return Decision(Action.ALLOW, reason="allow")


def build_engine(config: Dict[str, Any], logger_override: Optional[logging.Logger] = None) -> StealthEngine:
    # Create a StealthEngine from a plain dictionary.
    def b(x: Any) -> bool:
        # Defensive boolean parsing prevents silent misconfiguration.
        if isinstance(x, bool): return x
        if isinstance(x, (int, float)) and x in (0, 1): return bool(x)
        if isinstance(x, str) and x.strip().lower() in ("true", "1", "yes", "y", "on"): return True
        if isinstance(x, str) and x.strip().lower() in ("false", "0", "no", "n", "off"): return False
        raise ValueError(f"Invalid bool: {x!r}")

    def i(x: Any) -> int:
        # Prevent bool being treated as int (True == 1) to avoid subtle bugs.
        if isinstance(x, bool): raise ValueError(f"Invalid int: {x!r}")
        if isinstance(x, int): return x
        if isinstance(x, float) and x.is_integer(): return int(x)
        if isinstance(x, str): return int(x.strip())
        raise ValueError(f"Invalid int: {x!r}")

    def f(x: Any) -> float:
        # Same defensive approach for floats.
        if isinstance(x, bool): raise ValueError(f"Invalid float: {x!r}")
        if isinstance(x, (int, float)): return float(x)
        if isinstance(x, str): return float(x.strip())
        raise ValueError(f"Invalid float: {x!r}")

    # Build config with safe defaults when keys are missing.
    cfg = StealthConfig(
        enabled=b(config["enabled"]) if "enabled" in config else True,
        seed=None if config.get("seed", None) is None else i(config["seed"]),
        drop_probability=f(config["drop_probability"]) if "drop_probability" in config else 0.0,
        min_delay_ms=i(config["min_delay_ms"]) if "min_delay_ms" in config else 0,
        max_delay_ms=i(config["max_delay_ms"]) if "max_delay_ms" in config else 0,
        ignore_pings=b(config["ignore_pings"]) if "ignore_pings" in config else False,
    )

    # Log build event (simple)
    (logger_override or logger).info("StealthEngine built from config.")
    return StealthEngine(cfg, logger_override=logger_override or logger)


def set_stealth_mode(enable: bool) -> bool:
    # Toggle system-level ICMP echo (ping) responses on Windows by adding/removing
    # a Windows Firewall rule. Returns True on success. Requires administrator
    # privileges. On non-Windows systems this raises NotImplementedError.
    if platform.system() != "Windows":
        logger.error("set_stealth_mode called on non-Windows system.")
        raise NotImplementedError("set_stealth_mode is only implemented for Windows.")

    rule_name = "pythongroupproject_Block_ICMP_Echo"

    try:
        if enable:
            logger.info("Enabling system stealth mode (block ICMP echo).")
            # Delete any existing rule of the same name to keep behavior idempotent.
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"
            ], check=False, capture_output=True, text=True)
            # Add firewall rule to block inbound ICMPv4 echo.
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", "protocol=icmpv4"
            ], check=True, capture_output=True, text=True)
        else:
            logger.info("Disabling system stealth mode (remove ICMP block rule).")
            # Remove the firewall rule; check=True so errors are surfaced and logged.
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"
            ], check=True, capture_output=True, text=True)

        logger.info(f"Stealth mode updated successfully (enable={enable}).")
        return True

    except subprocess.CalledProcessError as e:
         # A controlled failure mode prevents the program from crashing and gives useful diagnostics.
        logger.error("Failed to set stealth mode: %s", e.stderr or e.stdout or str(e))
        return False

if __name__ == "__main__":
    set_stealth_mode(True)
    # Demo mode: evaluate a few probes and write results to the log.
    logger.info("Running stealth_engine demo (__main__)")

    cfg = StealthConfig(
        enabled=True,
        seed=123,
        drop_probability=0.2,
        min_delay_ms=10,
        max_delay_ms=50,
        ignore_pings=True
    )

    engine = StealthEngine(cfg)

    probes = [
        Probe.make(ProbeType.ICMP_ECHO, "10.0.0.5", 1000),
        Probe.make(ProbeType.TCP_SYN, "10.0.0.5", 1010),
        Probe.make(ProbeType.UDP_PACKET, "10.0.0.6", 1020),
    ]
    
    # Log decisions rather than printing them so the demo can be reviewed later.
    for p in probes:
        d = engine.evaluate(p)
        logger.info(f"Decision for {p.probe_type.value} from {p.source_ip}: {d}")

    print("Stealth demo finished. Check logs/stealth_engine.log")

