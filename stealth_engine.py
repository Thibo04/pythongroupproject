"""
stealth_engine.py

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


class Action(str, Enum):
    ALLOW = "allow"
    DROP = "drop"
    DELAY = "delay"


class ProbeType(str, Enum):
    ICMP_ECHO = "icmp_echo"
    TCP_SYN = "tcp_syn"
    UDP_PACKET = "udp_packet"
    OS_FINGERPRINT = "os_fingerprint"
    OTHER = "other"


def _freeze_meta(meta: Optional[Mapping[str, Any]]) -> Tuple[Tuple[str, Any], ...]:
    return () if not meta else tuple(sorted(meta.items(), key=lambda kv: kv[0]))


@dataclass(frozen=True)
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
        return cls(probe_type, source_ip, timestamp_ms, payload_size, event_id, _freeze_meta(metadata))


@dataclass(frozen=True)
class Decision:
    action: Action
    delay_ms: int = 0
    reason: str = "default"

    def __post_init__(self) -> None:
        if self.action == Action.DELAY:
            if self.delay_ms <= 0:
                raise ValueError("delay_ms must be > 0 when action == DELAY")
        elif self.delay_ms != 0:
            object.__setattr__(self, "delay_ms", 0)

    def __str__(self) -> str:
        return (f"DECISION: {self.action.value} ({self.delay_ms}ms) [{self.reason}]"
                if self.action == Action.DELAY
                else f"DECISION: {self.action.value} [{self.reason}]")


@dataclass(frozen=True)
class StealthConfig:
    enabled: bool = True
    seed: Optional[int] = None
    drop_probability: float = 0.0
    min_delay_ms: int = 0
    max_delay_ms: int = 0
    ignore_pings: bool = False

    def validate(self) -> None:
        if not (0.0 <= self.drop_probability <= 1.0):
            raise ValueError("drop_probability must be between 0.0 and 1.0")
        if self.min_delay_ms < 0 or self.max_delay_ms < 0:
            raise ValueError("min_delay_ms/max_delay_ms must be >= 0")
        if self.min_delay_ms > self.max_delay_ms:
            raise ValueError("min_delay_ms cannot be greater than max_delay_ms")


def _seed_int(seed: Optional[int], purpose: str, p: Probe) -> int:
    s = str(0 if seed is None else seed)
    blob = "|".join([s, purpose, p.probe_type.value, p.source_ip or "",
                     str(p.timestamp_ms), str(p.payload_size), p.event_id or ""]).encode()
    return int.from_bytes(hashlib.blake2b(blob, digest_size=8).digest(), "big")


class StealthEngine:
    def __init__(self, config: StealthConfig, logger: Optional[logging.Logger] = None) -> None:
        config.validate()
        self._config = config
        self._lock = threading.RLock()
        self._log = logger or logging.getLogger(__name__)
        self._log.info("StealthEngine initialized.")

    @property
    def config(self) -> StealthConfig:
        return self._config

    def update_config(self, new_config: StealthConfig) -> None:
        new_config.validate()
        with self._lock:
            self._config = new_config
        self._log.info("StealthEngine configuration updated.")

    def evaluate(self, probe: Probe) -> Decision:
        cfg = self._config  # snapshot; no I/O here

        if not cfg.enabled:
            return Decision(Action.ALLOW, reason="disabled")

        if cfg.ignore_pings and probe.probe_type == ProbeType.ICMP_ECHO:
            return Decision(Action.DROP, reason="icmp_drop")

        if cfg.drop_probability > 0.0:
            if random.Random(_seed_int(cfg.seed, "drop", probe)).random() < cfg.drop_probability:
                return Decision(Action.DROP, reason="prob_drop")

        if cfg.max_delay_ms > 0:
            delay = random.Random(_seed_int(cfg.seed, "delay", probe)).randint(cfg.min_delay_ms, cfg.max_delay_ms)
            if delay > 0:
                return Decision(Action.DELAY, delay_ms=delay, reason="jitter")

        return Decision(Action.ALLOW, reason="allow")


def build_engine(config: Dict[str, Any], logger: Optional[logging.Logger] = None) -> StealthEngine:
    def b(x: Any) -> bool:
        if isinstance(x, bool): return x
        if isinstance(x, (int, float)) and x in (0, 1): return bool(x)
        if isinstance(x, str) and x.strip().lower() in ("true", "1", "yes", "y", "on"): return True
        if isinstance(x, str) and x.strip().lower() in ("false", "0", "no", "n", "off"): return False
        raise ValueError(f"Invalid bool: {x!r}")

    def i(x: Any) -> int:
        if isinstance(x, bool): raise ValueError(f"Invalid int: {x!r}")
        if isinstance(x, int): return x
        if isinstance(x, float) and x.is_integer(): return int(x)
        if isinstance(x, str): return int(x.strip())
        raise ValueError(f"Invalid int: {x!r}")

    def f(x: Any) -> float:
        if isinstance(x, bool): raise ValueError(f"Invalid float: {x!r}")
        if isinstance(x, (int, float)): return float(x)
        if isinstance(x, str): return float(x.strip())
        raise ValueError(f"Invalid float: {x!r}")

    cfg = StealthConfig(
        enabled=b(config["enabled"]) if "enabled" in config else True,
        seed=None if config.get("seed", None) is None else i(config["seed"]),
        drop_probability=f(config["drop_probability"]) if "drop_probability" in config else 0.0,
        min_delay_ms=i(config["min_delay_ms"]) if "min_delay_ms" in config else 0,
        max_delay_ms=i(config["max_delay_ms"]) if "max_delay_ms" in config else 0,
        ignore_pings=b(config["ignore_pings"]) if "ignore_pings" in config else False,
    )
    return StealthEngine(cfg, logger=logger)


def set_stealth_mode(enable: bool) -> bool:
    """
    Toggle system-level ICMP echo (ping) responses on Windows by adding/removing
    a Windows Firewall rule. Returns True on success. Requires administrator
    privileges. On non-Windows systems this raises NotImplementedError.
    """
    # NOTE (added): This function was added to provide a simple, importable
    # system-level "stealth" toggle that blocks inbound ICMP echo requests on
    # Windows by creating/deleting a firewall rule. The original file
    # implemented only the in-process `StealthEngine` behaviour; this helper
    # provides a pragmatic OS-level option for the project when run with
    # administrator privileges.
    #
    # Safety and behaviour summary:
    # - Only supported on Windows (raises NotImplementedError otherwise).
    # - Requires Administrator privileges to modify the firewall.
    # - The rule name is fixed so calls are idempotent (calling enable twice
    #   will not create duplicate rules).
    # - We use `netsh advfirewall firewall add/delete rule` which is available
    #   on modern Windows. subprocess errors are caught and cause a False
    #   return value while logging the failure.
    if platform.system() != "Windows":
        raise NotImplementedError("set_stealth_mode is only implemented for Windows.")

    rule_name = "pythongroupproject_Block_ICMP_Echo"

    # Use netsh to add/delete a firewall rule that blocks ICMPv4 inbound (echo requests).
    try:
        if enable:
            # delete any existing rule with the same name (idempotence), then add
            # Remove any existing rule with the same name first so the add is
            # idempotent and predictable (avoids duplicates).
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"
            ], check=False, capture_output=True, text=True)

            # Add a rule blocking inbound ICMPv4 (ping) echo requests.
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", "protocol=icmpv4"
            ], check=True, capture_output=True, text=True)
        else:
            # When disabling we simply delete the rule; if it does not exist
            # netsh will report that but we treat that as success.
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"
            ], check=True, capture_output=True, text=True)

        return True
    except subprocess.CalledProcessError as e:
        logging.getLogger(__name__).error("Failed to set stealth mode: %s", e.stderr or e.stdout or str(e))
        return False
