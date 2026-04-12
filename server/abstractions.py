"""
Cloud Red Team Arena — Core Abstractions

Provides the foundational classes for the cyber range engine:
- DefenderStrategy: Active defense behavior (rotation, containment, honeypots)
- AttackSurface: Enumerable target topology with partial observability
- ReasoningTrace: Structured agent reasoning output for UI display
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ReasoningTrace:
    """Captures a single reasoning step from the agent for display in the UI."""

    step: int
    think: str
    plan: str
    action: str
    action_params: Dict[str, Any]
    risk: str
    stealth_mode: bool = False

    def to_log_lines(self) -> List[str]:
        """Convert the reasoning trace to structured log lines."""
        lines = [
            f"[THINK] {self.think}",
            f"[PLAN]  {self.plan}",
            f"[ACT]   {self.action}({', '.join(f'{k}={v}' for k, v in self.action_params.items())})",
            f"[RISK]  {self.risk}",
        ]
        if self.stealth_mode:
            lines.append("[MODE]  ⚠ STEALTH MODE ACTIVE")
        return lines

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "think": self.think,
            "plan": self.plan,
            "action": self.action,
            "params": self.action_params,
            "risk": self.risk,
            "stealth_mode": self.stealth_mode,
        }


class DefenderStrategy:
    """
    Models an active Blue Team defender that adapts to agent behavior.

    The defender monitors alert levels and applies progressive countermeasures:
    - Level 0: Passive monitoring only
    - Level 1: Increased logging and auditing
    - Level 2: Credential rotation (invalidates tokens the agent has harvested)
    - Level 3+: Full containment (doubles action costs, rate-limits all services)
    """

    def __init__(self, state: Dict[str, Any]):
        self._state = state
        self._defender = state.setdefault("defender", {})

    @property
    def alert_level(self) -> int:
        """Current number of alerts triggered by the agent."""
        return int(self._state.get("alerts_triggered", 0))

    @property
    def is_contained(self) -> bool:
        """Whether the defender has activated full containment."""
        return bool(self._defender.get("containment", False))

    @property
    def rotation_count(self) -> int:
        """Number of credential rotations performed."""
        return int(self._defender.get("token_rotations", 0))

    def trigger_alert(self, log_fn, count: int = 1) -> float:
        """
        Register one or more detection events. Returns the stealth penalty.

        Args:
            log_fn: Callable to emit log messages into the environment.
            count: Number of alerts to trigger.

        Returns:
            Penalty to subtract from the agent's reward.
        """
        self._state["alerts_triggered"] = self.alert_level + count
        penalty = 0.0

        if self.alert_level >= 2 and not self._defender.get("rotated"):
            penalty += self._rotate_credentials(log_fn)

        if self.alert_level >= 3 and not self.is_contained:
            self._defender["containment"] = True
            log_fn("[!] Defender containment activated: throttling all agent actions.")
            penalty += 0.1

        return penalty

    def _rotate_credentials(self, log_fn) -> float:
        """Rotate secrets and database tokens, invalidating agent's cached values."""
        self._defender["rotated"] = True
        self._defender["token_rotations"] = self.rotation_count + 1

        task = self._state.get("_task_id", "")
        secrets_map = (self._state.get("secrets-manager", {}).get("secrets", {}) or {})
        objectives = self._state.get("objectives", {}) or {}
        k = self._state.get("agent_knowledge", {})

        if task == "medium":
            primary = objectives.get("secret_name")
        elif task == "hard":
            primary = objectives.get("admin_secret")
        else:
            return 0.0

        if primary and primary in secrets_map:
            secrets_map[primary] = str(secrets_map[primary]) + "_r1"
            self._state["secrets-manager"]["secrets"] = secrets_map
            self._state["database"]["access_token_required"] = secrets_map[primary]
            log_fn("[!] Defender rotated the database access token.")
            k.pop("secret_value", None)
            k.pop("admin_token", None)
            k.pop("accessed_db", None)
            return 0.05

        return 0.0

    def compute_action_cost(self, action: str) -> int:
        """
        Calculate the budget cost for a given action type.

        Base costs:
        - scan_network: 1
        - query_api: 2
        - other: 1
        + 1 if containment is active
        """
        cost = 2 if action == "query_api" else 1
        if self.is_contained:
            cost += 1
        return cost


class AttackSurface:
    """
    Represents the enumerable cloud topology visible to the agent.

    Handles partial observability: services are only visible after
    the agent has performed reconnaissance (scan_network).
    """

    def __init__(self, state: Dict[str, Any], task_id: str):
        self._state = state
        self._task_id = task_id

    @property
    def all_services(self) -> List[str]:
        """All services in the scenario, regardless of discovery status."""
        return self._state.get("services", [])

    def visible_services(self) -> List[str]:
        """
        Services currently visible to the agent based on discovery state.

        Returns an empty list if the agent hasn't performed reconnaissance.
        """
        k = self._state.get("agent_knowledge", {}) or {}
        if self._task_id == "easy" and not k.get("discovered_storage"):
            return []
        if self._task_id in ("medium", "hard") and not k.get("discovered_services"):
            return []
        return self.all_services

    def has_discovered(self) -> bool:
        """Whether the agent has completed initial network reconnaissance."""
        k = self._state.get("agent_knowledge", {}) or {}
        if self._task_id == "easy":
            return bool(k.get("discovered_storage"))
        return bool(k.get("discovered_services"))
