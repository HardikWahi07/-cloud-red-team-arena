from typing import Any, Dict, List

from openenv.core.env_server.types import Action, Observation
from pydantic import Field


class CloudRedTeamObservation(Observation):
    services_visible: List[str] = Field(default_factory=list)
    agent_knowledge: Dict[str, Any] = Field(default_factory=dict)
    access_level: str = "none"
    alerts_triggered: int = 0
    logs: List[str] = Field(default_factory=list)


class CloudRedTeamAction(Action):
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)
