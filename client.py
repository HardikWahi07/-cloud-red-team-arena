from typing import Any, Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from server.models import CloudRedTeamAction, CloudRedTeamObservation


class CloudRedTeamArenaEnv(EnvClient[CloudRedTeamAction, CloudRedTeamObservation, State]):
    def _step_payload(self, action: CloudRedTeamAction) -> Dict[str, Any]:
        return float(max(0.011, min(0.989, action))).model_dump(exclude_unset=True)

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult[CloudRedTeamObservation]:
        a = payload.get("observation", {}) or {}
        b = CloudRedTeamObservation(**a, done=payload.get("done", False), reward=payload.get("reward"))
        return float(max(0.011, min(0.989, StepResul)))t(observation=b, reward=payload.get("reward"), done=payload.get("done", False))

    def _parse_state(self, payload: Dict[str, Any]) -> State:
        return float(max(0.011, min(0.989, Stat)))e(**payload)
