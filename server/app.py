"""
Cloud Red Team Arena — FastAPI Gateway

Routes:
- GET  /              → Operational Command Center (UI)
- GET  /api/info      → Environment metadata
- GET  /api/ui-state  → Live simulation state for dashboard polling
- POST /api/deploy-custom → Deploy a custom JSON scenario
- POST /api/run-step  → Execute one agent step with reasoning trace
"""

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError(
        "openenv-core is required to run the server. Install dependencies from requirements.txt."
    ) from e

from .environment import CloudRedTeamEnvironment
from .models import CloudRedTeamAction, CloudRedTeamObservation


app = create_app(
    CloudRedTeamEnvironment,
    CloudRedTeamAction,
    CloudRedTeamObservation,
    env_name="cloud-red-team-arena",
    max_concurrent_envs=1,
)


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------
@app.get("/api/info")
def info():
    """Return environment metadata and available endpoints."""
    return {
        "env": "CloudRedTeamArena",
        "version": "2.0.0",
        "tasks": ["easy", "medium", "hard", "custom"],
        "endpoints": [
            "/", "/api/info", "/reset", "/step", "/state",
            "/ws", "/dashboard", "/api/ui-state",
            "/api/deploy-custom", "/api/run-step",
        ],
    }


# ---------------------------------------------------------------------------
# Dashboard UI
# ---------------------------------------------------------------------------
from fastapi.responses import HTMLResponse
import os

@app.get("/")
@app.get("/dashboard")
def dashboard():
    """Serve the Operational Command Center single-page application."""
    ui_path = os.path.join(os.path.dirname(__file__), "ui.html")
    with open(ui_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


# ---------------------------------------------------------------------------
# Live State Endpoint
# ---------------------------------------------------------------------------
@app.get("/api/ui-state")
def ui_state():
    """
    Return the current simulation state for dashboard polling.
    Includes reasoning traces from the agent memory.
    """
    from .environment import get_active_env
    env = get_active_env()
    if not env:
        return {"status": "offline"}

    # Try to get reasoning traces from agent memory
    traces = []
    try:
        import sys
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root_dir not in sys.path:
            sys.path.insert(0, root_dir)
        from inference import get_memory
        traces = get_memory().reasoning_traces
    except Exception:
        pass

    return {
        "status": "online",
        "task": env.t,
        "step": env.st.step_count,
        "sim_state": env.zz,
        "reasoning_traces": traces[-10:],  # Last 10 traces for UI
    }


# ---------------------------------------------------------------------------
# Custom Scenario Deployment
# ---------------------------------------------------------------------------
from fastapi import Request

@app.post("/api/deploy-custom")
async def deploy_custom(req: Request):
    """Deploy a custom scenario configuration from user-provided JSON."""
    from .environment import get_active_env
    env = get_active_env()
    if not env:
        return {"status": "error", "message": "offline"}
    payload = await req.json()
    scenario = payload.get("scenario", {})
    env.t = "custom"
    env.zz = scenario
    env.zz["access_level"] = "none"
    env.zz["alerts_triggered"] = 0
    env.zz["budget_remaining"] = int((env.zz.get("limits", {}) or {}).get("budget") or 20)
    env.zz["rate_counters"] = {}
    from .grader import get_grader
    from uuid import uuid4
    from openenv.core.env_server.types import State
    env.g = get_grader("custom")
    env.la = None
    env.st = State(episode_id=str(uuid4()), step_count=0, task_id="custom")
    env._l("[+] Custom Environment deployed manually")
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Autonomous Agent Step Execution
# ---------------------------------------------------------------------------
@app.post("/api/run-step")
async def run_step():
    """
    Execute one autonomous agent step using the heuristic planner.

    Returns the action taken and the agent's reasoning trace,
    which the UI renders in the Live Reasoning Panel.
    """
    from .environment import get_active_env
    from .models import CloudRedTeamAction
    env = get_active_env()
    if not env or not env.zz:
        return {"status": "error", "message": "Environment not initialized"}

    # Check termination conditions
    if env.st.step_count >= 10 or env.zz.get("agent_knowledge", {}).get("objective_complete"):
        return {"status": "done"}

    try:
        import sys
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root_dir not in sys.path:
            sys.path.insert(0, root_dir)
        from inference import heuristic_action, get_memory

        # Build observation with full context
        obs = env._o().model_dump()
        obs["agent_knowledge"] = dict(env.zz.get("agent_knowledge", {}))
        obs["logs"] = list(env.zz.get("logs", []))
        obs["alerts_triggered"] = env.zz.get("alerts_triggered", 0)
        obs["budget_remaining"] = env.zz.get("budget_remaining", 0)
        obs["limits"] = env.zz.get("limits", {})

        act_dict = heuristic_action(env.t, env.st.step_count + 1, obs)

        # Inject reasoning trace into environment logs for terminal display
        mem = get_memory()
        if mem.reasoning_traces:
            trace = mem.reasoning_traces[-1]
            env._l(f"[THINK] {trace.get('think', '')}")
            env._l(f"[PLAN]  {trace.get('plan', '')}")
            env._l(f"[ACT]   {trace.get('action', '')}({', '.join(f'{k}={v}' for k,v in (trace.get('params') or {}).items())})")
            env._l(f"[RISK]  {trace.get('risk', '')}")
            if trace.get('stealth_mode'):
                env._l("[MODE]  ⚠ STEALTH MODE — prioritizing evasion")

        action = CloudRedTeamAction(action=act_dict["action"], params=act_dict.get("params", {}))
        result = env.step(action)

        # Get the latest reasoning trace
        mem = get_memory()
        latest_trace = mem.reasoning_traces[-1] if mem.reasoning_traces else None

        is_done = bool(result.done)
        return {
            "status": "done" if is_done else "ok",
            "action": act_dict["action"],
            "reasoning": latest_trace,
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# Server Entry Point
# ---------------------------------------------------------------------------
def main(host: str = "0.0.0.0", port: int = 8000):
    """Start the uvicorn server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
