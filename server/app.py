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


@app.get("/api/info")
def info():
    return {
        "env": "CloudRedTeamArena",
        "version": "1.0.0",
        "tasks": ["easy", "medium", "hard", "custom"],
        "endpoints": ["/", "/api/info", "/reset", "/step", "/state", "/ws", "/dashboard", "/api/ui-state", "/api/deploy-custom", "/api/run-step"],
    }

from fastapi.responses import HTMLResponse
import os
@app.get("/")
@app.get("/dashboard")
def dashboard():
    ui_path = os.path.join(os.path.dirname(__file__), "ui.html")
    with open(ui_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/api/ui-state")
def ui_state():
    from .environment import get_active_env
    env = get_active_env()
    if not env:
        return {"status": "offline"}
    return {
        "status": "online",
        "task": env.t,
        "step": env.st.step_count,
        "sim_state": env.zz
    }

from fastapi import Request
@app.post("/api/deploy-custom")
async def deploy_custom(req: Request):
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
    from server.grader import get_grader
    from uuid import uuid4
    from openenv.core.env_server.types import State
    env.g = get_grader("custom")
    env.la = None
    env.st = State(episode_id=str(uuid4()), step_count=0, task_id="custom")
    env._l("[+] Custom Environment deployed manually")
    return {"status": "ok"}

@app.post("/api/run-step")
async def run_step():
    from .environment import get_active_env
    from .models import CloudRedTeamAction
    env = get_active_env()
    if not env or not env.zz:
        return {"status": "error", "message": "Environment off"}
    
    # Check if already done
    if env.st.step_count >= 10 or env.zz.get("agent_knowledge", {}).get("objective_complete"):
        return {"status": "done"}
        
    try:
        import sys, os
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root_dir not in sys.path:
            sys.path.insert(0, root_dir)
        from inference import heuristic_action
        obs = env._o().model_dump()
        
        # Inject the most recent logs from the environment so the heuristic agent can read them
        if hasattr(env, "zz") and "logs" in env.zz:
            # Get logs from the last step by grabbing recent entries
            # heuristic_action expects obs["logs"] to have the immediate feedback
            obs["logs"] = env.zz["logs"][-5:]
            
        act_dict = heuristic_action(env.t, env.st.step_count + 1, obs)
        action = CloudRedTeamAction(action=act_dict["action"], params=act_dict.get("params", {}))
        env.step(action)
        return {"status": "ok", "action": act_dict["action"]}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def main(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
