import asyncio
from client import CloudRedTeamArenaEnv
from server.models import CloudRedTeamAction

async def test_client():
    # Use the running server
    env = CloudRedTeamArenaEnv(base_url="http://127.0.0.1:7860")
    
    print("Resetting...")
    res = await env.reset(task_id="easy")
    print("Reset obs:", res.observation)
    
    print("\nStepping...")
    action = CloudRedTeamAction(action="scan_network", params={})
    res = await env.step(action)
    print("Step reward:", res.reward)
    print("Step done:", res.done)
    print("Step logs:", res.observation.logs)

if __name__ == "__main__":
    asyncio.run(test_client())
