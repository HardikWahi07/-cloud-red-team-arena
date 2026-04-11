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


@app.get("/")
def read_root():
    return {
        "env": "CloudRedTeamArena",
        "version": "1.0.0",
        "tasks": ["easy", "medium", "hard"],
        "endpoints": ["/", "/reset", "/step", "/state", "/ws"],
    }


def main(host: str = "0.0.0.0", port: int = 8000):
    import uvicorn

    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
