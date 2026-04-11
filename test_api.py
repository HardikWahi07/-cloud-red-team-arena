import requests
import json

base_url = "http://127.0.0.1:7860"

def test_api():
    print("Testing / ...")
    r = requests.get(f"{base_url}/")
    print(r.status_code, r.json())
    
    print("\nTesting /reset (easy) ...")
    r = requests.post(f"{base_url}/reset", json={"task_id": "easy"})
    print(r.status_code, r.json())
    
    if r.status_code == 200:
        print("\nTesting /step (scan_network) ...")
        # The env_server might expect a specific structure for step
        # Based on client.py, it dumps the action model.
        # CloudRedTeamAction(action="...", params={})
        step_payload = {"action": "scan_network", "params": {}}
        r = requests.post(f"{base_url}/step", json=step_payload)
        print(r.status_code, r.json())

if __name__ == "__main__":
    test_api()
