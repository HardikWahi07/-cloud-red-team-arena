import pytest
from fastapi.testclient import TestClient
import sys
import os

# Add backend to path
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "backend"))

from main import app, agent_manager

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_get_agents():
    response = client.get("/agents")
    assert response.status_code == 200
    agents = response.json()
    assert len(agents) == 6
    assert any(a["name"] == "JARVIS" for a in agents)

def test_planning_connect():
    context = {
        "problem_statement": "Build an elite AI OS",
        "duration": "48h",
        "team_members": ["Alice", "Bob"]
    }
    response = client.post("/planning/connect", json=context)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert len(data["debate"]) > 0
    assert "JARVIS" in data["debate"][0]["agent"]

def test_rag_query():
    from rag import SimpleRAG
    rag = SimpleRAG()
    rag.add_document("The quick brown fox", metadata={"id": 1})
    results = rag.query("fox")
    assert len(results) > 0
    assert "fox" in results[0]["text"]
