from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import json
import asyncio

import models, database, orchestrator, rag
from database import engine, get_db

# Create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Project JARVIS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

agent_manager = orchestrator.AgentManager()
ai_orchestrator = orchestrator.Orchestrator(agent_manager)
rag_system = rag.SimpleRAG()

# Connection Manager for WebSockets
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            await connection.send_json(message)

manager = ConnectionManager()

@app.get("/health")
def health_check():
    return {"status": "healthy", "version": "1.0.0"}

@app.get("/agents")
def get_agents():
    return [
        {"name": a.name, "role": a.role, "model": a.model, "personality": a.personality}
        for a in agent_manager.agents.values()
    ]

@app.post("/planning/connect")
async def connect_to_jarvis(context: Dict[str, Any]):
    # Trigger the multi-agent debate
    debate = await ai_orchestrator.plan_debate(context)
    # Broadcast the debate progress via WebSocket in a real scenario
    # Here we return the final result
    return {
        "status": "success",
        "debate": debate,
        "recommendation": "Build 'Project JARVIS' - a multi-agent AI operating system."
    }

@app.get("/tasks")
def get_tasks(db: Session = Depends(get_db)):
    return db.query(models.Task).all()

@app.post("/tasks")
async def create_task(task_data: Dict[str, Any], db: Session = Depends(get_db)):
    new_task = models.Task(
        title=task_data["title"],
        description=task_data.get("description", ""),
        assigned_to=task_data.get("assigned_to", "JARVIS"),
        dependencies=task_data.get("dependencies", [])
    )
    db.add(new_task)
    db.commit()
    db.refresh(new_task)

    # Notify clients
    await manager.broadcast({"type": "task_created", "task": {
        "id": new_task.id,
        "title": new_task.title,
        "status": new_task.status,
        "assigned_to": new_task.assigned_to
    }})

    return new_task

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            # Handle incoming messages (e.g., chat)
            if message.get("type") == "chat":
                # Mock AI response
                agent_name = message.get("agent", "JARVIS")
                response = {
                    "type": "chat_response",
                    "agent": agent_name,
                    "message": f"I am {agent_name}. I've received your message: '{message.get('text')}'",
                    "timestamp": "now"
                }
                await websocket.send_json(response)
    except WebSocketDisconnect:
        manager.disconnect(websocket)
