# Project JARVIS: The Elite Multi-Agent AI OS

Built for the **API Avengers** hackathon team. Project JARVIS is an internal AI-powered team operating system where every team member has their own specialized AI agent.

## 🚀 Core Product Vision
Project JARVIS transforms the hackathon experience into a private elite AI war room.

### The Agent Squad
- **JARVIS**: Central Orchestrator & Strategist (Llama 3.1 8B)
- **KAIROS**: Engineering Lead (Qwen2.5-Coder 7B)
- **HERTZ**: Presentation Coach (Mistral 7B)
- **CHRONO**: Research & Logic (Qwen2.5 7B)
- **EDITH**: Team Helper (Phi-3 Mini)
- **RAPHAEL**: Design & UX (Qwen2.5-VL / Gemma 3)

## 🛠 Tech Stack
- **Frontend**: Next.js, TailwindCSS, Framer Motion, Lucide Icons
- **Backend**: FastAPI, SQLAlchemy, WebSockets, FAISS (RAG)
- **Database**: PostgreSQL
- **Infrastructure**: Docker, Docker Compose

## ⚡ Quick Start

### 1. Requirements
- Docker & Docker Compose
- Node.js (for local frontend dev)
- Python 3.11+ (for local backend dev)

### 2. Launch with Docker
```bash
cd project-jarvis
docker-compose up --build
```
The system will be available at:
- Frontend: `http://localhost:3000`
- Backend API: `http://localhost:8000`

### 3. Environment Variables
Create a `.env` file in the root:
```env
OPENAI_API_KEY=your_key_here
DATABASE_URL=postgresql://jarvis:jarvis_password@db:5432/jarvis_db
```

## 🧠 Key Features
- **Planning Chamber**: Multi-agent strategic debates to decompose problems and rank ideas.
- **Glassmorphism HUD**: A futuristic, premium UI inspired by high-tech command centers.
- **Realtime Task Matrix**: Live synchronization of task progress and agent assignments.
- **Knowledge Vault**: RAG-powered intelligence retrieval for API docs and research.
- **Desktop Companion**: Local automation agent for file system and browser tasks.

---
*Built with ❤️ by the lead autonomous engineering system for API Avengers.*
