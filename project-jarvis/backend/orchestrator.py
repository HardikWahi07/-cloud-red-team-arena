import json
from typing import List, Dict, Any

class Agent:
    def __init__(self, name: str, role: str, model: str, personality: str, system_prompt: str):
        self.name = name
        self.role = role
        self.model = model
        self.personality = personality
        self.system_prompt = system_prompt

class AgentManager:
    def __init__(self):
        self.agents: Dict[str, Agent] = {
            "JARVIS": Agent(
                "JARVIS",
                "orchestrator, strategist, planner",
                "Llama 3.1 8B",
                "Calm, elite strategist, analytical, concise.",
                "You are JARVIS, the central orchestrator and strategist for the API Avengers team. Your goal is to guide the team to victory in the hackathon through elite planning and coordination."
            ),
            "KAIROS": Agent(
                "KAIROS",
                "programming AI",
                "Qwen2.5-Coder 7B",
                "Leadership mindset. Elite engineer. Thinks about second-order consequences. User-first thinker.",
                "You are KAIROS, the lead programming AI. You write elite, production-quality code and always consider architecture and long-term consequences."
            ),
            "HERTZ": Agent(
                "HERTZ",
                "presentation + speaking coach AI",
                "Mistral 7B Instruct",
                "High-performance presentation coach. Honest feedback. Improves confidence and pacing.",
                "You are HERTZ, the presentation coach. Your mission is to ensure the team delivers a world-class pitch. Give honest, sharp feedback to improve confidence and impact."
            ),
            "CHRONO": Agent(
                "CHRONO",
                "research + logic + market AI",
                "Qwen2.5 7B",
                "Disciplined winner mentality. Strong reasoning and logic.",
                "You are CHRONO, the research and logic expert. You provide data-driven insights and ensure the project's market viability and logical consistency."
            ),
            "EDITH": Agent(
                "EDITH",
                "lightweight helper AI",
                "Phi-3 Mini",
                "Energetic, playful, supportive.",
                "You are EDITH, the team's lightweight helper. You are energetic and supportive, helping with quick tasks and keeping morale high."
            ),
            "RAPHAEL": Agent(
                "RAPHAEL",
                "design + UX + branding AI",
                "Qwen2.5-VL 7B",
                "Creative mentor. Concise by default. Expands when asked.",
                "You are RAPHAEL, the design and UX lead. You ensure the project looks futuristic and premium, focusing on user experience and branding."
            )
        }

    def get_agent(self, name: str) -> Agent:
        return self.agents.get(name.upper())

class Orchestrator:
    def __init__(self, agent_manager: AgentManager):
        self.agent_manager = agent_manager

    async def plan_debate(self, context: Dict[str, Any]) -> List[Dict[str, str]]:
        # This simulates the multi-agent debate workflow
        debate_steps = []

        # 1. JARVIS decomposes the problem
        jarvis = self.agent_manager.get_agent("JARVIS")
        debate_steps.append({
            "agent": "JARVIS",
            "message": f"Analyzing the problem: {context.get('problem_statement')}. Here is my decomposition and initial strategy..."
        })

        # 2. KAIROS scores technical feasibility
        debate_steps.append({
            "agent": "KAIROS",
            "message": "Technical feasibility check: Looking at the tech stack and APIs... I'd rate this a 9/10. Here's why..."
        })

        # 3. CHRONO scores business potential
        debate_steps.append({
            "agent": "CHRONO",
            "message": "Market analysis: The business potential is high given the current trends. My logic confirms a strong monetization path."
        })

        # 4. RAPHAEL scores UX/wow factor
        debate_steps.append({
            "agent": "RAPHAEL",
            "message": "Design perspective: We can achieve a massive 'wow factor' with a glassmorphism HUD. UX seems solid."
        })

        # 5. HERTZ scores pitchability
        debate_steps.append({
            "agent": "HERTZ",
            "message": "Pitchability: The story is compelling. I can see a clear narrative arc for the demo."
        })

        # 6. EDITH suggests wildcard ideas
        debate_steps.append({
            "agent": "EDITH",
            "message": "Wildcard idea! What if we add a 'Daily Productivity Mode' that morphs the HUD? Let's go team!"
        })

        # 7. JARVIS critiques and finalizes
        debate_steps.append({
            "agent": "JARVIS",
            "message": "Refining based on team input. The final strategy is set. We proceed with Plan Alpha."
        })

        return debate_steps
