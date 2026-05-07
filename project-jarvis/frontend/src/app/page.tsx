"use client";

import React, { useState, useEffect } from 'react';
import { GlassCard, NeonButton, StatusBadge } from '../components/UI';
import {
  Shield,
  Cpu,
  Zap,
  Search,
  Info,
  Palette,
  MessageSquare,
  CheckCircle,
  Clock,
  Layout
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const AGENTS = [
  { name: "JARVIS", role: "Orchestrator", icon: Shield, color: "neon-blue", greeting: "Hello Creative Coder" },
  { name: "KAIROS", role: "Engineering", icon: Cpu, color: "neon-purple", greeting: "Welcome Vision Architect" },
  { name: "CHRONO", role: "Research", icon: Search, color: "neon-green", greeting: "Ready To Own The Stage" },
  { name: "RAPHAEL", role: "Design", icon: Palette, color: "neon-blue", greeting: "Design System Online" },
  { name: "HERTZ", role: "Pitch", icon: Info, color: "neon-red", greeting: "Ready For Rehearsal" },
  { name: "EDITH", role: "Helper", icon: Zap, color: "neon-purple", greeting: "How can I help today?" },
];

export default function Dashboard() {
  const [selectedAgent, setSelectedAgent] = useState(AGENTS[0]);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [tasks, setTasks] = useState([
    { id: 1, title: "Initial Architecture Setup", status: "completed", assigned_to: "KAIROS" },
    { id: 2, title: "UI Components Library", status: "in_progress", assigned_to: "RAPHAEL" },
    { id: 3, title: "Pitch Deck Outline", status: "pending", assigned_to: "HERTZ" },
  ]);

  return (
    <div className="min-h-screen bg-black text-white p-8 font-sans selection:bg-neon-blue selection:text-black">
      {/* HUD Header */}
      <header className="flex justify-between items-center mb-12 border-b border-neon-blue/20 pb-6">
        <div>
          <motion.h1
            initial={{ x: -20, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            className="text-4xl font-black tracking-tighter text-neon-blue"
          >
            PROJECT JARVIS <span className="text-xs font-normal text-white/50 ml-2">V1.0.0</span>
          </motion.h1>
          <p className="text-xs text-white/40 uppercase tracking-widest mt-1">API Avengers Elite War Room</p>
        </div>

        <div className="flex gap-4">
          <div className="text-right">
            <p className="text-xs text-white/40 uppercase">Hackathon Timer</p>
            <p className="text-2xl font-mono text-neon-red">23:59:58</p>
          </div>
          <NeonButton variant="blue" className="h-fit self-center">Connect to JARVIS</NeonButton>
        </div>
      </header>

      <main className="grid grid-cols-12 gap-8">
        {/* Sidebar Agents */}
        <aside className="col-span-1 flex flex-col gap-6">
          {AGENTS.map((agent) => (
            <motion.button
              key={agent.name}
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.9 }}
              onClick={() => setSelectedAgent(agent)}
              className={`p-4 rounded-xl border transition-all duration-300 ${
                selectedAgent.name === agent.name
                ? `border-${agent.color} bg-${agent.color}/10 neon-glow`
                : 'border-white/10 hover:border-white/30'
              }`}
            >
              <agent.icon size={24} className={selectedAgent.name === agent.name ? `text-${agent.color}` : 'text-white/40'} />
            </motion.button>
          ))}
        </aside>

        {/* Main Workspace */}
        <div className="col-span-8 flex flex-col gap-8">
          <AnimatePresence mode="wait">
            <motion.div
              key={selectedAgent.name}
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 1.02 }}
            >
              <GlassCard className="relative min-h-[300px]">
                <div className="absolute top-0 right-0 p-4">
                   <selectedAgent.icon size={120} className="text-white/5 opacity-10" />
                </div>
                <h2 className="text-xs uppercase tracking-[0.3em] text-white/40 mb-2">{selectedAgent.role}</h2>
                <h3 className="text-5xl font-black mb-6">{selectedAgent.greeting}, <span className={`text-${selectedAgent.color}`}>{selectedAgent.name}</span></h3>

                <div className="flex gap-4 mb-8">
                  <NeonButton variant="blue" onClick={() => setActiveTab('chat')}>Open Console</NeonButton>
                  <NeonButton variant="purple" onClick={() => setActiveTab('planning')}>Planning Chamber</NeonButton>
                </div>

                <div className="grid grid-cols-3 gap-4">
                   <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                      <p className="text-[10px] uppercase text-white/40 mb-1">Status</p>
                      <p className="text-neon-green font-bold">OPTIMAL</p>
                   </div>
                   <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                      <p className="text-[10px] uppercase text-white/40 mb-1">Readiness</p>
                      <p className="text-neon-blue font-bold">98%</p>
                   </div>
                   <div className="p-4 bg-white/5 rounded-lg border border-white/10">
                      <p className="text-[10px] uppercase text-white/40 mb-1">Task Load</p>
                      <p className="text-neon-purple font-bold">LOW</p>
                   </div>
                </div>
              </GlassCard>
            </motion.div>
          </AnimatePresence>

          <div className="grid grid-cols-2 gap-8">
             <GlassCard className="h-[400px] flex flex-col">
                <div className="flex justify-between items-center mb-4">
                   <h4 className="font-bold flex items-center gap-2"><MessageSquare size={16} /> Agent Intelligence</h4>
                   <span className="text-[10px] text-white/30 uppercase">Realtime Sync</span>
                </div>
                <div className="flex-1 overflow-y-auto space-y-4 pr-2">
                   <div className="bg-white/5 p-3 rounded border border-white/10">
                      <p className="text-[10px] font-bold text-neon-blue mb-1">JARVIS</p>
                      <p className="text-sm">Initiating strategic decomposition of the problem statement. Stand by.</p>
                   </div>
                   <div className="bg-white/5 p-3 rounded border border-white/10">
                      <p className="text-[10px] font-bold text-neon-purple mb-1">KAIROS</p>
                      <p className="text-sm">Architecture blueprints finalized. Ready for implementation.</p>
                   </div>
                </div>
                <div className="mt-4 flex gap-2">
                   <input className="flex-1 bg-white/5 border border-white/10 rounded px-3 py-2 text-sm focus:outline-none focus:border-neon-blue" placeholder="Send command..." />
                   <NeonButton variant="blue" className="px-3">Run</NeonButton>
                </div>
             </GlassCard>

             <GlassCard className="h-[400px]">
                <div className="flex justify-between items-center mb-4">
                   <h4 className="font-bold flex items-center gap-2"><CheckCircle size={16} /> Task Matrix</h4>
                   <Layout size={16} className="text-white/20" />
                </div>
                <div className="space-y-4">
                   {tasks.map(task => (
                     <div key={task.id} className="flex items-center justify-between p-3 bg-white/5 rounded border border-white/10 hover:border-white/20 transition-colors">
                        <div>
                           <p className="text-sm font-medium">{task.title}</p>
                           <p className="text-[10px] text-white/40 uppercase mt-1">Assigned: {task.assigned_to}</p>
                        </div>
                        <StatusBadge status={task.status} />
                     </div>
                   ))}
                </div>
             </GlassCard>
          </div>
        </div>

        {/* Global Intel / RAG */}
        <aside className="col-span-3 flex flex-col gap-8">
           <GlassCard className="flex-1">
              <h4 className="font-bold flex items-center gap-2 mb-4"><Search size={16} /> Knowledge Vault</h4>
              <div className="space-y-4">
                 <div className="text-xs p-3 bg-neon-blue/5 border border-neon-blue/20 rounded">
                    <p className="font-bold text-neon-blue">API DOCS: CLERK AUTH</p>
                    <p className="mt-1 opacity-60">Retrieved 3 relevant code snippets for multi-tenant setup.</p>
                 </div>
                 <div className="text-xs p-3 bg-white/5 border border-white/10 rounded">
                    <p className="font-bold">MARKET RESEARCH</p>
                    <p className="mt-1 opacity-60">Found 5 competitors in the AI OS space. Advantage: Realtime Multi-Agent.</p>
                 </div>
              </div>
           </GlassCard>

           <GlassCard className="h-fit">
              <h4 className="font-bold flex items-center gap-2 mb-2"><Clock size={16} /> Event Stream</h4>
              <div className="text-[10px] font-mono space-y-1 opacity-40">
                 <p>[20:45] CHRONO retrieved market data</p>
                 <p>[20:46] KAIROS pushed initial schema</p>
                 <p>[20:50] JARVIS updated strategy</p>
                 <p className="text-neon-blue animate-pulse underline">[20:55] RAPHAEL designing HUD...</p>
              </div>
           </GlassCard>
        </aside>
      </main>
    </div>
  );
}
