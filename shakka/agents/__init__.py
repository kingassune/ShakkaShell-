"""Multi-Agent Orchestration for ShakkaShell.

This module provides a hierarchical agent system for complex, multi-step
security tasks. Agents can execute independently, share memory, and coordinate
through an orchestrator.
"""

from .base import Agent, AgentConfig, AgentRole, AgentState, AgentResult
from .message import AgentMessage, MessageType
from .orchestrator import Orchestrator, TaskPlan, TaskStep
from .roles import ReconAgent, ExploitAgent, PersistenceAgent, ReporterAgent

__all__ = [
    # Base
    "Agent",
    "AgentConfig",
    "AgentRole",
    "AgentState",
    "AgentResult",
    # Messages
    "AgentMessage",
    "MessageType",
    # Orchestrator
    "Orchestrator",
    "TaskPlan",
    "TaskStep",
    # Role agents
    "ReconAgent",
    "ExploitAgent",
    "PersistenceAgent",
    "ReporterAgent",
]
