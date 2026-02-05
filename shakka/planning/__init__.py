"""Chain-of-Thought Attack Planning for ShakkaShell.

This module provides AI-driven attack planning with visible reasoning processes.
Supports reasoning models like o1, DeepSeek-R1, and Claude with thinking.
"""

from .planner import AttackPlanner, PlannerConfig
from .models import (
    AttackPlan,
    AttackStep,
    PlanPhase,
    RiskLevel,
    StepAction,
    AlternativePath,
)

__all__ = [
    # Planner
    "AttackPlanner",
    "PlannerConfig",
    # Models
    "AttackPlan",
    "AttackStep",
    "PlanPhase",
    "RiskLevel",
    "StepAction",
    "AlternativePath",
]
