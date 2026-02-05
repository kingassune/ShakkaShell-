"""Attack planning data models.

Defines the structure for attack plans, steps, and risk assessments.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class PlanPhase(str, Enum):
    """Phases of an attack plan following standard methodology."""
    
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class RiskLevel(str, Enum):
    """Risk level for attack steps."""
    
    LOW = "low"           # Passive, unlikely to trigger alerts
    MEDIUM = "medium"     # Some noise, may be logged
    HIGH = "high"         # Active exploitation, likely detected
    CRITICAL = "critical" # Destructive or highly visible
    
    @classmethod
    def from_score(cls, score: float) -> "RiskLevel":
        """Get risk level from numeric score (0.0-1.0).
        
        Args:
            score: Risk score.
            
        Returns:
            Corresponding risk level.
        """
        if score < 0.25:
            return cls.LOW
        elif score < 0.5:
            return cls.MEDIUM
        elif score < 0.75:
            return cls.HIGH
        return cls.CRITICAL


@dataclass
class StepAction:
    """A specific action within an attack step.
    
    Represents a concrete command or technique to execute.
    """
    
    description: str
    command: Optional[str] = None
    tool: Optional[str] = None
    technique_id: Optional[str] = None  # MITRE ATT&CK ID
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "description": self.description,
            "command": self.command,
            "tool": self.tool,
            "technique_id": self.technique_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "StepAction":
        """Create from dictionary."""
        return cls(
            description=data.get("description", ""),
            command=data.get("command"),
            tool=data.get("tool"),
            technique_id=data.get("technique_id"),
        )


@dataclass
class AlternativePath:
    """An alternative approach for an attack step.
    
    Provides fallback options if primary approach fails.
    """
    
    condition: str          # When to use this alternative
    description: str        # What this alternative does
    actions: list[StepAction] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "condition": self.condition,
            "description": self.description,
            "actions": [a.to_dict() for a in self.actions],
            "risk_level": self.risk_level.value,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AlternativePath":
        """Create from dictionary."""
        return cls(
            condition=data.get("condition", ""),
            description=data.get("description", ""),
            actions=[StepAction.from_dict(a) for a in data.get("actions", [])],
            risk_level=RiskLevel(data.get("risk_level", "medium")),
        )


@dataclass
class AttackStep:
    """A single step in an attack plan.
    
    Contains the goal, actions, risk assessment, and alternatives.
    """
    
    phase: PlanPhase
    title: str
    goal: str
    reasoning: str = ""           # AI's thinking about this step
    actions: list[StepAction] = field(default_factory=list)
    alternatives: list[AlternativePath] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    risk_factors: list[str] = field(default_factory=list)
    prerequisites: list[str] = field(default_factory=list)
    expected_outcome: str = ""
    detection_notes: str = ""     # What defenders might see
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "phase": self.phase.value,
            "title": self.title,
            "goal": self.goal,
            "reasoning": self.reasoning,
            "actions": [a.to_dict() for a in self.actions],
            "alternatives": [a.to_dict() for a in self.alternatives],
            "risk_level": self.risk_level.value,
            "risk_factors": self.risk_factors,
            "prerequisites": self.prerequisites,
            "expected_outcome": self.expected_outcome,
            "detection_notes": self.detection_notes,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AttackStep":
        """Create from dictionary."""
        return cls(
            phase=PlanPhase(data.get("phase", "reconnaissance")),
            title=data.get("title", ""),
            goal=data.get("goal", ""),
            reasoning=data.get("reasoning", ""),
            actions=[StepAction.from_dict(a) for a in data.get("actions", [])],
            alternatives=[AlternativePath.from_dict(a) for a in data.get("alternatives", [])],
            risk_level=RiskLevel(data.get("risk_level", "medium")),
            risk_factors=data.get("risk_factors", []),
            prerequisites=data.get("prerequisites", []),
            expected_outcome=data.get("expected_outcome", ""),
            detection_notes=data.get("detection_notes", ""),
        )
    
    def format(self) -> str:
        """Format step for display.
        
        Returns:
            Formatted step string.
        """
        risk_icons = {
            RiskLevel.LOW: "🟢",
            RiskLevel.MEDIUM: "🟡",
            RiskLevel.HIGH: "🟠",
            RiskLevel.CRITICAL: "🔴",
        }
        icon = risk_icons.get(self.risk_level, "⚪")
        
        lines = [
            f"  {icon} {self.title}",
            f"     Goal: {self.goal}",
        ]
        
        if self.reasoning:
            lines.append(f"     Reasoning: {self.reasoning[:100]}...")
        
        for action in self.actions[:3]:
            if action.command:
                lines.append(f"     → {action.command}")
            else:
                lines.append(f"     → {action.description}")
        
        return "\n".join(lines)


@dataclass
class AttackPlan:
    """A complete attack plan with chain-of-thought reasoning.
    
    Contains the overall goal, thinking process, steps, and recommendations.
    """
    
    objective: str                         # The end goal
    thinking: str = ""                     # AI's reasoning process
    current_position: str = ""             # Starting point description
    steps: list[AttackStep] = field(default_factory=list)
    recommended_first_step: str = ""       # Suggested command to start
    overall_risk: RiskLevel = RiskLevel.MEDIUM
    estimated_time: str = ""               # Time estimate
    success_probability: float = 0.0       # 0.0 to 1.0
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "objective": self.objective,
            "thinking": self.thinking,
            "current_position": self.current_position,
            "steps": [s.to_dict() for s in self.steps],
            "recommended_first_step": self.recommended_first_step,
            "overall_risk": self.overall_risk.value,
            "estimated_time": self.estimated_time,
            "success_probability": self.success_probability,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AttackPlan":
        """Create from dictionary."""
        return cls(
            objective=data.get("objective", ""),
            thinking=data.get("thinking", ""),
            current_position=data.get("current_position", ""),
            steps=[AttackStep.from_dict(s) for s in data.get("steps", [])],
            recommended_first_step=data.get("recommended_first_step", ""),
            overall_risk=RiskLevel(data.get("overall_risk", "medium")),
            estimated_time=data.get("estimated_time", ""),
            success_probability=data.get("success_probability", 0.0),
            created_at=data.get("created_at", ""),
            metadata=data.get("metadata", {}),
        )
    
    def format(self) -> str:
        """Format plan for display.
        
        Returns:
            Formatted plan string with box drawing.
        """
        lines = [
            "┌─────────────────────────────────────────────────────────────┐",
            f"│ ATTACK PLAN: {self.objective[:45]:<45} │",
            "├─────────────────────────────────────────────────────────────┤",
        ]
        
        # Thinking section
        if self.thinking:
            lines.append("│ THINKING:                                                   │")
            lines.append("│ ─────────                                                   │")
            # Wrap thinking text
            thinking_lines = self._wrap_text(self.thinking, 57)
            for line in thinking_lines[:10]:  # Limit to 10 lines
                lines.append(f"│ {line:<59} │")
            lines.append("│                                                             │")
        
        # Steps section
        for i, step in enumerate(self.steps, 1):
            phase_name = step.phase.value.replace("_", " ").upper()
            lines.append(f"│ {i}. {phase_name:<55} │")
            
            # Format step goal
            goal_lines = self._wrap_text(step.goal, 54)
            for goal_line in goal_lines[:2]:
                lines.append(f"│    • {goal_line:<53} │")
            
            # Format actions
            for action in step.actions[:3]:
                desc = action.description[:52]
                lines.append(f"│    → {desc:<53} │")
            
            lines.append("│                                                             │")
        
        # Recommended first step
        if self.recommended_first_step:
            lines.append("│ RECOMMENDED FIRST STEP:                                     │")
            cmd_lines = self._wrap_text(self.recommended_first_step, 57)
            for cmd_line in cmd_lines[:2]:
                lines.append(f"│ {cmd_line:<59} │")
            lines.append("│                                                             │")
        
        lines.append("└─────────────────────────────────────────────────────────────┘")
        
        return "\n".join(lines)
    
    def _wrap_text(self, text: str, width: int) -> list[str]:
        """Wrap text to specified width.
        
        Args:
            text: Text to wrap.
            width: Maximum line width.
            
        Returns:
            List of wrapped lines.
        """
        words = text.split()
        lines = []
        current_line = ""
        
        for word in words:
            if len(current_line) + len(word) + 1 <= width:
                current_line = f"{current_line} {word}".strip()
            else:
                if current_line:
                    lines.append(current_line)
                current_line = word
        
        if current_line:
            lines.append(current_line)
        
        return lines
    
    def get_phase_steps(self, phase: PlanPhase) -> list[AttackStep]:
        """Get all steps for a specific phase.
        
        Args:
            phase: The attack phase.
            
        Returns:
            List of steps in that phase.
        """
        return [s for s in self.steps if s.phase == phase]
    
    def get_high_risk_steps(self) -> list[AttackStep]:
        """Get all high or critical risk steps.
        
        Returns:
            List of high-risk steps.
        """
        return [s for s in self.steps if s.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)]
