"""Honeypot indicator models.

Defines indicator types, confidence levels, and aggregation logic.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class IndicatorType(Enum):
    """Types of honeypot indicators."""
    
    NETWORK = "network"
    FILE = "file"
    BANNER = "banner"
    CREDENTIAL = "credential"
    TIMING = "timing"
    BEHAVIOR = "behavior"
    CONTENT = "content"


class IndicatorConfidence(Enum):
    """Confidence level for honeypot detection."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DEFINITE = "definite"
    
    @property
    def score(self) -> float:
        """Get numeric confidence score (0-1)."""
        scores = {
            "low": 0.25,
            "medium": 0.50,
            "high": 0.75,
            "definite": 1.00,
        }
        return scores[self.value]
    
    @classmethod
    def from_score(cls, score: float) -> "IndicatorConfidence":
        """Get confidence level from numeric score."""
        if score >= 0.9:
            return cls.DEFINITE
        elif score >= 0.7:
            return cls.HIGH
        elif score >= 0.4:
            return cls.MEDIUM
        else:
            return cls.LOW


@dataclass
class HoneypotIndicator:
    """A single honeypot indicator from analysis."""
    
    indicator_type: IndicatorType
    confidence: IndicatorConfidence
    description: str
    target: str  # IP, hostname, file path, etc.
    evidence: str = ""
    source: str = ""  # What detected this (pattern name, check function)
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "indicator_type": self.indicator_type.value,
            "confidence": self.confidence.value,
            "confidence_score": self.confidence.score,
            "description": self.description,
            "target": self.target,
            "evidence": self.evidence,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HoneypotIndicator":
        """Create from dictionary."""
        return cls(
            indicator_type=IndicatorType(data["indicator_type"]),
            confidence=IndicatorConfidence(data["confidence"]),
            description=data["description"],
            target=data["target"],
            evidence=data.get("evidence", ""),
            source=data.get("source", ""),
            timestamp=datetime.fromisoformat(data["timestamp"]) 
                if "timestamp" in data else datetime.now(),
            metadata=data.get("metadata", {}),
        )
    
    def format(self) -> str:
        """Format for display."""
        icons = {
            IndicatorConfidence.LOW: "ℹ",
            IndicatorConfidence.MEDIUM: "⚠",
            IndicatorConfidence.HIGH: "⚠",
            IndicatorConfidence.DEFINITE: "🚨",
        }
        icon = icons.get(self.confidence, "?")
        return f"[{icon}] {self.target} - {self.description}"


@dataclass
class IndicatorGroup:
    """Group of related indicators for a target."""
    
    target: str
    indicators: List[HoneypotIndicator] = field(default_factory=list)
    
    @property
    def count(self) -> int:
        """Number of indicators."""
        return len(self.indicators)
    
    @property
    def max_confidence(self) -> Optional[IndicatorConfidence]:
        """Highest confidence level in the group."""
        if not self.indicators:
            return None
        return max(self.indicators, key=lambda i: i.confidence.score).confidence
    
    @property
    def aggregate_score(self) -> float:
        """Aggregate honeypot likelihood score (0-1).
        
        Uses a weighted combination that increases
        with more indicators and higher confidence.
        """
        if not self.indicators:
            return 0.0
        
        # Sum confidence scores with diminishing returns
        total = 0.0
        for i, ind in enumerate(sorted(
            self.indicators, key=lambda x: -x.confidence.score
        )):
            # Each additional indicator adds less (diminishing returns)
            weight = 1.0 / (1 + i * 0.3)
            total += ind.confidence.score * weight
        
        # Normalize to 0-1 range (cap at 1.0)
        return min(1.0, total / 2.0)
    
    @property
    def is_likely_honeypot(self) -> bool:
        """Whether the target is likely a honeypot."""
        return self.aggregate_score >= 0.5
    
    @property
    def is_definite_honeypot(self) -> bool:
        """Whether the target is definitely a honeypot."""
        return (
            self.aggregate_score >= 0.8 or
            any(i.confidence == IndicatorConfidence.DEFINITE 
                for i in self.indicators)
        )
    
    def add(self, indicator: HoneypotIndicator):
        """Add an indicator to the group."""
        self.indicators.append(indicator)
    
    def get_by_type(self, indicator_type: IndicatorType) -> List[HoneypotIndicator]:
        """Get indicators of a specific type."""
        return [i for i in self.indicators if i.indicator_type == indicator_type]
    
    def get_by_confidence(
        self, min_confidence: IndicatorConfidence
    ) -> List[HoneypotIndicator]:
        """Get indicators at or above minimum confidence."""
        return [
            i for i in self.indicators
            if i.confidence.score >= min_confidence.score
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "indicator_count": self.count,
            "aggregate_score": self.aggregate_score,
            "is_likely_honeypot": self.is_likely_honeypot,
            "is_definite_honeypot": self.is_definite_honeypot,
            "max_confidence": self.max_confidence.value if self.max_confidence else None,
            "indicators": [i.to_dict() for i in self.indicators],
        }
    
    def format(self) -> str:
        """Format for display."""
        lines = [f"Target: {self.target}"]
        lines.append(f"Honeypot Score: {self.aggregate_score:.0%}")
        
        if self.is_definite_honeypot:
            lines.append("Status: 🚨 DEFINITE HONEYPOT")
        elif self.is_likely_honeypot:
            lines.append("Status: ⚠ LIKELY HONEYPOT")
        else:
            lines.append("Status: ℹ Suspicious indicators detected")
        
        lines.append("")
        lines.append("Indicators:")
        for indicator in sorted(
            self.indicators, key=lambda i: -i.confidence.score
        ):
            lines.append(f"  {indicator.format()}")
        
        return "\n".join(lines)


@dataclass
class IndicatorSummary:
    """Summary of all honeypot indicators from a scan."""
    
    groups: Dict[str, IndicatorGroup] = field(default_factory=dict)
    scan_time: datetime = field(default_factory=datetime.now)
    
    @property
    def total_indicators(self) -> int:
        """Total number of indicators across all groups."""
        return sum(g.count for g in self.groups.values())
    
    @property
    def targets_analyzed(self) -> int:
        """Number of targets analyzed."""
        return len(self.groups)
    
    @property
    def honeypot_targets(self) -> List[str]:
        """List of targets likely to be honeypots."""
        return [
            target for target, group in self.groups.items()
            if group.is_likely_honeypot
        ]
    
    @property
    def definite_honeypots(self) -> List[str]:
        """List of targets definitely honeypots."""
        return [
            target for target, group in self.groups.items()
            if group.is_definite_honeypot
        ]
    
    @property
    def clean_targets(self) -> List[str]:
        """List of targets with no honeypot indicators."""
        return [
            target for target, group in self.groups.items()
            if group.count == 0
        ]
    
    def get_group(self, target: str) -> IndicatorGroup:
        """Get or create indicator group for target."""
        if target not in self.groups:
            self.groups[target] = IndicatorGroup(target=target)
        return self.groups[target]
    
    def add_indicator(self, target: str, indicator: HoneypotIndicator):
        """Add indicator for a target."""
        self.get_group(target).add(indicator)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_time": self.scan_time.isoformat(),
            "total_indicators": self.total_indicators,
            "targets_analyzed": self.targets_analyzed,
            "honeypot_count": len(self.honeypot_targets),
            "definite_honeypot_count": len(self.definite_honeypots),
            "honeypot_targets": self.honeypot_targets,
            "definite_honeypots": self.definite_honeypots,
            "groups": {t: g.to_dict() for t, g in self.groups.items()},
        }
    
    def format(self) -> str:
        """Format for display."""
        lines = ["=" * 50]
        lines.append("⚠️  HONEYPOT DETECTION SUMMARY")
        lines.append("=" * 50)
        lines.append("")
        lines.append(f"Targets Analyzed: {self.targets_analyzed}")
        lines.append(f"Total Indicators: {self.total_indicators}")
        lines.append(f"Likely Honeypots: {len(self.honeypot_targets)}")
        lines.append(f"Definite Honeypots: {len(self.definite_honeypots)}")
        lines.append("")
        
        # Show definite honeypots first
        if self.definite_honeypots:
            lines.append("🚨 DEFINITE HONEYPOTS:")
            for target in self.definite_honeypots:
                group = self.groups[target]
                lines.append(f"  • {target} (score: {group.aggregate_score:.0%})")
            lines.append("")
        
        # Then likely honeypots
        likely = [t for t in self.honeypot_targets if t not in self.definite_honeypots]
        if likely:
            lines.append("⚠ LIKELY HONEYPOTS:")
            for target in likely:
                group = self.groups[target]
                lines.append(f"  • {target} (score: {group.aggregate_score:.0%})")
            lines.append("")
        
        # Recommendation
        if self.honeypot_targets:
            lines.append("Recommendation: Skip flagged hosts or proceed with caution")
        else:
            lines.append("No honeypot indicators detected")
        
        lines.append("")
        return "\n".join(lines)
