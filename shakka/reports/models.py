"""Report models for penetration testing reports.

Defines Finding, Evidence, and Report models with CVSS scoring.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional
import hashlib


class Severity(Enum):
    """Finding severity levels."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def score_range(self) -> tuple:
        """Get CVSS score range for this severity."""
        ranges = {
            "critical": (9.0, 10.0),
            "high": (7.0, 8.9),
            "medium": (4.0, 6.9),
            "low": (0.1, 3.9),
            "info": (0.0, 0.0),
        }
        return ranges[self.value]
    
    @property
    def color(self) -> str:
        """Get color for severity (for HTML reports)."""
        colors = {
            "critical": "#DC143C",
            "high": "#FF4500",
            "medium": "#FFA500",
            "low": "#FFD700",
            "info": "#1E90FF",
        }
        return colors[self.value]
    
    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Determine severity from CVSS score."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0:
            return cls.LOW
        else:
            return cls.INFO


class EvidenceType(Enum):
    """Types of evidence that can be attached."""
    
    COMMAND_OUTPUT = "command_output"
    SCREENSHOT = "screenshot"
    FILE = "file"
    LOG = "log"
    NETWORK_CAPTURE = "network_capture"
    CODE_SNIPPET = "code_snippet"


@dataclass
class CVSSScore:
    """CVSS v3.1 score with vector string."""
    
    score: float
    vector: str = ""
    
    # Attack Vector
    attack_vector: str = "N"  # N=Network, A=Adjacent, L=Local, P=Physical
    # Attack Complexity
    attack_complexity: str = "L"  # L=Low, H=High
    # Privileges Required
    privileges_required: str = "N"  # N=None, L=Low, H=High
    # User Interaction
    user_interaction: str = "N"  # N=None, R=Required
    # Scope
    scope: str = "U"  # U=Unchanged, C=Changed
    # Confidentiality Impact
    confidentiality: str = "H"  # N=None, L=Low, H=High
    # Integrity Impact
    integrity: str = "H"  # N=None, L=Low, H=High
    # Availability Impact
    availability: str = "H"  # N=None, L=Low, H=High
    
    @property
    def severity(self) -> Severity:
        """Get severity from score."""
        return Severity.from_cvss(self.score)
    
    def generate_vector(self) -> str:
        """Generate CVSS v3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/"
            f"A:{self.availability}"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "score": self.score,
            "vector": self.vector or self.generate_vector(),
            "severity": self.severity.value,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVSSScore":
        """Create from dictionary."""
        return cls(
            score=data.get("score", 0.0),
            vector=data.get("vector", ""),
        )


@dataclass
class Evidence:
    """Evidence attached to a finding."""
    
    evidence_type: EvidenceType
    title: str
    content: str  # Text content or file path
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def id(self) -> str:
        """Generate unique ID for evidence."""
        hash_input = f"{self.title}{self.timestamp.isoformat()}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:8]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "type": self.evidence_type.value,
            "title": self.title,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        """Create from dictionary."""
        return cls(
            evidence_type=EvidenceType(data["type"]),
            title=data["title"],
            content=data["content"],
            timestamp=datetime.fromisoformat(data["timestamp"])
                if "timestamp" in data else datetime.now(),
            metadata=data.get("metadata", {}),
        )
    
    def format_markdown(self) -> str:
        """Format evidence for Markdown output."""
        lines = [f"**{self.title}**"]
        lines.append(f"*Type: {self.evidence_type.value}*")
        lines.append("")
        
        if self.evidence_type == EvidenceType.COMMAND_OUTPUT:
            lines.append("```")
            lines.append(self.content)
            lines.append("```")
        elif self.evidence_type == EvidenceType.CODE_SNIPPET:
            lines.append("```")
            lines.append(self.content)
            lines.append("```")
        elif self.evidence_type == EvidenceType.SCREENSHOT:
            lines.append(f"![{self.title}]({self.content})")
        else:
            lines.append(self.content)
        
        return "\n".join(lines)


@dataclass
class Finding:
    """A single security finding."""
    
    title: str
    description: str
    severity: Severity
    cvss: Optional[CVSSScore] = None
    affected_asset: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    status: str = "open"  # open, fixed, accepted, false_positive
    discovered_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def id(self) -> str:
        """Generate unique ID for finding."""
        hash_input = f"{self.title}{self.affected_asset}{self.discovered_at.isoformat()}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:8]
    
    @property
    def cvss_score(self) -> float:
        """Get CVSS score or estimate from severity."""
        if self.cvss:
            return self.cvss.score
        # Estimate from severity
        mid_scores = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0,
        }
        return mid_scores.get(self.severity, 0.0)
    
    def add_evidence(self, evidence: Evidence):
        """Add evidence to finding."""
        self.evidence.append(evidence)
    
    def add_command_output(self, title: str, output: str):
        """Add command output as evidence."""
        self.evidence.append(Evidence(
            evidence_type=EvidenceType.COMMAND_OUTPUT,
            title=title,
            content=output,
        ))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss": self.cvss.to_dict() if self.cvss else None,
            "cvss_score": self.cvss_score,
            "affected_asset": self.affected_asset,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "evidence": [e.to_dict() for e in self.evidence],
            "remediation": self.remediation,
            "references": self.references,
            "status": self.status,
            "discovered_at": self.discovered_at.isoformat(),
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create from dictionary."""
        cvss = CVSSScore.from_dict(data["cvss"]) if data.get("cvss") else None
        evidence = [Evidence.from_dict(e) for e in data.get("evidence", [])]
        
        return cls(
            title=data["title"],
            description=data["description"],
            severity=Severity(data["severity"]),
            cvss=cvss,
            affected_asset=data.get("affected_asset", ""),
            cve_ids=data.get("cve_ids", []),
            cwe_ids=data.get("cwe_ids", []),
            evidence=evidence,
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            status=data.get("status", "open"),
            discovered_at=datetime.fromisoformat(data["discovered_at"])
                if "discovered_at" in data else datetime.now(),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ReportMetadata:
    """Metadata for a penetration testing report."""
    
    title: str = "Penetration Testing Report"
    client: str = ""
    assessor: str = ""
    assessment_type: str = "External Penetration Test"
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    scope: List[str] = field(default_factory=list)
    executive_summary: str = ""
    methodology: str = ""
    version: str = "1.0"
    classification: str = "Confidential"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "client": self.client,
            "assessor": self.assessor,
            "assessment_type": self.assessment_type,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "scope": self.scope,
            "executive_summary": self.executive_summary,
            "methodology": self.methodology,
            "version": self.version,
            "classification": self.classification,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReportMetadata":
        """Create from dictionary."""
        return cls(
            title=data.get("title", "Penetration Testing Report"),
            client=data.get("client", ""),
            assessor=data.get("assessor", ""),
            assessment_type=data.get("assessment_type", "External Penetration Test"),
            start_date=datetime.fromisoformat(data["start_date"]) 
                if data.get("start_date") else None,
            end_date=datetime.fromisoformat(data["end_date"])
                if data.get("end_date") else None,
            scope=data.get("scope", []),
            executive_summary=data.get("executive_summary", ""),
            methodology=data.get("methodology", ""),
            version=data.get("version", "1.0"),
            classification=data.get("classification", "Confidential"),
        )


@dataclass
class Report:
    """A complete penetration testing report."""
    
    metadata: ReportMetadata
    findings: List[Finding] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    
    @property
    def id(self) -> str:
        """Generate unique ID for report."""
        hash_input = f"{self.metadata.title}{self.created_at.isoformat()}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:12]
    
    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        """Count of high findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        """Count of medium findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        """Count of low findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)
    
    @property
    def info_count(self) -> int:
        """Count of info findings."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)
    
    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)
    
    @property
    def risk_score(self) -> float:
        """Calculate overall risk score (0-100)."""
        if not self.findings:
            return 0.0
        
        # Weighted score based on severity
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 25,
            Severity.MEDIUM: 10,
            Severity.LOW: 4,
            Severity.INFO: 1,
        }
        
        total = sum(weights[f.severity] for f in self.findings)
        # Normalize to 0-100, cap at 100
        return min(100.0, total)
    
    @property
    def sorted_findings(self) -> List[Finding]:
        """Get findings sorted by severity (critical first)."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(self.findings, key=lambda f: order[f.severity])
    
    def add_finding(self, finding: Finding):
        """Add a finding to the report."""
        self.findings.append(finding)
    
    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get all findings of a specific severity."""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_asset(self, asset: str) -> List[Finding]:
        """Get all findings for a specific asset."""
        return [f for f in self.findings if f.affected_asset == asset]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "metadata": self.metadata.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
                "risk_score": self.risk_score,
            },
            "created_at": self.created_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Report":
        """Create from dictionary."""
        metadata = ReportMetadata.from_dict(data.get("metadata", {}))
        findings = [Finding.from_dict(f) for f in data.get("findings", [])]
        
        return cls(
            metadata=metadata,
            findings=findings,
            created_at=datetime.fromisoformat(data["created_at"])
                if "created_at" in data else datetime.now(),
        )
