"""SQLAlchemy models for ShakkaShell database."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import String, Boolean, DateTime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""
    pass


class CommandHistory(Base):
    """Command history model for storing generated commands.
    
    Attributes:
        id: Primary key
        user_input: User's original natural language request
        generated_command: The generated security command
        explanation: Explanation of what the command does
        risk_level: Risk level (Low, Medium, High, Critical)
        provider: LLM provider used (openai, anthropic, ollama)
        executed: Whether the command was executed
        created_at: Timestamp when the command was generated
    """
    
    __tablename__ = "history"
    
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_input: Mapped[str] = mapped_column(String, nullable=False)
    generated_command: Mapped[str] = mapped_column(String, nullable=False)
    explanation: Mapped[str] = mapped_column(String, nullable=False)
    risk_level: Mapped[str] = mapped_column(String, nullable=False)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    executed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    
    def __repr__(self) -> str:
        """String representation of the history entry."""
        return (
            f"CommandHistory(id={self.id}, "
            f"command='{self.generated_command[:30]}...', "
            f"risk_level='{self.risk_level}')"
        )
    
    def to_dict(self) -> dict:
        """Convert history entry to dictionary.
        
        Returns:
            Dictionary representation of the history entry
        """
        return {
            "id": self.id,
            "user_input": self.user_input,
            "command": self.generated_command,
            "explanation": self.explanation,
            "risk_level": self.risk_level,
            "provider": self.provider,
            "executed": self.executed,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }
