"""CRUD operations for command history."""

from typing import Optional, List
from datetime import datetime

from sqlalchemy import desc
from sqlalchemy.orm import Session

from shakka.storage.models import CommandHistory
from shakka.storage.database import get_db_session
from shakka.providers.base import CommandResult


def add_to_history(
    user_input: str,
    result: CommandResult,
    provider: str,
    executed: bool = False,
    session: Optional[Session] = None
) -> CommandHistory:
    """Add a command to history.
    
    Args:
        user_input: User's natural language input
        result: CommandResult from generation
        provider: LLM provider used
        executed: Whether the command was executed
        session: Optional database session
        
    Returns:
        Created CommandHistory instance
    """
    if session is None:
        session = get_db_session()
        close_session = True
    else:
        close_session = False
    
    try:
        entry = CommandHistory(
            user_input=user_input,
            generated_command=result.command,
            explanation=result.explanation,
            risk_level=result.risk_level,
            provider=provider,
            executed=executed,
            created_at=datetime.utcnow()
        )
        
        session.add(entry)
        session.commit()
        session.refresh(entry)
        
        return entry
    finally:
        if close_session:
            session.close()


def get_history(
    limit: int = 100,
    offset: int = 0,
    session: Optional[Session] = None
) -> List[CommandHistory]:
    """Get command history entries.
    
    Args:
        limit: Maximum number of entries to return
        offset: Number of entries to skip
        session: Optional database session
        
    Returns:
        List of CommandHistory entries
    """
    if session is None:
        session = get_db_session()
        close_session = True
    else:
        close_session = False
    
    try:
        entries = (
            session.query(CommandHistory)
            .order_by(desc(CommandHistory.created_at))
            .limit(limit)
            .offset(offset)
            .all()
        )
        return entries
    finally:
        if close_session:
            session.close()


def get_history_by_id(
    entry_id: int,
    session: Optional[Session] = None
) -> Optional[CommandHistory]:
    """Get a specific history entry by ID.
    
    Args:
        entry_id: History entry ID
        session: Optional database session
        
    Returns:
        CommandHistory entry or None if not found
    """
    if session is None:
        session = get_db_session()
        close_session = True
    else:
        close_session = False
    
    try:
        return session.query(CommandHistory).filter(
            CommandHistory.id == entry_id
        ).first()
    finally:
        if close_session:
            session.close()


def clear_history(session: Optional[Session] = None) -> int:
    """Clear all history entries.
    
    Args:
        session: Optional database session
        
    Returns:
        Number of entries deleted
    """
    if session is None:
        session = get_db_session()
        close_session = True
    else:
        close_session = False
    
    try:
        count = session.query(CommandHistory).count()
        session.query(CommandHistory).delete()
        session.commit()
        return count
    finally:
        if close_session:
            session.close()


def mark_as_executed(
    entry_id: int,
    session: Optional[Session] = None
) -> Optional[CommandHistory]:
    """Mark a history entry as executed.
    
    Args:
        entry_id: History entry ID
        session: Optional database session
        
    Returns:
        Updated CommandHistory entry or None if not found
    """
    if session is None:
        session = get_db_session()
        close_session = True
    else:
        close_session = False
    
    try:
        entry = session.query(CommandHistory).filter(
            CommandHistory.id == entry_id
        ).first()
        
        if entry:
            entry.executed = True
            session.commit()
            session.refresh(entry)
        
        return entry
    finally:
        if close_session:
            session.close()


def get_history_count(session: Optional[Session] = None) -> int:
    """Get total number of history entries.
    
    Args:
        session: Optional database session
        
    Returns:
        Total count of history entries
    """
    if session is None:
        session = get_db_session()
        close_session = True
    else:
        close_session = False
    
    try:
        return session.query(CommandHistory).count()
    finally:
        if close_session:
            session.close()


def search_history(
    query: str,
    limit: int = 100,
    session: Optional[Session] = None
) -> List[CommandHistory]:
    """Search history entries by command or input.
    
    Args:
        query: Search query string
        limit: Maximum number of results
        session: Optional database session
        
    Returns:
        List of matching CommandHistory entries
    """
    if session is None:
        session = get_db_session()
        close_session = True
    else:
        close_session = False
    
    try:
        search_pattern = f"%{query}%"
        entries = (
            session.query(CommandHistory)
            .filter(
                (CommandHistory.user_input.like(search_pattern)) |
                (CommandHistory.generated_command.like(search_pattern))
            )
            .order_by(desc(CommandHistory.created_at))
            .limit(limit)
            .all()
        )
        return entries
    finally:
        if close_session:
            session.close()
