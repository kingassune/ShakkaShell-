"""Message passing for inter-agent communication.

Provides structured messages for agents to communicate tasks, results,
and coordination signals.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class MessageType(str, Enum):
    """Types of messages agents can exchange."""
    
    # Task messages
    TASK_REQUEST = "task_request"     # Request agent to perform task
    TASK_RESULT = "task_result"       # Result from completed task
    TASK_UPDATE = "task_update"       # Progress update during execution
    
    # Control messages
    INTERRUPT = "interrupt"           # Request to stop current task
    RESUME = "resume"                 # Request to resume paused task
    STATUS_REQUEST = "status_request" # Request current status
    STATUS_RESPONSE = "status_response"  # Response with status
    
    # Data messages
    DATA_SHARE = "data_share"         # Share data with other agents
    MEMORY_STORE = "memory_store"     # Store in shared memory
    MEMORY_RECALL = "memory_recall"   # Recall from shared memory
    
    # Orchestration
    PLAN_UPDATE = "plan_update"       # Update to execution plan
    AGENT_READY = "agent_ready"       # Agent ready for work
    AGENT_DONE = "agent_done"         # Agent finished all work


@dataclass
class AgentMessage:
    """A message exchanged between agents.
    
    Messages enable coordination between agents in a multi-agent workflow.
    They carry a type, payload, and optional routing information.
    """
    
    # Message identity
    message_type: MessageType
    message_id: str = ""
    
    # Routing
    sender: str = ""
    recipient: str = ""            # Empty = broadcast to all
    
    # Content
    content: str = ""
    data: dict = field(default_factory=dict)
    
    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    priority: int = 0              # Higher = more urgent
    requires_response: bool = False
    correlation_id: str = ""       # For request/response matching
    
    def __post_init__(self):
        """Generate message ID if not provided."""
        if not self.message_id:
            self.message_id = f"msg_{datetime.now().timestamp()}"
    
    def to_dict(self) -> dict:
        """Convert message to dictionary."""
        return {
            "message_type": self.message_type.value,
            "message_id": self.message_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "content": self.content,
            "data": self.data,
            "timestamp": self.timestamp,
            "priority": self.priority,
            "requires_response": self.requires_response,
            "correlation_id": self.correlation_id,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "AgentMessage":
        """Create message from dictionary."""
        return cls(
            message_type=MessageType(data["message_type"]),
            message_id=data.get("message_id", ""),
            sender=data.get("sender", ""),
            recipient=data.get("recipient", ""),
            content=data.get("content", ""),
            data=data.get("data", {}),
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            priority=data.get("priority", 0),
            requires_response=data.get("requires_response", False),
            correlation_id=data.get("correlation_id", ""),
        )
    
    @classmethod
    def task_request(
        cls,
        sender: str,
        recipient: str,
        task: str,
        context: Optional[dict] = None,
    ) -> "AgentMessage":
        """Create a task request message.
        
        Args:
            sender: Sending agent name.
            recipient: Target agent name.
            task: Task description.
            context: Optional context data.
            
        Returns:
            Task request message.
        """
        return cls(
            message_type=MessageType.TASK_REQUEST,
            sender=sender,
            recipient=recipient,
            content=task,
            data=context or {},
            requires_response=True,
        )
    
    @classmethod
    def task_result(
        cls,
        sender: str,
        recipient: str,
        success: bool,
        output: str,
        data: Optional[dict] = None,
        correlation_id: str = "",
    ) -> "AgentMessage":
        """Create a task result message.
        
        Args:
            sender: Sending agent name.
            recipient: Target agent name.
            success: Whether task succeeded.
            output: Task output text.
            data: Optional result data.
            correlation_id: ID of original request.
            
        Returns:
            Task result message.
        """
        return cls(
            message_type=MessageType.TASK_RESULT,
            sender=sender,
            recipient=recipient,
            content=output,
            data={"success": success, **(data or {})},
            correlation_id=correlation_id,
        )
    
    @classmethod
    def interrupt(cls, sender: str, recipient: str = "") -> "AgentMessage":
        """Create an interrupt message.
        
        Args:
            sender: Sending agent name.
            recipient: Target agent (empty = broadcast).
            
        Returns:
            Interrupt message.
        """
        return cls(
            message_type=MessageType.INTERRUPT,
            sender=sender,
            recipient=recipient,
            priority=10,  # High priority
        )
    
    @classmethod
    def data_share(
        cls,
        sender: str,
        recipient: str,
        data_type: str,
        data: dict,
    ) -> "AgentMessage":
        """Create a data sharing message.
        
        Args:
            sender: Sending agent name.
            recipient: Target agent (empty = broadcast).
            data_type: Type identifier for the data.
            data: Data to share.
            
        Returns:
            Data share message.
        """
        return cls(
            message_type=MessageType.DATA_SHARE,
            sender=sender,
            recipient=recipient,
            content=data_type,
            data=data,
        )
    
    def is_broadcast(self) -> bool:
        """Check if this is a broadcast message."""
        return not self.recipient
    
    def is_for(self, agent_name: str) -> bool:
        """Check if message is for a specific agent.
        
        Args:
            agent_name: Agent name to check.
            
        Returns:
            True if message is for this agent.
        """
        return self.is_broadcast() or self.recipient == agent_name


class MessageQueue:
    """Simple in-memory message queue for agent communication.
    
    Provides thread-safe message passing between agents.
    """
    
    def __init__(self):
        """Initialize the message queue."""
        self._messages: list[AgentMessage] = []
        self._processed: list[str] = []
    
    def send(self, message: AgentMessage) -> None:
        """Add a message to the queue.
        
        Args:
            message: Message to send.
        """
        self._messages.append(message)
        # Sort by priority (higher first)
        self._messages.sort(key=lambda m: m.priority, reverse=True)
    
    def receive(self, agent_name: str) -> Optional[AgentMessage]:
        """Get next message for an agent.
        
        Args:
            agent_name: Agent to receive messages for.
            
        Returns:
            Next message or None if queue empty.
        """
        for i, msg in enumerate(self._messages):
            if msg.is_for(agent_name) and msg.message_id not in self._processed:
                self._processed.append(msg.message_id)
                return msg
        return None
    
    def receive_all(self, agent_name: str) -> list[AgentMessage]:
        """Get all pending messages for an agent.
        
        Args:
            agent_name: Agent to receive messages for.
            
        Returns:
            List of pending messages.
        """
        messages = []
        for msg in self._messages:
            if msg.is_for(agent_name) and msg.message_id not in self._processed:
                self._processed.append(msg.message_id)
                messages.append(msg)
        return messages
    
    def peek(self, agent_name: str) -> Optional[AgentMessage]:
        """Peek at next message without consuming it.
        
        Args:
            agent_name: Agent to peek for.
            
        Returns:
            Next message or None.
        """
        for msg in self._messages:
            if msg.is_for(agent_name) and msg.message_id not in self._processed:
                return msg
        return None
    
    def has_messages(self, agent_name: str) -> bool:
        """Check if agent has pending messages.
        
        Args:
            agent_name: Agent to check.
            
        Returns:
            True if messages pending.
        """
        return self.peek(agent_name) is not None
    
    def clear(self) -> None:
        """Clear all messages."""
        self._messages.clear()
        self._processed.clear()
    
    def get_stats(self) -> dict:
        """Get queue statistics.
        
        Returns:
            Queue statistics.
        """
        return {
            "total_messages": len(self._messages),
            "processed": len(self._processed),
            "pending": len(self._messages) - len(self._processed),
        }
