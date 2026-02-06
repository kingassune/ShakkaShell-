"""Tests for the multi-agent orchestration module."""

import pytest

from shakka.agents.base import Agent, AgentConfig, AgentResult, AgentRole, AgentState
from shakka.agents.message import AgentMessage, MessageQueue, MessageType
from shakka.agents.orchestrator import Orchestrator, StepStatus, TaskPlan, TaskStep
from shakka.agents.roles import ExploitAgent, PersistenceAgent, ReconAgent, ReporterAgent


class TestAgentRole:
    """Tests for AgentRole enum."""
    
    def test_orchestrator_role(self):
        """Test ORCHESTRATOR role."""
        assert AgentRole.ORCHESTRATOR.value == "orchestrator"
    
    def test_recon_role(self):
        """Test RECON role."""
        assert AgentRole.RECON.value == "recon"
    
    def test_exploit_role(self):
        """Test EXPLOIT role."""
        assert AgentRole.EXPLOIT.value == "exploit"
    
    def test_persistence_role(self):
        """Test PERSISTENCE role."""
        assert AgentRole.PERSISTENCE.value == "persistence"
    
    def test_reporter_role(self):
        """Test REPORTER role."""
        assert AgentRole.REPORTER.value == "reporter"


class TestAgentState:
    """Tests for AgentState enum."""
    
    def test_idle_state(self):
        """Test IDLE state."""
        assert AgentState.IDLE.value == "idle"
    
    def test_executing_state(self):
        """Test EXECUTING state."""
        assert AgentState.EXECUTING.value == "executing"
    
    def test_completed_state(self):
        """Test COMPLETED state."""
        assert AgentState.COMPLETED.value == "completed"
    
    def test_failed_state(self):
        """Test FAILED state."""
        assert AgentState.FAILED.value == "failed"


class TestAgentConfig:
    """Tests for AgentConfig."""
    
    def test_default_config(self):
        """Test default configuration."""
        config = AgentConfig()
        
        assert config.role == AgentRole.RECON
        assert config.provider == "openai"
        assert config.model == "gpt-4o"
        assert config.max_retries == 3
        assert config.verbose is False
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = AgentConfig(
            role=AgentRole.EXPLOIT,
            name="custom_agent",
            provider="anthropic",
            model="claude-sonnet-4",
        )
        
        assert config.role == AgentRole.EXPLOIT
        assert config.name == "custom_agent"
        assert config.provider == "anthropic"
    
    def test_default_name_generation(self):
        """Test default name is generated from role."""
        config = AgentConfig(role=AgentRole.REPORTER)
        
        assert config.name == "reporter_agent"


class TestAgentResult:
    """Tests for AgentResult."""
    
    def test_success_result(self):
        """Test successful result."""
        result = AgentResult(
            success=True,
            output="Task completed",
            data={"key": "value"},
        )
        
        assert result.success is True
        assert result.has_data is True
        assert result.error is None
    
    def test_failure_result(self):
        """Test failure result."""
        result = AgentResult(
            success=False,
            output="",
            error="Connection failed",
        )
        
        assert result.success is False
        assert result.error == "Connection failed"
    
    def test_to_dict(self):
        """Test converting to dictionary."""
        result = AgentResult(
            success=True,
            output="Done",
            tokens_used=100,
        )
        
        data = result.to_dict()
        
        assert data["success"] is True
        assert data["output"] == "Done"
        assert data["tokens_used"] == 100
    
    def test_from_dict(self):
        """Test creating from dictionary."""
        data = {
            "success": True,
            "output": "Restored",
            "data": {"findings": []},
            "tokens_used": 50,
        }
        
        result = AgentResult.from_dict(data)
        
        assert result.success is True
        assert result.output == "Restored"
        assert result.tokens_used == 50


class TestMessageType:
    """Tests for MessageType enum."""
    
    def test_task_request(self):
        """Test TASK_REQUEST type."""
        assert MessageType.TASK_REQUEST.value == "task_request"
    
    def test_task_result(self):
        """Test TASK_RESULT type."""
        assert MessageType.TASK_RESULT.value == "task_result"
    
    def test_interrupt(self):
        """Test INTERRUPT type."""
        assert MessageType.INTERRUPT.value == "interrupt"


class TestAgentMessage:
    """Tests for AgentMessage."""
    
    def test_create_message(self):
        """Test creating a message."""
        msg = AgentMessage(
            message_type=MessageType.TASK_REQUEST,
            sender="orchestrator",
            recipient="recon_agent",
            content="Scan target",
        )
        
        assert msg.message_type == MessageType.TASK_REQUEST
        assert msg.sender == "orchestrator"
        assert msg.recipient == "recon_agent"
        assert msg.message_id.startswith("msg_")
    
    def test_task_request_factory(self):
        """Test task_request factory method."""
        msg = AgentMessage.task_request(
            sender="orchestrator",
            recipient="recon_agent",
            task="Enumerate hosts",
            context={"target": "192.168.1.0/24"},
        )
        
        assert msg.message_type == MessageType.TASK_REQUEST
        assert msg.content == "Enumerate hosts"
        assert msg.requires_response is True
    
    def test_task_result_factory(self):
        """Test task_result factory method."""
        msg = AgentMessage.task_result(
            sender="recon_agent",
            recipient="orchestrator",
            success=True,
            output="Found 5 hosts",
            data={"hosts": ["192.168.1.1", "192.168.1.2"]},
        )
        
        assert msg.message_type == MessageType.TASK_RESULT
        assert msg.data["success"] is True
    
    def test_interrupt_factory(self):
        """Test interrupt factory method."""
        msg = AgentMessage.interrupt(sender="user", recipient="")
        
        assert msg.message_type == MessageType.INTERRUPT
        assert msg.priority == 10
        assert msg.is_broadcast() is True
    
    def test_is_for(self):
        """Test is_for method."""
        msg = AgentMessage(
            message_type=MessageType.DATA_SHARE,
            recipient="recon_agent",
        )
        
        assert msg.is_for("recon_agent") is True
        assert msg.is_for("exploit_agent") is False
    
    def test_broadcast_is_for_all(self):
        """Test broadcast message is for all agents."""
        msg = AgentMessage(
            message_type=MessageType.INTERRUPT,
            recipient="",  # Broadcast
        )
        
        assert msg.is_for("recon_agent") is True
        assert msg.is_for("exploit_agent") is True
    
    def test_to_dict(self):
        """Test converting to dictionary."""
        msg = AgentMessage(
            message_type=MessageType.DATA_SHARE,
            sender="reporter",
            content="report_data",
        )
        
        data = msg.to_dict()
        
        assert data["message_type"] == "data_share"
        assert data["sender"] == "reporter"
    
    def test_from_dict(self):
        """Test creating from dictionary."""
        data = {
            "message_type": "task_request",
            "sender": "orchestrator",
            "recipient": "exploit_agent",
            "content": "Analyze vulnerabilities",
        }
        
        msg = AgentMessage.from_dict(data)
        
        assert msg.message_type == MessageType.TASK_REQUEST
        assert msg.content == "Analyze vulnerabilities"


class TestMessageQueue:
    """Tests for MessageQueue."""
    
    @pytest.fixture
    def queue(self):
        """Create a message queue."""
        return MessageQueue()
    
    def test_send_and_receive(self, queue):
        """Test sending and receiving messages."""
        msg = AgentMessage(
            message_type=MessageType.TASK_REQUEST,
            sender="orchestrator",
            recipient="recon_agent",
            content="Scan",
        )
        
        queue.send(msg)
        received = queue.receive("recon_agent")
        
        assert received is not None
        assert received.content == "Scan"
    
    def test_receive_returns_none_for_empty(self, queue):
        """Test receive returns None for empty queue."""
        received = queue.receive("any_agent")
        
        assert received is None
    
    def test_receive_filters_by_recipient(self, queue):
        """Test receive filters by recipient."""
        msg = AgentMessage(
            message_type=MessageType.TASK_REQUEST,
            recipient="recon_agent",
        )
        
        queue.send(msg)
        
        # Wrong recipient gets nothing
        received = queue.receive("exploit_agent")
        assert received is None
        
        # Right recipient gets message
        received = queue.receive("recon_agent")
        assert received is not None
    
    def test_priority_ordering(self, queue):
        """Test messages are ordered by priority."""
        low = AgentMessage(message_type=MessageType.DATA_SHARE, priority=1, recipient="agent")
        high = AgentMessage(message_type=MessageType.INTERRUPT, priority=10, recipient="agent")
        
        queue.send(low)
        queue.send(high)
        
        # Should get high priority first
        received = queue.receive("agent")
        assert received.priority == 10
    
    def test_receive_all(self, queue):
        """Test receiving all messages."""
        queue.send(AgentMessage(message_type=MessageType.DATA_SHARE, recipient="agent"))
        queue.send(AgentMessage(message_type=MessageType.TASK_UPDATE, recipient="agent"))
        
        messages = queue.receive_all("agent")
        
        assert len(messages) == 2
    
    def test_peek(self, queue):
        """Test peeking without consuming."""
        msg = AgentMessage(message_type=MessageType.TASK_REQUEST, recipient="agent")
        queue.send(msg)
        
        # Peek doesn't consume
        peeked = queue.peek("agent")
        assert peeked is not None
        
        # Can still receive
        received = queue.receive("agent")
        assert received is not None
    
    def test_has_messages(self, queue):
        """Test has_messages check."""
        assert queue.has_messages("agent") is False
        
        queue.send(AgentMessage(message_type=MessageType.DATA_SHARE, recipient="agent"))
        
        assert queue.has_messages("agent") is True
    
    def test_get_stats(self, queue):
        """Test getting queue statistics."""
        queue.send(AgentMessage(message_type=MessageType.DATA_SHARE, recipient="agent"))
        queue.receive("agent")
        
        stats = queue.get_stats()
        
        assert stats["total_messages"] == 1
        assert stats["processed"] == 1


class TestTaskStep:
    """Tests for TaskStep."""
    
    def test_create_step(self):
        """Test creating a step."""
        step = TaskStep(
            step_id="step_1",
            description="Scan network",
            assigned_agent=AgentRole.RECON,
        )
        
        assert step.step_id == "step_1"
        assert step.status == StepStatus.PENDING
        assert step.is_ready is True
    
    def test_step_with_dependencies(self):
        """Test step with dependencies is not ready."""
        step = TaskStep(
            step_id="step_2",
            description="Exploit",
            assigned_agent=AgentRole.EXPLOIT,
            dependencies=["step_1"],
        )
        
        assert step.is_ready is False
    
    def test_step_complete_status(self):
        """Test is_complete property."""
        step = TaskStep(
            step_id="step_1",
            description="Test",
            assigned_agent=AgentRole.RECON,
        )
        
        assert step.is_complete is False
        
        step.status = StepStatus.COMPLETED
        assert step.is_complete is True
    
    def test_can_retry(self):
        """Test can_retry property."""
        step = TaskStep(
            step_id="step_1",
            description="Test",
            assigned_agent=AgentRole.RECON,
            max_retries=3,
        )
        
        assert step.can_retry is True
        
        step.retry_count = 3
        assert step.can_retry is False


class TestTaskPlan:
    """Tests for TaskPlan."""
    
    def test_create_plan(self):
        """Test creating a plan."""
        plan = TaskPlan(
            plan_id="plan_1",
            objective="Full assessment",
        )
        
        assert plan.plan_id == "plan_1"
        assert plan.status == "pending"
        assert len(plan.steps) == 0
    
    def test_add_step(self):
        """Test adding steps to plan."""
        plan = TaskPlan(plan_id="plan_1", objective="Test")
        
        step = plan.add_step(
            description="Recon",
            agent=AgentRole.RECON,
        )
        
        assert step.step_id == "step_1"
        assert len(plan.steps) == 1
    
    def test_get_ready_steps(self):
        """Test getting ready steps."""
        plan = TaskPlan(plan_id="plan_1", objective="Test")
        
        plan.add_step("Recon", AgentRole.RECON)
        plan.add_step("Exploit", AgentRole.EXPLOIT, dependencies=["step_1"])
        
        ready = plan.get_ready_steps()
        
        assert len(ready) == 1
        assert ready[0].step_id == "step_1"
    
    def test_mark_step_complete(self):
        """Test marking step complete."""
        plan = TaskPlan(plan_id="plan_1", objective="Test")
        plan.add_step("Recon", AgentRole.RECON)
        
        result = AgentResult(success=True, output="Done")
        plan.mark_step_complete("step_1", result)
        
        step = plan.get_step("step_1")
        assert step.status == StepStatus.COMPLETED
        assert step.result.success is True
    
    def test_progress(self):
        """Test progress calculation."""
        plan = TaskPlan(plan_id="plan_1", objective="Test")
        plan.add_step("Step 1", AgentRole.RECON)
        plan.add_step("Step 2", AgentRole.EXPLOIT)
        
        assert plan.progress == 0.0
        
        plan.mark_step_complete("step_1", AgentResult(success=True, output=""))
        
        assert plan.progress == 50.0
    
    def test_is_complete(self):
        """Test is_complete property."""
        plan = TaskPlan(plan_id="plan_1", objective="Test")
        plan.add_step("Step 1", AgentRole.RECON)
        
        assert plan.is_complete is False
        
        plan.mark_step_complete("step_1", AgentResult(success=True, output=""))
        
        assert plan.is_complete is True
    
    def test_format_plan(self):
        """Test plan formatting."""
        plan = TaskPlan(plan_id="plan_1", objective="Test assessment")
        plan.add_step("Recon", AgentRole.RECON)
        
        formatted = plan.format_plan()
        
        assert "Test assessment" in formatted
        assert "RECON" in formatted


class TestReconAgent:
    """Tests for ReconAgent."""
    
    @pytest.fixture
    def agent(self):
        """Create a recon agent."""
        return ReconAgent()
    
    def test_agent_role(self, agent):
        """Test agent has correct role."""
        assert agent.role == AgentRole.RECON
    
    def test_agent_name(self, agent):
        """Test agent has default name."""
        assert agent.name == "recon_agent"
    
    def test_initial_state(self, agent):
        """Test agent starts in idle state."""
        assert agent.state == AgentState.IDLE
        assert agent.is_busy is False
    
    @pytest.mark.asyncio
    async def test_execute(self, agent):
        """Test agent execution."""
        result = await agent.run("Scan target network")
        
        assert result.success is True
        assert "Reconnaissance completed" in result.output
        assert "open_ports" in result.data
    
    @pytest.mark.asyncio
    async def test_state_transitions(self, agent):
        """Test state transitions during execution."""
        assert agent.state == AgentState.IDLE
        
        await agent.run("Test task")
        
        assert agent.state == AgentState.COMPLETED


class TestExploitAgent:
    """Tests for ExploitAgent."""
    
    @pytest.fixture
    def agent(self):
        """Create an exploit agent."""
        return ExploitAgent()
    
    def test_agent_role(self, agent):
        """Test agent has correct role."""
        assert agent.role == AgentRole.EXPLOIT
    
    @pytest.mark.asyncio
    async def test_execute(self, agent):
        """Test agent execution."""
        result = await agent.run("Analyze vulnerabilities")
        
        assert result.success is True
        assert "Exploitation analysis" in result.output


class TestPersistenceAgent:
    """Tests for PersistenceAgent."""
    
    @pytest.fixture
    def agent(self):
        """Create a persistence agent."""
        return PersistenceAgent()
    
    def test_agent_role(self, agent):
        """Test agent has correct role."""
        assert agent.role == AgentRole.PERSISTENCE
    
    @pytest.mark.asyncio
    async def test_execute(self, agent):
        """Test agent execution."""
        result = await agent.run("Establish persistence")
        
        assert result.success is True
        assert "techniques" in result.data


class TestReporterAgent:
    """Tests for ReporterAgent."""
    
    @pytest.fixture
    def agent(self):
        """Create a reporter agent."""
        return ReporterAgent()
    
    def test_agent_role(self, agent):
        """Test agent has correct role."""
        assert agent.role == AgentRole.REPORTER
    
    @pytest.mark.asyncio
    async def test_execute(self, agent):
        """Test agent execution."""
        result = await agent.run("Generate report")
        
        assert result.success is True
        assert "report" in result.data


class TestOrchestrator:
    """Tests for Orchestrator."""
    
    @pytest.fixture
    def orchestrator(self):
        """Create an orchestrator."""
        return Orchestrator()
    
    def test_orchestrator_role(self, orchestrator):
        """Test orchestrator has correct role."""
        assert orchestrator.role == AgentRole.ORCHESTRATOR
    
    def test_register_agent(self, orchestrator):
        """Test registering agents."""
        recon = ReconAgent()
        orchestrator.register_agent(recon)
        
        assert AgentRole.RECON in orchestrator.registered_agents
        assert orchestrator.get_agent(AgentRole.RECON) is recon
    
    def test_unregister_agent(self, orchestrator):
        """Test unregistering agents."""
        recon = ReconAgent()
        orchestrator.register_agent(recon)
        orchestrator.unregister_agent(AgentRole.RECON)
        
        assert AgentRole.RECON not in orchestrator.registered_agents
    
    def test_create_plan(self, orchestrator):
        """Test creating a plan."""
        plan = orchestrator.create_plan("Scan the network")
        
        assert plan is not None
        assert "Scan" in plan.objective or "scan" in plan.objective
        assert len(plan.steps) > 0
    
    def test_create_plan_for_exploit(self, orchestrator):
        """Test creating a plan for exploit task."""
        plan = orchestrator.create_plan("Exploit target system")
        
        # Should have multiple steps
        assert len(plan.steps) >= 2
    
    @pytest.mark.asyncio
    async def test_orchestrate(self, orchestrator):
        """Test full orchestration."""
        agents = {
            AgentRole.RECON: ReconAgent(),
            AgentRole.EXPLOIT: ExploitAgent(),
            AgentRole.REPORTER: ReporterAgent(),
        }
        
        result = await orchestrator.orchestrate(
            "Scan and assess target",
            agents=agents,
        )
        
        assert result.success is True
        assert "plan" in result.data
    
    @pytest.mark.asyncio
    async def test_orchestrate_handles_missing_agent(self, orchestrator):
        """Test orchestration handles missing agents gracefully."""
        # Only register recon, but plan may need others
        orchestrator.register_agent(ReconAgent())
        
        result = await orchestrator.run("Scan target")
        
        # Should not crash, but may have incomplete results
        assert result is not None
    
    def test_get_plan_history(self, orchestrator):
        """Test plan history tracking."""
        assert len(orchestrator.get_plan_history()) == 0
    
    def test_format_status(self, orchestrator):
        """Test status formatting."""
        orchestrator.register_agent(ReconAgent())
        
        status = orchestrator.format_status()
        
        assert "orchestrator" in status.lower()
        assert "recon" in status.lower()


class TestAgentInterrupt:
    """Tests for agent interruption."""
    
    @pytest.fixture
    def agent(self):
        """Create a recon agent."""
        return ReconAgent()
    
    def test_interrupt_idle_agent(self, agent):
        """Test interrupting an idle agent."""
        agent.interrupt()
        
        # Idle agent should stay idle
        assert agent.state == AgentState.IDLE
    
    def test_reset_agent(self, agent):
        """Test resetting an agent."""
        agent._state = AgentState.FAILED
        agent.reset()
        
        assert agent.state == AgentState.IDLE


class TestAgentHistory:
    """Tests for agent history tracking."""
    
    @pytest.fixture
    def agent(self):
        """Create a recon agent."""
        return ReconAgent()
    
    @pytest.mark.asyncio
    async def test_history_tracking(self, agent):
        """Test that history is tracked."""
        await agent.run("Test task")
        
        history = agent.get_history()
        
        assert len(history) > 0
        assert any(h["event"] == "task_started" for h in history)
    
    def test_clear_history(self, agent):
        """Test clearing history."""
        agent._log_event("test", {})
        agent.clear_history()
        
        assert len(agent.get_history()) == 0


class TestAgentSystemPrompts:
    """Tests for agent system prompts."""
    
    def test_orchestrator_prompt(self):
        """Test orchestrator system prompt."""
        agent = Orchestrator()
        prompt = agent.get_system_prompt()
        
        assert "Orchestrator" in prompt
        assert "coordinating" in prompt.lower()
    
    def test_recon_prompt(self):
        """Test recon agent system prompt."""
        agent = ReconAgent()
        prompt = agent.get_system_prompt()
        
        assert "Recon" in prompt
        assert "enumeration" in prompt.lower()
    
    def test_exploit_prompt(self):
        """Test exploit agent system prompt."""
        agent = ExploitAgent()
        prompt = agent.get_system_prompt()
        
        assert "Exploit" in prompt
        assert "vulnerability" in prompt.lower()


class TestShakkaConfigAgents:
    """Tests for agent config in ShakkaConfig."""
    
    def test_default_agent_config(self):
        """Test default agent configuration."""
        from shakka.config import ShakkaConfig
        
        config = ShakkaConfig()
        
        assert config.agent_enabled is True
        assert config.agent_verbose is False
        assert config.agent_max_retries == 3
        assert config.agent_timeout == 300
        assert config.agent_orchestrator_model == "gpt-4o"
    
    def test_agent_config_from_env(self, monkeypatch):
        """Test agent config from environment variables."""
        from shakka.config import ShakkaConfig
        
        monkeypatch.setenv("SHAKKA_AGENT_ENABLED", "false")
        monkeypatch.setenv("SHAKKA_AGENT_VERBOSE", "true")
        monkeypatch.setenv("SHAKKA_AGENT_MAX_RETRIES", "5")
        
        config = ShakkaConfig()
        
        assert config.agent_enabled is False
        assert config.agent_verbose is True
        assert config.agent_max_retries == 5


# =============================================================================
# Agent Factory Tests
# =============================================================================

class TestCreateAgentFromConfig:
    """Tests for create_agent_from_config factory function."""
    
    def test_factory_import(self):
        """Test factory function is importable."""
        from shakka.agents import create_agent_from_config
        assert create_agent_from_config is not None
    
    def test_create_recon_agent_default_config(self):
        """Test creating recon agent with default config."""
        from shakka.config import ShakkaConfig
        from shakka.agents import create_agent_from_config, AgentRole
        
        config = ShakkaConfig()
        agent = create_agent_from_config(AgentRole.RECON, config)
        
        assert agent.role == AgentRole.RECON
        assert agent.config.model == "gpt-4o"
        assert agent.config.provider == "openai"
    
    def test_create_exploit_agent_default_config(self):
        """Test creating exploit agent with default config."""
        from shakka.config import ShakkaConfig
        from shakka.agents import create_agent_from_config, AgentRole
        
        config = ShakkaConfig()
        agent = create_agent_from_config(AgentRole.EXPLOIT, config)
        
        assert agent.role == AgentRole.EXPLOIT
        assert isinstance(agent, ExploitAgent)
    
    def test_create_persistence_agent_default_config(self):
        """Test creating persistence agent with default config."""
        from shakka.config import ShakkaConfig
        from shakka.agents import create_agent_from_config, AgentRole
        
        config = ShakkaConfig()
        agent = create_agent_from_config(AgentRole.PERSISTENCE, config)
        
        assert agent.role == AgentRole.PERSISTENCE
        assert isinstance(agent, PersistenceAgent)
    
    def test_create_reporter_agent_default_config(self):
        """Test creating reporter agent with default config."""
        from shakka.config import ShakkaConfig
        from shakka.agents import create_agent_from_config, AgentRole
        
        config = ShakkaConfig()
        agent = create_agent_from_config(AgentRole.REPORTER, config)
        
        assert agent.role == AgentRole.REPORTER
        assert isinstance(agent, ReporterAgent)
    
    def test_create_agent_with_custom_model(self):
        """Test creating agent with per-role model configuration."""
        from shakka.config import ShakkaConfig
        from shakka.agents import create_agent_from_config, AgentRole
        
        config = ShakkaConfig(
            agent_recon_model="claude-sonnet-4",
            agent_recon_provider="anthropic",
        )
        agent = create_agent_from_config(AgentRole.RECON, config)
        
        assert agent.config.model == "claude-sonnet-4"
        assert agent.config.provider == "anthropic"
    
    def test_create_agent_with_custom_default_model(self):
        """Test creating agent with custom default model."""
        from shakka.config import ShakkaConfig
        from shakka.agents import create_agent_from_config, AgentRole
        
        config = ShakkaConfig(agent_default_model="custom-model")
        agent = create_agent_from_config(AgentRole.EXPLOIT, config)
        
        assert agent.config.model == "custom-model"
    
    def test_create_agent_inherits_config_settings(self):
        """Test agent inherits settings from config."""
        from shakka.config import ShakkaConfig
        from shakka.agents import create_agent_from_config, AgentRole
        
        config = ShakkaConfig(
            agent_max_retries=5,
            agent_timeout=600,
            agent_verbose=True,
        )
        agent = create_agent_from_config(AgentRole.RECON, config)
        
        assert agent.config.max_retries == 5
        assert agent.config.timeout_seconds == 600
        assert agent.config.verbose is True
    
    def test_create_agent_with_shared_memory(self):
        """Test creating agent with shared memory."""
        from shakka.config import ShakkaConfig
        from shakka.agents import create_agent_from_config, AgentRole
        from shakka.storage.memory import MemoryStore, MemoryConfig
        
        config = ShakkaConfig()
        memory = MemoryStore(MemoryConfig(privacy_mode=True))
        agent = create_agent_from_config(AgentRole.RECON, config, shared_memory=memory)
        
        assert agent.config.use_shared_memory is True
    
    def test_create_agent_unsupported_role_raises(self):
        """Test unsupported role raises ValueError."""
        from shakka.config import ShakkaConfig
        from shakka.agents import create_agent_from_config, AgentRole
        
        config = ShakkaConfig()
        
        # ORCHESTRATOR role is not supported by the factory
        with pytest.raises(ValueError, match="Unsupported agent role"):
            create_agent_from_config(AgentRole.ORCHESTRATOR, config)
    
    def test_create_multiple_agents_different_roles(self):
        """Test creating multiple agents with different configurations."""
        from shakka.config import ShakkaConfig
        from shakka.agents import create_agent_from_config, AgentRole
        
        config = ShakkaConfig(
            agent_recon_model="claude-sonnet-4",
            agent_recon_provider="anthropic",
            agent_exploit_model="o1",
            agent_exploit_provider="openai",
            agent_default_model="gpt-4o-mini",
        )
        
        recon = create_agent_from_config(AgentRole.RECON, config)
        exploit = create_agent_from_config(AgentRole.EXPLOIT, config)
        persistence = create_agent_from_config(AgentRole.PERSISTENCE, config)
        
        assert recon.config.model == "claude-sonnet-4"
        assert recon.config.provider == "anthropic"
        
        assert exploit.config.model == "o1"
        assert exploit.config.provider == "openai"
        
        # Persistence uses default
        assert persistence.config.model == "gpt-4o-mini"
