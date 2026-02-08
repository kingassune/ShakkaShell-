"""Tests for the multi-agent orchestration module."""

import pytest
from unittest.mock import AsyncMock, patch

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
        """Test agent execution with real nmap mocked."""
        # Mock nmap output - returns a dict, not tuple
        mock_nmap_output = """Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-01 12:00 UTC
Nmap scan report for 192.168.1.1
Host is up (0.001s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.52
443/tcp  open  https   nginx 1.18.0

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 5.00 seconds"""
        
        mock_nmap_result = {
            "command": "nmap -sV -sC 192.168.1.1",
            "success": True,
            "output": mock_nmap_output,
            "stderr": "",
            "execution_time": 5.0,
        }
        
        # Mock LLM analysis response
        mock_llm_response = '''{
            "summary": "Target 192.168.1.1 has 3 open ports with web services",
            "risk_assessment": "Medium risk due to exposed web services",
            "recommendations": ["Check for web vulnerabilities", "Review SSH config"]
        }'''
        
        with patch.object(agent, '_run_nmap', return_value=mock_nmap_result):
            with patch.object(agent, '_call_llm', return_value=mock_llm_response):
                result = await agent.run("Scan 192.168.1.1 for open ports")
                
                assert result.success is True
                assert result.data.get("target") == "192.168.1.1"
    
    @pytest.mark.asyncio
    async def test_execute_no_target(self, agent):
        """Test agent fails gracefully when no target in task."""
        result = await agent.run("Scan target network")
        
        assert result.success is False
        assert "No valid IP address or hostname" in result.error
    
    @pytest.mark.asyncio
    async def test_state_transitions(self, agent):
        """Test state transitions during execution."""
        assert agent.state == AgentState.IDLE
        
        mock_nmap_result = {
            "command": "nmap -sV -sC 10.0.0.1",
            "success": True,
            "output": "Nmap done: 1 IP address scanned",
            "stderr": "",
            "execution_time": 1.0,
        }
        mock_llm_response = '{"summary": "done", "risk_assessment": "low", "recommendations": []}'
        
        with patch.object(agent, '_run_nmap', return_value=mock_nmap_result):
            with patch.object(agent, '_call_llm', return_value=mock_llm_response):
                await agent.run("Scan 10.0.0.1")
        
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
        """Test agent execution with recon context."""
        # Context format matches what orchestrator passes - previous_results array
        context = {
            "previous_results": [{
                "step": "recon",
                "data": {
                    "target": "192.168.1.1",
                    "parsed_ports": [
                        {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.9p1"},
                        {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.52"}
                    ],
                    "raw_output": "Nmap scan results..."
                }
            }]
        }
        
        mock_response = '''{
            "target": "192.168.1.1",
            "services_analyzed": [{"port": 22, "service": "ssh", "version": "OpenSSH 8.9p1"}],
            "vulnerabilities": [{"service": "http", "port": 80, "cve": "N/A", "severity": "medium", "description": "Web server exposed", "exploitable": true, "exploit_difficulty": "medium"}],
            "recommended_exploits": [{"name": "apache_mod_cgi", "target_service": "http", "source": "metasploit", "command_hint": "use exploit/multi/http/apache_mod_cgi_bash_env_exec", "success_probability": "medium"}],
            "attack_chain": ["1. Exploit Apache vulnerability", "2. Gain shell access"],
            "risk_summary": "Medium risk - web services exposed"
        }'''
        
        with patch.object(agent, '_call_llm', return_value=mock_response):
            result = await agent.run("Analyze vulnerabilities", context=context)
            
            assert result.success is True


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
        mock_response = '''{
            "techniques": [{"name": "cron job", "mitre_id": "T1053"}],
            "lateral_movement": [],
            "privilege_escalation": [],
            "cleanup_plan": [],
            "summary": "Persistence established"
        }'''
        
        with patch.object(agent, '_call_llm', return_value=mock_response):
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
        """Test agent execution with previous findings context."""
        # Context matching what orchestrator passes from recon/exploit steps
        context = {
            "previous_results": [
                {
                    "step": "recon",
                    "data": {
                        "target": "192.168.1.1",
                        "scan_command": "nmap -sV -sC 192.168.1.1",
                        "parsed_ports": [
                            {"port": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.9p1"},
                            {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache 2.4.52"}
                        ],
                        "raw_output": "Nmap scan results...",
                        "analysis": {"summary": "Two services found"}
                    }
                },
                {
                    "step": "exploit",
                    "data": {
                        "analysis": {
                            "vulnerabilities": [{"severity": "medium", "service": "http", "description": "Web server exposed"}],
                            "recommended_exploits": [],
                            "summary": "Medium risk target"
                        }
                    }
                }
            ]
        }
        
        mock_response = '''{
            "title": "Penetration Test Report - 192.168.1.1",
            "date": "2024-01-01",
            "target": "192.168.1.1",
            "scope": "Network scan of single host",
            "executive_summary": "Test summary - medium risk target",
            "methodology": "nmap service scan",
            "findings": [],
            "risk_summary": {"critical": 0, "high": 0, "medium": 1, "low": 0},
            "recommendations": [{"priority": 1, "action": "Review web server", "rationale": "Exposed service"}],
            "conclusion": "Target has medium security posture"
        }'''
        
        with patch.object(agent, '_call_llm', return_value=mock_response):
            result = await agent.run("Generate report", context=context)
            
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
        recon_agent = ReconAgent()
        exploit_agent = ExploitAgent()
        reporter_agent = ReporterAgent()
        
        agents = {
            AgentRole.RECON: recon_agent,
            AgentRole.EXPLOIT: exploit_agent,
            AgentRole.REPORTER: reporter_agent,
        }
        
        # Mock nmap execution for ReconAgent
        mock_nmap_result = {
            "command": "nmap -sV -sC 192.168.1.1",
            "success": True,
            "output": """Nmap scan report for 192.168.1.1
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache 2.4.52""",
            "stderr": "",
            "execution_time": 5.0,
        }
        
        # Mock LLM responses for all agents
        mock_recon_llm = '{"summary": "Found web server", "risk_assessment": "low", "recommendations": []}'
        mock_exploit = '''{
            "target": "192.168.1.1",
            "services_analyzed": [{"port": 80, "service": "http", "version": "Apache 2.4.52"}],
            "vulnerabilities": [],
            "recommended_exploits": [],
            "attack_chain": [],
            "risk_summary": "Low risk"
        }'''
        mock_report = '{"title": "Report", "executive_summary": "test", "findings": [], "risk_summary": {}, "recommendations": [], "conclusion": "done"}'
        
        with patch.object(recon_agent, '_run_nmap', return_value=mock_nmap_result):
            with patch.object(recon_agent, '_call_llm', return_value=mock_recon_llm):
                with patch.object(exploit_agent, '_call_llm', return_value=mock_exploit):
                    with patch.object(reporter_agent, '_call_llm', return_value=mock_report):
                        result = await orchestrator.orchestrate(
                            "Scan and assess 192.168.1.1",  # Include IP in task
                            agents=agents,
                        )
        
        assert result.success is True
        assert "plan" in result.data
    
    @pytest.mark.asyncio
    async def test_orchestrate_handles_missing_agent(self, orchestrator):
        """Test orchestration handles missing agents gracefully."""
        # Only register recon, but plan may need others
        recon_agent = ReconAgent()
        orchestrator.register_agent(recon_agent)
        
        mock_nmap_result = {
            "command": "nmap -sV -sC 10.0.0.1",
            "success": True,
            "output": "Nmap done: 1 IP scanned",
            "stderr": "",
            "execution_time": 1.0,
        }
        mock_llm_response = '{"summary": "done", "risk_assessment": "low", "recommendations": []}'
        
        with patch.object(recon_agent, '_run_nmap', return_value=mock_nmap_result):
            with patch.object(recon_agent, '_call_llm', return_value=mock_llm_response):
                result = await orchestrator.run("Scan 10.0.0.1")
        
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


class TestInterruptResume:
    """Tests for interrupt and resume capability."""
    
    @pytest.fixture
    def temp_checkpoint_dir(self, tmp_path):
        """Create a temporary directory for checkpoints."""
        return tmp_path / "checkpoints"
    
    def test_task_step_from_dict(self):
        """Test creating TaskStep from dictionary."""
        data = {
            "step_id": "step_1",
            "description": "Scan network",
            "assigned_agent": "recon",
            "status": "completed",
            "dependencies": [],
            "retry_count": 1,
            "max_retries": 3,
            "result": {
                "success": True,
                "output": "Found 3 hosts",
                "data": {"hosts": 3},
                "error": None,
                "execution_time": 1.5,
                "tokens_used": 100,
            },
        }
        
        step = TaskStep.from_dict(data)
        
        assert step.step_id == "step_1"
        assert step.description == "Scan network"
        assert step.assigned_agent == AgentRole.RECON
        assert step.status == StepStatus.COMPLETED
        assert step.retry_count == 1
        assert step.max_retries == 3
        assert step.result is not None
        assert step.result.success is True
        assert step.result.output == "Found 3 hosts"
    
    def test_task_step_from_dict_minimal(self):
        """Test creating TaskStep from minimal dictionary."""
        data = {
            "step_id": "step_1",
            "description": "Test step",
            "assigned_agent": "exploit",
        }
        
        step = TaskStep.from_dict(data)
        
        assert step.step_id == "step_1"
        assert step.status == StepStatus.PENDING
        assert step.result is None
        assert step.retry_count == 0
    
    def test_task_plan_from_dict(self):
        """Test creating TaskPlan from dictionary."""
        data = {
            "plan_id": "plan_123",
            "objective": "Full assessment",
            "status": "pending",
            "created_at": "2024-01-01T00:00:00",
            "steps": [
                {
                    "step_id": "step_1",
                    "description": "Recon",
                    "assigned_agent": "recon",
                    "status": "completed",
                    "dependencies": [],
                },
                {
                    "step_id": "step_2",
                    "description": "Exploit",
                    "assigned_agent": "exploit",
                    "status": "pending",
                    "dependencies": ["step_1"],
                },
            ],
        }
        
        plan = TaskPlan.from_dict(data)
        
        assert plan.plan_id == "plan_123"
        assert plan.objective == "Full assessment"
        assert len(plan.steps) == 2
        assert plan.steps[0].status == StepStatus.COMPLETED
        assert plan.steps[1].status == StepStatus.PENDING
    
    def test_save_and_load_checkpoint(self, temp_checkpoint_dir):
        """Test saving and loading a checkpoint."""
        # Create plan with some progress
        plan = TaskPlan(plan_id="plan_test", objective="Test save/load")
        plan.add_step("Recon", AgentRole.RECON)
        plan.add_step("Exploit", AgentRole.EXPLOIT, dependencies=["step_1"])
        
        # Mark first step complete
        result = AgentResult(success=True, output="Recon done", data={"hosts": 5})
        plan.mark_step_complete("step_1", result)
        
        # Save checkpoint
        checkpoint_path = temp_checkpoint_dir / "test.json"
        plan.save_checkpoint(checkpoint_path)
        
        assert checkpoint_path.exists()
        
        # Load checkpoint
        loaded_plan = TaskPlan.load_checkpoint(checkpoint_path)
        
        assert loaded_plan.plan_id == "plan_test"
        assert loaded_plan.objective == "Test save/load"
        assert len(loaded_plan.steps) == 2
        
        # Verify step states preserved
        step1 = loaded_plan.get_step("step_1")
        assert step1.status == StepStatus.COMPLETED
        assert step1.result.success is True
        assert step1.result.data == {"hosts": 5}
        
        step2 = loaded_plan.get_step("step_2")
        assert step2.status == StepStatus.PENDING
    
    def test_load_checkpoint_not_found(self, temp_checkpoint_dir):
        """Test loading non-existent checkpoint raises error."""
        with pytest.raises(FileNotFoundError, match="Checkpoint not found"):
            TaskPlan.load_checkpoint(temp_checkpoint_dir / "nonexistent.json")
    
    def test_load_checkpoint_invalid_json(self, temp_checkpoint_dir):
        """Test loading invalid JSON raises error."""
        checkpoint_path = temp_checkpoint_dir / "invalid.json"
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        checkpoint_path.write_text("not valid json {{{")
        
        with pytest.raises(ValueError, match="Invalid checkpoint format"):
            TaskPlan.load_checkpoint(checkpoint_path)
    
    def test_load_checkpoint_missing_plan(self, temp_checkpoint_dir):
        """Test loading checkpoint without plan data raises error."""
        checkpoint_path = temp_checkpoint_dir / "empty.json"
        checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        checkpoint_path.write_text('{"version": "1.0"}')
        
        with pytest.raises(ValueError, match="Checkpoint missing plan data"):
            TaskPlan.load_checkpoint(checkpoint_path)
    
    def test_orchestrator_interrupt_with_checkpoint(self, temp_checkpoint_dir):
        """Test orchestrator interrupt saves checkpoint."""
        orchestrator = Orchestrator()
        
        # Create a plan
        plan = orchestrator.create_plan("Test task")
        
        checkpoint_path = temp_checkpoint_dir / "checkpoint.json"
        result = orchestrator.interrupt_with_checkpoint(checkpoint_path)
        
        assert result is True
        assert checkpoint_path.exists()
        
        # Verify checkpoint content
        loaded = TaskPlan.load_checkpoint(checkpoint_path)
        assert loaded.plan_id == plan.plan_id
    
    def test_orchestrator_interrupt_without_plan(self, temp_checkpoint_dir):
        """Test interrupt without active plan returns False."""
        orchestrator = Orchestrator()
        
        checkpoint_path = temp_checkpoint_dir / "checkpoint.json"
        result = orchestrator.interrupt_with_checkpoint(checkpoint_path)
        
        assert result is False
        assert not checkpoint_path.exists()
    
    @pytest.mark.asyncio
    async def test_orchestrator_resume(self, temp_checkpoint_dir):
        """Test orchestrator resume from checkpoint."""
        # Create initial orchestrator and plan
        orchestrator1 = Orchestrator()
        plan = TaskPlan(plan_id="plan_resume", objective="Resume test")
        plan.add_step("Recon", AgentRole.RECON)
        plan.add_step("Report", AgentRole.REPORTER, dependencies=["step_1"])
        
        # Mark step 1 complete (simulating partial execution)
        result1 = AgentResult(success=True, output="Recon done")
        plan.mark_step_complete("step_1", result1)
        
        # Save checkpoint
        checkpoint_path = temp_checkpoint_dir / "resume_test.json"
        plan.save_checkpoint(checkpoint_path)
        
        # Create new orchestrator with mocked agents
        orchestrator2 = Orchestrator()
        
        # Register a mock reporter agent
        from unittest.mock import AsyncMock, MagicMock
        mock_reporter = MagicMock(spec=ReporterAgent)
        mock_reporter.role = AgentRole.REPORTER
        mock_reporter.run = AsyncMock(return_value=AgentResult(
            success=True,
            output="Report generated",
        ))
        orchestrator2.register_agent(mock_reporter)
        
        # Resume execution
        result = await orchestrator2.resume(checkpoint_path)
        
        assert result.success is True
        assert "Report generated" in result.output
        assert result.data.get("resumed") is True
        
        # Verify reporter was called
        mock_reporter.run.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_orchestrator_resume_file_not_found(self, temp_checkpoint_dir):
        """Test resume with non-existent checkpoint raises error."""
        orchestrator = Orchestrator()
        
        with pytest.raises(FileNotFoundError):
            await orchestrator.resume(temp_checkpoint_dir / "nonexistent.json")
    
    def test_checkpoint_preserves_all_step_data(self, temp_checkpoint_dir):
        """Test checkpoint preserves all step metadata."""
        plan = TaskPlan(plan_id="plan_full", objective="Full data test")
        step = plan.add_step("Test", AgentRole.EXPLOIT)
        step.status = StepStatus.IN_PROGRESS
        step.retry_count = 2
        step.result = AgentResult(
            success=False,
            output="Failed attempt",
            error="Connection timeout",
            execution_time=5.5,
            tokens_used=250,
        )
        
        checkpoint_path = temp_checkpoint_dir / "full_data.json"
        plan.save_checkpoint(checkpoint_path)
        
        loaded = TaskPlan.load_checkpoint(checkpoint_path)
        loaded_step = loaded.get_step("step_1")
        
        assert loaded_step.status == StepStatus.IN_PROGRESS
        assert loaded_step.retry_count == 2
        assert loaded_step.result.error == "Connection timeout"
        assert loaded_step.result.execution_time == 5.5
        assert loaded_step.result.tokens_used == 250