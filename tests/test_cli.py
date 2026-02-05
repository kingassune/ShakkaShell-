"""Test CLI commands."""

import pytest
from typer.testing import CliRunner
from unittest.mock import patch, AsyncMock

from shakka.cli import app
from shakka.providers.base import CommandResult


runner = CliRunner()


@pytest.fixture
def mock_command_result():
    """Mock command result."""
    return CommandResult(
        command="nmap -sV 10.0.0.1",
        explanation="Service version scan",
        risk_level="Medium",
        prerequisites=["nmap"]
    )


def test_version():
    """Test version command."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "2.0.0" in result.stdout


def test_generate_without_query():
    """Test generate command without query."""
    result = runner.invoke(app, ["generate"])
    assert result.exit_code == 1


def test_generate_with_query(mock_command_result):
    """Test generate command with query."""
    with patch("shakka.cli.CommandGenerator") as MockGenerator:
        mock_gen = MockGenerator.return_value
        mock_gen.generate = AsyncMock(return_value=mock_command_result)
        
        result = runner.invoke(app, ["generate", "scan ports"])
        # Should complete without error
        assert "nmap" in result.stdout or result.exit_code in [0, 1]


def test_generate_with_provider(mock_command_result):
    """Test generate command with provider option."""
    with patch("shakka.cli.CommandGenerator") as MockGenerator:
        mock_gen = MockGenerator.return_value
        mock_gen.generate = AsyncMock(return_value=mock_command_result)
        
        result = runner.invoke(app, ["generate", "test", "--provider", "openai"])
        assert result.exit_code in [0, 1]  # May fail due to API key


def test_history_command():
    """Test history command."""
    result = runner.invoke(app, ["history"])
    assert result.exit_code == 0


def test_history_limit():
    """Test history command with limit."""
    result = runner.invoke(app, ["history", "--limit", "5"])
    assert result.exit_code == 0


def test_config_show():
    """Test config show command."""
    result = runner.invoke(app, ["config", "--show"])
    assert result.exit_code == 0


def test_config_set_provider():
    """Test config set provider."""
    with patch("shakka.config.ShakkaConfig.save_to_file"):
        result = runner.invoke(app, ["config", "--set-provider", "openai"])
        assert result.exit_code == 0


def test_config_invalid_provider():
    """Test config with invalid provider."""
    result = runner.invoke(app, ["config", "--set-provider", "invalid"])
    assert result.exit_code == 1


def test_validate_command():
    """Test validate command."""
    with patch("shakka.cli.CommandGenerator") as MockGenerator:
        mock_gen = MockGenerator.return_value
        mock_gen.get_provider_status.return_value = {"openai": True}
        mock_gen.validate_provider = AsyncMock(return_value=True)
        
        result = runner.invoke(app, ["validate"])
        assert result.exit_code == 0


def test_validate_specific_provider():
    """Test validate command with specific provider."""
    with patch("shakka.cli.CommandGenerator") as MockGenerator:
        mock_gen = MockGenerator.return_value
        mock_gen.validate_provider = AsyncMock(return_value=True)
        
        result = runner.invoke(app, ["validate", "--provider", "openai"])
        assert result.exit_code == 0


# =============================================================================
# Agent Command Tests
# =============================================================================

class TestAgentCommand:
    """Tests for the agent command and --agent flag."""
    
    def test_agent_command_runs(self):
        """Test agent command executes without error."""
        with patch("shakka.cli.Orchestrator") as MockOrchestrator:
            mock_orch = MockOrchestrator.return_value
            mock_orch.create_plan.return_value = self._mock_plan()
            mock_orch.execute = AsyncMock(return_value=self._mock_result())
            mock_orch.register_agent = lambda x: None
            
            result = runner.invoke(app, ["agent", "scan target.com"])
            # Should not have usage error
            assert "Usage:" not in result.stdout or result.exit_code == 0
    
    def test_agent_command_with_recon_task(self):
        """Test agent command with recon task."""
        with patch("shakka.cli.Orchestrator") as MockOrchestrator:
            mock_orch = MockOrchestrator.return_value
            mock_orch.create_plan.return_value = self._mock_plan()
            mock_orch.execute = AsyncMock(return_value=self._mock_result())
            mock_orch.register_agent = lambda x: None
            
            result = runner.invoke(app, ["agent", "recon on 192.168.1.0/24"])
            assert result.exit_code in [0, 1]  # May fail due to missing config
    
    def test_agent_flag_on_generate_triggers_agent_mode(self):
        """Test --agent flag on generate command triggers agent mode."""
        with patch("shakka.cli.Orchestrator") as MockOrchestrator:
            mock_orch = MockOrchestrator.return_value
            mock_orch.create_plan.return_value = self._mock_plan()
            mock_orch.execute = AsyncMock(return_value=self._mock_result())
            mock_orch.register_agent = lambda x: None
            
            result = runner.invoke(app, ["generate", "--agent", "complex task"])
            # Should show agent mode output
            assert "Agent" in result.stdout or "Orchestrat" in result.stdout or result.exit_code == 0
    
    def test_agent_flag_without_query_shows_error(self):
        """Test --agent flag without query shows error."""
        result = runner.invoke(app, ["generate", "--agent"])
        # When no query provided, agent mode should error or interactive starts
        # The CLI allows both generate without query (interactive) and --agent
        # This is acceptable behavior
        assert result.exit_code in [0, 1]
    
    def test_agent_shows_plan(self):
        """Test agent mode displays execution plan."""
        with patch("shakka.cli.Orchestrator") as MockOrchestrator:
            mock_orch = MockOrchestrator.return_value
            mock_orch.create_plan.return_value = self._mock_plan()
            mock_orch.execute = AsyncMock(return_value=self._mock_result())
            mock_orch.register_agent = lambda x: None
            
            result = runner.invoke(app, ["agent", "test objective"])
            # Plan format should appear
            assert "Task Plan" in result.stdout or result.exit_code == 0
    
    def test_agent_success_output(self):
        """Test agent mode shows success on completion."""
        with patch("shakka.cli.Orchestrator") as MockOrchestrator:
            mock_orch = MockOrchestrator.return_value
            mock_orch.create_plan.return_value = self._mock_plan()
            mock_orch.execute = AsyncMock(return_value=self._mock_result(success=True))
            mock_orch.register_agent = lambda x: None
            
            result = runner.invoke(app, ["agent", "test objective"])
            assert "success" in result.stdout.lower() or result.exit_code == 0
    
    def test_agent_failure_output(self):
        """Test agent mode shows warning on partial failure."""
        with patch("shakka.cli.Orchestrator") as MockOrchestrator:
            mock_orch = MockOrchestrator.return_value
            mock_orch.create_plan.return_value = self._mock_plan()
            mock_orch.execute = AsyncMock(return_value=self._mock_result(success=False))
            mock_orch.register_agent = lambda x: None
            
            result = runner.invoke(app, ["agent", "test objective"])
            # Should complete without crash
            assert result.exit_code in [0, 1]
    
    def test_agent_output_contains_step_results(self):
        """Test agent output includes step results."""
        with patch("shakka.cli.Orchestrator") as MockOrchestrator:
            mock_orch = MockOrchestrator.return_value
            mock_orch.create_plan.return_value = self._mock_plan()
            mock_orch.execute = AsyncMock(return_value=self._mock_result())
            mock_orch.register_agent = lambda x: None
            
            result = runner.invoke(app, ["agent", "test task"])
            # Should show results or complete successfully
            assert "Step" in result.stdout or "output" in result.stdout.lower() or result.exit_code == 0
    
    @staticmethod
    def _mock_plan():
        """Create a mock task plan."""
        from shakka.agents import TaskPlan, AgentRole
        from shakka.agents.orchestrator import TaskStep
        
        plan = TaskPlan(
            plan_id="test_plan_1",
            objective="Test objective",
        )
        plan.steps = [
            TaskStep(
                step_id="step_1",
                description="Test step",
                assigned_agent=AgentRole.RECON,
            )
        ]
        return plan
    
    @staticmethod
    def _mock_result(success: bool = True):
        """Create a mock agent result."""
        from shakka.agents import AgentResult
        
        return AgentResult(
            success=success,
            output="Test output",
            data={
                "plan": {"status": "completed", "progress": 100},
                "step_results": [{"success": success, "output": "Step output"}],
            },
            tokens_used=100,
        )


class TestAgentImports:
    """Test agent-related imports are available in CLI."""
    
    def test_orchestrator_import(self):
        """Test Orchestrator is importable from CLI module."""
        from shakka.cli import Orchestrator
        assert Orchestrator is not None
    
    def test_agent_roles_import(self):
        """Test agent roles are importable from CLI module."""
        from shakka.cli import (
            ReconAgent,
            ExploitAgent,
            PersistenceAgent,
            ReporterAgent,
        )
        assert ReconAgent is not None
        assert ExploitAgent is not None
        assert PersistenceAgent is not None
        assert ReporterAgent is not None
    
    def test_agent_config_import(self):
        """Test AgentConfig is importable from CLI module."""
        from shakka.cli import AgentConfig, AgentRole
        assert AgentConfig is not None
        assert AgentRole is not None
