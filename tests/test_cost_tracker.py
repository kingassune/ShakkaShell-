"""Test cost tracking functionality."""

import pytest
from unittest.mock import AsyncMock, patch

from shakka.config import ShakkaConfig
from shakka.core.cost_tracker import (
    CostTracker,
    UsageRecord,
    ProviderStats,
    PROVIDER_PRICING,
)
from shakka.core.generator import CommandGenerator
from shakka.providers.base import CommandResult, UsageInfo


class TestUsageRecord:
    """Tests for UsageRecord dataclass."""
    
    def test_usage_record_creation(self):
        """Test creating a usage record."""
        record = UsageRecord(
            provider="openai",
            model="gpt-4o",
            input_tokens=100,
            output_tokens=50,
            estimated_cost=0.00075,
        )
        
        assert record.provider == "openai"
        assert record.model == "gpt-4o"
        assert record.input_tokens == 100
        assert record.output_tokens == 50
        assert record.estimated_cost == 0.00075
    
    def test_total_tokens(self):
        """Test total_tokens property."""
        record = UsageRecord(
            provider="openai",
            model="gpt-4o",
            input_tokens=100,
            output_tokens=50,
            estimated_cost=0.0,
        )
        
        assert record.total_tokens == 150


class TestProviderStats:
    """Tests for ProviderStats dataclass."""
    
    def test_empty_stats(self):
        """Test default empty stats."""
        stats = ProviderStats(provider="openai")
        
        assert stats.total_input_tokens == 0
        assert stats.total_output_tokens == 0
        assert stats.total_cost == 0.0
        assert stats.request_count == 0
    
    def test_total_tokens(self):
        """Test total_tokens property."""
        stats = ProviderStats(
            provider="openai",
            total_input_tokens=100,
            total_output_tokens=50,
        )
        
        assert stats.total_tokens == 150
    
    def test_avg_tokens_per_request(self):
        """Test average tokens calculation."""
        stats = ProviderStats(
            provider="openai",
            total_input_tokens=200,
            total_output_tokens=100,
            request_count=3,
        )
        
        assert stats.avg_tokens_per_request == 100.0
    
    def test_avg_tokens_per_request_zero_requests(self):
        """Test average tokens with zero requests."""
        stats = ProviderStats(provider="openai")
        
        assert stats.avg_tokens_per_request == 0.0
    
    def test_avg_cost_per_request(self):
        """Test average cost calculation."""
        stats = ProviderStats(
            provider="openai",
            total_cost=0.30,
            request_count=3,
        )
        
        assert stats.avg_cost_per_request == pytest.approx(0.10)
    
    def test_avg_cost_per_request_zero_requests(self):
        """Test average cost with zero requests."""
        stats = ProviderStats(provider="openai")
        
        assert stats.avg_cost_per_request == 0.0


class TestCostTracker:
    """Tests for CostTracker class."""
    
    def test_tracker_disabled(self):
        """Test disabled tracker returns None."""
        tracker = CostTracker(enabled=False)
        result = tracker.record_usage("openai", "gpt-4o", 100, 50)
        
        assert result is None
        assert tracker.get_total_cost() == 0.0
    
    def test_record_usage(self):
        """Test recording usage creates a record."""
        tracker = CostTracker()
        record = tracker.record_usage("openai", "gpt-4o", 100, 50)
        
        assert record is not None
        assert record.provider == "openai"
        assert record.model == "gpt-4o"
        assert record.input_tokens == 100
        assert record.output_tokens == 50
    
    def test_cost_calculation_openai(self):
        """Test cost calculation for OpenAI models."""
        tracker = CostTracker()
        record = tracker.record_usage("openai", "gpt-4o", 1000, 500)
        
        # gpt-4o: $0.0025/1K input, $0.01/1K output
        expected_cost = (1000 / 1000) * 0.0025 + (500 / 1000) * 0.01
        assert record.estimated_cost == pytest.approx(expected_cost)
    
    def test_cost_calculation_anthropic(self):
        """Test cost calculation for Anthropic models."""
        tracker = CostTracker()
        record = tracker.record_usage("anthropic", "claude-sonnet-4", 1000, 500)
        
        # claude-sonnet-4: $0.003/1K input, $0.015/1K output
        expected_cost = (1000 / 1000) * 0.003 + (500 / 1000) * 0.015
        assert record.estimated_cost == pytest.approx(expected_cost)
    
    def test_cost_calculation_ollama_free(self):
        """Test that Ollama usage is free."""
        tracker = CostTracker()
        record = tracker.record_usage("ollama", "llama2", 1000, 500)
        
        assert record.estimated_cost == 0.0
    
    def test_cost_calculation_default_model(self):
        """Test cost calculation falls back to default model pricing."""
        tracker = CostTracker()
        record = tracker.record_usage("openai", "unknown-model", 1000, 500)
        
        # Should use default pricing for openai
        assert record.estimated_cost > 0
    
    def test_cost_override(self):
        """Test cost override bypasses calculation."""
        tracker = CostTracker()
        record = tracker.record_usage("openai", "gpt-4o", 1000, 500, cost_override=0.99)
        
        assert record.estimated_cost == 0.99
    
    def test_provider_stats_aggregation(self):
        """Test that stats are aggregated per provider."""
        tracker = CostTracker()
        tracker.record_usage("openai", "gpt-4o", 100, 50)
        tracker.record_usage("openai", "gpt-4o", 200, 100)
        
        stats = tracker.get_provider_stats("openai")
        
        assert stats.total_input_tokens == 300
        assert stats.total_output_tokens == 150
        assert stats.request_count == 2
    
    def test_get_all_stats(self):
        """Test getting stats for all providers."""
        tracker = CostTracker()
        tracker.record_usage("openai", "gpt-4o", 100, 50)
        tracker.record_usage("anthropic", "claude-sonnet-4", 200, 100)
        
        all_stats = tracker.get_all_stats()
        
        assert "openai" in all_stats
        assert "anthropic" in all_stats
        assert len(all_stats) == 2
    
    def test_get_total_cost(self):
        """Test total cost across all providers."""
        tracker = CostTracker()
        tracker.record_usage("openai", "gpt-4o", 1000, 500)
        tracker.record_usage("anthropic", "claude-sonnet-4", 1000, 500)
        
        total = tracker.get_total_cost()
        
        openai_cost = tracker.get_provider_stats("openai").total_cost
        anthropic_cost = tracker.get_provider_stats("anthropic").total_cost
        assert total == pytest.approx(openai_cost + anthropic_cost)
    
    def test_get_total_tokens(self):
        """Test total tokens across all providers."""
        tracker = CostTracker()
        tracker.record_usage("openai", "gpt-4o", 100, 50)
        tracker.record_usage("anthropic", "claude-sonnet-4", 200, 100)
        
        total = tracker.get_total_tokens()
        
        assert total == 450  # 100 + 50 + 200 + 100
    
    def test_get_recent_records(self):
        """Test getting recent records."""
        tracker = CostTracker()
        for i in range(15):
            tracker.record_usage("openai", "gpt-4o", i * 10, i * 5)
        
        recent = tracker.get_recent_records(limit=5)
        
        assert len(recent) == 5
        assert recent[-1].input_tokens == 140  # Last record
    
    def test_reset(self):
        """Test resetting all data."""
        tracker = CostTracker()
        tracker.record_usage("openai", "gpt-4o", 100, 50)
        tracker.record_usage("anthropic", "claude-sonnet-4", 200, 100)
        
        tracker.reset()
        
        assert tracker.get_total_cost() == 0.0
        assert tracker.get_total_tokens() == 0
        assert len(tracker.get_all_stats()) == 0
    
    def test_reset_provider(self):
        """Test resetting a single provider."""
        tracker = CostTracker()
        tracker.record_usage("openai", "gpt-4o", 100, 50)
        tracker.record_usage("anthropic", "claude-sonnet-4", 200, 100)
        
        tracker.reset_provider("openai")
        
        assert tracker.get_provider_stats("openai").request_count == 0
        assert tracker.get_provider_stats("anthropic").request_count == 1
    
    def test_get_stats_for_unused_provider(self):
        """Test getting stats for a provider with no usage."""
        tracker = CostTracker()
        stats = tracker.get_provider_stats("openai")
        
        assert stats.provider == "openai"
        assert stats.request_count == 0


class TestGeneratorCostTracking:
    """Tests for cost tracking integration in CommandGenerator."""
    
    @pytest.fixture
    def mock_config(self):
        """Mock configuration with API keys and cost tracking enabled."""
        return ShakkaConfig(
            openai_api_key="sk-test-openai",
            anthropic_api_key="sk-ant-test",
            default_provider="openai",
            enable_cost_tracking=True,
        )
    
    @pytest.fixture
    def mock_result_with_usage(self):
        """Mock command result with usage info."""
        return CommandResult(
            command="nmap -sV 10.0.0.1",
            explanation="Service version scan",
            risk_level="Medium",
            usage=UsageInfo(
                input_tokens=150,
                output_tokens=75,
                model="gpt-4o",
            ),
        )
    
    def test_generator_has_cost_tracker(self, mock_config):
        """Test generator initializes with cost tracker."""
        generator = CommandGenerator(config=mock_config)
        
        assert hasattr(generator, "cost_tracker")
        assert generator.cost_tracker.enabled is True
    
    def test_generator_cost_tracker_disabled(self):
        """Test generator respects cost tracking config."""
        config = ShakkaConfig(
            openai_api_key="sk-test",
            enable_cost_tracking=False,
        )
        generator = CommandGenerator(config=config)
        
        assert generator.cost_tracker.enabled is False
    
    @pytest.mark.asyncio
    async def test_generate_records_usage(self, mock_config, mock_result_with_usage):
        """Test that generate() records usage when available."""
        generator = CommandGenerator(config=mock_config)
        
        with patch("shakka.providers.openai.OpenAIProvider") as MockProvider:
            mock_provider = AsyncMock()
            mock_provider.generate.return_value = mock_result_with_usage
            MockProvider.return_value = mock_provider
            
            await generator.generate("scan ports")
            
            stats = generator.cost_tracker.get_provider_stats("openai")
            assert stats.request_count == 1
            assert stats.total_input_tokens == 150
            assert stats.total_output_tokens == 75
    
    @pytest.mark.asyncio
    async def test_generate_no_usage_info(self, mock_config):
        """Test generate() handles results without usage info."""
        generator = CommandGenerator(config=mock_config)
        result_no_usage = CommandResult(
            command="nmap -sV 10.0.0.1",
            explanation="Service version scan",
            risk_level="Medium",
            usage=None,
        )
        
        with patch("shakka.providers.openai.OpenAIProvider") as MockProvider:
            mock_provider = AsyncMock()
            mock_provider.generate.return_value = result_no_usage
            MockProvider.return_value = mock_provider
            
            # Should not raise
            await generator.generate("scan ports")
            
            stats = generator.cost_tracker.get_provider_stats("openai")
            assert stats.request_count == 0  # No usage recorded
    
    def test_get_cost_summary(self, mock_config):
        """Test get_cost_summary returns proper structure."""
        generator = CommandGenerator(config=mock_config)
        generator.cost_tracker.record_usage("openai", "gpt-4o", 100, 50)
        
        summary = generator.get_cost_summary()
        
        assert "total_cost" in summary
        assert "total_tokens" in summary
        assert "providers" in summary
        assert "openai" in summary["providers"]
        assert summary["providers"]["openai"]["request_count"] == 1
    
    def test_reset_cost_tracking_all(self, mock_config):
        """Test resetting all cost tracking data."""
        generator = CommandGenerator(config=mock_config)
        generator.cost_tracker.record_usage("openai", "gpt-4o", 100, 50)
        generator.cost_tracker.record_usage("anthropic", "claude-sonnet-4", 100, 50)
        
        generator.reset_cost_tracking()
        
        summary = generator.get_cost_summary()
        assert summary["total_cost"] == 0.0
        assert summary["total_tokens"] == 0
    
    def test_reset_cost_tracking_single_provider(self, mock_config):
        """Test resetting cost tracking for single provider."""
        generator = CommandGenerator(config=mock_config)
        generator.cost_tracker.record_usage("openai", "gpt-4o", 100, 50)
        generator.cost_tracker.record_usage("anthropic", "claude-sonnet-4", 100, 50)
        
        generator.reset_cost_tracking("openai")
        
        summary = generator.get_cost_summary()
        assert "openai" not in summary["providers"]
        assert "anthropic" in summary["providers"]


class TestConfigCostTracking:
    """Tests for cost tracking config options."""
    
    def test_config_default_cost_tracking_enabled(self):
        """Test cost tracking is enabled by default."""
        config = ShakkaConfig()
        assert config.enable_cost_tracking is True
    
    def test_config_cost_tracking_from_env(self, monkeypatch):
        """Test cost tracking can be disabled via env var."""
        monkeypatch.setenv("SHAKKA_ENABLE_COST_TRACKING", "false")
        config = ShakkaConfig()
        assert config.enable_cost_tracking is False
