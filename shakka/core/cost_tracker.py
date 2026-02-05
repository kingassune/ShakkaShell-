"""Cost tracking for LLM provider usage.

This module tracks token usage and estimated costs per provider.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# Pricing per 1K tokens (as of 2025-2026)
# These are approximate and should be updated periodically
PROVIDER_PRICING = {
    "openai": {
        "gpt-4o": {"input": 0.0025, "output": 0.01},
        "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "o1": {"input": 0.015, "output": 0.06},
        "o3-mini": {"input": 0.0011, "output": 0.0044},
        "default": {"input": 0.0025, "output": 0.01},
    },
    "anthropic": {
        "claude-sonnet-4": {"input": 0.003, "output": 0.015},
        "claude-opus-4": {"input": 0.015, "output": 0.075},
        "claude-3-5-sonnet": {"input": 0.003, "output": 0.015},
        "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
        "default": {"input": 0.003, "output": 0.015},
    },
    "ollama": {
        # Local models are free
        "default": {"input": 0.0, "output": 0.0},
    },
}


@dataclass
class UsageRecord:
    """Record of a single LLM API call usage."""
    
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    estimated_cost: float
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def total_tokens(self) -> int:
        """Total tokens used in this call."""
        return self.input_tokens + self.output_tokens


@dataclass
class ProviderStats:
    """Aggregated statistics for a provider."""
    
    provider: str
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost: float = 0.0
    request_count: int = 0
    
    @property
    def total_tokens(self) -> int:
        """Total tokens used across all calls."""
        return self.total_input_tokens + self.total_output_tokens
    
    @property
    def avg_tokens_per_request(self) -> float:
        """Average tokens per request."""
        if self.request_count == 0:
            return 0.0
        return self.total_tokens / self.request_count
    
    @property
    def avg_cost_per_request(self) -> float:
        """Average cost per request."""
        if self.request_count == 0:
            return 0.0
        return self.total_cost / self.request_count


class CostTracker:
    """Tracks token usage and costs across LLM providers.
    
    Example:
        tracker = CostTracker()
        tracker.record_usage("openai", "gpt-4o", input_tokens=100, output_tokens=50)
        stats = tracker.get_provider_stats("openai")
        print(f"Total cost: ${stats.total_cost:.4f}")
    """
    
    def __init__(self, enabled: bool = True):
        """Initialize the cost tracker.
        
        Args:
            enabled: Whether cost tracking is enabled.
        """
        self.enabled = enabled
        self._records: list[UsageRecord] = []
        self._provider_stats: dict[str, ProviderStats] = {}
    
    def record_usage(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_override: Optional[float] = None,
    ) -> Optional[UsageRecord]:
        """Record token usage from an LLM call.
        
        Args:
            provider: Provider name (openai, anthropic, ollama).
            model: Model name used.
            input_tokens: Number of input/prompt tokens.
            output_tokens: Number of output/completion tokens.
            cost_override: Override calculated cost (for custom pricing).
            
        Returns:
            UsageRecord if tracking is enabled, None otherwise.
        """
        if not self.enabled:
            return None
        
        # Calculate cost
        if cost_override is not None:
            cost = cost_override
        else:
            cost = self._calculate_cost(provider, model, input_tokens, output_tokens)
        
        # Create record
        record = UsageRecord(
            provider=provider,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            estimated_cost=cost,
        )
        self._records.append(record)
        
        # Update provider stats
        self._update_provider_stats(record)
        
        return record
    
    def _calculate_cost(
        self,
        provider: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """Calculate estimated cost for token usage.
        
        Args:
            provider: Provider name.
            model: Model name.
            input_tokens: Number of input tokens.
            output_tokens: Number of output tokens.
            
        Returns:
            Estimated cost in USD.
        """
        provider_prices = PROVIDER_PRICING.get(provider, {})
        model_prices = provider_prices.get(model, provider_prices.get("default", {}))
        
        input_price = model_prices.get("input", 0.0)
        output_price = model_prices.get("output", 0.0)
        
        # Pricing is per 1K tokens
        input_cost = (input_tokens / 1000) * input_price
        output_cost = (output_tokens / 1000) * output_price
        
        return input_cost + output_cost
    
    def _update_provider_stats(self, record: UsageRecord) -> None:
        """Update aggregated stats for a provider.
        
        Args:
            record: Usage record to incorporate.
        """
        provider = record.provider
        
        if provider not in self._provider_stats:
            self._provider_stats[provider] = ProviderStats(provider=provider)
        
        stats = self._provider_stats[provider]
        stats.total_input_tokens += record.input_tokens
        stats.total_output_tokens += record.output_tokens
        stats.total_cost += record.estimated_cost
        stats.request_count += 1
    
    def get_provider_stats(self, provider: str) -> ProviderStats:
        """Get aggregated statistics for a provider.
        
        Args:
            provider: Provider name.
            
        Returns:
            ProviderStats for the provider (empty stats if no usage).
        """
        return self._provider_stats.get(provider, ProviderStats(provider=provider))
    
    def get_all_stats(self) -> dict[str, ProviderStats]:
        """Get statistics for all providers with usage.
        
        Returns:
            Dictionary mapping provider names to their stats.
        """
        return dict(self._provider_stats)
    
    def get_total_cost(self) -> float:
        """Get total cost across all providers.
        
        Returns:
            Total cost in USD.
        """
        return sum(s.total_cost for s in self._provider_stats.values())
    
    def get_total_tokens(self) -> int:
        """Get total tokens used across all providers.
        
        Returns:
            Total token count.
        """
        return sum(s.total_tokens for s in self._provider_stats.values())
    
    def get_recent_records(self, limit: int = 10) -> list[UsageRecord]:
        """Get most recent usage records.
        
        Args:
            limit: Maximum number of records to return.
            
        Returns:
            List of recent UsageRecord objects.
        """
        return self._records[-limit:]
    
    def reset(self) -> None:
        """Clear all tracked usage data."""
        self._records.clear()
        self._provider_stats.clear()
    
    def reset_provider(self, provider: str) -> None:
        """Clear tracked data for a specific provider.
        
        Args:
            provider: Provider name to reset.
        """
        self._records = [r for r in self._records if r.provider != provider]
        if provider in self._provider_stats:
            del self._provider_stats[provider]
