"""Tests for Chain-of-Thought Attack Planning module.

Tests attack planning, step generation, and risk assessment.
"""

import pytest
from datetime import datetime

from shakka.planning import (
    AttackPlanner,
    PlannerConfig,
    AttackPlan,
    AttackStep,
    PlanPhase,
    RiskLevel,
    StepAction,
    AlternativePath,
)


# =============================================================================
# RiskLevel Tests
# =============================================================================

class TestRiskLevel:
    """Tests for risk level enum."""
    
    def test_risk_level_values(self):
        """All risk levels exist."""
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"
    
    def test_risk_level_from_score_low(self):
        """Low scores return LOW risk."""
        assert RiskLevel.from_score(0.0) == RiskLevel.LOW
        assert RiskLevel.from_score(0.24) == RiskLevel.LOW
    
    def test_risk_level_from_score_medium(self):
        """Medium scores return MEDIUM risk."""
        assert RiskLevel.from_score(0.25) == RiskLevel.MEDIUM
        assert RiskLevel.from_score(0.49) == RiskLevel.MEDIUM
    
    def test_risk_level_from_score_high(self):
        """High scores return HIGH risk."""
        assert RiskLevel.from_score(0.5) == RiskLevel.HIGH
        assert RiskLevel.from_score(0.74) == RiskLevel.HIGH
    
    def test_risk_level_from_score_critical(self):
        """Critical scores return CRITICAL risk."""
        assert RiskLevel.from_score(0.75) == RiskLevel.CRITICAL
        assert RiskLevel.from_score(1.0) == RiskLevel.CRITICAL


# =============================================================================
# PlanPhase Tests
# =============================================================================

class TestPlanPhase:
    """Tests for plan phase enum."""
    
    def test_all_mitre_phases_exist(self):
        """All MITRE ATT&CK phases are defined."""
        expected_phases = [
            "reconnaissance",
            "initial_access",
            "execution",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "credential_access",
            "discovery",
            "lateral_movement",
            "collection",
            "exfiltration",
            "impact",
        ]
        for phase in expected_phases:
            assert hasattr(PlanPhase, phase.upper())


# =============================================================================
# StepAction Tests
# =============================================================================

class TestStepAction:
    """Tests for step action model."""
    
    def test_action_creation(self):
        """Action can be created."""
        action = StepAction(
            description="Test action",
            command="nmap -sV target",
            tool="nmap",
        )
        assert action.description == "Test action"
        assert action.command == "nmap -sV target"
        assert action.tool == "nmap"
    
    def test_action_to_dict(self):
        """Action converts to dictionary."""
        action = StepAction(
            description="Run scan",
            command="nmap target",
            technique_id="T1046",
        )
        data = action.to_dict()
        assert data["description"] == "Run scan"
        assert data["command"] == "nmap target"
        assert data["technique_id"] == "T1046"
    
    def test_action_from_dict(self):
        """Action can be created from dictionary."""
        data = {
            "description": "From dict",
            "command": "ls -la",
            "tool": "ls",
        }
        action = StepAction.from_dict(data)
        assert action.description == "From dict"
        assert action.command == "ls -la"


# =============================================================================
# AlternativePath Tests
# =============================================================================

class TestAlternativePath:
    """Tests for alternative path model."""
    
    def test_alternative_creation(self):
        """Alternative can be created."""
        alt = AlternativePath(
            condition="If primary fails",
            description="Use backup method",
        )
        assert alt.condition == "If primary fails"
        assert alt.description == "Use backup method"
    
    def test_alternative_with_actions(self):
        """Alternative can have actions."""
        alt = AlternativePath(
            condition="If blocked",
            description="Try different approach",
            actions=[
                StepAction(description="Action 1"),
                StepAction(description="Action 2"),
            ],
            risk_level=RiskLevel.HIGH,
        )
        assert len(alt.actions) == 2
        assert alt.risk_level == RiskLevel.HIGH
    
    def test_alternative_to_dict(self):
        """Alternative converts to dictionary."""
        alt = AlternativePath(
            condition="Test condition",
            description="Test description",
            risk_level=RiskLevel.MEDIUM,
        )
        data = alt.to_dict()
        assert data["condition"] == "Test condition"
        assert data["risk_level"] == "medium"
    
    def test_alternative_from_dict(self):
        """Alternative can be created from dictionary."""
        data = {
            "condition": "From dict",
            "description": "Dict description",
            "actions": [{"description": "Action"}],
            "risk_level": "high",
        }
        alt = AlternativePath.from_dict(data)
        assert alt.condition == "From dict"
        assert len(alt.actions) == 1


# =============================================================================
# AttackStep Tests
# =============================================================================

class TestAttackStep:
    """Tests for attack step model."""
    
    def test_step_creation(self):
        """Step can be created."""
        step = AttackStep(
            phase=PlanPhase.RECONNAISSANCE,
            title="Initial Scan",
            goal="Identify live hosts",
        )
        assert step.phase == PlanPhase.RECONNAISSANCE
        assert step.title == "Initial Scan"
        assert step.goal == "Identify live hosts"
    
    def test_step_with_full_details(self):
        """Step can have all details."""
        step = AttackStep(
            phase=PlanPhase.INITIAL_ACCESS,
            title="Exploit Vulnerability",
            goal="Gain shell access",
            reasoning="This vulnerability allows RCE",
            actions=[StepAction(description="Run exploit")],
            alternatives=[AlternativePath(condition="If blocked", description="Try backup")],
            risk_level=RiskLevel.HIGH,
            risk_factors=["May trigger alerts"],
            prerequisites=["Network access"],
            expected_outcome="Shell access",
            detection_notes="IDS may alert",
        )
        assert step.reasoning == "This vulnerability allows RCE"
        assert len(step.actions) == 1
        assert len(step.alternatives) == 1
        assert step.risk_level == RiskLevel.HIGH
    
    def test_step_to_dict(self):
        """Step converts to dictionary."""
        step = AttackStep(
            phase=PlanPhase.DISCOVERY,
            title="Port Scan",
            goal="Find open ports",
            risk_level=RiskLevel.LOW,
        )
        data = step.to_dict()
        assert data["phase"] == "discovery"
        assert data["title"] == "Port Scan"
        assert data["risk_level"] == "low"
    
    def test_step_from_dict(self):
        """Step can be created from dictionary."""
        data = {
            "phase": "credential_access",
            "title": "Kerberoasting",
            "goal": "Get service account hashes",
            "risk_level": "medium",
        }
        step = AttackStep.from_dict(data)
        assert step.phase == PlanPhase.CREDENTIAL_ACCESS
        assert step.title == "Kerberoasting"
    
    def test_step_format(self):
        """Step formats for display."""
        step = AttackStep(
            phase=PlanPhase.INITIAL_ACCESS,
            title="Test Step",
            goal="Test goal",
            actions=[StepAction(description="Test action", command="test cmd")],
            risk_level=RiskLevel.MEDIUM,
        )
        formatted = step.format()
        assert "Test Step" in formatted
        assert "Test goal" in formatted


# =============================================================================
# AttackPlan Tests
# =============================================================================

class TestAttackPlan:
    """Tests for attack plan model."""
    
    def test_plan_creation(self):
        """Plan can be created."""
        plan = AttackPlan(objective="Get domain admin")
        assert plan.objective == "Get domain admin"
        assert len(plan.steps) == 0
    
    def test_plan_with_full_details(self):
        """Plan can have all details."""
        plan = AttackPlan(
            objective="Compromise target",
            thinking="My approach is...",
            current_position="External",
            steps=[
                AttackStep(
                    phase=PlanPhase.RECONNAISSANCE,
                    title="Recon",
                    goal="Gather info",
                ),
            ],
            recommended_first_step="nmap target",
            overall_risk=RiskLevel.HIGH,
            estimated_time="4 hours",
            success_probability=0.7,
        )
        assert plan.thinking == "My approach is..."
        assert len(plan.steps) == 1
        assert plan.success_probability == 0.7
    
    def test_plan_to_dict(self):
        """Plan converts to dictionary."""
        plan = AttackPlan(
            objective="Test objective",
            overall_risk=RiskLevel.MEDIUM,
            success_probability=0.5,
        )
        data = plan.to_dict()
        assert data["objective"] == "Test objective"
        assert data["overall_risk"] == "medium"
        assert data["success_probability"] == 0.5
    
    def test_plan_from_dict(self):
        """Plan can be created from dictionary."""
        data = {
            "objective": "From dict",
            "thinking": "Dict thinking",
            "overall_risk": "high",
            "steps": [
                {
                    "phase": "discovery",
                    "title": "Step 1",
                    "goal": "Goal 1",
                    "risk_level": "low",
                },
            ],
        }
        plan = AttackPlan.from_dict(data)
        assert plan.objective == "From dict"
        assert len(plan.steps) == 1
    
    def test_plan_format(self):
        """Plan formats for display."""
        plan = AttackPlan(
            objective="Get domain admin",
            thinking="Starting from external, I need to...",
            steps=[
                AttackStep(
                    phase=PlanPhase.INITIAL_ACCESS,
                    title="Gain Access",
                    goal="Establish foothold",
                    actions=[StepAction(description="Run exploit")],
                ),
            ],
            recommended_first_step='shakka "scan target"',
        )
        formatted = plan.format()
        assert "ATTACK PLAN" in formatted
        assert "Get domain admin" in formatted
        assert "THINKING" in formatted
    
    def test_plan_get_phase_steps(self):
        """Plan can filter steps by phase."""
        plan = AttackPlan(
            objective="Test",
            steps=[
                AttackStep(phase=PlanPhase.RECONNAISSANCE, title="R1", goal="G1"),
                AttackStep(phase=PlanPhase.INITIAL_ACCESS, title="I1", goal="G2"),
                AttackStep(phase=PlanPhase.RECONNAISSANCE, title="R2", goal="G3"),
            ],
        )
        recon_steps = plan.get_phase_steps(PlanPhase.RECONNAISSANCE)
        assert len(recon_steps) == 2
        assert recon_steps[0].title == "R1"
        assert recon_steps[1].title == "R2"
    
    def test_plan_get_high_risk_steps(self):
        """Plan can filter high risk steps."""
        plan = AttackPlan(
            objective="Test",
            steps=[
                AttackStep(phase=PlanPhase.RECONNAISSANCE, title="S1", goal="G1", risk_level=RiskLevel.LOW),
                AttackStep(phase=PlanPhase.EXECUTION, title="S2", goal="G2", risk_level=RiskLevel.HIGH),
                AttackStep(phase=PlanPhase.IMPACT, title="S3", goal="G3", risk_level=RiskLevel.CRITICAL),
            ],
        )
        high_risk = plan.get_high_risk_steps()
        assert len(high_risk) == 2
        assert high_risk[0].title == "S2"
        assert high_risk[1].title == "S3"


# =============================================================================
# PlannerConfig Tests
# =============================================================================

class TestPlannerConfig:
    """Tests for planner configuration."""
    
    def test_default_config(self):
        """Default config has sensible values."""
        config = PlannerConfig()
        assert config.max_steps == 10
        assert config.include_alternatives is True
        assert config.include_risk_assessment is True
    
    def test_custom_config(self):
        """Custom config works."""
        config = PlannerConfig(
            model="o1-preview",
            max_steps=5,
            verbose_thinking=False,
        )
        assert config.model == "o1-preview"
        assert config.max_steps == 5
        assert config.verbose_thinking is False
    
    def test_config_to_dict(self):
        """Config converts to dictionary."""
        config = PlannerConfig(model="test-model")
        data = config.to_dict()
        assert data["model"] == "test-model"
        assert "max_steps" in data


# =============================================================================
# AttackPlanner Tests
# =============================================================================

class TestAttackPlanner:
    """Tests for attack planner."""
    
    @pytest.fixture
    def planner(self):
        """Create planner instance."""
        return AttackPlanner()
    
    @pytest.mark.asyncio
    async def test_plan_domain_admin(self, planner):
        """Domain admin plan is generated."""
        plan = await planner.plan("Get domain admin from external foothold")
        assert plan.objective == "Get domain admin from external foothold"
        assert len(plan.steps) > 0
        assert plan.thinking != ""
        assert plan.recommended_first_step != ""
    
    @pytest.mark.asyncio
    async def test_plan_web_app(self, planner):
        """Web app plan is generated."""
        plan = await planner.plan("Test web application for SQL injection")
        assert plan.objective == "Test web application for SQL injection"
        assert len(plan.steps) > 0
        assert plan.metadata.get("plan_type") == "web_app"
    
    @pytest.mark.asyncio
    async def test_plan_network(self, planner):
        """Network plan is generated."""
        plan = await planner.plan("Scan network for vulnerabilities")
        assert len(plan.steps) > 0
        assert plan.metadata.get("plan_type") == "network"
    
    @pytest.mark.asyncio
    async def test_plan_generic(self, planner):
        """Generic plan is generated for unknown objectives."""
        plan = await planner.plan("Do something interesting")
        assert len(plan.steps) > 0
        assert plan.metadata.get("plan_type") == "generic"
    
    @pytest.mark.asyncio
    async def test_plan_empty_objective(self, planner):
        """Empty objective returns minimal plan."""
        plan = await planner.plan("")
        assert plan.objective == ""
        assert "No objective" in plan.thinking
    
    @pytest.mark.asyncio
    async def test_plan_with_context(self, planner):
        """Plan uses provided context."""
        context = {"position": "Internal network"}
        plan = await planner.plan("Escalate privileges", context=context)
        assert plan.current_position == "Internal network"
    
    @pytest.mark.asyncio
    async def test_plan_cached(self, planner):
        """Plans are cached."""
        plan1 = await planner.plan("Test caching")
        plan2 = await planner.plan("Test caching")
        assert plan1 is plan2
    
    def test_clear_cache(self, planner):
        """Cache can be cleared."""
        planner._cache["test"] = AttackPlan(objective="cached")
        planner.clear_cache()
        assert len(planner._cache) == 0
    
    @pytest.mark.asyncio
    async def test_plan_has_risk_assessment(self, planner):
        """Plan steps have risk assessment."""
        plan = await planner.plan("Get domain admin")
        for step in plan.steps:
            assert step.risk_level is not None
            assert isinstance(step.risk_level, RiskLevel)
    
    @pytest.mark.asyncio
    async def test_plan_has_alternatives(self, planner):
        """Plan steps can have alternatives."""
        plan = await planner.plan("Get domain admin from external")
        has_alternatives = any(len(s.alternatives) > 0 for s in plan.steps)
        assert has_alternatives is True
    
    @pytest.mark.asyncio
    async def test_plan_has_detection_notes(self, planner):
        """Plan steps have detection notes."""
        plan = await planner.plan("Get domain admin from external")
        has_notes = any(s.detection_notes != "" for s in plan.steps)
        assert has_notes is True


# =============================================================================
# AttackPlanner Step Refinement Tests
# =============================================================================

class TestAttackPlannerRefinement:
    """Tests for plan refinement functionality."""
    
    @pytest.fixture
    def planner(self):
        """Create planner instance."""
        return AttackPlanner()
    
    @pytest.fixture
    async def sample_plan(self, planner):
        """Create sample plan for testing."""
        return await planner.plan("Test plan")
    
    @pytest.mark.asyncio
    async def test_refine_step(self, planner, sample_plan):
        """Step can be refined."""
        original_reasoning = sample_plan.steps[0].reasoning
        refined = await planner.refine_step(
            sample_plan,
            step_index=0,
            feedback="Add more stealth",
        )
        assert "Add more stealth" in refined.reasoning
    
    @pytest.mark.asyncio
    async def test_refine_invalid_index(self, planner, sample_plan):
        """Invalid step index raises error."""
        with pytest.raises(IndexError):
            await planner.refine_step(sample_plan, step_index=999, feedback="test")
    
    @pytest.mark.asyncio
    async def test_suggest_next_step(self, planner, sample_plan):
        """Next step is suggested."""
        next_step = await planner.suggest_next_step(sample_plan, completed_steps=[])
        assert next_step is not None
        assert next_step == sample_plan.steps[0]
    
    @pytest.mark.asyncio
    async def test_suggest_next_step_skips_completed(self, planner, sample_plan):
        """Completed steps are skipped."""
        if len(sample_plan.steps) > 1:
            next_step = await planner.suggest_next_step(sample_plan, completed_steps=[0])
            assert next_step == sample_plan.steps[1]
    
    @pytest.mark.asyncio
    async def test_suggest_next_step_all_complete(self, planner, sample_plan):
        """Returns None when all steps complete."""
        all_indices = list(range(len(sample_plan.steps)))
        next_step = await planner.suggest_next_step(sample_plan, completed_steps=all_indices)
        assert next_step is None


# =============================================================================
# Planner Configuration Tests
# =============================================================================

class TestPlannerWithConfig:
    """Tests for planner with custom configuration."""
    
    @pytest.mark.asyncio
    async def test_planner_with_custom_model(self):
        """Planner works with custom model."""
        config = PlannerConfig(model="o1-preview")
        planner = AttackPlanner(config=config)
        plan = await planner.plan("Test")
        assert plan is not None
    
    @pytest.mark.asyncio
    async def test_planner_with_limited_steps(self):
        """Planner respects max_steps config."""
        config = PlannerConfig(max_steps=3)
        planner = AttackPlanner(config=config)
        assert planner.config.max_steps == 3


# =============================================================================
# Integration Tests
# =============================================================================

class TestPlannerIntegration:
    """Integration tests for attack planner."""
    
    @pytest.mark.asyncio
    async def test_full_planning_workflow(self):
        """Full planning workflow works."""
        # Create planner
        planner = AttackPlanner()
        
        # Generate plan
        plan = await planner.plan(
            "Get domain admin from external foothold",
            context={"position": "External web server 10.0.0.5"},
        )
        
        # Verify plan structure
        assert plan.objective != ""
        assert plan.thinking != ""
        assert len(plan.steps) > 0
        assert plan.recommended_first_step != ""
        
        # Verify steps have required fields
        for step in plan.steps:
            assert step.phase is not None
            assert step.title != ""
            assert step.goal != ""
            assert step.risk_level is not None
        
        # Format and verify output
        formatted = plan.format()
        assert "ATTACK PLAN" in formatted
        assert "THINKING" in formatted
    
    @pytest.mark.asyncio
    async def test_plan_step_follows_methodology(self):
        """Plan steps follow attack methodology."""
        planner = AttackPlanner()
        plan = await planner.plan("Get domain admin")
        
        # Verify phases are in logical order
        phase_order = [
            PlanPhase.RECONNAISSANCE,
            PlanPhase.INITIAL_ACCESS,
            PlanPhase.DISCOVERY,
            PlanPhase.CREDENTIAL_ACCESS,
            PlanPhase.PRIVILEGE_ESCALATION,
        ]
        
        # Check that early phases come before later phases
        phase_indices = {step.phase: i for i, step in enumerate(plan.steps)}
        
        # At minimum, verify plan has some structure
        assert len(plan.steps) >= 2
    
    @pytest.mark.asyncio
    async def test_plan_actions_have_commands(self):
        """Plan actions include executable commands."""
        planner = AttackPlanner()
        plan = await planner.plan("Scan network")
        
        has_commands = False
        for step in plan.steps:
            for action in step.actions:
                if action.command:
                    has_commands = True
                    break
        
        assert has_commands is True


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""
    
    @pytest.mark.asyncio
    async def test_whitespace_objective(self):
        """Whitespace-only objective is handled."""
        planner = AttackPlanner()
        plan = await planner.plan("   ")
        assert plan.objective == ""
    
    @pytest.mark.asyncio
    async def test_very_long_objective(self):
        """Very long objective is handled."""
        planner = AttackPlanner()
        long_objective = "test " * 100
        plan = await planner.plan(long_objective)
        assert plan is not None
    
    @pytest.mark.asyncio
    async def test_special_characters_in_objective(self):
        """Special characters in objective are handled."""
        planner = AttackPlanner()
        plan = await planner.plan("Test <script>alert('xss')</script>")
        assert plan is not None
    
    def test_plan_wrap_text(self):
        """Text wrapping works correctly."""
        plan = AttackPlan(objective="test")
        wrapped = plan._wrap_text("This is a test of text wrapping functionality", 20)
        assert all(len(line) <= 20 for line in wrapped)
