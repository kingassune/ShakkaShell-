"""Tool registry for known security tools.

Defines tool metadata, categories, and installation instructions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ToolCategory(str, Enum):
    """Categories of security tools."""
    
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    PASSWORD_CRACKING = "password_cracking"
    WEB_TESTING = "web_testing"
    WIRELESS = "wireless"
    FORENSICS = "forensics"
    UTILITY = "utility"


@dataclass
class ToolInfo:
    """Information about a security tool.
    
    Contains metadata for detection, installation, and usage.
    """
    
    name: str
    description: str
    category: ToolCategory
    command: str                          # Primary binary name
    version_arg: str = "--version"        # Argument to get version
    install_apt: Optional[str] = None     # apt package name
    install_brew: Optional[str] = None    # brew package name
    install_pip: Optional[str] = None     # pip package name
    install_url: Optional[str] = None     # Manual installation URL
    alternatives: list[str] = field(default_factory=list)  # Alternative tools
    common_args: list[str] = field(default_factory=list)   # Common argument patterns
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "command": self.command,
            "version_arg": self.version_arg,
            "install_apt": self.install_apt,
            "install_brew": self.install_brew,
            "install_pip": self.install_pip,
            "install_url": self.install_url,
            "alternatives": self.alternatives,
            "common_args": self.common_args,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ToolInfo":
        """Create from dictionary."""
        return cls(
            name=data.get("name", ""),
            description=data.get("description", ""),
            category=ToolCategory(data.get("category", "utility")),
            command=data.get("command", ""),
            version_arg=data.get("version_arg", "--version"),
            install_apt=data.get("install_apt"),
            install_brew=data.get("install_brew"),
            install_pip=data.get("install_pip"),
            install_url=data.get("install_url"),
            alternatives=data.get("alternatives", []),
            common_args=data.get("common_args", []),
        )
    
    def get_install_command(self, platform: str = "linux") -> Optional[str]:
        """Get installation command for the platform.
        
        Args:
            platform: Target platform (linux, darwin, pip).
            
        Returns:
            Installation command or None.
        """
        if platform == "linux" and self.install_apt:
            return f"sudo apt-get install -y {self.install_apt}"
        elif platform == "darwin" and self.install_brew:
            return f"brew install {self.install_brew}"
        elif self.install_pip:
            return f"pip install {self.install_pip}"
        return None


class ToolRegistry:
    """Registry of known security tools.
    
    Provides lookup, registration, and discovery of security tools.
    
    Example:
        registry = ToolRegistry()
        nmap = registry.get("nmap")
        scan_tools = registry.get_by_category(ToolCategory.SCANNING)
    """
    
    def __init__(self):
        """Initialize the registry with default tools."""
        self._tools: dict[str, ToolInfo] = {}
        self._register_defaults()
    
    def _register_defaults(self) -> None:
        """Register default security tools."""
        # Scanning tools
        self.register(ToolInfo(
            name="nmap",
            description="Network exploration and security auditing",
            category=ToolCategory.SCANNING,
            command="nmap",
            version_arg="-V",
            install_apt="nmap",
            install_brew="nmap",
            alternatives=["masscan", "rustscan"],
            common_args=["-sV", "-sC", "-p-", "-A", "-T4"],
        ))
        
        self.register(ToolInfo(
            name="masscan",
            description="TCP port scanner, faster than nmap",
            category=ToolCategory.SCANNING,
            command="masscan",
            version_arg="--version",
            install_apt="masscan",
            install_brew="masscan",
            alternatives=["nmap", "rustscan"],
            common_args=["--rate", "-p", "--banners"],
        ))
        
        self.register(ToolInfo(
            name="rustscan",
            description="Fast port scanner written in Rust",
            category=ToolCategory.SCANNING,
            command="rustscan",
            version_arg="--version",
            install_url="https://github.com/RustScan/RustScan",
            alternatives=["nmap", "masscan"],
            common_args=["-a", "--ulimit"],
        ))
        
        # Web testing tools
        self.register(ToolInfo(
            name="gobuster",
            description="Directory/file and DNS busting tool",
            category=ToolCategory.WEB_TESTING,
            command="gobuster",
            version_arg="version",
            install_apt="gobuster",
            install_brew="gobuster",
            alternatives=["ffuf", "dirsearch", "feroxbuster"],
            common_args=["dir", "-u", "-w", "-t"],
        ))
        
        self.register(ToolInfo(
            name="ffuf",
            description="Fast web fuzzer",
            category=ToolCategory.WEB_TESTING,
            command="ffuf",
            version_arg="-V",
            install_apt="ffuf",
            install_brew="ffuf",
            alternatives=["gobuster", "wfuzz", "feroxbuster"],
            common_args=["-u", "-w", "-mc", "-H"],
        ))
        
        self.register(ToolInfo(
            name="feroxbuster",
            description="Fast, simple recursive content discovery",
            category=ToolCategory.WEB_TESTING,
            command="feroxbuster",
            version_arg="--version",
            install_url="https://github.com/epi052/feroxbuster",
            alternatives=["gobuster", "ffuf"],
            common_args=["-u", "-w", "--depth"],
        ))
        
        self.register(ToolInfo(
            name="sqlmap",
            description="Automatic SQL injection detection and exploitation",
            category=ToolCategory.WEB_TESTING,
            command="sqlmap",
            version_arg="--version",
            install_apt="sqlmap",
            install_brew="sqlmap",
            install_pip="sqlmap",
            alternatives=["ghauri"],
            common_args=["-u", "--dbs", "--batch", "--forms"],
        ))
        
        self.register(ToolInfo(
            name="nikto",
            description="Web server scanner",
            category=ToolCategory.WEB_TESTING,
            command="nikto",
            version_arg="-Version",
            install_apt="nikto",
            install_brew="nikto",
            alternatives=["nuclei"],
            common_args=["-h", "-p", "-ssl"],
        ))
        
        # Vulnerability scanning
        self.register(ToolInfo(
            name="nuclei",
            description="Fast and customizable vulnerability scanner",
            category=ToolCategory.SCANNING,
            command="nuclei",
            version_arg="-version",
            install_url="https://github.com/projectdiscovery/nuclei",
            alternatives=["nikto", "nmap"],
            common_args=["-u", "-t", "-l", "-severity"],
        ))
        
        # Exploitation tools
        self.register(ToolInfo(
            name="metasploit",
            description="Penetration testing framework",
            category=ToolCategory.EXPLOITATION,
            command="msfconsole",
            version_arg="--version",
            install_apt="metasploit-framework",
            install_url="https://www.metasploit.com/download",
            alternatives=[],
            common_args=["-q", "-x", "-r"],
        ))
        
        self.register(ToolInfo(
            name="searchsploit",
            description="Exploit-DB command line search",
            category=ToolCategory.EXPLOITATION,
            command="searchsploit",
            version_arg="--version",
            install_apt="exploitdb",
            alternatives=[],
            common_args=["-t", "-e", "--cve"],
        ))
        
        # Password tools
        self.register(ToolInfo(
            name="hashcat",
            description="Advanced password recovery",
            category=ToolCategory.PASSWORD_CRACKING,
            command="hashcat",
            version_arg="--version",
            install_apt="hashcat",
            install_brew="hashcat",
            alternatives=["john"],
            common_args=["-m", "-a", "-o", "-w"],
        ))
        
        self.register(ToolInfo(
            name="john",
            description="John the Ripper password cracker",
            category=ToolCategory.PASSWORD_CRACKING,
            command="john",
            version_arg="--version",
            install_apt="john",
            install_brew="john-jumbo",
            alternatives=["hashcat"],
            common_args=["--wordlist", "--format", "--show"],
        ))
        
        self.register(ToolInfo(
            name="hydra",
            description="Network logon cracker",
            category=ToolCategory.PASSWORD_CRACKING,
            command="hydra",
            version_arg="-h",
            install_apt="hydra",
            install_brew="hydra",
            alternatives=["medusa", "ncrack"],
            common_args=["-l", "-P", "-t", "-f"],
        ))
        
        # Enumeration tools
        self.register(ToolInfo(
            name="enum4linux",
            description="Linux alternative to enum.exe for SMB enumeration",
            category=ToolCategory.ENUMERATION,
            command="enum4linux",
            version_arg="-h",
            install_apt="enum4linux",
            alternatives=["enum4linux-ng", "smbclient"],
            common_args=["-a", "-U", "-S"],
        ))
        
        self.register(ToolInfo(
            name="ldapsearch",
            description="LDAP directory search tool",
            category=ToolCategory.ENUMERATION,
            command="ldapsearch",
            version_arg="-V",
            install_apt="ldap-utils",
            install_brew="openldap",
            alternatives=[],
            common_args=["-x", "-H", "-b", "-D"],
        ))
        
        # Network utilities
        self.register(ToolInfo(
            name="netcat",
            description="TCP/IP swiss army knife",
            category=ToolCategory.UTILITY,
            command="nc",
            version_arg="-h",
            install_apt="netcat-openbsd",
            install_brew="netcat",
            alternatives=["ncat", "socat"],
            common_args=["-l", "-p", "-v", "-n"],
        ))
        
        self.register(ToolInfo(
            name="socat",
            description="Multipurpose relay for bidirectional data transfer",
            category=ToolCategory.UTILITY,
            command="socat",
            version_arg="-V",
            install_apt="socat",
            install_brew="socat",
            alternatives=["netcat"],
            common_args=["TCP:", "FILE:", "EXEC:"],
        ))
        
        self.register(ToolInfo(
            name="curl",
            description="Command line tool for transferring data",
            category=ToolCategory.UTILITY,
            command="curl",
            version_arg="--version",
            install_apt="curl",
            install_brew="curl",
            alternatives=["wget", "httpx"],
            common_args=["-X", "-H", "-d", "-o", "-L"],
        ))
        
        self.register(ToolInfo(
            name="wget",
            description="Non-interactive network downloader",
            category=ToolCategory.UTILITY,
            command="wget",
            version_arg="--version",
            install_apt="wget",
            install_brew="wget",
            alternatives=["curl"],
            common_args=["-O", "-r", "-q", "--mirror"],
        ))
        
        # Impacket tools
        self.register(ToolInfo(
            name="impacket",
            description="Collection of Python classes for network protocols",
            category=ToolCategory.POST_EXPLOITATION,
            command="impacket-secretsdump",
            version_arg="--help",
            install_pip="impacket",
            alternatives=[],
            common_args=[],
        ))
        
        # Reconnaissance
        self.register(ToolInfo(
            name="subfinder",
            description="Subdomain discovery tool",
            category=ToolCategory.RECONNAISSANCE,
            command="subfinder",
            version_arg="-version",
            install_url="https://github.com/projectdiscovery/subfinder",
            alternatives=["amass", "assetfinder"],
            common_args=["-d", "-o", "-all"],
        ))
        
        self.register(ToolInfo(
            name="amass",
            description="In-depth Attack Surface Mapping",
            category=ToolCategory.RECONNAISSANCE,
            command="amass",
            version_arg="version",
            install_apt="amass",
            install_brew="amass",
            alternatives=["subfinder"],
            common_args=["enum", "-d", "-passive"],
        ))
        
        self.register(ToolInfo(
            name="httpx",
            description="Fast HTTP probing tool",
            category=ToolCategory.RECONNAISSANCE,
            command="httpx",
            version_arg="-version",
            install_url="https://github.com/projectdiscovery/httpx",
            alternatives=["httprobe"],
            common_args=["-l", "-sc", "-title", "-tech-detect"],
        ))
    
    def register(self, tool: ToolInfo) -> None:
        """Register a tool in the registry.
        
        Args:
            tool: Tool information to register.
        """
        self._tools[tool.name.lower()] = tool
    
    def unregister(self, name: str) -> bool:
        """Remove a tool from the registry.
        
        Args:
            name: Tool name to remove.
            
        Returns:
            True if removed, False if not found.
        """
        name = name.lower()
        if name in self._tools:
            del self._tools[name]
            return True
        return False
    
    def get(self, name: str) -> Optional[ToolInfo]:
        """Get tool information by name.
        
        Args:
            name: Tool name.
            
        Returns:
            ToolInfo or None if not found.
        """
        return self._tools.get(name.lower())
    
    def get_all(self) -> list[ToolInfo]:
        """Get all registered tools.
        
        Returns:
            List of all tool info.
        """
        return list(self._tools.values())
    
    def get_by_category(self, category: ToolCategory) -> list[ToolInfo]:
        """Get tools by category.
        
        Args:
            category: Tool category.
            
        Returns:
            List of tools in that category.
        """
        return [t for t in self._tools.values() if t.category == category]
    
    def get_by_command(self, command: str) -> Optional[ToolInfo]:
        """Get tool by its command name.
        
        Args:
            command: Binary/command name.
            
        Returns:
            ToolInfo or None.
        """
        for tool in self._tools.values():
            if tool.command == command:
                return tool
        return None
    
    def find_alternatives(self, name: str) -> list[ToolInfo]:
        """Find alternative tools for the given tool.
        
        Args:
            name: Tool name to find alternatives for.
            
        Returns:
            List of alternative tools.
        """
        tool = self.get(name)
        if not tool:
            return []
        
        alternatives = []
        for alt_name in tool.alternatives:
            alt_tool = self.get(alt_name)
            if alt_tool:
                alternatives.append(alt_tool)
        
        return alternatives
    
    def search(self, query: str) -> list[ToolInfo]:
        """Search for tools by name or description.
        
        Args:
            query: Search query.
            
        Returns:
            List of matching tools.
        """
        query = query.lower()
        results = []
        
        for tool in self._tools.values():
            if query in tool.name.lower() or query in tool.description.lower():
                results.append(tool)
        
        return results
    
    @property
    def count(self) -> int:
        """Get number of registered tools."""
        return len(self._tools)
