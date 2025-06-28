"""
Advanced Share Permission Analyzer
Provides detailed analysis and visualization of SMB share permissions and access levels.
"""

import os
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime
from colorama import Fore, Style, init
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

# Initialize colorama and rich
init(autoreset=True)
console = Console()


class PermissionLevel(Enum):
    """Permission level enumeration."""
    NONE = "none"
    READ = "read"
    WRITE = "write"
    FULL = "full"
    ADMIN = "admin"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk level enumeration for security assessment."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SharePermission:
    """Data class for share permission information."""
    share_name: str
    path: str
    permission_level: PermissionLevel
    access_type: str
    user_context: str
    is_writable: bool
    is_readable: bool
    is_administrative: bool
    contains_sensitive_data: bool
    risk_level: RiskLevel
    timestamp: str
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization."""
        return {
            'share_name': self.share_name,
            'path': self.path,
            'permission_level': self.permission_level.value,
            'access_type': self.access_type,
            'user_context': self.user_context,
            'is_writable': self.is_writable,
            'is_readable': self.is_readable,
            'is_administrative': self.is_administrative,
            'contains_sensitive_data': self.contains_sensitive_data,
            'risk_level': self.risk_level.value,
            'timestamp': self.timestamp
        }


class PermissionAnalyzer:
    """Advanced permission analyzer for SMB shares."""
    
    def __init__(self):
        self.permissions = []
        self.sensitive_patterns = [
            'password', 'passwd', 'secret', 'key', 'token', 'credential',
            'config', 'settings', 'admin', 'backup', 'database', 'db',
            'finance', 'hr', 'payroll', 'personal', 'confidential',
            'private', 'internal', 'restricted'
        ]
        self.admin_shares = ['admin$', 'c$', 'd$', 'ipc$']
    
    def analyze_share_permissions(self, target, share_name, credentials, logger=None):
        """
        Analyze permissions for a specific share.
        
        Args:
            target (str): Target IP or hostname
            share_name (str): Share name to analyze
            credentials (tuple): (username, password, ntlm_hash)
            logger: Logger instance
        
        Returns:
            SharePermission: Permission analysis result
        """
        username, password, ntlm_hash = credentials
        
        # Determine permission level based on access testing
        permission_level = self._test_permission_level(target, share_name, credentials)
        
        # Analyze share characteristics
        is_administrative = self._is_administrative_share(share_name)
        contains_sensitive = self._contains_sensitive_data(share_name)
        risk_level = self._calculate_risk_level(permission_level, is_administrative, contains_sensitive)
        
        # Create permission object
        permission = SharePermission(
            share_name=share_name,
            path=f"//{target}/{share_name}",
            permission_level=permission_level,
            access_type=self._get_access_type(permission_level),
            user_context=username or "anonymous",
            is_writable=permission_level in [PermissionLevel.WRITE, PermissionLevel.FULL, PermissionLevel.ADMIN],
            is_readable=permission_level != PermissionLevel.NONE,
            is_administrative=is_administrative,
            contains_sensitive_data=contains_sensitive,
            risk_level=risk_level,
            timestamp=datetime.now().isoformat()
        )
        
        self.permissions.append(permission)
        
        if logger:
            logger.info(f"[*] Share {share_name}: {permission_level.value} access, {risk_level.value} risk")
        
        return permission
    
    def _test_permission_level(self, target, share_name, credentials):
        """Test the actual permission level for a share."""
        username, password, ntlm_hash = credentials
        
        try:
            # Import here to avoid circular imports
            from scanner.permission_tester import test_share_access
            
            # Test read access
            read_result = test_share_access(target, share_name, username, password, ntlm_hash, test_type="read")
            if not read_result:
                return PermissionLevel.NONE
            
            # Test write access
            write_result = test_share_access(target, share_name, username, password, ntlm_hash, test_type="write")
            if write_result:
                # Test admin operations
                admin_result = test_share_access(target, share_name, username, password, ntlm_hash, test_type="admin")
                if admin_result:
                    return PermissionLevel.ADMIN
                else:
                    return PermissionLevel.FULL
            else:
                return PermissionLevel.READ
                
        except Exception:
            return PermissionLevel.UNKNOWN
    
    def _is_administrative_share(self, share_name):
        """Check if share is administrative."""
        return share_name.lower() in self.admin_shares or share_name.endswith('$')
    
    def _contains_sensitive_data(self, share_name):
        """Check if share likely contains sensitive data based on name."""
        share_lower = share_name.lower()
        return any(pattern in share_lower for pattern in self.sensitive_patterns)
    
    def _calculate_risk_level(self, permission_level, is_administrative, contains_sensitive):
        """Calculate risk level based on permission characteristics."""
        if permission_level == PermissionLevel.NONE:
            return RiskLevel.LOW
        
        if permission_level == PermissionLevel.ADMIN:
            return RiskLevel.CRITICAL
        
        if is_administrative and permission_level in [PermissionLevel.WRITE, PermissionLevel.FULL]:
            return RiskLevel.CRITICAL
        
        if contains_sensitive and permission_level in [PermissionLevel.WRITE, PermissionLevel.FULL]:
            return RiskLevel.HIGH
        
        if permission_level == PermissionLevel.WRITE:
            return RiskLevel.MEDIUM if not contains_sensitive else RiskLevel.HIGH
        
        if contains_sensitive and permission_level == PermissionLevel.READ:
            return RiskLevel.MEDIUM
        
        return RiskLevel.LOW
    
    def _get_access_type(self, permission_level):
        """Get human-readable access type."""
        access_types = {
            PermissionLevel.NONE: "No Access",
            PermissionLevel.READ: "Read Only",
            PermissionLevel.WRITE: "Read/Write",
            PermissionLevel.FULL: "Full Control",
            PermissionLevel.ADMIN: "Administrative",
            PermissionLevel.UNKNOWN: "Unknown"
        }
        return access_types.get(permission_level, "Unknown")
    
    def generate_permission_matrix(self):
        """Generate a permission matrix visualization."""
        if not self.permissions:
            console.print("[yellow]No permissions analyzed yet.[/yellow]")
            return
        
        # Create permission matrix table
        table = Table(title="SMB Share Permission Matrix", show_header=True, header_style="bold blue")
        table.add_column("Share Name", style="cyan", min_width=15)
        table.add_column("User Context", style="white", width=12)
        table.add_column("Access Level", style="green", width=12)
        table.add_column("Read", justify="center", width=6)
        table.add_column("Write", justify="center", width=6)
        table.add_column("Admin", justify="center", width=6)
        table.add_column("Sensitive", justify="center", width=9)
        table.add_column("Risk Level", style="bold", width=10)
        
        for perm in sorted(self.permissions, key=lambda x: x.risk_level.value, reverse=True):
            # Color coding for risk levels
            risk_colors = {
                RiskLevel.LOW: "green",
                RiskLevel.MEDIUM: "yellow", 
                RiskLevel.HIGH: "red",
                RiskLevel.CRITICAL: "bold red"
            }
            
            risk_color = risk_colors.get(perm.risk_level, "white")
            
            table.add_row(
                perm.share_name,
                perm.user_context,
                perm.access_type,
                "✓" if perm.is_readable else "✗",
                "✓" if perm.is_writable else "✗",
                "✓" if perm.is_administrative else "✗",
                "⚠" if perm.contains_sensitive_data else "○",
                f"[{risk_color}]{perm.risk_level.value.upper()}[/{risk_color}]"
            )
        
        console.print(table)
    
    def generate_risk_summary(self):
        """Generate risk level summary."""
        if not self.permissions:
            return
        
        risk_counts = {level: 0 for level in RiskLevel}
        for perm in self.permissions:
            risk_counts[perm.risk_level] += 1
        
        # Create risk summary table
        summary_table = Table(title="Security Risk Summary", show_header=True, header_style="bold yellow")
        summary_table.add_column("Risk Level", style="bold", width=15)
        summary_table.add_column("Count", justify="center", width=8)
        summary_table.add_column("Percentage", justify="center", width=12)
        summary_table.add_column("Impact", style="italic", width=30)
        
        total_shares = len(self.permissions)
        
        risk_impacts = {
            RiskLevel.CRITICAL: "Immediate attention required",
            RiskLevel.HIGH: "Security review recommended", 
            RiskLevel.MEDIUM: "Monitor and assess",
            RiskLevel.LOW: "Standard security posture"
        }
        
        risk_colors = {
            RiskLevel.CRITICAL: "bold red",
            RiskLevel.HIGH: "red",
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green"
        }
        
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            count = risk_counts[risk_level]
            percentage = (count / total_shares * 100) if total_shares > 0 else 0
            color = risk_colors[risk_level]
            
            summary_table.add_row(
                f"[{color}]{risk_level.value.upper()}[/{color}]",
                str(count),
                f"{percentage:.1f}%",
                risk_impacts[risk_level]
            )
        
        console.print(summary_table)
    
    def generate_permission_tree(self):
        """Generate hierarchical permission tree visualization."""
        if not self.permissions:
            return
        
        tree = Tree("📁 SMB Share Permissions", style="bold blue")
        
        # Group by risk level
        risk_groups = {level: [] for level in RiskLevel}
        for perm in self.permissions:
            risk_groups[perm.risk_level].append(perm)
        
        risk_colors = {
            RiskLevel.CRITICAL: "bold red",
            RiskLevel.HIGH: "red", 
            RiskLevel.MEDIUM: "yellow",
            RiskLevel.LOW: "green"
        }
        
        for risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW]:
            perms = risk_groups[risk_level]
            if not perms:
                continue
            
            color = risk_colors[risk_level]
            risk_branch = tree.add(f"[{color}]🔒 {risk_level.value.upper()} RISK ({len(perms)} shares)[/{color}]")
            
            for perm in sorted(perms, key=lambda x: x.share_name):
                share_icon = "🛡️" if perm.is_administrative else "📂"
                sensitive_icon = "⚠️" if perm.contains_sensitive_data else ""
                
                share_branch = risk_branch.add(
                    f"{share_icon} {perm.share_name} {sensitive_icon}",
                    style=color
                )
                
                # Add permission details
                share_branch.add(f"👤 User: {perm.user_context}")
                share_branch.add(f"🔑 Access: {perm.access_type}")
                share_branch.add(f"📍 Path: {perm.path}")
                
                # Add capability indicators
                capabilities = []
                if perm.is_readable:
                    capabilities.append("📖 Read")
                if perm.is_writable:
                    capabilities.append("✏️ Write")
                if perm.is_administrative:
                    capabilities.append("⚙️ Admin")
                
                if capabilities:
                    share_branch.add(f"🔧 Capabilities: {' | '.join(capabilities)}")
        
        console.print(tree)
    
    def generate_detailed_report(self, target):
        """Generate comprehensive permission report."""
        if not self.permissions:
            console.print("[yellow]No permissions to report.[/yellow]")
            return
        
        # Header
        console.print()
        console.print(Panel.fit(
            f"[bold cyan]SMB Share Permission Analysis Report[/bold cyan]\n"
            f"[white]Target: {target}[/white]\n"
            f"[white]Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/white]\n"
            f"[white]Total Shares Analyzed: {len(self.permissions)}[/white]",
            border_style="cyan"
        ))
        
        # Risk Summary
        console.print("\n[bold yellow]🔍 SECURITY RISK OVERVIEW[/bold yellow]")
        self.generate_risk_summary()
        
        # Permission Matrix
        console.print("\n[bold blue]📊 PERMISSION MATRIX[/bold blue]")
        self.generate_permission_matrix()
        
        # Permission Tree
        console.print("\n[bold green]🌳 HIERARCHICAL VIEW[/bold green]")
        self.generate_permission_tree()
        
        # Critical findings
        critical_perms = [p for p in self.permissions if p.risk_level == RiskLevel.CRITICAL]
        if critical_perms:
            console.print("\n[bold red]🚨 CRITICAL SECURITY FINDINGS[/bold red]")
            for perm in critical_perms:
                console.print(
                    f"[red]• {perm.share_name}[/red] - {perm.access_type} access "
                    f"{'(Administrative)' if perm.is_administrative else ''}"
                    f"{'(Sensitive Data)' if perm.contains_sensitive_data else ''}"
                )
        
        # Recommendations
        self._generate_recommendations()
    
    def _generate_recommendations(self):
        """Generate security recommendations based on analysis."""
        console.print("\n[bold magenta]💡 SECURITY RECOMMENDATIONS[/bold magenta]")
        
        recommendations = []
        
        # Check for critical risks
        critical_count = len([p for p in self.permissions if p.risk_level == RiskLevel.CRITICAL])
        if critical_count > 0:
            recommendations.append(
                f"🔴 URGENT: {critical_count} shares have critical security risks - immediate review required"
            )
        
        # Check for write access to sensitive shares
        sensitive_write = [p for p in self.permissions if p.contains_sensitive_data and p.is_writable]
        if sensitive_write:
            recommendations.append(
                f"🟡 {len(sensitive_write)} sensitive shares have write access - consider read-only restrictions"
            )
        
        # Check for administrative access
        admin_access = [p for p in self.permissions if p.is_administrative and p.permission_level != PermissionLevel.NONE]
        if admin_access:
            recommendations.append(
                f"🟠 {len(admin_access)} administrative shares are accessible - review necessity"
            )
        
        # Check for anonymous access
        anon_access = [p for p in self.permissions if p.user_context in ["", "anonymous", "guest"]]
        if anon_access:
            recommendations.append(
                f"🔵 {len(anon_access)} shares allow anonymous/guest access - consider authentication requirements"
            )
        
        if not recommendations:
            recommendations.append("✅ No immediate security concerns identified")
        
        for rec in recommendations:
            console.print(f"  {rec}")
    
    def export_to_json(self, filename):
        """Export permission analysis to JSON file."""
        export_data = {
            'analysis_metadata': {
                'timestamp': datetime.now().isoformat(),
                'tool': 'CRED-SHADOW Permission Analyzer',
                'version': '1.0',
                'total_shares': len(self.permissions)
            },
            'permissions': [perm.to_dict() for perm in self.permissions],
            'risk_summary': self._get_risk_summary_data()
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            console.print(f"[green]✓ Permission analysis exported to {filename}[/green]")
        except Exception as e:
            console.print(f"[red]✗ Failed to export to {filename}: {str(e)}[/red]")
    
    def _get_risk_summary_data(self):
        """Get risk summary data for export."""
        risk_counts = {level.value: 0 for level in RiskLevel}
        for perm in self.permissions:
            risk_counts[perm.risk_level.value] += 1
        
        return {
            'risk_distribution': risk_counts,
            'total_shares': len(self.permissions),
            'critical_shares': [p.share_name for p in self.permissions if p.risk_level == RiskLevel.CRITICAL],
            'writable_shares': [p.share_name for p in self.permissions if p.is_writable],
            'sensitive_shares': [p.share_name for p in self.permissions if p.contains_sensitive_data]
        }


def analyze_share_permissions(target, shares, credentials_list, logger=None):
    """
    Analyze permissions for multiple shares with multiple credential sets.
    
    Args:
        target (str): Target IP or hostname
        shares (list): List of share names or share dictionaries
        credentials_list (list): List of credential tuples
        logger: Logger instance
    
    Returns:
        PermissionAnalyzer: Analyzer instance with results
    """
    analyzer = PermissionAnalyzer()
    
    if logger:
        logger.info(f"[*] Starting permission analysis for {len(shares)} shares")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        
        task = progress.add_task("Analyzing permissions...", total=len(shares) * len(credentials_list))
        
        for share in shares:
            share_name = share if isinstance(share, str) else share.get('name', 'unknown')
            
            for credentials in credentials_list:
                username = credentials[0] if credentials[0] else "anonymous"
                progress.update(task, description=f"Testing {share_name} with {username}")
                
                try:
                    analyzer.analyze_share_permissions(target, share_name, credentials, logger)
                except Exception as e:
                    if logger:
                        logger.error(f"[-] Error analyzing {share_name}: {str(e)}")
                
                progress.advance(task)
    
    if logger:
        logger.info(f"[+] Permission analysis complete - {len(analyzer.permissions)} results")
    
    return analyzer