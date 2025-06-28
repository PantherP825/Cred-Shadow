"""
Network Diagnostic Utilities
Basic connectivity testing and network troubleshooting for SMB targets.
"""

import socket
import subprocess
import platform
import time
from rich.console import Console
from rich.table import Table

console = Console()

def test_basic_connectivity(target, port=445, timeout=10):
    """
    Test basic TCP connectivity to target:port
    
    Args:
        target (str): Target IP or hostname
        port (int): Target port (default: 445 for SMB)
        timeout (int): Connection timeout in seconds
    
    Returns:
        tuple: (success, error_code, message)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result == 0:
            return True, 0, f"Successfully connected to {target}:{port}"
        else:
            error_messages = {
                111: "Connection refused - target may not be running SMB service",
                110: "Connection timeout - target may be unreachable or firewalled", 
                113: "No route to host - check network connectivity",
                101: "Network unreachable",
                104: "Connection reset by peer"
            }
            
            message = error_messages.get(result, f"Connection failed with error code {result}")
            return False, result, message
            
    except Exception as e:
        return False, -1, f"Socket error: {str(e)}"

def test_dns_resolution(target):
    """
    Test DNS resolution for the target
    
    Args:
        target (str): Target hostname or IP
    
    Returns:
        tuple: (success, resolved_ip, message)
    """
    try:
        # Skip DNS test if target is already an IP address
        try:
            socket.inet_aton(target)
            return True, target, f"{target} is already an IP address"
        except socket.error:
            pass
        
        # Resolve hostname
        resolved_ip = socket.gethostbyname(target)
        return True, resolved_ip, f"Resolved {target} to {resolved_ip}"
        
    except socket.gaierror as e:
        return False, None, f"DNS resolution failed: {str(e)}"
    except Exception as e:
        return False, None, f"DNS error: {str(e)}"

def test_ping(target, count=3):
    """
    Test ICMP connectivity using ping
    
    Args:
        target (str): Target IP or hostname
        count (int): Number of ping packets
    
    Returns:
        tuple: (success, output, message)
    """
    try:
        system = platform.system().lower()
        
        if system == "windows":
            cmd = ["ping", "-n", str(count), target]
        else:
            cmd = ["ping", "-c", str(count), "-W", "3", target]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            return True, result.stdout, f"Ping to {target} successful"
        else:
            return False, result.stderr, f"Ping to {target} failed"
            
    except subprocess.TimeoutExpired:
        return False, "", f"Ping to {target} timed out"
    except Exception as e:
        return False, "", f"Ping error: {str(e)}"

def run_connectivity_diagnostic(target, port=445):
    """
    Run comprehensive connectivity diagnostic
    
    Args:
        target (str): Target IP or hostname
        port (int): Target port
    
    Returns:
        dict: Diagnostic results
    """
    console.print(f"\n[cyan]Running connectivity diagnostic for {target}:{port}[/cyan]")
    
    results = {}
    
    # Test 1: DNS Resolution
    console.print("[yellow]Testing DNS resolution...[/yellow]")
    dns_success, resolved_ip, dns_msg = test_dns_resolution(target)
    results['dns'] = {'success': dns_success, 'ip': resolved_ip, 'message': dns_msg}
    
    if dns_success:
        console.print(f"[green]✓[/green] {dns_msg}")
        actual_target = resolved_ip if resolved_ip != target else target
    else:
        console.print(f"[red]✗[/red] {dns_msg}")
        actual_target = target
    
    # Test 2: ICMP Ping
    console.print("[yellow]Testing ICMP connectivity...[/yellow]")
    ping_success, ping_output, ping_msg = test_ping(actual_target)
    results['ping'] = {'success': ping_success, 'output': ping_output, 'message': ping_msg}
    
    if ping_success:
        console.print(f"[green]✓[/green] {ping_msg}")
    else:
        console.print(f"[red]✗[/red] {ping_msg}")
    
    # Test 3: TCP Connectivity
    console.print(f"[yellow]Testing TCP connectivity to port {port}...[/yellow]")
    tcp_success, error_code, tcp_msg = test_basic_connectivity(actual_target, port)
    results['tcp'] = {'success': tcp_success, 'error_code': error_code, 'message': tcp_msg}
    
    if tcp_success:
        console.print(f"[green]✓[/green] {tcp_msg}")
    else:
        console.print(f"[red]✗[/red] {tcp_msg}")
    
    # Summary and recommendations
    console.print(f"\n[cyan]Diagnostic Summary for {target}:{port}[/cyan]")
    
    table = Table()
    table.add_column("Test", style="cyan")
    table.add_column("Status", style="yellow")
    table.add_column("Details", style="white")
    
    table.add_row("DNS Resolution", "✓ PASS" if dns_success else "✗ FAIL", dns_msg)
    table.add_row("ICMP Ping", "✓ PASS" if ping_success else "✗ FAIL", ping_msg)
    table.add_row("TCP Connection", "✓ PASS" if tcp_success else "✗ FAIL", tcp_msg)
    
    console.print(table)
    
    # Recommendations
    if not tcp_success:
        console.print(f"\n[red]Connection to {target}:{port} failed. Recommendations:[/red]")
        
        if not dns_success:
            console.print("• Fix DNS resolution issues first")
            console.print("• Try using IP address instead of hostname")
        
        if not ping_success:
            console.print("• Check network connectivity")
            console.print("• Verify VPN connection if using lab environment")
            console.print("• Check routing table")
        
        if dns_success and ping_success:
            console.print(f"• SMB service may not be running on port {port}")
            console.print(f"• Port {port} may be filtered by firewall")
            console.print("• Try different ports (139, 445)")
    
    results['overall_success'] = tcp_success
    return results

def quick_smb_test(target):
    """
    Quick test for common SMB ports
    
    Args:
        target (str): Target IP or hostname
    
    Returns:
        dict: Results for each port tested
    """
    ports = [139, 445]
    results = {}
    
    console.print(f"\n[cyan]Quick SMB port scan for {target}[/cyan]")
    
    for port in ports:
        success, error_code, message = test_basic_connectivity(target, port, timeout=5)
        results[port] = {'success': success, 'error_code': error_code, 'message': message}
        
        status = "✓ OPEN" if success else "✗ CLOSED"
        console.print(f"Port {port}/tcp: {status}")
    
    return results

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 445
        
        # Run full diagnostic
        results = run_connectivity_diagnostic(target, port)
        
        # Run quick SMB test
        smb_results = quick_smb_test(target)
        
        print(f"\nOverall connectivity: {'SUCCESS' if results['overall_success'] else 'FAILED'}")
    else:
        console.print("[red]Usage: python network_diagnostic.py <target> [port][/red]")