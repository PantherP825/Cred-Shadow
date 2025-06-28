"""
Webhook and API Export Module
Handles sending results to external systems via webhooks and APIs.
"""

import json
import requests
import time
from datetime import datetime
from utils.logger import get_logger


class WebhookExporter:
    """Webhook exporter for sending scan results to external systems."""
    
    def __init__(self, webhook_url, api_key=None, timeout=30, retry_attempts=3):
        """
        Initialize webhook exporter.
        
        Args:
            webhook_url (str): Webhook endpoint URL
            api_key (str): API key for authentication
            timeout (int): Request timeout in seconds
            retry_attempts (int): Number of retry attempts
        """
        self.webhook_url = webhook_url
        self.api_key = api_key
        self.timeout = timeout
        self.retry_attempts = retry_attempts
        self.logger = get_logger()
    
    def format_results(self, scan_results, target, scan_type="smb_scan"):
        """
        Format scan results for webhook payload.
        
        Args:
            scan_results (dict): Scan results data
            target (str): Target that was scanned
            scan_type (str): Type of scan performed
        
        Returns:
            dict: Formatted payload
        """
        payload = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "scan_type": scan_type,
            "target": target,
            "tool": "CRED-SHADOW",
            "version": "1.0.0",
            "results": scan_results,
            "summary": {
                "total_findings": len(scan_results.get('findings', [])),
                "shares_enumerated": len(scan_results.get('shares', [])),
                "credentials_found": len(scan_results.get('credentials', [])),
                "high_severity": len([f for f in scan_results.get('findings', []) 
                                    if f.get('severity') == 'high']),
                "medium_severity": len([f for f in scan_results.get('findings', []) 
                                      if f.get('severity') == 'medium']),
                "low_severity": len([f for f in scan_results.get('findings', []) 
                                   if f.get('severity') == 'low'])
            }
        }
        
        return payload
    
    def send_webhook(self, payload):
        """
        Send webhook with retry logic.
        
        Args:
            payload (dict): Payload to send
        
        Returns:
            bool: True if successful
        """
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "CRED-SHADOW/1.0.0"
        }
        
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        
        for attempt in range(self.retry_attempts):
            try:
                self.logger.info(f"[*] Sending webhook (attempt {attempt + 1}/{self.retry_attempts})")
                
                response = requests.post(
                    self.webhook_url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout
                )
                
                if response.status_code in [200, 201, 202]:
                    self.logger.info(f"[+] Webhook sent successfully (HTTP {response.status_code})")
                    return True
                else:
                    self.logger.warning(f"[-] Webhook failed with HTTP {response.status_code}: {response.text}")
                
            except requests.exceptions.Timeout:
                self.logger.warning(f"[-] Webhook timeout (attempt {attempt + 1})")
            except requests.exceptions.ConnectionError:
                self.logger.warning(f"[-] Webhook connection error (attempt {attempt + 1})")
            except Exception as e:
                self.logger.error(f"[-] Webhook error: {e}")
            
            if attempt < self.retry_attempts - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
        
        self.logger.error("[-] Failed to send webhook after all attempts")
        return False
    
    def export_results(self, scan_results, target, scan_type="smb_scan"):
        """
        Export scan results via webhook.
        
        Args:
            scan_results (dict): Scan results data
            target (str): Target that was scanned
            scan_type (str): Type of scan performed
        
        Returns:
            bool: True if successful
        """
        payload = self.format_results(scan_results, target, scan_type)
        return self.send_webhook(payload)


class SlackExporter:
    """Slack-specific webhook exporter."""
    
    def __init__(self, webhook_url, channel=None, username="CRED-SHADOW"):
        """
        Initialize Slack exporter.
        
        Args:
            webhook_url (str): Slack webhook URL
            channel (str): Slack channel to post to
            username (str): Bot username
        """
        self.webhook_url = webhook_url
        self.channel = channel
        self.username = username
        self.logger = get_logger()
    
    def format_slack_message(self, scan_results, target):
        """
        Format results for Slack message.
        
        Args:
            scan_results (dict): Scan results data
            target (str): Target that was scanned
        
        Returns:
            dict: Slack message payload
        """
        findings = scan_results.get('findings', [])
        shares = scan_results.get('shares', [])
        
        # Determine alert color based on findings
        color = "good"  # Green
        if any(f.get('severity') == 'high' for f in findings):
            color = "danger"  # Red
        elif any(f.get('severity') == 'medium' for f in findings):
            color = "warning"  # Yellow
        
        # Create summary text
        summary = f"CRED-SHADOW scan completed for {target}"
        if findings:
            summary += f"\n🔍 Found {len(findings)} potential secrets"
        if shares:
            summary += f"\n📁 Enumerated {len(shares)} accessible shares"
        
        # Create detailed fields
        fields = [
            {
                "title": "Target",
                "value": target,
                "short": True
            },
            {
                "title": "Shares Found",
                "value": str(len(shares)),
                "short": True
            },
            {
                "title": "Total Findings",
                "value": str(len(findings)),
                "short": True
            }
        ]
        
        # Add severity breakdown
        high_count = len([f for f in findings if f.get('severity') == 'high'])
        medium_count = len([f for f in findings if f.get('severity') == 'medium'])
        low_count = len([f for f in findings if f.get('severity') == 'low'])
        
        severity_text = f"🔴 High: {high_count} | 🟡 Medium: {medium_count} | 🟢 Low: {low_count}"
        fields.append({
            "title": "Severity Breakdown",
            "value": severity_text,
            "short": False
        })
        
        payload = {
            "username": self.username,
            "text": summary,
            "attachments": [
                {
                    "color": color,
                    "fields": fields,
                    "footer": "CRED-SHADOW",
                    "ts": int(time.time())
                }
            ]
        }
        
        if self.channel:
            payload["channel"] = self.channel
        
        return payload
    
    def send_slack_alert(self, scan_results, target):
        """
        Send Slack alert with scan results.
        
        Args:
            scan_results (dict): Scan results data
            target (str): Target that was scanned
        
        Returns:
            bool: True if successful
        """
        payload = self.format_slack_message(scan_results, target)
        
        try:
            response = requests.post(self.webhook_url, json=payload, timeout=30)
            
            if response.status_code == 200:
                self.logger.info("[+] Slack alert sent successfully")
                return True
            else:
                self.logger.error(f"[-] Slack alert failed: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"[-] Error sending Slack alert: {e}")
            return False


class SIEMExporter:
    """SIEM-specific exporter for security platforms."""
    
    def __init__(self, siem_url, api_key, siem_type="splunk"):
        """
        Initialize SIEM exporter.
        
        Args:
            siem_url (str): SIEM API endpoint
            api_key (str): API key for authentication
            siem_type (str): Type of SIEM (splunk, qradar, sentinel)
        """
        self.siem_url = siem_url
        self.api_key = api_key
        self.siem_type = siem_type.lower()
        self.logger = get_logger()
    
    def format_siem_event(self, finding, target):
        """
        Format finding as SIEM event.
        
        Args:
            finding (dict): Individual finding
            target (str): Target that was scanned
        
        Returns:
            dict: SIEM event format
        """
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source": "CRED-SHADOW",
            "sourcetype": "smb_secret_scan",
            "host": target,
            "event": {
                "action": "secret_detected",
                "category": "security",
                "severity": finding.get('severity', 'unknown'),
                "rule_name": finding.get('rule', ''),
                "file_path": finding.get('file_path', ''),
                "share": finding.get('share', ''),
                "pattern_type": finding.get('pattern_type', ''),
                "confidence": finding.get('confidence', 0),
                "description": finding.get('description', ''),
                "raw_finding": finding
            }
        }
        
        return event
    
    def send_to_siem(self, scan_results, target):
        """
        Send results to SIEM platform.
        
        Args:
            scan_results (dict): Scan results data
            target (str): Target that was scanned
        
        Returns:
            bool: True if successful
        """
        findings = scan_results.get('findings', [])
        
        if not findings:
            self.logger.info("[*] No findings to send to SIEM")
            return True
        
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        success_count = 0
        
        for finding in findings:
            event = self.format_siem_event(finding, target)
            
            try:
                response = requests.post(
                    self.siem_url,
                    json=event,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code in [200, 201, 202]:
                    success_count += 1
                else:
                    self.logger.warning(f"[-] SIEM event failed: HTTP {response.status_code}")
                    
            except Exception as e:
                self.logger.error(f"[-] Error sending to SIEM: {e}")
        
        self.logger.info(f"[+] Sent {success_count}/{len(findings)} events to SIEM")
        return success_count == len(findings)


def export_via_webhook(scan_results, target, webhook_config):
    """
    Export results using webhook configuration.
    
    Args:
        scan_results (dict): Scan results data
        target (str): Target that was scanned
        webhook_config (dict): Webhook configuration
    
    Returns:
        bool: True if successful
    """
    webhook_type = webhook_config.get('type', 'generic').lower()
    
    try:
        if webhook_type == 'slack':
            exporter = SlackExporter(
                webhook_config['url'],
                webhook_config.get('channel'),
                webhook_config.get('username', 'CRED-SHADOW')
            )
            return exporter.send_slack_alert(scan_results, target)
        
        elif webhook_type == 'siem':
            exporter = SIEMExporter(
                webhook_config['url'],
                webhook_config['api_key'],
                webhook_config.get('siem_type', 'splunk')
            )
            return exporter.send_to_siem(scan_results, target)
        
        else:  # Generic webhook
            exporter = WebhookExporter(
                webhook_config['url'],
                webhook_config.get('api_key'),
                webhook_config.get('timeout', 30),
                webhook_config.get('retry_attempts', 3)
            )
            return exporter.export_results(scan_results, target)
    
    except Exception as e:
        logger = get_logger()
        logger.error(f"[-] Webhook export error: {e}")
        return False