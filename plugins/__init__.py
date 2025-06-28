"""
Plugin System for CRED-SHADOW
Provides extensible detection rules and custom scanning logic.
"""

import os
import importlib.util
import inspect
from abc import ABC, abstractmethod
from utils.logger import get_logger


class BasePlugin(ABC):
    """Base class for CRED-SHADOW plugins."""
    
    def __init__(self):
        self.name = self.__class__.__name__
        self.version = getattr(self, 'version', '1.0.0')
        self.description = getattr(self, 'description', 'No description provided')
        self.author = getattr(self, 'author', 'Unknown')
        self.logger = get_logger()
    
    @abstractmethod
    def scan(self, file_content, file_path, file_info=None):
        """
        Scan file content for secrets or patterns.
        
        Args:
            file_content (bytes): File content to scan
            file_path (str): Path to the file
            file_info (dict): Additional file information
        
        Returns:
            list: List of findings (dict objects)
        """
        pass
    
    def get_info(self):
        """Get plugin information."""
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': self.author
        }


class PluginManager:
    """Plugin manager for loading and executing detection plugins."""
    
    def __init__(self, plugins_directory="plugins"):
        """
        Initialize plugin manager.
        
        Args:
            plugins_directory (str): Directory containing plugin files
        """
        self.plugins_directory = plugins_directory
        self.logger = get_logger()
        self.plugins = {}
        self.loaded_plugins = []
        
        # Ensure plugins directory exists
        if not os.path.exists(self.plugins_directory):
            os.makedirs(self.plugins_directory)
            self._create_example_plugins()
        
        self.load_plugins()
    
    def _create_example_plugins(self):
        """Create example plugins for demonstration."""
        
        # Cryptocurrency wallet plugin
        crypto_plugin = '''
from plugins import BasePlugin
import re

class CryptocurrencyPlugin(BasePlugin):
    """Plugin to detect cryptocurrency wallet addresses and private keys."""
    
    version = "1.0.0"
    description = "Detects Bitcoin, Ethereum, and other cryptocurrency addresses"
    author = "CRED-SHADOW Team"
    
    def __init__(self):
        super().__init__()
        self.patterns = {
            'bitcoin_address': re.compile(r'\\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\\b'),
            'ethereum_address': re.compile(r'\\b0x[a-fA-F0-9]{40}\\b'),
            'bitcoin_private_key': re.compile(r'\\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\\b'),
            'ethereum_private_key': re.compile(r'\\b0x[a-fA-F0-9]{64}\\b'),
            'monero_address': re.compile(r'\\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\\b')
        }
    
    def scan(self, file_content, file_path, file_info=None):
        """Scan for cryptocurrency-related secrets."""
        findings = []
        
        try:
            content_str = file_content.decode('utf-8', errors='ignore')
        except:
            return findings
        
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.finditer(content_str)
            
            for match in matches:
                finding = {
                    'plugin': self.name,
                    'type': pattern_name,
                    'severity': 'high' if 'private_key' in pattern_name else 'medium',
                    'confidence': 0.9,
                    'file_path': file_path,
                    'line_number': content_str[:match.start()].count('\\n') + 1,
                    'matched_content': match.group(),
                    'description': f"Potential {pattern_name.replace('_', ' ')} detected",
                    'recommendation': "Review and secure cryptocurrency credentials"
                }
                findings.append(finding)
        
        return findings
'''
        
        # Cloud configuration plugin
        cloud_plugin = '''
from plugins import BasePlugin
import re
import json

class CloudConfigPlugin(BasePlugin):
    """Plugin to detect cloud service configurations and secrets."""
    
    version = "1.0.0"
    description = "Detects cloud service configurations and credentials"
    author = "CRED-SHADOW Team"
    
    def __init__(self):
        super().__init__()
        self.config_patterns = {
            'aws_config': re.compile(r'aws_access_key_id|aws_secret_access_key', re.IGNORECASE),
            'azure_config': re.compile(r'client_id|client_secret|tenant_id', re.IGNORECASE),
            'gcp_config': re.compile(r'private_key_id|private_key|client_email', re.IGNORECASE),
            'docker_config': re.compile(r'registry|username|password', re.IGNORECASE)
        }
    
    def scan(self, file_content, file_path, file_info=None):
        """Scan for cloud configuration files."""
        findings = []
        
        # Check if this looks like a config file
        if not any(ext in file_path.lower() for ext in ['.json', '.yaml', '.yml', '.config', '.env']):
            return findings
        
        try:
            content_str = file_content.decode('utf-8', errors='ignore')
        except:
            return findings
        
        # Try to parse as JSON first
        try:
            data = json.loads(content_str)
            findings.extend(self._scan_json_config(data, file_path))
        except:
            # Fall back to regex scanning
            findings.extend(self._scan_text_config(content_str, file_path))
        
        return findings
    
    def _scan_json_config(self, data, file_path):
        """Scan JSON configuration data."""
        findings = []
        
        def scan_dict(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Check for sensitive keys
                    if any(pattern in key.lower() for pattern in ['key', 'secret', 'password', 'token']):
                        if isinstance(value, str) and value:
                            finding = {
                                'plugin': self.name,
                                'type': 'cloud_config_secret',
                                'severity': 'high',
                                'confidence': 0.8,
                                'file_path': file_path,
                                'matched_content': f"{key}: [REDACTED]",
                                'description': f"Sensitive configuration key detected: {current_path}",
                                'recommendation': "Review and secure configuration secrets"
                            }
                            findings.append(finding)
                    
                    scan_dict(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    scan_dict(item, f"{path}[{i}]")
        
        scan_dict(data)
        return findings
    
    def _scan_text_config(self, content, file_path):
        """Scan text-based configuration."""
        findings = []
        
        for pattern_name, pattern in self.config_patterns.items():
            matches = pattern.finditer(content)
            
            for match in matches:
                finding = {
                    'plugin': self.name,
                    'type': pattern_name,
                    'severity': 'medium',
                    'confidence': 0.7,
                    'file_path': file_path,
                    'line_number': content[:match.start()].count('\\n') + 1,
                    'matched_content': match.group(),
                    'description': f"Cloud configuration pattern detected: {pattern_name}",
                    'recommendation': "Review cloud service configuration"
                }
                findings.append(finding)
        
        return findings
'''
        
        # Write example plugins
        plugins = [
            ("cryptocurrency_plugin.py", crypto_plugin),
            ("cloud_config_plugin.py", cloud_plugin)
        ]
        
        for filename, content in plugins:
            plugin_path = os.path.join(self.plugins_directory, filename)
            with open(plugin_path, 'w') as f:
                f.write(content)
        
        self.logger.info(f"[+] Created {len(plugins)} example plugins")
    
    def load_plugins(self):
        """Load all plugins from the plugins directory."""
        if not os.path.exists(self.plugins_directory):
            return
        
        loaded_count = 0
        
        for filename in os.listdir(self.plugins_directory):
            if filename.endswith('.py') and not filename.startswith('__'):
                plugin_path = os.path.join(self.plugins_directory, filename)
                
                try:
                    # Load module
                    spec = importlib.util.spec_from_file_location(filename[:-3], plugin_path)
                    if spec is None or spec.loader is None:
                        continue
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Find plugin classes
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, BasePlugin) and 
                            obj != BasePlugin):
                            
                            plugin_instance = obj()
                            self.plugins[plugin_instance.name] = plugin_instance
                            self.loaded_plugins.append(plugin_instance)
                            loaded_count += 1
                            
                            self.logger.info(f"[+] Loaded plugin: {plugin_instance.name}")
                
                except Exception as e:
                    self.logger.error(f"[-] Error loading plugin {filename}: {e}")
        
        self.logger.info(f"[+] Loaded {loaded_count} plugins total")
    
    def scan_with_plugins(self, file_content, file_path, file_info=None):
        """
        Scan file content with all loaded plugins.
        
        Args:
            file_content (bytes): File content to scan
            file_path (str): Path to the file
            file_info (dict): Additional file information
        
        Returns:
            list: Combined findings from all plugins
        """
        all_findings = []
        
        for plugin in self.loaded_plugins:
            try:
                findings = plugin.scan(file_content, file_path, file_info)
                if findings:
                    all_findings.extend(findings)
                    self.logger.debug(f"[+] Plugin {plugin.name} found {len(findings)} items")
            
            except Exception as e:
                self.logger.error(f"[-] Error in plugin {plugin.name}: {e}")
        
        return all_findings
    
    def get_plugin_info(self):
        """Get information about all loaded plugins."""
        return [plugin.get_info() for plugin in self.loaded_plugins]
    
    def get_plugin_by_name(self, name):
        """Get plugin instance by name."""
        return self.plugins.get(name)
    
    def reload_plugins(self):
        """Reload all plugins."""
        self.plugins.clear()
        self.loaded_plugins.clear()
        self.load_plugins()


# Global plugin manager instance
plugin_manager = None

def get_plugin_manager():
    """Get global plugin manager instance."""
    global plugin_manager
    if plugin_manager is None:
        plugin_manager = PluginManager()
    return plugin_manager