"""
YARA Rules Engine for Advanced Pattern Detection
Provides YARA rule compilation and file scanning capabilities.
"""

import os
from utils.logger import get_logger

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    yara = None


class YARAEngine:
    """YARA rules engine for advanced pattern detection."""
    
    def __init__(self, rules_directory="yara_rules"):
        """
        Initialize YARA engine.
        
        Args:
            rules_directory (str): Directory containing YARA rule files
        """
        self.rules_directory = rules_directory
        self.logger = get_logger()
        self.compiled_rules = None
        self.rule_files = []
        
        if not YARA_AVAILABLE:
            self.logger.warning("YARA not available - YARA scanning disabled")
            return
        
        # Create rules directory if it doesn't exist
        if not os.path.exists(self.rules_directory):
            os.makedirs(self.rules_directory)
            self._create_default_rules()
        
        self.load_rules()
    
    def _create_default_rules(self):
        """Create default YARA rules for common secrets."""
        
        # AWS credentials rule
        aws_rule = '''
rule AWS_Credentials {
    meta:
        description = "Detects AWS access keys and secrets"
        author = "CRED-SHADOW"
        severity = "high"
    
    strings:
        $aws_access_key = /AKIA[0-9A-Z]{16}/ nocase
        $aws_secret_key = /[0-9a-zA-Z\\/+]{40}/ nocase
        $aws_session_token = /[A-Za-z0-9+\\\/]{100,}/ nocase
        $aws_pattern1 = "aws_access_key_id" nocase
        $aws_pattern2 = "aws_secret_access_key" nocase
        $aws_pattern3 = "aws_session_token" nocase
    
    condition:
        any of ($aws_access_key, $aws_secret_key) or
        (any of ($aws_pattern*) and any of ($aws_access_key, $aws_secret_key))
}
'''
        
        # Azure credentials rule
        azure_rule = '''
rule Azure_Credentials {
    meta:
        description = "Detects Azure service principals and keys"
        author = "CRED-SHADOW"
        severity = "high"
    
    strings:
        $azure_client_id = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/ nocase
        $azure_client_secret = /[0-9A-Za-z~._-]{34,44}/ nocase
        $azure_pattern1 = "client_id" nocase
        $azure_pattern2 = "client_secret" nocase
        $azure_pattern3 = "tenant_id" nocase
        $azure_pattern4 = "subscription_id" nocase
    
    condition:
        ($azure_client_id and any of ($azure_pattern*)) or
        ($azure_client_secret and any of ($azure_pattern*))
}
'''
        
        # SSH keys rule
        ssh_rule = '''
rule SSH_Private_Keys {
    meta:
        description = "Detects SSH private keys"
        author = "CRED-SHADOW"
        severity = "high"
    
    strings:
        $ssh_rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $ssh_dsa = "-----BEGIN DSA PRIVATE KEY-----"
        $ssh_ec = "-----BEGIN EC PRIVATE KEY-----"
        $ssh_openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $ssh_ed25519 = "-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----"
    
    condition:
        any of them
}
'''
        
        # Database credentials rule
        db_rule = '''
rule Database_Credentials {
    meta:
        description = "Detects database connection strings and credentials"
        author = "CRED-SHADOW"
        severity = "medium"
    
    strings:
        $mysql_conn = /mysql:\\/\\/[^\\/\\s]+:[^@\\s]+@/ nocase
        $postgres_conn = /postgres:\\/\\/[^\\/\\s]+:[^@\\s]+@/ nocase
        $mongodb_conn = /mongodb:\\/\\/[^\\/\\s]+:[^@\\s]+@/ nocase
        $sql_server = /Server\s*=.*Password\s*=/ nocase
        $oracle_conn = /jdbc:oracle:thin:.*\/.*@/ nocase
        
        $db_password = "password" nocase
        $db_user = "username" nocase
        $db_host = "hostname" nocase
    
    condition:
        any of ($mysql_conn, $postgres_conn, $mongodb_conn, $sql_server, $oracle_conn) or
        (#db_password > 2 and #db_user > 2)
}
'''
        
        # API keys rule
        api_rule = '''
rule API_Keys {
    meta:
        description = "Detects various API keys and tokens"
        author = "CRED-SHADOW"
        severity = "medium"
    
    strings:
        $github_token = /ghp_[A-Za-z0-9]{36}/ nocase
        $slack_token = /xox[baprs]-[A-Za-z0-9-]/ nocase
        $discord_token = /[MN][A-Za-z\\d]{23}\\.[\\w-]{6}\\.[\\w-]{27}/ nocase
        $stripe_key = /sk_live_[0-9a-zA-Z]{24}/ nocase
        $mailgun_key = /key-[0-9a-zA-Z]{32}/ nocase
        
        $api_key_pattern = "api_key" nocase
        $access_token = "access_token" nocase
        $bearer_token = "bearer" nocase
    
    condition:
        any of ($github_token, $slack_token, $discord_token, $stripe_key, $mailgun_key) or
        (any of ($api_key_pattern, $access_token, $bearer_token) and filesize < 10KB)
}
'''
        
        # Write default rules
        rules = [
            ("aws_credentials.yar", aws_rule),
            ("azure_credentials.yar", azure_rule),
            ("ssh_keys.yar", ssh_rule),
            ("database_credentials.yar", db_rule),
            ("api_keys.yar", api_rule)
        ]
        
        for filename, rule_content in rules:
            rule_path = os.path.join(self.rules_directory, filename)
            with open(rule_path, 'w') as f:
                f.write(rule_content)
        
        self.logger.info(f"[+] Created {len(rules)} default YARA rules in {self.rules_directory}")
    
    def load_rules(self):
        """Load and compile YARA rules from directory."""
        if not YARA_AVAILABLE:
            self.logger.warning("[-] YARA not available - skipping rule compilation")
            return False
            
        try:
            # Find all .yar and .yara files
            rule_files = []
            if os.path.exists(self.rules_directory):
                for filename in os.listdir(self.rules_directory):
                    if filename.endswith(('.yar', '.yara')):
                        rule_files.append(os.path.join(self.rules_directory, filename))
            
            if not rule_files:
                self.logger.warning("[-] No YARA rule files found")
                return False
            
            # Compile rules
            rules_dict = {}
            for rule_file in rule_files:
                rule_name = os.path.basename(rule_file).replace('.yar', '').replace('.yara', '')
                rules_dict[rule_name] = rule_file
            
            if YARA_AVAILABLE:
                self.compiled_rules = yara.compile(filepaths=rules_dict)
            else:
                return False
            self.rule_files = rule_files
            
            self.logger.info(f"[+] Loaded {len(rule_files)} YARA rule files")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Error compiling YARA rules: {e}")
            return False
    
    def scan_data(self, data, filename="<memory>"):
        """
        Scan data with compiled YARA rules.
        
        Args:
            data (bytes): Data to scan
            filename (str): Filename for context
        
        Returns:
            list: List of YARA matches
        """
        if not self.compiled_rules:
            return []
        
        try:
            matches = self.compiled_rules.match(data=data)
            
            results = []
            for match in matches:
                result = {
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [],
                    'file': filename
                }
                
                # Extract string matches with context
                for string in match.strings:
                    string_match = {
                        'identifier': string.identifier,
                        'instances': []
                    }
                    
                    for instance in string.instances:
                        # Get context around the match
                        start = max(0, instance.offset - 50)
                        end = min(len(data), instance.offset + instance.length + 50)
                        context = data[start:end].decode('utf-8', errors='ignore')
                        
                        string_match['instances'].append({
                            'offset': instance.offset,
                            'length': instance.length,
                            'matched_data': instance.matched_data.decode('utf-8', errors='ignore'),
                            'context': context
                        })
                    
                    result['strings'].append(string_match)
                
                results.append(result)
            
            return results
            
        except Exception as e:
            self.logger.error(f"[-] Error scanning data with YARA: {e}")
            return []
    
    def scan_file(self, file_path):
        """
        Scan file with compiled YARA rules.
        
        Args:
            file_path (str): Path to file to scan
        
        Returns:
            list: List of YARA matches
        """
        if not self.compiled_rules:
            return []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            return self.scan_data(data, file_path)
            
        except Exception as e:
            self.logger.error(f"[-] Error scanning file {file_path}: {e}")
            return []
    
    def add_custom_rule(self, rule_name, rule_content):
        """
        Add a custom YARA rule.
        
        Args:
            rule_name (str): Name for the rule file
            rule_content (str): YARA rule content
        
        Returns:
            bool: True if successful
        """
        if not YARA_AVAILABLE:
            self.logger.warning("[-] YARA not available - cannot add custom rules")
            return False
            
        try:
            # Validate rule syntax by compiling
            if YARA_AVAILABLE:
                yara.compile(source=rule_content)
            else:
                return False
            
            # Write rule to file
            rule_file = os.path.join(self.rules_directory, f"{rule_name}.yar")
            with open(rule_file, 'w') as f:
                f.write(rule_content)
            
            # Reload all rules
            self.load_rules()
            
            self.logger.info(f"[+] Added custom YARA rule: {rule_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"[-] Error adding custom rule: {e}")
            return False
        except Exception as e:
            self.logger.error(f"[-] Error adding custom rule: {e}")
            return False
    
    def get_rule_info(self):
        """
        Get information about loaded rules.
        
        Returns:
            dict: Rule information
        """
        if not self.compiled_rules:
            return {'total_rules': 0, 'rule_files': []}
        
        return {
            'total_rules': len(self.rule_files),
            'rule_files': self.rule_files,
            'rules_directory': self.rules_directory
        }


def scan_with_yara(data, filename="<memory>", rules_directory="yara_rules"):
    """
    Convenience function to scan data with YARA rules.
    
    Args:
        data (bytes): Data to scan
        filename (str): Filename for context
        rules_directory (str): Directory containing YARA rules
    
    Returns:
        list: List of YARA matches
    """
    engine = YARAEngine(rules_directory)
    return engine.scan_data(data, filename)