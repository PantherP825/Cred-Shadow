"""
Cache Manager for CRED-SHADOW
Handles proper cleanup and cross-platform compatibility to prevent stale data.
"""

import os
import sys
import tempfile
import shutil
import threading
from pathlib import Path


class CacheManager:
    """Manages temporary data and prevents cross-session contamination."""
    
    def __init__(self):
        self._temp_dir = None
        self._session_id = None
        self._lock = threading.Lock()
        self._initialized = False
    
    def initialize_session(self, target=None):
        """Initialize a fresh session, clearing any previous data."""
        with self._lock:
            # Clean up any existing session
            self.cleanup_session()
            
            # Create new session
            import time
            import hashlib
            
            session_data = f"{target or 'unknown'}_{time.time()}_{os.getpid()}"
            self._session_id = hashlib.md5(session_data.encode()).hexdigest()[:8]
            
            # Create temporary directory for this session
            self._temp_dir = tempfile.mkdtemp(prefix=f"cred_shadow_{self._session_id}_")
            self._initialized = True
            
            return self._session_id
    
    def cleanup_session(self):
        """Clean up current session data."""
        with self._lock:
            if self._temp_dir and os.path.exists(self._temp_dir):
                try:
                    shutil.rmtree(self._temp_dir)
                except Exception:
                    pass  # Best effort cleanup
            
            self._temp_dir = None
            self._session_id = None
            self._initialized = False
    
    def get_temp_path(self, filename):
        """Get a temporary file path for this session."""
        if not self._initialized or self._temp_dir is None:
            self.initialize_session()
        
        return os.path.join(str(self._temp_dir), filename)
    
    def is_initialized(self):
        """Check if session is initialized."""
        return self._initialized
    
    def get_session_id(self):
        """Get current session ID."""
        return self._session_id


# Global cache manager instance
_cache_manager = CacheManager()


def get_cache_manager():
    """Get the global cache manager instance."""
    return _cache_manager


def initialize_fresh_session(target=None):
    """Initialize a fresh session for the given target."""
    return _cache_manager.initialize_session(target)


def cleanup_session():
    """Clean up the current session."""
    _cache_manager.cleanup_session()


def get_session_temp_path(filename):
    """Get a temporary file path for the current session."""
    return _cache_manager.get_temp_path(filename)


# Cleanup on exit
import atexit
atexit.register(cleanup_session)