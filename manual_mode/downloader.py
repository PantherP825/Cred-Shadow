"""
File Download Module
Handles file download functionality for manual mode.
"""

import os
import time
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from scanner.share_enum import download_file, get_file_info
from utils.logger import get_logger

console = Console()


def download_file_interactive(target, share, file_path, username, password, ntlm_hash, port=445, local_path=None):
    """
    Download a file with interactive progress display.
    
    Args:
        target (str): Target IP or hostname
        share (str): Share name
        file_path (str): File path on the share
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        port (int): SMB port
        local_path (str): Local path to save file (optional)
    
    Returns:
        bool: True if download successful
    """
    logger = get_logger()
    
    try:
        # Get file info first
        file_info = get_file_info(target, share, file_path, username, password, ntlm_hash, port)
        
        if not file_info:
            console.print("[red]Could not get file information.[/red]")
            return False
        
        if file_info['is_directory']:
            console.print("[red]Cannot download directories. Use 'ls' to see contents.[/red]")
            return False
        
        # Determine local filename
        if local_path:
            local_file_path = Path(local_path)
        else:
            # Create downloads directory
            downloads_dir = Path("downloads")
            downloads_dir.mkdir(exist_ok=True)
            
            # Generate safe filename
            safe_filename = file_path.replace('/', '_').replace('\\', '_')
            local_file_path = downloads_dir / safe_filename
        
        # Ensure parent directory exists
        local_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_size = file_info['size']
        
        # Show file info
        console.print(f"[blue]Downloading: {file_path}[/blue]")
        console.print(f"[blue]Size: {_format_size(file_size)}[/blue]")
        console.print(f"[blue]Local path: {local_file_path}[/blue]")
        
        # Download with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            
            task = progress.add_task("Downloading...", total=file_size)
            
            # Download file content
            content = download_file(target, share, file_path, username, password, ntlm_hash, port)
            
            if content:
                # Write to local file
                with open(local_file_path, 'wb') as f:
                    f.write(content)
                
                progress.update(task, completed=file_size)
                
                console.print(f"[green]✓ Download completed: {local_file_path}[/green]")
                logger.info(f"Downloaded file: {file_path} -> {local_file_path}")
                return True
            else:
                console.print("[red]Failed to download file content.[/red]")
                return False
    
    except Exception as e:
        console.print(f"[red]Download error: {str(e)}[/red]")
        logger.error(f"Download error for {file_path}: {str(e)}")
        return False


def view_file_content(target, share, file_path, username, password, ntlm_hash, port=445, max_size=1024*1024):
    """
    View file content (for cat command).
    
    Args:
        target (str): Target IP or hostname
        share (str): Share name
        file_path (str): File path on the share
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        port (int): SMB port
        max_size (int): Maximum file size to view (default: 1MB)
    
    Returns:
        bytes: File content or None if failed
    """
    from impacket.smbconnection import SMBConnection
    import tempfile
    import os
    
    logger = get_logger()
    smb_conn = None
    
    try:
        # Create SMB connection
        smb_conn = SMBConnection(target, target, None, port, timeout=30)
        
        # Authenticate
        if ntlm_hash:
            if isinstance(ntlm_hash, str) and ':' in ntlm_hash:
                lm_hash, nt_hash = ntlm_hash.split(':', 1)
            else:
                lm_hash, nt_hash = ntlm_hash
            smb_conn.login(username, password, '', lm_hash, nt_hash)
        elif not username and not password:
            try:
                smb_conn.login('', '')
            except:
                smb_conn.close()
                smb_conn = SMBConnection(target, target, None, port, timeout=30)
                smb_conn.login('guest', '')
        else:
            smb_conn.login(username or '', password or '')
        
        # Normalize file path
        if file_path.startswith('/'):
            file_path = file_path[1:]
        
        # Try multiple path formats for file reading
        path_attempts = [
            file_path,
            file_path.replace('/', '\\'),
            file_path.replace('\\', '/'),
            '\\' + file_path if not file_path.startswith('\\') else file_path[1:],
            file_path.lstrip('\\').lstrip('/')
        ]
        
        for attempt_path in path_attempts:
            try:
                logger.debug(f"Attempting to read file with path: {attempt_path}")
                with tempfile.NamedTemporaryFile() as temp_file:
                    smb_conn.retrieveFile(share, attempt_path, temp_file)
                    temp_file.seek(0)
                    content = temp_file.read()
                    
                    if content:
                        # Limit content size for viewing
                        if len(content) > max_size:
                            logger.debug(f"File too large ({len(content)} bytes), truncating to {max_size}")
                            content = content[:max_size]
                        
                        logger.debug(f"Successfully read {len(content)} bytes from {attempt_path}")
                        return content
                    
            except Exception as read_error:
                logger.debug(f"Path {attempt_path} failed: {str(read_error)}")
                continue
        
        logger.debug(f"All path attempts failed for file: {file_path}")
        return None
    
    except Exception as e:
        logger.debug(f"Error viewing file content: {str(e)}")
        return None
    finally:
        if smb_conn:
            try:
                smb_conn.close()
            except:
                pass


def download_directory(target, share, dir_path, username, password, ntlm_hash, port=445, local_base_path=None, max_depth=3):
    """
    Download entire directory recursively.
    
    Args:
        target (str): Target IP or hostname
        share (str): Share name
        dir_path (str): Directory path on the share
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        port (int): SMB port
        local_base_path (str): Local base path for downloads
        max_depth (int): Maximum recursion depth
    
    Returns:
        dict: Download statistics
    """
    logger = get_logger()
    
    from scanner.share_enum import list_directory
    
    stats = {
        'files_downloaded': 0,
        'files_failed': 0,
        'bytes_downloaded': 0,
        'directories_created': 0
    }
    
    if local_base_path is None:
        local_base_path = Path("downloads") / f"{target}_{share}"
    else:
        local_base_path = Path(local_base_path)
    
    def download_recursive(current_path, current_depth):
        if current_depth > max_depth:
            return
        
        try:
            files = list_directory(target, share, current_path, username, password, ntlm_hash, port, logger)
            
            for file_entry in files:
                filename = file_entry.get_longname()
                if filename in ['.', '..']:
                    continue
                
                file_path = f"{current_path}/{filename}" if current_path and current_path != "*" else filename
                
                if file_entry.is_directory():
                    # Create local directory
                    local_dir = local_base_path / file_path
                    local_dir.mkdir(parents=True, exist_ok=True)
                    stats['directories_created'] += 1
                    
                    console.print(f"[blue]Created directory: {local_dir}[/blue]")
                    
                    # Recurse into subdirectory
                    download_recursive(file_path, current_depth + 1)
                else:
                    # Download file
                    local_file_path = local_base_path / file_path
                    local_file_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    try:
                        content = download_file(target, share, file_path, username, password, ntlm_hash, port)
                        
                        if content:
                            with open(local_file_path, 'wb') as f:
                                f.write(content)
                            
                            stats['files_downloaded'] += 1
                            stats['bytes_downloaded'] += len(content)
                            
                            console.print(f"[green]Downloaded: {file_path}[/green]")
                        else:
                            stats['files_failed'] += 1
                            console.print(f"[red]Failed: {file_path}[/red]")
                    
                    except Exception as e:
                        stats['files_failed'] += 1
                        console.print(f"[red]Error downloading {file_path}: {str(e)}[/red]")
        
        except Exception as e:
            console.print(f"[red]Error listing directory {current_path}: {str(e)}[/red]")
    
    try:
        console.print(f"[blue]Starting directory download: {dir_path}[/blue]")
        console.print(f"[blue]Local path: {local_base_path}[/blue]")
        
        # Create base directory
        local_base_path.mkdir(parents=True, exist_ok=True)
        
        # Start recursive download
        download_recursive(dir_path, 0)
        
        # Print statistics
        console.print(f"\n[green]Download completed![/green]")
        console.print(f"[green]Files downloaded: {stats['files_downloaded']}[/green]")
        console.print(f"[green]Files failed: {stats['files_failed']}[/green]")
        console.print(f"[green]Bytes downloaded: {_format_size(stats['bytes_downloaded'])}[/green]")
        console.print(f"[green]Directories created: {stats['directories_created']}[/green]")
        
        return stats
    
    except Exception as e:
        console.print(f"[red]Directory download error: {str(e)}[/red]")
        logger.error(f"Directory download error for {dir_path}: {str(e)}")
        return stats


def batch_download_files(target, share, file_list, username, password, ntlm_hash, port=445, local_base_path=None):
    """
    Download multiple files in batch.
    
    Args:
        target (str): Target IP or hostname
        share (str): Share name
        file_list (list): List of file paths to download
        username (str): Username for authentication
        password (str): Password for authentication
        ntlm_hash (tuple): NTLM hash tuple
        port (int): SMB port
        local_base_path (str): Local base path for downloads
    
    Returns:
        dict: Download statistics
    """
    logger = get_logger()
    
    stats = {
        'files_downloaded': 0,
        'files_failed': 0,
        'bytes_downloaded': 0
    }
    
    if local_base_path is None:
        local_base_path = Path("downloads") / f"{target}_{share}_batch"
    else:
        local_base_path = Path(local_base_path)
    
    local_base_path.mkdir(parents=True, exist_ok=True)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        
        task = progress.add_task("Batch downloading...", total=len(file_list))
        
        for i, file_path in enumerate(file_list):
            try:
                progress.update(task, description=f"Downloading {os.path.basename(file_path)}")
                
                content = download_file(target, share, file_path, username, password, ntlm_hash, port)
                
                if content:
                    # Create safe local filename
                    safe_filename = file_path.replace('/', '_').replace('\\', '_')
                    local_file_path = local_base_path / safe_filename
                    
                    with open(local_file_path, 'wb') as f:
                        f.write(content)
                    
                    stats['files_downloaded'] += 1
                    stats['bytes_downloaded'] += len(content)
                else:
                    stats['files_failed'] += 1
                
                progress.update(task, completed=i + 1)
            
            except Exception as e:
                stats['files_failed'] += 1
                logger.error(f"Batch download error for {file_path}: {str(e)}")
                progress.update(task, completed=i + 1)
    
    console.print(f"\n[green]Batch download completed![/green]")
    console.print(f"[green]Files downloaded: {stats['files_downloaded']}[/green]")
    console.print(f"[green]Files failed: {stats['files_failed']}[/green]")
    console.print(f"[green]Bytes downloaded: {_format_size(stats['bytes_downloaded'])}[/green]")
    
    return stats


def _format_size(size):
    """Format file size in human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def save_file_locally(content, filename, directory="downloads"):
    """
    Save file content to local filesystem.
    
    Args:
        content (bytes): File content
        filename (str): Local filename
        directory (str): Local directory
    
    Returns:
        str: Local file path or None if failed
    """
    try:
        local_dir = Path(directory)
        local_dir.mkdir(exist_ok=True)
        
        local_file_path = local_dir / filename
        
        with open(local_file_path, 'wb') as f:
            f.write(content)
        
        return str(local_file_path)
    
    except Exception as e:
        console.print(f"[red]Error saving file locally: {str(e)}[/red]")
        return None


def preview_file_content(content, max_lines=50):
    """
    Preview file content with syntax highlighting if possible.
    
    Args:
        content (bytes): File content
        max_lines (int): Maximum lines to show
    
    Returns:
        str: Formatted content preview
    """
    try:
        # Try to decode as text
        text_content = content.decode('utf-8', errors='ignore')
        lines = text_content.split('\n')
        
        if len(lines) > max_lines:
            preview_lines = lines[:max_lines]
            preview_text = '\n'.join(preview_lines)
            preview_text += f"\n\n... ({len(lines) - max_lines} more lines)"
        else:
            preview_text = text_content
        
        return preview_text
    
    except Exception:
        return "[Binary file - cannot preview]"
