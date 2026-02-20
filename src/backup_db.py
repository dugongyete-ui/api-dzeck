#!/usr/bin/env python3
"""
Database Auto-Backup Script

This script manages SQLite database backups with the following features:
- Create timestamped backups
- Restore from backups
- List available backups
- Automatically maintain a maximum of 10 backups

Usage:
    python backup_db.py --backup                    # Create a new backup
    python backup_db.py --restore FILENAME          # Restore from backup
    python backup_db.py --list                      # List all backups
    python backup_db.py --db-path /path/to/db.db    # Use custom database path
"""

import os
import sys
import shutil
import argparse
from datetime import datetime
from glob import glob
from pathlib import Path


class DatabaseBackup:
    """Manages SQLite database backups."""
    
    MAX_BACKUPS = 10
    BACKUP_PREFIX = "settings_backup_"
    BACKUP_EXTENSION = ".db"
    
    def __init__(self, db_path=None):
        """
        Initialize the backup manager.
        
        Args:
            db_path (str, optional): Path to the database file. Defaults to 'data/settings.db'
                                     relative to the script's directory.
        """
        if db_path:
            self.db_path = Path(db_path).resolve()
        else:
            # Get the directory where this script is located (src/)
            script_dir = Path(__file__).parent
            self.db_path = script_dir / "data" / "settings.db"
        
        # Backup directory is next to the database file
        self.backup_dir = self.db_path.parent / "backups"
    
    def create_backup(self):
        """
        Create a timestamped backup of the database.
        
        Returns:
            bool: True if backup was successful, False otherwise.
        """
        # Validate that the database file exists
        if not self.db_path.exists():
            print(f"❌ Error: Database file not found at {self.db_path}", file=sys.stderr)
            return False
        
        # Create backup directory if it doesn't exist
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as e:
            print(f"❌ Error: Failed to create backup directory: {e}", file=sys.stderr)
            return False
        
        # Generate timestamp for backup filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{self.BACKUP_PREFIX}{timestamp}{self.BACKUP_EXTENSION}"
        backup_path = self.backup_dir / backup_filename
        
        # Copy the database file to backup location
        try:
            shutil.copy2(self.db_path, backup_path)
            print(f"✅ Backup created successfully: {backup_path}")
        except (shutil.Error, OSError, PermissionError) as e:
            print(f"❌ Error: Failed to create backup: {e}", file=sys.stderr)
            return False
        
        # Cleanup old backups
        self._cleanup_old_backups()
        
        return True
    
    def restore_backup(self, filename):
        """
        Restore the database from a backup file.
        
        Args:
            filename (str): Name of the backup file (e.g., 'settings_backup_20260218_143022.db')
        
        Returns:
            bool: True if restore was successful, False otherwise.
        """
        backup_path = self.backup_dir / filename
        
        # Validate that the backup file exists
        if not backup_path.exists():
            print(f"❌ Error: Backup file not found: {backup_path}", file=sys.stderr)
            return False
        
        # Check if database file exists (for safety)
        if self.db_path.exists():
            # Create a safety backup of the current database
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safety_backup = self.backup_dir / f"settings_backup_PRE_RESTORE_{timestamp}{self.BACKUP_EXTENSION}"
            try:
                shutil.copy2(self.db_path, safety_backup)
                print(f"ℹ️  Safety backup created: {safety_backup}")
            except (shutil.Error, OSError, PermissionError) as e:
                print(f"⚠️  Warning: Could not create safety backup: {e}", file=sys.stderr)
        
        # Restore the backup
        try:
            shutil.copy2(backup_path, self.db_path)
            print(f"✅ Database restored successfully from: {backup_path}")
            return True
        except (shutil.Error, OSError, PermissionError) as e:
            print(f"❌ Error: Failed to restore backup: {e}", file=sys.stderr)
            return False
    
    def list_backups(self):
        """
        List all available backups.
        
        Returns:
            list: List of backup filenames, sorted by date (newest first).
        """
        if not self.backup_dir.exists():
            print(f"ℹ️  Backup directory does not exist: {self.backup_dir}")
            return []
        
        # Find all backup files matching the pattern
        pattern = str(self.backup_dir / f"{self.BACKUP_PREFIX}*{self.BACKUP_EXTENSION}")
        backups = sorted(glob(pattern), reverse=True)
        
        if not backups:
            print(f"ℹ️  No backups found in {self.backup_dir}")
            return []
        
        print(f"📋 Available backups ({len(backups)} total):\n")
        for i, backup_path in enumerate(backups, 1):
            backup_filename = Path(backup_path).name
            file_size = Path(backup_path).stat().st_size / (1024 * 1024)  # Convert to MB
            mod_time = datetime.fromtimestamp(Path(backup_path).stat().st_mtime)
            print(f"  {i}. {backup_filename}")
            print(f"     Size: {file_size:.2f} MB | Modified: {mod_time}")
        
        return backups
    
    def _cleanup_old_backups(self):
        """Remove backups older than MAX_BACKUPS limit."""
        if not self.backup_dir.exists():
            return
        
        # Find all backup files matching the pattern (exclude safety backups)
        pattern = str(self.backup_dir / f"{self.BACKUP_PREFIX}????????_??????{self.BACKUP_EXTENSION}")
        backups = sorted(glob(pattern), reverse=True)
        
        # Remove backups exceeding the limit
        if len(backups) > self.MAX_BACKUPS:
            for old_backup in backups[self.MAX_BACKUPS:]:
                try:
                    os.remove(old_backup)
                    print(f"🗑️  Removed old backup: {Path(old_backup).name}")
                except (OSError, PermissionError) as e:
                    print(f"⚠️  Warning: Could not remove old backup {Path(old_backup).name}: {e}", file=sys.stderr)


def main():
    """Parse command-line arguments and execute requested action."""
    parser = argparse.ArgumentParser(
        description="Manage SQLite database backups",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python backup_db.py --backup                    # Create a new backup
  python backup_db.py --restore settings_backup_20260218_143022.db  # Restore from backup
  python backup_db.py --list                      # List all backups
  python backup_db.py --db-path /custom/path.db --backup  # Use custom database path
        """
    )
    
    parser.add_argument(
        "--db-path",
        type=str,
        default=None,
        help="Path to the SQLite database file (default: src/data/settings.db)"
    )
    
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Create a new backup of the database"
    )
    
    parser.add_argument(
        "--restore",
        type=str,
        metavar="FILENAME",
        help="Restore the database from a specific backup file"
    )
    
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available backups"
    )
    
    args = parser.parse_args()
    
    # Initialize the backup manager
    backup = DatabaseBackup(args.db_path)
    
    # Execute the requested action
    if args.backup:
        success = backup.create_backup()
        sys.exit(0 if success else 1)
    
    elif args.restore:
        success = backup.restore_backup(args.restore)
        sys.exit(0 if success else 1)
    
    elif args.list:
        backup.list_backups()
        sys.exit(0)
    
    else:
        # If no action is specified, show help and exit
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
