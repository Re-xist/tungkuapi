"""
TungkuApi - Credential Manager
Persistent storage for authentication credentials

Author: Re-xist
GitHub: https://github.com/Re-xist
Version: 3.0
"""

import json
import base64
import getpass
from pathlib import Path
from typing import Dict, Optional, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import os


class CredentialManager:
    """Manage persistent credentials for API scanning"""

    def __init__(self, config_dir: str = None):
        """
        Initialize credential manager

        Args:
            config_dir: Directory for storing credentials (default: ~/.tungkuapi)
        """
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            self.config_dir = Path.home() / ".tungkuapi"

        self.config_dir.mkdir(exist_ok=True)
        self.credentials_file = self.config_dir / "credentials.json"
        self.key_file = self.config_dir / ".key"

        # Initialize encryption
        self._init_encryption()

    def _init_encryption(self):
        """Initialize encryption key"""
        if self.key_file.exists():
            # Load existing key
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)

            # Set restrictive permissions
            os.chmod(self.key_file, 0o600)

        self.cipher = Fernet(key)

    def _encrypt(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not data:
            return ""
        encrypted = self.cipher.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()

    def _decrypt(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not encrypted_data:
            return ""
        try:
            encrypted = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(encrypted)
            return decrypted.decode()
        except Exception:
            return ""

    def save_profile(self, name: str, credentials: Dict) -> bool:
        """
        Save a credential profile

        Args:
            name: Profile name (e.g., "production", "staging")
            credentials: Dictionary with credentials:
                - username: Username
                - password: Password (will be encrypted)
                - jwt_token: JWT bearer token (will be encrypted)
                - api_key: API key (will be encrypted)
                - headers: Custom headers dict
                - description: Profile description

        Returns:
            True if saved successfully
        """
        try:
            # Load existing credentials
            all_credentials = self._load_credentials()

            # Encrypt sensitive fields
            encrypted_creds = {}
            for key, value in credentials.items():
                if key in ['password', 'jwt_token', 'api_key', 'session_token']:
                    encrypted_creds[key] = self._encrypt(value)
                else:
                    encrypted_creds[key] = value

            all_credentials['profiles'][name] = encrypted_creds

            # Save to file
            with open(self.credentials_file, 'w') as f:
                json.dump(all_credentials, f, indent=2)

            # Set restrictive permissions
            os.chmod(self.credentials_file, 0o600)

            return True
        except Exception as e:
            print(f"[ERROR] Failed to save profile: {e}")
            return False

    def load_profile(self, name: str) -> Optional[Dict]:
        """
        Load a credential profile

        Args:
            name: Profile name

        Returns:
            Dictionary with decrypted credentials, or None if not found
        """
        try:
            all_credentials = self._load_credentials()

            if name not in all_credentials['profiles']:
                return None

            profile = all_credentials['profiles'][name]

            # Decrypt sensitive fields
            decrypted_creds = {}
            for key, value in profile.items():
                if key in ['password', 'jwt_token', 'api_key', 'session_token']:
                    decrypted_creds[key] = self._decrypt(value)
                else:
                    decrypted_creds[key] = value

            return decrypted_creds
        except Exception as e:
            print(f"[ERROR] Failed to load profile: {e}")
            return None

    def delete_profile(self, name: str) -> bool:
        """
        Delete a credential profile

        Args:
            name: Profile name

        Returns:
            True if deleted successfully
        """
        try:
            all_credentials = self._load_credentials()

            if name in all_credentials['profiles']:
                del all_credentials['profiles'][name]

                with open(self.credentials_file, 'w') as f:
                    json.dump(all_credentials, f, indent=2)

                return True
            return False
        except Exception as e:
            print(f"[ERROR] Failed to delete profile: {e}")
            return False

    def list_profiles(self) -> List[Dict]:
        """
        List all credential profiles

        Returns:
            List of profile info (name, description, username)
        """
        try:
            all_credentials = self._load_credentials()

            profiles = []
            for name, creds in all_credentials['profiles'].items():
                profiles.append({
                    'name': name,
                    'description': creds.get('description', ''),
                    'username': creds.get('username', ''),
                    'has_password': bool(creds.get('password')),
                    'has_jwt': bool(creds.get('jwt_token')),
                    'has_api_key': bool(creds.get('api_key'))
                })

            return profiles
        except Exception as e:
            print(f"[ERROR] Failed to list profiles: {e}")
            return []

    def _load_credentials(self) -> Dict:
        """Load credentials from file"""
        if not self.credentials_file.exists():
            return {'profiles': {}}

        try:
            with open(self.credentials_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {'profiles': {}}

    def get_headers_from_profile(self, name: str) -> Optional[Dict]:
        """
        Get HTTP headers from a credential profile

        Args:
            name: Profile name

        Returns:
            Dictionary of HTTP headers ready to use
        """
        profile = self.load_profile(name)

        if not profile:
            return None

        headers = profile.get('headers', {}).copy()

        # Add authentication headers
        if profile.get('jwt_token'):
            headers['Authorization'] = f"Bearer {profile['jwt_token']}"

        if profile.get('api_key'):
            # Common API key header names
            key_name = profile.get('api_key_header', 'X-API-Key')
            headers[key_name] = profile['api_key']

        if profile.get('session_token'):
            headers['Cookie'] = f"session={profile['session_token']}"

        return headers if headers else None

    def set_default_profile(self, name: str) -> bool:
        """
        Set default credential profile

        Args:
            name: Profile name to set as default

        Returns:
            True if set successfully
        """
        try:
            all_credentials = self._load_credentials()

            # Verify profile exists
            if name not in all_credentials['profiles']:
                return False

            all_credentials['default_profile'] = name

            with open(self.credentials_file, 'w') as f:
                json.dump(all_credentials, f, indent=2)

            return True
        except Exception as e:
            print(f"[ERROR] Failed to set default profile: {e}")
            return False

    def get_default_profile(self) -> Optional[str]:
        """
        Get default credential profile name

        Returns:
            Default profile name or None
        """
        try:
            all_credentials = self._load_credentials()
            return all_credentials.get('default_profile')
        except Exception:
            return None

    def update_profile(self, name: str, updates: Dict) -> bool:
        """
        Update specific fields in a profile

        Args:
            name: Profile name
            updates: Dictionary of fields to update

        Returns:
            True if updated successfully
        """
        try:
            profile = self.load_profile(name)

            if not profile:
                return False

            # Merge updates
            profile.update(updates)

            # Save updated profile
            return self.save_profile(name, profile)
        except Exception as e:
            print(f"[ERROR] Failed to update profile: {e}")
            return False
