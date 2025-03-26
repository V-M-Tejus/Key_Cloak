import logging
import requests
from django.conf import settings
from typing import Dict, Any
from django.conf import settings

KEYCLOAK_CONFIG = settings.KEYCLOAK_CONFIG


logger = logging.getLogger(__name__)

class KeycloakService:
    def __init__(self):
        self.server_url = KEYCLOAK_CONFIG['SERVER_URL']
        self.realm = KEYCLOAK_CONFIG['REALM']
        self.client_id = KEYCLOAK_CONFIG['CLIENT_ID']
        self.client_secret = KEYCLOAK_CONFIG['CLIENT_SECRET']

    def get_admin_token(self) -> str:
        """
        Obtain admin access token for Keycloak operations
        """
        token_url = f"{self.server_url}/realms/master/protocol/openid-connect/token"
        payload = {
            'grant_type': 'password',
            'client_id': 'admin-cli',
            'username': KEYCLOAK_CONFIG['ADMIN_USERNAME'],
            'password': KEYCLOAK_CONFIG['ADMIN_PASSWORD']
        }
        
        try:
            response = requests.post(token_url, data=payload)
            response.raise_for_status()
            return response.json()['access_token']
        except requests.RequestException as e:
            logger.error(f"Failed to obtain admin token: {e}")
            raise

    def create_keycloak_user(self, user_data: Dict[str, Any]) -> bool:
        """
        Create a user in Keycloak
        """
        admin_token = self.get_admin_token()
        
        create_user_url = f"{self.server_url}/admin/realms/{self.realm}/users"
        
        keycloak_user_payload = {
            'username': user_data['username'],
            'email': user_data.get('email'),
            'firstName': user_data.get('first_name', ''),
            'lastName': user_data.get('last_name', ''),
            'enabled': True,
            'credentials': [{
                'type': 'password',
                'value': user_data['password'],
                'temporary': False
            }]
        }
        
        headers = {
            'Authorization': f'Bearer {admin_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            response = requests.post(create_user_url, json=keycloak_user_payload, headers=headers)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.error(f"Failed to create Keycloak user: {e}")
            return False

    def authenticate_user(self, username: str, password: str) -> Dict[str, str]:
        """
        Authenticate user and retrieve tokens
        """
        token_url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/token"
        
        payload = {
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': username,
            'password': password
        }
        
        try:
            response = requests.post(token_url, data=payload)
            response.raise_for_status()
            token_data = response.json()
            return {
                'access_token': token_data['access_token'],
                'refresh_token': token_data['refresh_token'],
                'expires_in': token_data['expires_in']
            }
        except requests.RequestException as e:
            logger.error(f"Authentication failed: {e}")
            return {}

    def logout(self, refresh_token: str) -> bool:
        """
        Logout and invalidate tokens
        """
        logout_url = f"{self.server_url}/realms/{self.realm}/protocol/openid-connect/logout"
        
        payload = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'refresh_token': refresh_token
        }
        
        try:
            response = requests.post(logout_url, data=payload)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            logger.error(f"Logout failed: {e}")
            return False