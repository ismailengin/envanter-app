import os
from dotenv import load_dotenv

load_dotenv()

# LDAP Configuration
LDAP_ENABLED = os.environ.get('LDAP_ENABLED', 'false').lower() == 'true'
LDAP_SERVER = os.environ.get('LDAP_SERVER', 'ldap://localhost:389')
LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN', 'dc=example,dc=com')
LDAP_BIND_DN = os.environ.get('LDAP_BIND_DN', None)
LDAP_BIND_PASSWORD = os.environ.get('LDAP_BIND_PASSWORD', None)
LDAP_USER_SEARCH_BASE = os.environ.get('LDAP_USER_SEARCH_BASE', LDAP_BASE_DN)
LDAP_USER_SEARCH_FILTER = os.environ.get('LDAP_USER_SEARCH_FILTER', '(uid={})') # For OpenLDAP
LDAP_USER_SEARCH_ATTRIBUTE = os.environ.get('LDAP_USER_SEARCH_ATTRIBUTE', 'uid') # The attribute to match username against in LDAP
LDAP_TLS_CACERTFILE = os.environ.get('LDAP_TLS_CACERTFILE', None) # Path to CA cert file for TLS
LDAP_TLS_REQCERT = os.environ.get('LDAP_TLS_REQCERT', 'demand') # "never", "allow", "try", "demand"

# SharePoint Configuration
SHAREPOINT_SITE_URL = os.environ.get('SHAREPOINT_SITE_URL')
SHAREPOINT_USERNAME = os.environ.get('SHAREPOINT_USERNAME')
SHAREPOINT_PASSWORD = os.environ.get('SHAREPOINT_PASSWORD')
SHAREPOINT_DOMAIN = os.environ.get('SHAREPOINT_DOMAIN')
SHAREPOINT_ROOT_FOLDER = os.environ.get('SHAREPOINT_ROOT_FOLDER', '/Shared Documents')

# MSSQL database credentials
db_config = {
    'server': os.environ.get('DB_SERVER', 'localhost'),
    'user': os.environ.get('DB_USER', 'SA'),
    'password': os.environ.get('DB_PASSWORD', 'Passw0rd'),
    'database': os.environ.get('DB_DATABASE', 'TestDB'),
}

# Local users
users = {
    'user1': 'password1',
    'user2': 'password2',
    'user3': 'password3',
    'infrafw': 'infrafw',
    'admin': 'admin'
}

# User roles and their allowed endpoints
user_roles = {
    'infrafw': ['/fw'],  # infrafw user can only access /fw
    'admin': ['/', '/chart', '/fw'],  # admin has access to all endpoints
    'default': ['/', '/chart', '/fw']  # other users can access all endpoints
}

entries_per_page = 10
