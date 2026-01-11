from parse_fw import parse_fw_file
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import pyodbc
from datetime import timedelta
from pypika import Table, Query, Schema, functions as fn
import os
import requests
from requests_ntlm import HttpNtlmAuth
import json
import schedule
import time
from datetime import datetime, timezone
from dotenv import load_dotenv
import urllib3
import pytz
from flask_ldap3_login import LDAP3LoginManager, AuthenticationResponseStatus
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_ldap3_login.forms import LDAPLoginForm
import logging

# FastAPI and MongoDB imports for inventory API
from fastapi import FastAPI as FastAPIApp, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import UpdateOne, MongoClient
import re

load_dotenv()

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
log_level = os.environ.get('LOG_LEVEL', 'DEBUG').upper()
log_level_map = {
    'DEBUG': logging.DEBUG,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING,
    'ERROR': logging.ERROR,
    'CRITICAL': logging.CRITICAL
}

root_logger_level = log_level_map.get(log_level, logging.DEBUG)
logging.basicConfig(level=root_logger_level, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('flask_ldap3_login')
logger.setLevel(root_logger_level) # Set the level for flask_ldap3_login logger
logger.addHandler(logging.StreamHandler())

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# LDAP Configuration
app.config['LDAP_HOST'] = os.environ.get('LDAP_HOST', 'ldap.forumsys.com')
app.config['LDAP_PORT'] = int(os.environ.get('LDAP_PORT', 389))
app.config['LDAP_USE_SSL'] = os.environ.get('LDAP_USE_SSL', 'False') == 'True'
app.config['LDAP_BASE_DN'] = os.environ.get('LDAP_BASE_DN', 'dc=example,dc=com')
app.config['LDAP_USER_RDN_ATTR'] = os.environ.get('LDAP_USER_RDN_ATTR', 'uid')
app.config['LDAP_USER_LOGIN_ATTR'] = os.environ.get('LDAP_USER_LOGIN_ATTR', 'uid')
app.config['LDAP_BIND_USER_DN'] = os.environ.get('LDAP_BIND_USER_DN', 'cn=read-only-admin,dc=example,dc=com')
app.config['LDAP_BIND_USER_PASSWORD'] = os.environ.get('LDAP_BIND_USER_PASSWORD', 'password')
app.config['LDAP_GROUP_DN'] = os.environ.get('LDAP_GROUP_DN', '')
app.config['LDAP_USER_SEARCH_SCOPE'] = os.environ.get('LDAP_USER_SEARCH_SCOPE', 'LEVEL')
app.config['LDAP_GROUP_SEARCH_SCOPE'] = os.environ.get('LDAP_GROUP_SEARCH_SCOPE', 'LEVEL')
app.config['LDAP_GROUP_OBJECT_FILTER'] = os.environ.get('LDAP_GROUP_OBJECT_FILTER', '(objectclass=groupOfUniqueNames)')
app.config['LDAP_GROUP_MEMBERS_ATTR'] = os.environ.get('LDAP_GROUP_MEMBERS_ATTR', 'uniqueMember')
app.config["WTF_CSRF_ENABLED"] = False

# Enable Flask-LDAP3-Login debug logging
app.config['LDAP_BIND_VERBOSE'] = True

# Initialize LDAP Manager
ldap_manager = LDAP3LoginManager(app)
ldap_manager.init_app(app)

# Initialize Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User class
class User(UserMixin):
    def __init__(self, dn, username, data, role=None):
        self.dn = dn
        self.username = username
        self.data = data
        self.role = role

    def get_id(self):
        return self.dn

users = {}

# User loader
@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@ldap_manager.save_user
def save_user(dn, username, data, memberships):
    admin_group = os.environ.get('ADMIN_LDAP_GROUP')
    role = "infrafw"  # Default role
    for group in memberships:
        if "cn" in group and admin_group in group["cn"]:
            role = "admin"
            break
    user = User(dn, username, data, role)
    users[dn] = user
    # print(f"User {username} saved with role: {role} and memberships: {memberships}")
    return user

# Replace these with your MSSQL database credentials
db_config = {
    'server': os.environ.get('DB_SERVER', 'localhost'),
    'user': os.environ.get('DB_USER', 'SA'),
    'password': os.environ.get('DB_PASSWORD', 'Passw0rd'),
    'database': os.environ.get('DB_DATABASE', 'TestDB'),
}

users = {
    'user1': 'password1',
    'user2': 'password2',
    'user3': 'password3',
    'infrafw': 'infrafw',
    'admin': 'admin'
}

# Define user roles and their allowed endpoints
user_roles = {
    'infrafw': ['/fw'],  # infrafw user can only access /fw
    'admin': ['/', '/chart', '/fw', '/search'],  # admin has access to all endpoints
    'default': ['/', '/chart', '/fw', '/search']  # other users can access all endpoints
}


PARSED_FW_DATA_PATH = os.path.join('static', 'parsed_fw_data.json')


def process_and_cache_fw_data(file_path):
    """Parses the firewall file, generates groups, and caches them to a JSON file."""
    print(f"Processing and caching firewall data from {file_path}...")
    try:
        groups = parse_fw_file(file_path)
        groups_dict = {g['name']: g for g in groups}

        # Filter out groups that are children of other groups
        child_groups = {child for group in groups for child in group['children']}
        filtered_groups = [group for group in groups if group['name'] not in child_groups]

        cached_data = {
            'timestamp': datetime.now(pytz.timezone('Europe/Istanbul')).isoformat(),
            'groups': filtered_groups,
            'groups_dict': groups_dict
        }

        with open(PARSED_FW_DATA_PATH, 'w', encoding='utf-8') as f:
            json.dump(cached_data, f, indent=4)
        print(f"Successfully cached parsed firewall data to {PARSED_FW_DATA_PATH}")
        return True
    except Exception as e:
        print(f"Error processing and caching firewall data: {e}")
        return False


def is_valid_credentials(username, password):
    # Check if the provided username and password are valid
    # return users.get(username) == password # Old local auth check
    return users.get(username) == password


def get_user_allowed_endpoints():
    # Return allowed endpoints for the user based on their role
    allowed_endpoints = user_roles.get(current_user.role, user_roles['default'])
    return allowed_endpoints


# Number of entries per page
entries_per_page = 10


def get_db_connection():

    if (os.name == "nt"):
        driver = "SQL Server"

    else:
        driver = "ODBC Driver 18 for SQL Server"

    connection = pyodbc.connect(
        f'DRIVER={driver};'
        f'SERVER={db_config["server"]};'
        f'DATABASE={db_config["database"]};'
        f'UID={db_config["user"]};'
        f'PWD={db_config["password"]};'
        f'TrustServerCertificate=yes'
    )

    return connection


def get_all_columns(table_name):
    # Connect to the MSSQL database
    connection = get_db_connection()
    cursor = connection.cursor()

    info_schema = Schema('INFORMATION_SCHEMA')
    # Execute a query to get all column names for the specified table
    # query = f"SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '{table_name}'"
    query = Query.from_(info_schema.COLUMNS).select('COLUMN_NAME').where(info_schema.COLUMNS.TABLE_NAME == table_name)
    print(str(query))
    cursor.execute(str(query))

    # Fetch all column names
    columns = [row.COLUMN_NAME for row in cursor.fetchall()]

    # Close the connection
    connection.close()

    return columns


def update_os_version(hostname, os_version):
    connection = get_db_connection()

    cursor = connection.cursor()
    hostname = hostname.strip().split('.')[0]
    BackendEnvanterTable = Table('BackendEnvanter')

    q = Query.update(BackendEnvanterTable).set('OsVersion', os_version).where(BackendEnvanterTable.Makine == hostname)
    print(q)
    cursor.execute(str(q))
    connection.commit()
    print("Successfully added entry for ", hostname)


def insert_query(hostname, servicenames):

    connection = get_db_connection()

    cursor = connection.cursor()
    hostname = hostname.strip().split('.')[0]

    for app in servicenames.split(","):
        print(app)
        service_name, jvm_name, ortam, runtime = [
            element.strip() for element in app.split(":")]

        ServiceNameDetailsTable = Table('SERVICENAMEDETAILS')
        AppOrtamTable = Table('APPORTAMTABLE')
        OperationPathsTable = Table('OPERATIONSPATHS')
        BackendEnvanterTable = Table('BackendEnvanter')

        servicename_details_data = {
            'HostName': hostname,
            'ServiceName': service_name,
            'ServiceType': ortam,
            'InstanceName': 'STDJVMS',
            'J2EE': 0,
            'AppServer': 'Others' if runtime != "Standalone" else 'Standalone',
            'AppServerVersion': None,
            'AppProfile': None,
            'AppFileSystem': "/fbapp/hebele",
            'AppInstPath': None,
            'SuccessEmailGroups': None,
            'FailEmailGroups': None,
            'HealthCheckCount': None,
            'HealthCheckSleepTime': None,
            'Company': None,
            'MasterAddress': None,
            'ExtraLogPattern': None,
            'ExtraLogDirectory': None,
            'AppServerType': runtime
        }

        backendenvanter_data = {
            'ServisTipi':  ortam,
            'ServisAdı': service_name,
            'Makine': hostname,
            'ApplicationServerTipi': 'Liberty' if runtime == 'WLP' else runtime,
            'AppServerVersion': None,
            'ApplicationServerPath': '/WLP' if runtime == 'WLP' else None,
            'JavaTipi': None,
            'JavaPath': None,
            'UygulamaTipi': None,
            'ostip': None,
            'JavaVersion': None,
            'UygulamaKritiklik': None,
            'uygulamaversion': None,
            'uygulamaPath': None,
            'ownercompany': None,
            'AAMEnabled': None,
            'dependecyJarTarama': 1
        }

        select_servicenamedetails_query = Query.from_(ServiceNameDetailsTable).select(
            ServiceNameDetailsTable.HostName).where(
            (ServiceNameDetailsTable.HostName == hostname) & (ServiceNameDetailsTable.ServiceName == service_name) &
            (ServiceNameDetailsTable.ServiceType == ortam))

        cursor.execute(str(select_servicenamedetails_query))
        row = cursor.fetchone()

        if not row:
            print("hello world")
            # # Construct the insert query
            insert_query = Query.into(ServiceNameDetailsTable).columns(
                *servicename_details_data.keys()).insert(*servicename_details_data.values())

            # # Execute the insert query
            cursor.execute(str(insert_query))

        select_backendenvanter_query = Query.from_(BackendEnvanterTable).select(
            BackendEnvanterTable.Makine).where(
            (BackendEnvanterTable.ServisTipi == ortam) & (BackendEnvanterTable.ServisAdı == service_name) &
            (BackendEnvanterTable.Makine == hostname))

        cursor.execute(str(select_backendenvanter_query))
        envanter_row = cursor.fetchone()

        if not envanter_row:
            insert_query = Query.into(BackendEnvanterTable).columns(
                *backendenvanter_data.keys()).insert(*backendenvanter_data.values())

            # # Execute the insert query
            cursor.execute(str(insert_query))

        if runtime == 'WLP':
            process_search_name = "/WLP/wlp/bin/tools/ws-server.jar {}".format(
                jvm_name)
        elif runtime == 'Tomcat':
            process_search_name = '/Tomcat/{}/temp org.apache.catalina.startup.Bootstrap.start'.format(service_name)
        else:
            process_search_name = "SampleProcessName"

        # Commit the changes
        apportamtable_data = {
            'ServiceType': ortam,
            'ServiceName': service_name,
            'Hostname': hostname,
            'ApplicationType': service_name,
            'ApplicationName': "{}({})".format(jvm_name, hostname),
            'J2EE': 0,
            'LBServiceName': 'SampleLBName',
            'OperasyonDurumu': 0,
            'generaltype': 'STDJVMS',
            'WebContainerPort': '8080',
            'LBServiceGroup': None,
            'DeployStage': None,
            'HealthCheckRequest': None,
            'HealthCheckResponse': None,
            'HealthCheckProtocol': None,
            'ProcessSearchName': process_search_name.strip(),
            'step': None,
            'kesintiservisismi': None,
            'istirakadi': None
        }

        # Construct the insert query
        insert_query = Query.into(AppOrtamTable).columns(
            'ServiceType', 'ServiceName', 'Hostname', 'ApplicationType', 'ApplicationName', 'J2EE',
            'LBServiceName', 'OperasyonDurumu', 'generaltype', 'WebContainerPort', 'LBServiceGroup',
            'DeployStage', 'HealthCheckRequest', 'HealthCheckResponse', 'HealthCheckProtocol',
            'ProcessSearchName', 'step', 'kesintiservisismi', 'istirakadi'
        ).insert(*apportamtable_data.values())
        cursor.execute(str(insert_query))
        id = cursor.execute("SELECT @@Identity").fetchone()[0]
        print(id)

        # Sample data

        if runtime == 'WLP':
            op_query = Query.into(OperationPathsTable).columns(
                'Appid', 'Operation', 'OperationScript', 'ServerOperationScript').insert(
                (id, 'start', '/fbapp/scripts/bin/appctl {} start {}'.format(service_name + ortam, jvm_name),
                 '/WLP/wlp/bin/server start {}'.format(jvm_name)),
                (id, 'stop', '/fbapp/scripts/bin/appctl {} stop {}'.format(service_name + ortam, jvm_name),
                 '/WLP/wlp/bin/server stop {}'.format(jvm_name)),
                (id, 'status', '/fbapp/scripts/bin/appctl {} status {}'.format(service_name + ortam, jvm_name),
                 '/fbapp/scripts/bin/appctl {} status {}'.format(service_name + ortam, jvm_name)),
                (id, 'restart', '/fbapp/scripts/bin/appctl {} restart {}'.format(service_name + ortam, jvm_name),
                 '/fbapp/scripts/bin/appctl {} saferestart {}'.format(service_name + ortam, jvm_name)),
                (id, 'dump', '/fbapp/scripts/bin/appctl {} dump {}'.format(service_name + ortam, jvm_name),
                 '/WLP/WLP/bin/server javadump {} --include=thread'.format(jvm_name)),
                (id, 'threaddump', '/fbapp/scripts/bin/appctl {} threaddump {}'.format(
                     service_name + ortam, jvm_name),
                 '/WLP/WLP/bin/server javadump {} --include=thread'.format(jvm_name)),
                (id, 'heapdump', '/fbapp/scripts/bin/appctl {} heapdump {}'.format(service_name + ortam, jvm_name),
                 '/WLP/WLP/bin/server javadump {} --include=heap'.format(jvm_name)),
                (id, 'alldump', '/fbapp/scripts/bin/appctl {} alldump {}'.format(service_name + ortam, jvm_name),
                 '/WLP/WLP/bin/server javadump {} --include=thread,heap,system'.format(jvm_name)))

        elif runtime == 'Tomcat':
            op_query = Query.into(OperationPathsTable).columns(
                'Appid', 'Operation', 'OperationScript', 'ServerOperationScript').insert(
                (id, 'start', '/fbapp/scripts/bin/appctl {} start {}'.format(service_name + ortam, jvm_name),
                 '/Tomcat/{}/bin/startup.sh'.format(service_name)),
                (id, 'stop', '/fbapp/scripts/bin/appctl {} stop {}'.format(service_name + ortam, jvm_name),
                 '/Tomcat/{}/bin/shutdown.sh'.format(service_name)),
                (id, 'status', '/fbapp/scripts/bin/appctl {} status {}'.format(service_name + ortam, jvm_name),
                 '/fbapp/scripts/bin/appctl {} status {}'.format(service_name + ortam, jvm_name)),
                (id, 'restart', '/fbapp/scripts/bin/appctl {} restart {}'.format(service_name + ortam, jvm_name),
                 '/fbapp/scripts/bin/appctl {} saferestart {}'.format(service_name + ortam, jvm_name)))

        elif runtime == 'Standalone':
            op_query = Query.into(OperationPathsTable).columns(
                'Appid', 'Operation', 'OperationScript', 'ServerOperationScript').insert(
                (id, 'start', '/fbapp/scripts/bin/appctl {} start {}'.format(service_name + ortam, jvm_name),
                 '/fbapp/scripts/bin/appctl {} start {}'.format(service_name + ortam, jvm_name)),
                (id, 'stop', '/fbapp/scripts/bin/appctl {} stop {}'.format(service_name + ortam, jvm_name),
                 '/fbapp/scripts/bin/appctl {} stop {}'.format(service_name + ortam, jvm_name)),
                (id, 'status', '/fbapp/scripts/bin/appctl {} status {}'.format(service_name + ortam, jvm_name),
                 '/fbapp/scripts/bin/appctl {} status {}'.format(service_name + ortam, jvm_name)),
                (id, 'restart', '/fbapp/scripts/bin/appctl {} restart {}'.format(service_name + ortam, jvm_name),
                 '/fbapp/scripts/bin/appctl {} saferestart {}'.format(service_name + ortam, jvm_name)))

        cursor.execute(str(op_query))

    connection.commit()
    print("Data inserted successfully")


def get_data(table_name):

    connection = get_db_connection()
    cursor = connection.cursor()
    table = Query.Table(table_name)

    # Calculate the offset based on the current page
    # offset = (page - 1) * entries_per_page

    # Execute a query to get the total number of rows
    # count_query = 'SELECT COUNT(*) FROM AppOrtamTable'
    # cursor.execute(count_query)
    # total_rows = cursor.fetchone()[0]

    # Execute a query to get data from your table (replace 'your_table' with your actual table name)
    # query = f'SELECT * FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    # cursor.execute(query)

    # Execute a query to get data from your table (replace 'your_table' with your actual table name)
    # Only select the specified columns
    # query = f'SELECT {", ".join(selected_columns)} FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    # query = f'SELECT {", ".join(selected_columns)} FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH FIRST {entries_per_page} ROWS ONLY'
    # query = f'SELECT {", ".join(selected_columns)} FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    # query = f'SELECT * from {table_name}'
    query = Query.from_(table).select('*')

    cursor.execute(str(query))

    # num_pages = (total_rows // entries_per_page) + (1 if total_rows % entries_per_page > 0 else 0)

    # Fetch column names
    columns = [column[0] for column in cursor.description]

    # Fetch all rows
    data = cursor.fetchall()

    # Close the connection
    connection.close()

    return columns, data


def get_runtime_stats():
    connection = get_db_connection()
    cursor = connection.cursor()

    # Calculate the offset based on the current page
    # offset = (page - 1) * entries_per_page

    # Execute a query to get the total number of rows
    # count_query = 'select ApplicationServerTipi, COUNT(ApplicationServerTipi) AS ApplicationServerTipiCount from BackendEnvanter group by ApplicationServerTipi'
    BackendEnvanterTable = Table('BackendEnvanter')
    count_query = Query.from_(BackendEnvanterTable).select(BackendEnvanterTable.ApplicationServerTipi, fn.Count(
        BackendEnvanterTable.ApplicationServerTipi)).groupby(BackendEnvanterTable.ApplicationServerTipi)
    cursor.execute(str(count_query))
    # total_rows = cursor.fetchone()[0]

    # Execute a query to get data from your table (replace 'your_table' with your actual table name)
    # query = f'SELECT * FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    # cursor.execute(query)

    # Execute a query to get data from your table (replace 'your_table' with your actual table name)
    # Only select the specified columns
    # query = f'SELECT {", ".join(selected_columns)} FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    # query = f'SELECT {", ".join(selected_columns)} FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH FIRST {entries_per_page} ROWS ONLY'
    # query = f'SELECT {", ".join(selected_columns)} FROM AppOrtamTable ORDER BY id OFFSET {offset} ROWS FETCH NEXT {entries_per_page} ROWS ONLY'
    # num_pages = (total_rows // entries_per_page) + (1 if total_rows % entries_per_page > 0 else 0)

    # Fetch column names

    # Fetch all rows
    data = cursor.fetchall()

    # Close the connection
    connection.close()

    return data


@app.route('/')
def index():
    if current_user.is_authenticated:
        # Check if user has access to this endpoint
        if '/' not in get_user_allowed_endpoints():
            return redirect(url_for('firewall'))

        envanter_table_name = "BackendEnvanter"
        columns, data = get_data(envanter_table_name)

        selected_columns = ["ServisTipi", "ServisAdı", "Makine",
                            "ApplicationServerTipi", "JavaTipi", "UygulamaKritiklik", "UygulamaTipi"]
        detail_columns = ["ostip", "JavaVersion", "AAMEnabled", "ApplicationServerPath"]

        all_columns = get_all_columns(envanter_table_name)
        return render_template(
            'index.html', username=current_user.username,
            all_columns=all_columns, selected_columns=selected_columns, columns=columns, detail_columns=detail_columns,
            data=data, allowed_endpoints=get_user_allowed_endpoints())
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        use_ldap = os.getenv('USE_LDAP_AUTH', 'False').lower() in ['true', '1', 't']

        if use_ldap:
            # LDAP Authentication
            logging.debug(f"Attempting LDAP authentication for user: {username}")
            form = LDAPLoginForm()
            # response = ldap_manager.authenticate(username, password)
            # if response.status == AuthenticationResponseStatus.success:
            if form.validate_on_submit():
                logging.debug(f"LDAP authentication successful for user: {username}")
                logging.debug(f"User attributes are {form.user.data}, DN: {form.user.dn}, Role: {form.user.role}")
                # Successfully logged in, We can now access the saved user object
                # via form.user.
                login_user(form.user)  # Tell flask-login to log them in.
                logging.debug(f"Logged in LDAP user: {current_user.username} with role: {current_user.role}")
                return redirect('/')  # Send them home
            else:
                # logging.warning(f"LDAP authentication failed for user: {username} with status: ")
                error='Invalid credentials.'
                return render_template('login.html',error=error)
        else:
            # Local Authentication
            logging.debug(f"Attempting local authentication for user: {username}")
            if is_valid_credentials(username, password):
                logging.debug(f"Local authentication successful for user: {username}")
                user = User(username, username, {}, role='default') # Local auth doesn't have dn, data, assign default role
                login_user(user)
                logging.debug(f"Logged in local user: {current_user.username} with role: {current_user.role}")
                flash('Logged in successfully.', 'success')
                return redirect(url_for('index'))
            else:
                logging.warning(f"Local authentication failed for user: {username}")
                error='Invalid local credentials. Please try again.'
                return render_template('login.html', error=error)

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))


@app.route('/chart')
def deneme():
    if current_user.is_authenticated:
        # Check if user has access to this endpoint
        if '/chart' not in get_user_allowed_endpoints():
            return redirect(url_for('fw'))

        runtime_stats = get_runtime_stats()
        return render_template('chart.html', runtime_stats=runtime_stats,
                               allowed_endpoints=get_user_allowed_endpoints(),
                               username=current_user.username)
    else:
        return redirect(url_for('login'))


def discover_sharepoint_folders():
    """Discover all folders in the SharePoint site"""
    try:
        # Get SharePoint credentials from environment variables
        site_url = os.getenv('SHAREPOINT_SITE_URL')
        username = os.getenv('SHAREPOINT_USERNAME')
        password = os.getenv('SHAREPOINT_PASSWORD')
        domain = os.getenv('SHAREPOINT_DOMAIN')
        root_folder = os.getenv('SHAREPOINT_ROOT_FOLDER', '/Shared Documents')

        # Set up NTLM authentication
        auth = HttpNtlmAuth(f"{domain}\\{username}", password)

        # Headers for SharePoint REST API
        headers = {
            'Accept': 'application/json;odata=verbose',
            'Content-Type': 'application/json;odata=verbose'
        }

        # Get root folder
        api_base = f"{site_url}/_api/web"
        root_folder_url = f"{api_base}/GetFolderByServerRelativeUrl('{root_folder}')/Folders"

        response = requests.get(root_folder_url, auth=auth, headers=headers, verify=False)
        response.raise_for_status()

        folders = []
        root_folders = response.json()['d']['results']

        # Process each root folder
        for folder in root_folders:
            folder_url = folder['ServerRelativeUrl']
            folders.append(folder_url)

            # Get subfolders recursively
            try:
                subfolders_url = f"{api_base}/GetFolderByServerRelativeUrl('{folder_url}')/Folders"
                subfolders_response = requests.get(subfolders_url, auth=auth, headers=headers, verify=False)
                subfolders_response.raise_for_status()

                subfolders = subfolders_response.json()['d']['results']
                for subfolder in subfolders:
                    folders.append(subfolder['ServerRelativeUrl'])
            except Exception as e:
                print(f"Error getting subfolders for {folder_url}: {str(e)}")
                continue

        return folders

    except Exception as e:
        print(f"Error discovering folders: {str(e)}")
        return []


def download_latest_sharepoint_files():
    """Download the latest file from each discovered SharePoint folder using NTLM authentication"""
    print(f"Starting download at {datetime.now(pytz.timezone('Europe/Istanbul')).strftime('%Y-%m-%d %H:%M:%S %Z')}")
    try:
        # Get SharePoint credentials from environment variables
        site_url = os.getenv('SHAREPOINT_SITE_URL')
        username = os.getenv('SHAREPOINT_USERNAME')
        password = os.getenv('SHAREPOINT_PASSWORD')
        domain = os.getenv('SHAREPOINT_DOMAIN')
        root_folder = os.getenv('SHAREPOINT_ROOT_FOLDER', '/Shared Documents')

        # Discover folders
        folder_urls = discover_sharepoint_folders()
        if not folder_urls:
            print("No folders discovered")
            return {}

        # Set up NTLM authentication
        auth = HttpNtlmAuth(f"{domain}\\{username}", password)

        # Headers for SharePoint REST API
        headers = {
            'Accept': 'application/json;odata=verbose',
            'Content-Type': 'application/json;odata=verbose'
        }

        downloaded_files = {}  # Dictionary to store downloaded files by folder

        for folder_url in folder_urls:
            try:
                # Construct the API URL for this folder
                api_base = f"{site_url}/_api/web"
                folder_api_url = f"{api_base}/GetFolderByServerRelativeUrl('{folder_url}')/Files"

                # Get list of files in the folder
                response = requests.get(folder_api_url, auth=auth, headers=headers, verify=False)
                response.raise_for_status()

                # Parse the response
                files_data = response.json()['d']['results']

                if not files_data:
                    print(f"No files found in folder: {folder_url}")
                    continue

                # Filter files for .txt extension and '2026' in name
                # TODO: Make this dynamic and not hardcoded
                filtered_files = [
                    f for f in files_data
                    if f['Name'].lower().endswith('.txt') and '2026' in f['Name']
                ]

                if not filtered_files:
                    print(f"No matching files found in folder: {folder_url}")
                    continue

                # Find the latest file from filtered list
                latest_file = max(filtered_files, key=lambda x: datetime.strptime(
                    x['TimeLastModified'], "%Y-%m-%dT%H:%M:%SZ"))

                # Download the file
                file_url = latest_file['ServerRelativeUrl'].split('/')
                file_actual_url = '/' + '/'.join(file_url[(len(root_folder.split('/')) -1):])
                file_name = os.path.basename(file_actual_url)
                download_path = os.path.join('static', file_name)

                # Get the file content
                file_response = requests.get(f"{site_url}{file_actual_url}", auth=auth, verify=False)
                file_response.raise_for_status()

                # Save the file
                with open(download_path, "wb") as local_file:
                    local_file.write(file_response.content)

                print(f"Successfully downloaded {file_name} from {folder_url}")
                downloaded_files[folder_url] = download_path

            except requests.exceptions.RequestException as e:
                print(f"Error processing folder {folder_url}: {str(e)}")
                continue
            except Exception as e:
                print(f"Unexpected error processing folder {folder_url}: {str(e)}")
                continue

    except Exception as e:
        print(f"Unexpected error in main process: {str(e)}")
        return {}

    # After all files are downloaded, if any, merge and cache
    if downloaded_files:
        merged_file_path = os.path.join('static', 'merged_fw.txt')
        merged_content = merge_fw_files(downloaded_files.values())
        with open(merged_file_path, 'w', encoding='utf-8') as f:
            f.write(merged_content)
        process_and_cache_fw_data(merged_file_path)

    return downloaded_files


def schedule_daily_download():
    """Schedule the daily download at 7:00 AM Istanbul time"""
    def job():
        # Convert current time to Istanbul time to check if we should run
        istanbul_tz = pytz.timezone('Europe/Istanbul')
        ist_time = datetime.now(istanbul_tz)
        print(f"Current time in Istanbul: {ist_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        # Download latest files and, if any were downloaded, merge into the merged_fw file
        downloaded_files = download_latest_sharepoint_files()
        if downloaded_files:
            try:
                merged_file_path = os.path.join('static', 'merged_fw.txt')
                merged_content = merge_fw_files(downloaded_files.values())
                with open(merged_file_path, 'w', encoding='utf-8') as f:
                    f.write(merged_content)
                print(f"Scheduled job: merged {len(downloaded_files)} files into {merged_file_path}")
                process_and_cache_fw_data(merged_file_path)
            except Exception as e:
                print(f"Scheduled job: failed to merge downloaded files: {e}")

    # Schedule for 5 AM every day
    schedule.every().day.at("04:00").do(job)
    print("Scheduled daily download for 7:00 AM Istanbul time...")
    
    while True:
        schedule.run_pending()
        time.sleep(60)


def merge_fw_files(file_paths):
    """Merge multiple firewall files into a single file with proper separators"""
    merged_content = []

    for file_path in file_paths:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read().strip()
                if content:  # Only add non-empty content
                    merged_content.append(content)
        except Exception as e:
            print(f"Error reading file {file_path}: {str(e)}")
            continue

    # Join all content with separator
    return '\n==============================\n'.join(merged_content)


def should_download_files():
    """Check if files should be downloaded based on file existence and age"""
    merged_file_path = os.path.join('static', 'merged_fw.txt')

    # If file doesn't exist, we should download
    if not os.path.exists(merged_file_path):
        return True

    # Check file age
    file_age = datetime.now() - datetime.fromtimestamp(os.path.getmtime(merged_file_path))

    # If file is older than 24 hours, we should download
    return file_age.total_seconds() > 24 * 3600


@app.route('/fw')
def firewall():
    if current_user.is_authenticated:
        # Check if user has access to this endpoint
        if '/fw' not in get_user_allowed_endpoints():
            return redirect(url_for('index'))

        file_path = os.path.join('static', 'merged_fw.txt')
        last_updated = None

        # Only download if necessary
        if should_download_files():
            print("Downloading new files...")
            downloaded_files = download_latest_sharepoint_files()

            if downloaded_files:
                # Create a merged file
                merged_content = merge_fw_files(downloaded_files.values())

                # Write merged content to file
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(merged_content)

                process_and_cache_fw_data(file_path) # Cache the new data
                last_updated = datetime.now(pytz.timezone('Europe/Istanbul')) # Update last_updated

            else:
                # If download fails, use sample file
                file_path = 'static/samplefw.txt'
                process_and_cache_fw_data(file_path) # Cache sample data as well
                last_updated = datetime.now(pytz.timezone('Europe/Istanbul'))

        else:
            print("Using existing merged file...")
            if os.path.exists(file_path):
                last_updated = datetime.fromtimestamp(os.path.getmtime(file_path), pytz.timezone('Europe/Istanbul'))

        # Try to load from cache first
        if os.path.exists(PARSED_FW_DATA_PATH):
            try:
                with open(PARSED_FW_DATA_PATH, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                cached_timestamp = datetime.fromisoformat(cached_data['timestamp'])

                # Check if cache is fresh enough (e.g., less than an hour old or newer than merged_fw.txt)
                if (datetime.now(pytz.timezone('Europe/Istanbul')) - cached_timestamp).total_seconds() < 3600 or \
                   (os.path.exists(file_path) and cached_timestamp >= datetime.fromtimestamp(os.path.getmtime(file_path), pytz.timezone('Europe/Istanbul'))):
                    groups = cached_data['groups']
                    groups_dict = cached_data['groups_dict']
                    print("Loaded firewall data from cache.")
                else:
                    print("Cached data is stale, re-parsing...")
                    if process_and_cache_fw_data(file_path):
                        with open(PARSED_FW_DATA_PATH, 'r', encoding='utf-8') as f:
                            cached_data = json.load(f)
                            groups = cached_data['groups']
                            groups_dict = cached_data['groups_dict']
                    else:
                        # Fallback if parsing and caching fails
                        groups = parse_fw_file(file_path)
                        groups_dict = {g['name']: g for g in groups}
            except Exception as e:
                print(f"Error loading from cache, re-parsing: {e}")
                groups = parse_fw_file(file_path)
                groups_dict = {g['name']: g for g in groups}
        else:
            # If no cache file, parse and create cache
            print("No cache file found, parsing and creating...")
            if process_and_cache_fw_data(file_path):
                with open(PARSED_FW_DATA_PATH, 'r', encoding='utf-8') as f:
                    cached_data = json.load(f)
                    groups = cached_data['groups']
                    groups_dict = cached_data['groups_dict']
            else:
                # Fallback if parsing and caching fails
                groups = parse_fw_file(file_path)
                groups_dict = {g['name']: g for g in groups}

        # Filter out groups that are children of other groups
        child_groups = {child for group in groups for child in group['children']}
        filtered_groups = [group for group in groups if group['name'] not in child_groups]

        return render_template('fw.html',
                               groups=filtered_groups,
                               groups_dict=groups_dict,
                               last_updated=last_updated.strftime('%Y-%m-%d %H:%M:%S') if last_updated else None,
                               allowed_endpoints=get_user_allowed_endpoints(),
                               username=current_user.username)
    else:
        return redirect(url_for('login'))


@app.route('/trigger-download', methods=['POST'])
@login_required
def trigger_download():
    # if 'username' not in session:
    #     return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401

    try:
        # Download the latest files from SharePoint
        downloaded_files = download_latest_sharepoint_files()

        if downloaded_files:
            # Create a merged file
            merged_file_path = os.path.join('static', 'merged_fw.txt')
            merged_content = merge_fw_files(downloaded_files.values())

            # Write merged content to file
            with open(merged_file_path, 'w', encoding='utf-8') as f:
                f.write(merged_content)

            process_and_cache_fw_data(merged_file_path)
            
            return jsonify({
                'status': 'success',
                'message': f'Successfully downloaded and merged {len(downloaded_files)} files',
                'files': list(downloaded_files.keys()),
                'last_updated': datetime.now(pytz.timezone('Europe/Istanbul')).strftime('%Y-%m-%d %H:%M:%S')
            })
        else:
            return jsonify({
                'status': 'warning',
                'message': 'No files were downloaded'
            })

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': f'Error during download: {str(e)}'
        }), 500


@app.route('/add_service', methods=['POST'])
def add_service():
    if request.method == 'POST':
        hostname = request.json['hostname']
        servicenames = request.json['servicenames']
        insert_query(hostname, servicenames)
        return "Succesfully added entry"


@app.route('/update_os_version', methods=['POST'])
def update_os_handler():
    if request.method == 'POST':
        hostname = request.json['hostname']
        os_version = request.json['os_version']
        update_os_version(hostname, os_version)
        return "Succesfully added entry"

@app.route('/topology/<app_name>')
def get_topology(app_name):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    if flask_mongodb_db is None:
        return jsonify({"error": "MongoDB connection not available"}), 500
    
    # Query all instances and filter by base app name extracted from instance_name
    # JVM names follow pattern like AppName+NodeID, extract base name for grouping
    all_instances = list(flask_mongodb_db.apps_current.find({}))
    
    # Filter instances where the base app name (extracted from instance_name) matches
    instances = []
    for inst in all_instances:
        instance_name = inst.get('instance_name', '')
        # Extract base application name by removing trailing digits
        base_app_name = re.sub(r'\d+$', '', instance_name).rstrip('_').rstrip('-')
        # Also check the stored app_name field as fallback
        if base_app_name == app_name or inst.get('app_name') == app_name:
            instances.append(inst)
    
    nodes = []
    edges = []
    seen_nodes = set()

    for inst in instances:
        instance_id = inst.get('instance_name', inst.get('_id', 'unknown'))
        
        # 1. Uygulama Node'u (JVM)
        if instance_id not in seen_nodes:
            nodes.append({
                "id": instance_id,
                "label": f"{instance_id}\n({inst.get('type', 'Unknown')})",
                "group": "jvm",
                "title": f"Java: {inst.get('java', {}).get('version', 'Unknown')}", # Hover bilgisi
                "details": inst # Tüm datayı JS tarafına gönderiyoruz
            })
            seen_nodes.add(instance_id)

        # 2. NetScaler Node'ları ve Bağlantıları
        for dns in inst.get('dns_records', []):
            if dns not in seen_nodes:
                nodes.append({"id": dns, "label": dns, "group": "netscaler"})
                seen_nodes.add(dns)
            edges.append({"from": dns, "to": instance_id, "arrows": "to"})

        # 3. Database Node'ları ve Bağlantıları
        for db_conn in inst.get('connected_dbs', []):
            if db_conn not in seen_nodes:
                nodes.append({"id": db_conn, "label": db_conn, "group": "database"})
                seen_nodes.add(db_conn)
            edges.append({"from": instance_id, "to": db_conn, "arrows": "to"})

    return render_template('topology_vis.html', 
        nodes=nodes, 
        edges=edges, 
        app_name=app_name,
        allowed_endpoints=get_user_allowed_endpoints()
    )


# =============================
# ENVANTER ARAMA (SEARCH PAGE)
# =============================
import re
import json

def build_mongo_query_from_filters(filters_json_str):
    """
    Görsel query builder'dan gelen filtreleri MongoDB query'sine çevirir.
    
    filters_json_str: JSON string, örnek:
    {
        "filter-0": {
            "field": "java.vendor",
            "operator": "equals",
            "value": "IBM",
            "logic": "AND"
        },
        "filter-1": {
            "field": "type",
            "operator": "contains",
            "value": "Tomcat",
            "logic": "OR"
        }
    }
    """
    if not filters_json_str:
        return {}
    
    try:
        filters = json.loads(filters_json_str)
    except:
        return {}
    
    if not filters:
        return {}
    
    # Filtreleri logic'e göre grupla
    and_conditions = {}
    or_groups = []
    current_and_group = {}
    
    filter_items = list(filters.items())
    
    for idx, (filter_id, filter_data) in enumerate(filter_items):
        field = filter_data.get('field', '').strip()
        operator = filter_data.get('operator', 'equals')
        value = filter_data.get('value', '').strip()
        logic = filter_data.get('logic', 'AND')
        
        if not field or not value:
            continue
        
        # Operator'a göre MongoDB query oluştur
        mongo_condition = None
        if operator == 'equals':
            # Case-insensitive exact match
            mongo_condition = {field: {"$regex": f"^{re.escape(value)}$", "$options": "i"}}
        elif operator == 'contains':
            mongo_condition = {field: {"$regex": re.escape(value), "$options": "i"}}
        elif operator == 'starts_with':
            mongo_condition = {field: {"$regex": f"^{re.escape(value)}", "$options": "i"}}
        elif operator == 'ends_with':
            mongo_condition = {field: {"$regex": f"{re.escape(value)}$", "$options": "i"}}
        elif operator == 'regex':
            mongo_condition = {field: {"$regex": value, "$options": "i"}}
        
        # Array field'lar için $elemMatch kullan (on_netscalers, connected_dbs gibi)
        if field in ['on_netscalers', 'connected_dbs', 'dns_records']:
            if operator == 'equals':
                mongo_condition = {field: {"$elemMatch": {"$regex": f"^{re.escape(value)}$", "$options": "i"}}}
            elif operator == 'contains':
                mongo_condition = {field: {"$elemMatch": {"$regex": re.escape(value), "$options": "i"}}}
            elif operator == 'starts_with':
                mongo_condition = {field: {"$elemMatch": {"$regex": f"^{re.escape(value)}", "$options": "i"}}}
            elif operator == 'ends_with':
                mongo_condition = {field: {"$elemMatch": {"$regex": f"{re.escape(value)}$", "$options": "i"}}}
            elif operator == 'regex':
                mongo_condition = {field: {"$elemMatch": {"$regex": value, "$options": "i"}}}
        
        if not mongo_condition:
            continue
        
        # Logic'e göre ekle
        if logic == 'OR' or (idx > 0 and filter_items[idx-1][1].get('logic') == 'OR'):
            # OR grubu başlat veya mevcut AND grubunu OR grubuna ekle
            if current_and_group:
                or_groups.append(current_and_group)
                current_and_group = {}
            current_and_group.update(mongo_condition)
        else:
            # AND - mevcut gruba ekle
            current_and_group.update(mongo_condition)
    
    # Son grubu ekle
    if current_and_group:
        if or_groups:
            or_groups.append(current_and_group)
        else:
            and_conditions.update(current_and_group)
    
    # Final query oluştur
    if or_groups:
        # OR grupları varsa $or kullan
        if len(or_groups) == 1:
            return or_groups[0]
        return {"$or": or_groups}
    elif and_conditions:
        return and_conditions
    
    return {}

@app.route('/search', methods=['GET'])
def search_inventory():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    if flask_mongodb_db is None:
        return 'MongoDB bağlantısı yok', 500

    filters_json = request.args.get('filters_json', '')
    
    # Autocomplete için tüm field'ların distinct değerlerini hazırla
    field_values = {
        'app_name': sorted(flask_mongodb_db.apps_current.distinct('app_name')),
        'instance_name': sorted(flask_mongodb_db.apps_current.distinct('instance_name')),
        'server_ip': sorted(flask_mongodb_db.apps_current.distinct('server_ip')),
        'hostname': sorted(flask_mongodb_db.apps_current.distinct('hostname')),
        'type': sorted(flask_mongodb_db.apps_current.distinct('type')),
        'java.vendor': sorted([j for j in set([doc.get('java', {}).get('vendor','') for doc in flask_mongodb_db.apps_current.find({}, {'java.vendor': 1})]) if j]),
        'java.version': sorted([j for j in set([doc.get('java', {}).get('version','') for doc in flask_mongodb_db.apps_current.find({}, {'java.version': 1})]) if j]),
        'pid': sorted([str(p) for p in set([doc.get('pid','') for doc in flask_mongodb_db.apps_current.find({}, {'pid': 1})]) if p]),
    }
    
    # Array field'lar için tüm değerleri topla
    all_netscalers = set()
    all_dbs = set()
    all_dns = set()
    for doc in flask_mongodb_db.apps_current.find({}, {'on_netscalers': 1, 'connected_dbs': 1, 'dns_records': 1}):
        all_netscalers.update(doc.get('on_netscalers', []))
        all_dbs.update(doc.get('connected_dbs', []))
        all_dns.update(doc.get('dns_records', []))
    field_values['on_netscalers'] = sorted(list(all_netscalers))
    field_values['connected_dbs'] = sorted(list(all_dbs))
    field_values['dns_records'] = sorted(list(all_dns))

    # Filtreleri parse et ve query oluştur
    query = build_mongo_query_from_filters(filters_json) if filters_json else {}
    
    # Sonuçları bul - boş query ise tüm sonuçları getir
    if query:
        results = list(flask_mongodb_db.apps_current.find(query))
    else:
        # Filtre yoksa tüm sonuçları getir
        results = list(flask_mongodb_db.apps_current.find({}))

    return render_template('search.html',
        results=results,
        filters_json=filters_json,  # Filtreleri geri gönder
        field_values=field_values,  # Autocomplete için
        allowed_endpoints=get_user_allowed_endpoints()
    )

# ============================================================================
# FastAPI MongoDB Backend for Java/Middleware Inventory
# ============================================================================

# FastAPI app for inventory API
fastapi_app = FastAPIApp(
    title="Middleware & Java Inventory API",
    description="Centralized inventory system for Middleware and Java applications",
    version="1.0.0"
)

# CORS middleware for FastAPI
fastapi_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection for inventory
mongodb_client: Optional[AsyncIOMotorClient] = None
mongodb_db = None
mongodb_collection = None

# Synchronous MongoDB client for Flask routes
flask_mongodb_client = None
flask_mongodb_db = None

def init_flask_mongodb():
    """Initialize synchronous MongoDB connection for Flask routes."""
    global flask_mongodb_client, flask_mongodb_db
    try:
        mongodb_url = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
        mongodb_db_name = os.getenv("MONGODB_DB", "inventory")
        # Check if middleware_db exists (from seed.py), otherwise use inventory
        flask_mongodb_client = MongoClient(mongodb_url)
        # Try middleware_db first (used by seed.py), fallback to inventory
        if "middleware_db" in flask_mongodb_client.list_database_names():
            flask_mongodb_db = flask_mongodb_client["middleware_db"]
        else:
            flask_mongodb_db = flask_mongodb_client[mongodb_db_name]
        logging.info(f"Flask: Connected to MongoDB {flask_mongodb_db.name}")
    except Exception as e:
        logging.error(f"Flask: Failed to connect to MongoDB: {e}")

# Initialize Flask MongoDB on import
init_flask_mongodb()

# Pydantic models for FastAPI
class JavaInfo(BaseModel):
    path: str
    vendor: str
    version: str


class DBConnection(BaseModel):
    host: str
    port: int
    type: str


class ProcessData(BaseModel):
    pid: int
    hostname: str
    app_name: str
    runtime_type: str
    java: JavaInfo
    jvm_args: List[str]
    jvm_args_raw: str
    db_connections: List[DBConnection]
    working_directory: Optional[str] = None
    discovered_at: str


class DiscoveryPayload(BaseModel):
    hostname: str
    discovered_at: str
    processes: List[ProcessData]
    process_count: int


class AppSummary(BaseModel):
    app_name: str
    total_instances: int
    running_instances: int
    hosts: List[str]
    runtime_types: List[str]
    config_differences: Dict[str, Any] = {}


@fastapi_app.on_event("startup")
async def startup_mongodb():
    """Initialize MongoDB connection for FastAPI."""
    global mongodb_client, mongodb_db, mongodb_collection
    try:
        mongodb_url = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
        mongodb_db_name = os.getenv("MONGODB_DB", "inventory")
        mongodb_collection_name = os.getenv("MONGODB_COLLECTION", "java_apps")
        
        mongodb_client = AsyncIOMotorClient(mongodb_url)
        mongodb_db = mongodb_client[mongodb_db_name]
        mongodb_collection = mongodb_db[mongodb_collection_name]
        
        # Create indexes for efficient queries
        await mongodb_collection.create_index([("hostname", 1), ("pid", 1)], unique=True)
        await mongodb_collection.create_index([("app_name", 1)])
        await mongodb_collection.create_index([("hostname", 1)])
        await mongodb_collection.create_index([("last_seen", -1)])
        await mongodb_collection.create_index([("is_running", 1)])
        
        logging.info(f"FastAPI: Connected to MongoDB {mongodb_db_name}/{mongodb_collection_name}")
    except Exception as e:
        logging.error(f"FastAPI: Failed to connect to MongoDB: {e}")


@fastapi_app.on_event("shutdown")
async def shutdown_mongodb():
    """Close MongoDB connection."""
    global mongodb_client
    if mongodb_client:
        mongodb_client.close()
        logging.info("FastAPI: MongoDB connection closed")


async def mark_missing_processes_as_stopped(
    hostname: str,
    current_pids: set,
    current_time: datetime
):
    """
    Mark processes that were not found in the latest scan as is_running: False.
    This handles lifecycle management.
    """
    try:
        # Find all processes for this host that are marked as running
        running_processes = await mongodb_collection.find({
            "hostname": hostname,
            "is_running": True
        }).to_list(length=None)
        
        # Mark processes that are no longer running
        updates = []
        for proc in running_processes:
            if proc["pid"] not in current_pids:
                updates.append(
                    UpdateOne(
                        {"_id": proc["_id"]},
                        {
                            "$set": {
                                "is_running": False,
                                "last_seen": current_time
                            }
                        }
                    )
                )
        
        if updates:
            await mongodb_collection.bulk_write(updates)
            logging.info(f"FastAPI: Marked {len(updates)} processes as stopped on {hostname}")
            
    except Exception as e:
        logging.error(f"FastAPI: Error marking stopped processes: {e}", exc_info=True)


def detect_config_drift(instances: List[Dict]) -> Dict[str, Any]:
    """
    Detect configuration differences between instances of the same app.
    Compares JVM args, Java versions, etc.
    """
    if len(instances) < 2:
        return {}
    
    differences = {}
    
    # Compare JVM args
    jvm_args_sets = [set(inst.get("jvm_args", [])) for inst in instances]
    if len(set(tuple(sorted(args)) for args in jvm_args_sets)) > 1:
        differences["jvm_args"] = {
            "status": "drift_detected",
            "message": "JVM arguments differ between instances",
            "instances": {
                f"{inst['hostname']}:{inst['pid']}": inst.get("jvm_args", [])
                for inst in instances
            }
        }
    
    # Compare Java versions
    java_versions = [inst.get("java", {}).get("version", "Unknown") for inst in instances]
    unique_versions = set(java_versions)
    if len(unique_versions) > 1:
        differences["java_versions"] = {
            "status": "drift_detected",
            "message": "Java versions differ between instances",
            "versions": list(unique_versions),
            "instances": {
                f"{inst['hostname']}:{inst['pid']}": inst.get("java", {}).get("version", "Unknown")
                for inst in instances
            }
        }
    
    # Compare Java vendors
    java_vendors = [inst.get("java", {}).get("vendor", "Unknown") for inst in instances]
    unique_vendors = set(java_vendors)
    if len(unique_vendors) > 1:
        differences["java_vendors"] = {
            "status": "drift_detected",
            "message": "Java vendors differ between instances",
            "vendors": list(unique_vendors)
        }
    
    return differences


# FastAPI Endpoints
@fastapi_app.post("/api/v1/discovery", status_code=200)
async def receive_discovery(
    payload: DiscoveryPayload,
    background_tasks: BackgroundTasks
):
    """
    Receive discovery data from collector scripts.
    Stores each JVM process as a separate document (app-centric model).
    """
    try:
        current_time = datetime.now(timezone.utc)
        hostname = payload.hostname
        
        # Track current PIDs for this host to mark missing ones as not running
        current_pids = {p.pid for p in payload.processes}
        
        # Prepare bulk operations
        bulk_operations = []
        
        for process in payload.processes:
            # Create document for this JVM process
            doc = {
                "pid": process.pid,
                "hostname": hostname,
                "app_name": process.app_name,
                "runtime_type": process.runtime_type,
                "java": process.java.dict(),
                "jvm_args": process.jvm_args,
                "jvm_args_raw": process.jvm_args_raw,
                "db_connections": [conn.dict() for conn in process.db_connections],
                "working_directory": process.working_directory,
                "discovered_at": process.discovered_at,
                "last_seen": current_time,
                "is_running": True
            }
            
            # Upsert: update if exists (same hostname + pid), insert if new
            bulk_operations.append(
                UpdateOne(
                    {"hostname": hostname, "app_name": process.app_name},
                    {"$set": doc},
                    upsert=True
                )
            )
        
        # Execute bulk operations
        if bulk_operations:
            result = await mongodb_collection.bulk_write(bulk_operations)
            logging.info(
                f"FastAPI: Processed {result.upserted_count + result.modified_count} processes "
                f"from {hostname} ({result.upserted_count} new, {result.modified_count} updated)"
            )
        
        # Mark missing PIDs as not running (background task)
        background_tasks.add_task(
            mark_missing_processes_as_stopped,
            hostname,
            current_pids,
            current_time
        )
        
        return {
            "status": "success",
            "hostname": hostname,
            "processed": len(payload.processes),
            "timestamp": current_time.isoformat()
        }
        
    except Exception as e:
        logging.error(f"FastAPI: Error processing discovery data: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@fastapi_app.get("/api/v1/apps", response_model=List[AppSummary])
async def get_apps_summary(
    app_name: Optional[str] = None,
    hostname: Optional[str] = None,
    runtime_type: Optional[str] = None,
    is_running: Optional[bool] = None
):
    """
    Get summary of applications grouped by app_name.
    Supports filtering and provides HA/drift detection insights.
    """
    try:
        # Build query
        query = {}
        if app_name:
            query["app_name"] = app_name
        if hostname:
            query["hostname"] = hostname
        if runtime_type:
            query["runtime_type"] = runtime_type
        if is_running is not None:
            query["is_running"] = is_running
        
        # Aggregate by app_name
        pipeline = [
            {"$match": query},
            {
                "$group": {
                    "_id": "$app_name",
                    "instances": {"$push": "$$ROOT"},
                    "total_count": {"$sum": 1},
                    "running_count": {
                        "$sum": {"$cond": ["$is_running", 1, 0]}
                    },
                    "hosts": {"$addToSet": "$hostname"},
                    "runtime_types": {"$addToSet": "$runtime_type"}
                }
            }
        ]
        
        results = []
        async for group in mongodb_collection.aggregate(pipeline):
            instances = group["instances"]
            app_name_val = group["_id"]
            
            # Detect config differences (drift detection)
            config_differences = detect_config_drift(instances)
            
            results.append(AppSummary(
                app_name=app_name_val,
                total_instances=group["total_count"],
                running_instances=group["running_count"],
                hosts=sorted(group["hosts"]),
                runtime_types=sorted(group["runtime_types"]),
                config_differences=config_differences
            ))
        
        return sorted(results, key=lambda x: x.app_name)
        
    except Exception as e:
        logging.error(f"FastAPI: Error getting apps summary: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@fastapi_app.get("/api/v1/processes")
async def get_processes(
    hostname: Optional[str] = None,
    app_name: Optional[str] = None,
    is_running: Optional[bool] = None,
    limit: int = 100,
    skip: int = 0
):
    """
    Get detailed process information with filtering.
    """
    try:
        query = {}
        if hostname:
            query["hostname"] = hostname
        if app_name:
            query["app_name"] = app_name
        if is_running is not None:
            query["is_running"] = is_running
        
        cursor = mongodb_collection.find(query).sort("last_seen", -1).skip(skip).limit(limit)
        processes = await cursor.to_list(length=limit)
        
        # Convert ObjectId to string for JSON serialization
        for proc in processes:
            proc["_id"] = str(proc["_id"])
        
        total = await mongodb_collection.count_documents(query)
        
        return {
            "processes": processes,
            "total": total,
            "limit": limit,
            "skip": skip
        }
        
    except Exception as e:
        logging.error(f"FastAPI: Error getting processes: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@fastapi_app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    try:
        # Check MongoDB connection
        await mongodb_db.command("ping")
        return {
            "status": "healthy",
            "mongodb": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        logging.error(f"FastAPI: Health check failed: {e}")
        raise HTTPException(status_code=503, detail="MongoDB connection failed")


@fastapi_app.get("/")
async def fastapi_root():
    """Root endpoint with API information."""
    return {
        "name": "Middleware & Java Inventory API",
        "version": "1.0.0",
        "endpoints": {
            "discovery": "/api/v1/discovery",
            "apps": "/api/v1/apps",
            "processes": "/api/v1/processes",
            "health": "/api/v1/health"
        }
    }


if __name__ == '__main__':
    # Do initial download
    test_env = os.getenv('TEST', 'False').lower() in ['true', '1', 't']

    if not test_env:
        download_latest_sharepoint_files()
    
    # Start the scheduler in a separate thread
    import threading
    scheduler_thread = threading.Thread(target=schedule_daily_download)
    scheduler_thread.daemon = True
    scheduler_thread.start()
    
    # Run both Flask and FastAPI concurrently
    flask_port = int(os.getenv('FLASK_PORT', '5000'))
    fastapi_port = int(os.getenv('FASTAPI_PORT', '8000'))
    
    def run_flask():
        """Run Flask app in a separate thread."""
        logging.info(f"Starting Flask on port {flask_port}")
        app.run(host='0.0.0.0', port=flask_port, debug=False, use_reloader=False)
    
    def run_fastapi():
        """Run FastAPI app."""
        import uvicorn
        logging.info(f"Starting FastAPI on port {fastapi_port}")
        uvicorn.run(fastapi_app, host='0.0.0.0', port=fastapi_port)
    
    # Start Flask in a daemon thread
    flask_thread = threading.Thread(target=run_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    # Run FastAPI in the main thread (blocking)
    # This keeps the main process alive
    try:
        run_fastapi()
    except KeyboardInterrupt:
        logging.info("Shutting down servers...")


