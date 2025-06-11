from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import pyodbc
from datetime import timedelta
from pypika import Table, Query, Schema, functions as fn
import os
import requests
from requests_ntlm import HttpNtlmAuth
import json
import schedule
import time
from datetime import datetime
from dotenv import load_dotenv

from parse_fw import parse_fw_file

load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

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
}


def is_valid_credentials(username, password):
    # Check if the provided username and password are valid
    return users.get(username) == password


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

    if 'username' in session:

        envanter_table_name = "BackendEnvanter"
    # for key in request.form.keys():
    #     values = request.form.getlist(key)
    #     print("Key", key, "Value:", values)

    # # Get the selected columns from the submitted form data
    # selected_columns = request.args.getlist('selected_columns')

    # if not selected_columns:
    #     selected_columns = ['*']

        columns, data = get_data(envanter_table_name)

        selected_columns = ["ServisTipi", "ServisAdı", "Makine",
                            "ApplicationServerTipi", "JavaTipi", "UygulamaKritiklik", "UygulamaTipi"]
        detail_columns = ["ostip", "JavaVersion", "AAMEnabled", "ApplicationServerPath"]

        all_columns = get_all_columns(envanter_table_name)
        return render_template(
            'index.html', username=session['username'],
            all_columns=all_columns, selected_columns=selected_columns, columns=columns, detail_columns=detail_columns,
            data=data)
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if is_valid_credentials(username, password):
            session.permanent = True
            session['username'] = username
            return redirect(url_for('index'))
        else:
            error = 'Invalid credentials. Please try again.'
            return render_template('login.html', error=error) if 'error' in locals() else render_template('login.html')

    else:
        if 'username' in session:
            return redirect(url_for('index'))
        else:
            return render_template('login.html') if 'error' in locals() else render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))


@app.route('/chart')
def deneme():
    if 'username' in session:
        runtime_stats = get_runtime_stats()
        return render_template('chart.html', runtime_stats=runtime_stats)
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
    try:
        # Get SharePoint credentials from environment variables
        site_url = os.getenv('SHAREPOINT_SITE_URL')
        username = os.getenv('SHAREPOINT_USERNAME')
        password = os.getenv('SHAREPOINT_PASSWORD')
        domain = os.getenv('SHAREPOINT_DOMAIN')

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

                # Filter files for .txt extension and '2025' in name
                filtered_files = [
                    f for f in files_data
                    if f['Name'].lower().endswith('.txt') and '2025' in f['Name']
                ]

                if not filtered_files:
                    print(f"No matching files found in folder: {folder_url}")
                    continue

                # Find the latest file from filtered list
                latest_file = max(filtered_files, key=lambda x: datetime.strptime(
                    x['TimeLastModified'], "%Y-%m-%dT%H:%M:%SZ"))

                # Download the file
                file_url = latest_file['ServerRelativeUrl'].split('/')
                file_actual_url = '/'+'/'.join(file_url[2:])
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

        return downloaded_files

    except Exception as e:
        print(f"Unexpected error in main process: {str(e)}")
        return {}


def schedule_daily_download():
    """Schedule the daily download at 5:00 AM"""
    schedule.every().day.at("05:00").do(download_latest_sharepoint_files)

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
    if 'username' in session:
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
                last_updated = datetime.now()
            else:
                # If download fails, use sample file
                file_path = 'static/samplefw.txt'
        else:
            print("Using existing merged file...")
            if os.path.exists(file_path):
                last_updated = datetime.fromtimestamp(os.path.getmtime(file_path))

        groups = parse_fw_file(file_path)
        groups_dict = {g['name']: g for g in groups}

        # Filter out groups that are children of other groups
        child_groups = {child for group in groups for child in group['children']}
        filtered_groups = [group for group in groups if group['name'] not in child_groups]

        return render_template('fw.html',
                               groups=filtered_groups,
                               groups_dict=groups_dict,
                               last_updated=last_updated.strftime('%Y-%m-%d %H:%M:%S') if last_updated else None)
    else:
        return redirect(url_for('login'))


@app.route('/trigger-download', methods=['POST'])
def trigger_download():
    if 'username' not in session:
        return jsonify({'status': 'error', 'message': 'Not authenticated'}), 401

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

            return jsonify({
                'status': 'success',
                'message': f'Successfully downloaded and merged {len(downloaded_files)} files',
                'files': list(downloaded_files.keys()),
                'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
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


if __name__ == '__main__':
    # Start the scheduler in a separate thread
    import threading
    scheduler_thread = threading.Thread(target=schedule_daily_download)
    scheduler_thread.daemon = True
    scheduler_thread.start()

    app.run(debug=True)
