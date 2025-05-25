from flask import Flask, render_template, request, redirect, url_for, session
import pyodbc
from datetime import timedelta
from pypika import Table, Query, Schema, functions as fn
import os

from parse_fw import parse_fw_file

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


@app.route('/fw')
def firewall():
    if 'username' in session:
        groups = parse_fw_file('static/samplefw.txt')
        groups_dict = {g['name']: g for g in groups}

        # Filter out groups that are children of other groups
        child_groups = {child for group in groups for child in group['children']}
        filtered_groups = [group for group in groups if group['name'] not in child_groups]

        return render_template('fw.html', groups=filtered_groups, groups_dict=groups_dict)
    else:
        return redirect(url_for('login'))


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
    app.run(debug=True)
