import pyodbc
import os
from pypika import Table, Query, Schema, functions as fn
from config import db_config

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
    connection = get_db_connection()
    cursor = connection.cursor()

    info_schema = Schema('INFORMATION_SCHEMA')
    query = Query.from_(info_schema.COLUMNS).select('COLUMN_NAME').where(info_schema.COLUMNS.TABLE_NAME == table_name)
    print(str(query))
    cursor.execute(str(query))

    columns = [row.COLUMN_NAME for row in cursor.fetchall()]

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
            insert_query = Query.into(ServiceNameDetailsTable).columns(
                *servicename_details_data.keys()).insert(*servicename_details_data.values())

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

            cursor.execute(str(insert_query))

        if runtime == 'WLP':
            process_search_name = "/WLP/wlp/bin/tools/ws-server.jar {}".format(
                jvm_name)
        elif runtime == 'Tomcat':
            process_search_name = '/Tomcat/{}/temp org.apache.catalina.startup.Bootstrap.start'.format(service_name)
        else:
            process_search_name = "SampleProcessName"

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

        insert_query = Query.into(AppOrtamTable).columns(
            'ServiceType', 'ServiceName', 'Hostname', 'ApplicationType', 'ApplicationName', 'J2EE',
            'LBServiceName', 'OperasyonDurumu', 'generaltype', 'WebContainerPort', 'LBServiceGroup',
            'DeployStage', 'HealthCheckRequest', 'HealthCheckResponse', 'HealthCheckProtocol',
            'ProcessSearchName', 'step', 'kesintiservisismi', 'istirakadi'
        ).insert(*apportamtable_data.values())
        cursor.execute(str(insert_query))
        id = cursor.execute("SELECT @@Identity").fetchone()[0]
        print(id)

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

    query = Query.from_(table).select('*')

    cursor.execute(str(query))

    columns = [column[0] for column in cursor.description]

    data = cursor.fetchall()

    connection.close()

    return columns, data

def get_runtime_stats():
    connection = get_db_connection()
    cursor = connection.cursor()

    BackendEnvanterTable = Table('BackendEnvanter')
    count_query = Query.from_(BackendEnvanterTable).select(BackendEnvanterTable.ApplicationServerTipi, fn.Count(
        BackendEnvanterTable.ApplicationServerTipi)).groupby(BackendEnvanterTable.ApplicationServerTipi)
    cursor.execute(str(count_query))

    data = cursor.fetchall()

    connection.close()

    return data
